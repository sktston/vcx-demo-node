const { DisclosedProof } = require('../dist/src/api/disclosed-proof')
const { Connection } = require('../dist/src/api/connection')
const { Credential } = require('../dist/src/api/credential')
const { StateType } = require('../dist/src')
const sleepPromise = require('sleep-promise')
const demoCommon = require('./common')
const logger = require('./logger')
const url = require('url')
const ip = require('ip');
const isPortReachable = require('is-port-reachable')
const { runScript } = require('./script-comon')
const { shutdownVcx, downloadMessages, updateMessages, getVersion } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')
const { PhaseType, Report } = require('./report')

const express = require('express')
const bodyParser = require('body-parser')
const cluster = require('cluster')
const os = require('os')
const axios = require('axios')

const utime = Math.floor(new Date() / 1000)

let provisionConfig = {
  agency_url: process.env.AGENCY_URL ? process.env.AGENCY_URL : 'http://localhost:8080',
  agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
  agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  wallet_name: `node_vcx_demo_alice_wallet_${utime}`,
  wallet_key: '123',
  payment_method: 'null',
  enterprise_seed: '000000000000000000000000Trustee1'
}

const logLevel = process.env.VCX_LOG_LEVEL ? process.env.VCX_LOG_LEVEL : 'error'

const ariesProtocolType = '4.0'
const webHookUrl = 'http://' + ip.address() + ':7203/notifications/'
const inviteIssuerUrl = process.env.INVITE_ISSUER_URL ? process.env.INVITE_ISSUER_URL : 'http://localhost:7201/invitations'
const inviteVerifierUrl = process.env.INVITE_VERIFIER_URL ? process.env.INVITE_VERIFIER_URL : 'http://localhost:7202/invitations'

const report = new Report()
const maxRetry = 3
let initVCX = false
let numResponse = 0, numAck = 0, numCredOffer = 0, numCredential = 0, numPresent = 0

/***
 "@" symbol specifies  web hook received step -> total 9-step which receives corresponding agency message
 |------------|-----------------------------------------------|----------------------------------------------------|
 |   Phase    |                     FABER                     |                       ALICE                        |
 |------------|-----------------------------------------------|----------------------------------------------------|
 | Connection | STEP.1: create connection F & send invitation | STEP.2: receive invitation & create connection A2F |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.3: update connection from F to F2A      | @STEP.4 - connection created                       |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.5: receive connection created ACK       |                                                    |
 |------------|-----------------------------------------------|----------------------------------------------------|
 | Credential | STEP.6: send credential offer                 | @STEP.7: accept credential offer&request credential|
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.8: receive request & send credential    | @STEP.9: accept credential                         |
 |------------|-----------------------------------------------|----------------------------------------------------|
 | Proof      | STEP.10: request proof                        | @STEP.11: receive request & send proof             |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.12: receive & verify proof              | @STEP.13: receive proof ACK                        |
 |------------|-----------------------------------------------|----------------------------------------------------|
 ***/

async function runAliceMultiple (options) {
  // master process
  if (cluster.isMaster) {
    let numStart = 0
    let numDone = 0
    let numCycles = options.numCycles
    const numAlice = options.numAlice

    if (numCycles < numAlice) {
      numCycles = numAlice
    }

    logger.verbose(`IP: ${ip.address()}`)
    logger.verbose(`Num CPUS: ${os.cpus().length}`)

    await runWebHookServer()

    cluster.schedulingPolicy = cluster.SCHED_RR
    for (let i = 0; i < options.numAlice; i++) {
      const worker = cluster.fork()

      worker.on('message', async (msg) => {
        switch (msg.cmd) {
          case 'aliceDone':
            numDone += 1
            report.addRecordArray(msg.report)

            // start next transaction
            if (numStart < numCycles || options.infinite) {
              numStart += 1
              logger.verbose(`Running cycle number: ${numStart}/${numCycles}`)
              worker.send({cmd: 'aliceStart'})
            }

            // all transactions are done successfully
            if (numDone >= numCycles && !options.infinite) {
              await exitAllWorkers(true)
            }
            break

          // when error occurs, stop & exit all worker process
          case 'exitAll':
            await exitAllWorkers(false)
            break

          default:
            logger.error(`undefined cmd: ${msg.cmd}`)
            throw new Error(`undefined cmd: ${msg.cmd}`)
        }
      })

      numStart += 1
      worker.send({cmd: 'aliceStart'})
      await sleepPromise(options.aliceInterval * 1000)
    }

    cluster.on('exit', (worker, code, signal) => {
      const message = `Worker ${worker.process.pid} exits ` + (!code ? 'successfully' : `with error ${code}`)
      logger.verbose(message)
    })
  }
  // worker process
  else {
    process.on('message', async (msg) => {
      switch (msg.cmd) {
        case 'aliceStart':
          logger.verbose(`Alice[${cluster.worker.id}] starts`)
          try {
            await runAlice(cluster.worker.id, options)
          } catch (err) {
            logger.error(`runAlice error: ${err.message}`)
            process.send({cmd: 'exitAll'})
          }
          break

        case 'aliceExit':
          process.exit(0)
          break

        case 'aliceMessage':
          try {
            await processMessage(msg.body, cluster.worker.id, options)
          } catch (err) {
            logger.error(`processMessage error: ${err.message}`)
            process.send({cmd: 'exitAll'})
          }
          break

        default:
          logger.error(`Alice[${cluster.worker.id}] unknown master command`)
          throw new Error(`Alice[${cluster.worker.id}] unknown master command`)
      }
    })

    // register Ctrl-C handler to shutdown VCX with deleting wallet
    process.on('SIGINT', async (signal) => {
      logger.verbose(`${signal} worker [${cluster.worker.id}] -> shutdown VCX with deleting wallet`)
      await shutdownVcx(true)
      process.exit(0)
    })
  }
}

async function exitAllWorkers(print) {
  for (const id in cluster.workers) {
    cluster.workers[id].send({cmd: 'aliceExit'})
  }

  // wait all workers exits
  while (cluster.workers.length) {
    await sleepPromise(100)
  }

  if (print) {
    await sleepPromise(2000)
    report.print(report.getReport())
  }

  process.exit(0)
}

async function runWebHookServer() {
  const app = express()
  const port = url.parse(webHookUrl).port

  app.use(bodyParser.json())

  app.post('/notifications/:aliceId', async (req, res) => {
    const { aliceId } = req.params

    // push web hook message to corresponding worker
    cluster.workers[aliceId].send({ cmd: 'aliceMessage', body: req.body })
    res.status(200).send()
  })

  app.listen(port, () => logger.verbose(`Server listening on port ${port}...`))
}

async function runAlice (aliceId, options) {
  report.clearRecords()

  if (initVCX === false) {
    initVCX = true
    await demoCommon.initLibNullPay()

    logger.info(`Alice[${aliceId}]  #0 Initialize rust API from NodeJS`)
    await demoCommon.initRustApiAndLogger(logLevel)

    logger.info('#0-1 Check LibVCX version')
    const libVcxVersion = await getVersion()
    logger.info(`LibVCX Version: ${libVcxVersion}`)
    if (libVcxVersion.substr(0, 3) < 0.8) {
      logger.error(`LibVCX version must be higher than 0.8`)
      process.exit(1)
    }

    if (options.comm === 'aries') {
      //provisionConfig.protocol_type = '2.0'
      provisionConfig.protocol_type = ariesProtocolType
      provisionConfig.communication_method = 'aries'
      logger.info(`Alice[${aliceId}] Running with Aries VCX Enabled! Make sure VCX agency is configured to use protocol_type 2.0`)
    }

    if (options.postgresql) {
      await demoCommon.loadPostgresPlugin(provisionConfig)
      provisionConfig.wallet_type = 'postgres_storage'
      provisionConfig.storage_config = '{"url":"localhost:5432"}'
      provisionConfig.storage_credentials = '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}'
      logger.info(`Alice[${aliceId}] Running with PostreSQL wallet enabled! Config = ${provisionConfig.storage_config}`)
    } else {
      logger.info(`Alice[${aliceId}] Running with builtin wallet.`)
    }

    if (await isPortReachable(url.parse(webHookUrl).port, {host: url.parse(webHookUrl).hostname})) { // eslint-disable-line
      provisionConfig.webhook_url = webHookUrl + `${aliceId}`
      logger.info(`Alice[${aliceId}] Running with webhook notifications enabled! Webhook url = ${webHookUrl}`)
    } else {
      logger.info(`Alice[${aliceId}] Webhook url will not be used`)
    }
  }

  report.setStartTime(PhaseType.Onboard)

  logger.info(`Alice[${aliceId}] #8 Provision an agent and wallet, get back configuration details`)
  provisionConfig.wallet_name = `node_vcx_demo_alice_wallet_${utime}` + `_${aliceId}`

  const agentProvision = await demoCommon.provisionAgentInAgency(provisionConfig)
  agentProvision.institution_name = 'faber'
  agentProvision.institution_logo_url = 'http://robohash.org/234'
  agentProvision.genesis_path = `${__dirname}/docker.txn`

  logger.info(`Alice[${aliceId}] #9 Initialize libvcx with new configuration`)

  let retry = maxRetry
  do {
    try {
      await demoCommon.initVcxWithProvisionedAgentConfig(agentProvision)
      retry = 0
    } catch (err) {
      logger.warn(`initVcxWithProvisionedAgentConfig: ${err.message}`)
      await sleepPromise(1000 * Math.pow(2, maxRetry - retry))
      retry -= 1
    }
  } while(retry > 0)

  report.addRecord(aliceId, PhaseType.Onboard)

  // STEP.2 - receive invitation & create connection A2F
  // accept invitation
  logger.info(`Alice[${aliceId}] #10 Convert to valid json and string and create a connection to faber`)
  if (options.issuerInvite === 'auto') {
    try {
      const response = await axios.get(inviteIssuerUrl)
      options.issuerInvite = JSON.stringify(response.data)
    } catch (err) {
      throw new Error(`error response from issuer: ${err.message}`)
      return
    }
  }

  report.setStartTime(PhaseType.Issue)

  const connectionToFaber = await Connection.createWithInvite({id: 'faber', invite: options.issuerInvite})
  await connectionToFaber.connect({data: '{"use_public_did": true}'})
  await connectionToFaber.updateState()

  const serialConnectionToFaber = JSON.stringify(await connectionToFaber.serialize())
  const connectionToFaberPwDid = await connectionToFaber.getPwDid()

  await connectionToFaber.release()
  await walletAddRecord('connection', connectionToFaberPwDid, serialConnectionToFaber, {})
}

async function processMessage(message, aliceId, options) {
  const downloadMessagesParam = {
    //status: message.msgStatusCode,
    uids: message.msgUid,
    pairwiseDids: message.pwDid,
  }
  const dlMessages = JSON.parse(await downloadMessages(downloadMessagesParam))
  logger.debug(`Alice[${aliceId}] dlMessages: ${JSON.stringify(dlMessages, null, 2)}`)

  for (const message of dlMessages) {
    if (message.msgs.length < 1) {
      logger.error(`Alice[${aliceId}] message: ${JSON.stringify(message, null, 2)}`)
      throw new Error(`Alice[${aliceId}] message: ${JSON.stringify(message, null, 2)}`)
    }

    const pwDid = message.pairwiseDID
    const record = await walletGetRecord('connection', pwDid, {})
    const connectionToFaber = await Connection.deserialize(JSON.parse(JSON.parse(record).value))

    for (const msg of message.msgs) {
      // 'decryptedPayload' consists of 'payloadType' and 'payloadMsg'
      const payload = JSON.parse(msg.decryptedPayload)  // JSON Object
      const payloadType = payload['@type']              // JSON Object
      const payloadTypeName = payloadType.name          // String
      const payloadMsg = JSON.parse(payload['@msg'])    // JSON Object
      const payloadMsgType = payloadMsg['@type']        // String

      switch (payloadTypeName) {
        case 'aries': {
          // STEP.4 - connection created
          // connection response - At Invitee:
          if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/response') {
            logger.verbose(`Alice[${aliceId}] aries: spec/connections/1.0/response [${++numResponse}]`)
            await connectionToFaber.updateState()
            const connectionState = await connectionToFaber.getState()

            if (connectionState === StateType.Accepted) {
              const serialConnectionToFaber = JSON.stringify(await connectionToFaber.serialize())
              await walletUpdateRecordValue('connection', pwDid, serialConnectionToFaber)
            } else {
              logger.error(`Alice[${aliceId}] unexpected connection state: ${connectionState}`)
              throw new Error(`Alice[${aliceId}] unexpected connection state: ${connectionState}`)
            }
          }
          // STEP.13 - receive proof ACK
          // ack of proof request
          else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/present-proof/1.0/ack') {
            logger.verbose(`Alice[${aliceId}] aries: spec/present-proof/1.0/ack [${++numAck}]`)
            const threadId = payloadMsg['~thread'].thid
            const record = await walletGetRecord('proof', threadId, {})

            // TODO: Must replace connection_handle in credential - Need to consider better way
            const serialProof = JSON.parse(JSON.parse(record).value)
            serialProof.data.prover_sm.state.PresentationSent.connection_handle = connectionToFaber.handle
            const proof = await DisclosedProof.deserialize(serialProof)

            await proof.updateState()
            const proofState = await proof.getState()

            if (proofState === StateType.Accepted) {
              logger.info(`Alice[${aliceId}] Faber received & verified the proof`)
              report.addRecord(aliceId, PhaseType.Verify)

              const serialProof = JSON.stringify(await proof.serialize())
              await walletUpdateRecordValue('proof', threadId, serialProof)
            } else {
              logger.error(`Alice[${aliceId}] unexpected proof state: ${proofState}`)
              throw new Error(`Alice[${aliceId}] unexpected proof state: ${proofState}`)
            }

            await proof.release()
            logger.verbose(`Alice[${aliceId}] proof is verified`)

            logger.verbose(`Alice[${aliceId}] shutdown VCX with deleting wallet`)
            await shutdownVcx(true)

            process.send({cmd: 'aliceDone', report: report.getRecords()})
          } else {
            logger.error(`Alice[${aliceId}] msg: ${JSON.stringify(msg, null, 2)}`)
            logger.error(`Alice[${aliceId}] unknown payload message type name: ${payloadMsgType}`)
            throw new Error(`Alice[${aliceId}] unknown payload message type name: ${payloadMsgType}`)
          }
          break
        }

        // STEP.7 - accept credential offer & request credential
        case 'credential-offer': {
          logger.verbose(`Alice[${aliceId}] credential-offer: / [${++numCredOffer}]`)
          logger.info(`#11 Alice[${aliceId}] Wait for faber.py to issue a credential offer`)
          let offers = await Credential.getOffers(connectionToFaber)
          while (offers === undefined || offers.length < 1) {
            offers = await Credential.getOffers(connectionToFaber)
          }

          logger.verbose(`Alice[${aliceId}] found ${offers.length} credential offers.`)

          // Create a credential object from the credential offer
          const credential = await Credential.create({sourceId: 'credential', offer: JSON.stringify(offers[0])})

          logger.info(`Alice[${aliceId}] #15 After receiving credential offer, send credential request`)
          await credential.sendRequest({connection: connectionToFaber, payment: 0})

          const serialCredential = JSON.stringify(await credential.serialize())
          const threadId = JSON.parse(serialCredential).data.holder_sm.thread_id
          await walletAddRecord('credential', threadId, serialCredential, {})

          await credential.release()

          // Update agency message status manually (xxxUpdateState automatically update message status, but not here)
          const msgJsonData = {
            msgJson: JSON.stringify([{pairwiseDID: pwDid, uids: [msg.uid]}])
          }
          await updateMessages(msgJsonData)
          break
        }

        // STEP.9 - accept credential
        case 'credential': {
          logger.verbose(`Alice[${aliceId}] credential: / [${++numCredential}]`)

          const threadId = payloadMsg['~thread'].thid
          const record = await walletGetRecord('credential', threadId, {})

          // TODO: Must replace connection_handle in credential - Need to consider better way
          const serialCredential = JSON.parse(JSON.parse(record).value)
          serialCredential.data.holder_sm.state.RequestSent.connection_handle = connectionToFaber.handle
          const credential = await Credential.deserialize(serialCredential)

          await credential.updateState()
          const credentialState = await credential.getState()

          if (credentialState === StateType.Accepted) {
            logger.info(`Alice[${aliceId}] #16 Accepted credential from faber`)
            report.addRecord(aliceId, PhaseType.Issue)

            const serialCredential = JSON.stringify(await credential.serialize())
            await walletUpdateRecordValue('credential', threadId, serialCredential)
          } else {
            logger.error(`Alice[${aliceId}] unexpected credential state: ${credentialState}`)
            throw new Error(`Alice[${aliceId}] unexpected credential state: ${credentialState}`)
          }

          await credential.release()
          logger.verbose(`Alice[${aliceId}] End of issue credential`)

          // proceed to verify
          if (!isValidJson(options.verifierInvite) && options.verifierInvite !== 'auto') {
            logger.verbose(`Alice[${aliceId}] shutdown VCX with deleting wallet`)
            await shutdownVcx(true)
            process.send({cmd: 'aliceDone', report: report.getRecords()})
          } else {
            if (options.verifierInvite === 'auto') {
              try {
                const response = await axios.get(inviteVerifierUrl)
                options.verifierInvite = JSON.stringify(response.data)
              } catch (err) {
                throw new Error(`error response from verifier: ${err.message}`)
                return
              }
            }

            // STEP.2 - receive invitation & create connection A2F
            // accept invitation
            logger.info(`Alice[${aliceId}] #10(verify) Convert to valid json and string and create a connection to faber`)

            report.setStartTime(PhaseType.Verify)

            const connectionToFaber = await Connection.createWithInvite({id: 'faber', invite: options.verifierInvite})
            await connectionToFaber.connect({data: '{"use_public_did": true}'})
            await connectionToFaber.updateState()

            const serialConnectionToFaber = JSON.stringify(await connectionToFaber.serialize())
            const connectionToFaberPwDid = await connectionToFaber.getPwDid()

            await connectionToFaber.release()
            await walletAddRecord('connection', connectionToFaberPwDid, serialConnectionToFaber, {})
          }

          break
        }

        // STEP.11 - receive request & send proof
        case 'presentation-request': {
          logger.verbose(`Alice[${aliceId}] presentation-request: / [${++numPresent}]`)

          logger.info(`Alice[${aliceId}] #22 Check agency for a proof request`)
          let requests = await DisclosedProof.getRequests(connectionToFaber)
          while (requests === undefined || requests.length < 1) {
            requests = await DisclosedProof.getRequests(connectionToFaber)
          }
          logger.verbose(`Alice [${aliceId}] found ${requests.length} proof request.`)

          logger.info(`Alice[${aliceId}] #23 Create a Disclosed proof object from proof request`)
          const proof = await DisclosedProof.create({sourceId: 'proof', request: JSON.stringify(requests[0])})

          logger.info(`Alice[${aliceId}] #24 Query for credentials in the wallet that satisfy the proof request`)
          const credentials = await proof.getCredentials()

          // Use the first available credentials to satisfy the proof request
          for (let i = 0; i < Object.keys(credentials.attrs).length; i++) {
            const attr = Object.keys(credentials.attrs)[i]
            credentials.attrs[attr] = {
              credential: credentials.attrs[attr][0]
            }
          }

          logger.info(`Alice[${aliceId}] #25 Generate the proof`)
          await proof.generateProof({selectedCreds: credentials, selfAttestedAttrs: {}})

          logger.info(`Alice[${aliceId}] #26 Send the proof to faber`)
          await proof.sendProof(connectionToFaber)

          const serialProof = JSON.stringify(await proof.serialize())
          const threadId = JSON.parse(serialProof).data.prover_sm.thread_id
          await walletAddRecord('proof', threadId, serialProof, {})

          await proof.release()

          // Update agency message status manually (xxxUpdateState automatically update message status, but not here)
          const msgJsonData = {
            msgJson: JSON.stringify([{pairwiseDID: pwDid, uids: [msg.uid]}])
          }
          await updateMessages(msgJsonData)
          break
        }

        default: {
          logger.error(`Alice[${aliceId}] msg: ${JSON.stringify(msg, null, 2)}`)
          logger.error(`Alice[${aliceId}] unknown payload type name: ${payloadTypeName}`)
          throw new Error(`Alice[${aliceId}] unknown payload type name: ${payloadTypeName}`)
        }
      } //switch (payloadTypeName)
    } //for (const msg of message.msgs)

    await connectionToFaber.release()
  } //for (const message of dlMessages)
}

const optionDefinitions = [
  {
    name: 'help',
    alias: 'h',
    type: Boolean,
    description: 'Display this usage guide.'
  },
  {
    name: 'comm',
    type: String,
    description: 'Communication method. Possible values: aries, legacy. Default is aries.',
    defaultValue: 'aries'
  },
  {
    name: 'postgresql',
    type: Boolean,
    description: 'If specified, postresql wallet will be used.',
    defaultValue: false
  },
  {
    name: 'issuerInvite',
    alias: 'i',
    type: String,
    description: 'Issuer invitation message',
    defaultValue: 'auto'
  },
  {
    name: 'verifierInvite',
    alias: 'v',
    type: String,
    description: 'Verifier invitation message',
    defaultValue: 'auto'
  },
  {
    name: 'numAlice',
    alias: 'n',
    type: Number,
    description: 'Number of alice',
    defaultValue: 1
  },
  {
    name: 'aliceInterval',
    alias: 'l',
    type: Number,
    description: 'Interval between each alice starts (seconds)',
    defaultValue: 0
  },
  {
    name: 'numCycles',
    alias: 'c',
    type: Number,
    description: 'Number of Alice\'s running cycles (1 cycle = onboard/issue/verify)',
    defaultValue: 1
  },
  {
    name: 'infinite',
    alias: 'f',
    type: Boolean,
    description: 'If specified, run infinitely',
    defaultValue: false
  }
]

const usage = [
  {
    header: 'Options',
    optionList: optionDefinitions
  },
  {
    content: 'Project home: {underline https://github.com/Patrik-Stas/indy-wallet-watch}'
  }
]

function isValidJson(str) {
  if (!str) {
    return false
  }

  try {
    JSON.parse(str)
  } catch (e) {
    return false
  }
  return true
}

function areOptionsValid (options) {
  const allowedCommMethods = ['aries', 'legacy']
  if (!(allowedCommMethods.includes(options.comm))) {
    console.error(`Unknown communication method ${options.comm}. Only ${JSON.stringify(allowedCommMethods)} are allowed.`)
    return false
  }

  if (!isValidJson(options.issuerInvite) && options.issuerInvite !== 'auto') {
    console.error(`Issuer invitation string "${options.issuerInvite}" is invalid`)
    return false
  }

  return true
}

runScript(optionDefinitions, usage, areOptionsValid, runAliceMultiple)
