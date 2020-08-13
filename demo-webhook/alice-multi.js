/**************************************************
 * Author  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since August 10, 2020                          *
 **************************************************/

'use strict'

const { DisclosedProof } = require('../dist/src/api/disclosed-proof')
const { Connection } = require('../dist/src/api/connection')
const { Credential } = require('../dist/src/api/credential')
const { StateType } = require('../dist/src')
const common = require('./common')
const log = require('./logger')
const { runScript } = require('./script-comon')
const { shutdownVcx, downloadMessages, updateMessages, getVersion } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')
const { PhaseType, Report } = require('./report')
const config = require('./alice-config.json')

const express = require('express')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const url = require('url')
const ip = require('ip')
const util = require('util')
const sleepPromise = require('sleep-promise')
const cluster = require('cluster')
const os = require('os')
const axios = require('axios')
const fs = require('fs')

const webHookUrl = 'http://' + ip.address() + ':7203/notifications'
const tailsFileRoot = os.homedir() + '/.indy_client/tails'
const inviteIssuerUrl = process.env.INVITE_ISSUER_URL ? process.env.INVITE_ISSUER_URL : config.inviteIssuerURL
const inviteVerifierUrl = process.env.INVITE_VERIFIER_URL ? process.env.INVITE_VERIFIER_URL : config.inviteVerifierURL

const provisionConfig = {
  agency_url: process.env.AGENCY_URL ? process.env.AGENCY_URL : config.agencyURL,
  agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
  agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  wallet_name: `node_vcx_demo_alice_wallet`,
  wallet_key: '123',
  payment_method: 'null',
  // SEED of alice's DID that does not need to be registered in the ledger
  enterprise_seed: '000000000000000000000000000User1'
}

const report = new Report()
const maxRetry = 5
let initVCX = false, verifyCount = 0
let numResponse = 0, numAck = 0, numCredOffer = 0, numCredential = 0, numPresent = 0

/***
 '@' symbol specifies  web hook received step -> total 10-step which receives corresponding agency message
 |------------|-----------------------------------------------|----------------------------------------------------|
 |   Phase    |                     FABER                     |                       ALICE                        |
 |------------|-----------------------------------------------|----------------------------------------------------|
 | Connection | STEP.1: create connection & send invitation   | STEP.2:  receive invitation & request connection   |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.3: accept connection request            | @STEP.4 - connection created                       |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.5: receive connection ACK               |                                                    |
 |------------|-----------------------------------------------|----------------------------------------------------|
 | Credential | STEP.6: send credential offer                 | @STEP.7: check credential offer&request credential |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.8: send credential                      | @STEP.9:  accept credential                        |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.10: receive credential ACK              |                                                    |
 |------------|-----------------------------------------------|----------------------------------------------------|
 | Proof      | STEP.11: request proof                        | @STEP.12: send proof                               |
 |            |-----------------------------------------------|----------------------------------------------------|
 |            | @STEP.13: receive & verify proof              | @STEP.14: receive proof ACK                        |
 |------------|-----------------------------------------------|----------------------------------------------------|
 ***/

async function startUp(options) {
  log.level = process.env.APP_LOG_LEVEL ? process.env.APP_LOG_LEVEL : config.appLogLevel

  // master process
  if (cluster.isMaster) {
    let numStart = 0
    let numDone = 0
    let numCycles = options.numCycles
    const numAlice = options.numAlice

    if (numCycles < numAlice) {
      numCycles = numAlice
    }

    log.verbose(`IP: ${ip.address()}`)
    log.verbose(`Num CPUS: ${os.cpus().length}`)

    runWebHookServer()

    cluster.schedulingPolicy = cluster.SCHED_RR
    for (let i = 0; i < options.numAlice; i++) {
      const worker = cluster.fork()

      worker.on('message', async (msg) => {
        switch (msg.cmd) {
          case 'toMasterDone':
            numDone += 1
            report.addRecordArray(msg.report)

            // start next transaction
            if (numStart < numCycles || options.infinite) {
              numStart += 1
              log.verbose(`Running cycle number: ${numStart}/${numCycles}`)
              worker.send({cmd: 'toWorkerStart'})
            }

            // all transactions are done successfully
            if (numDone >= numCycles && !options.infinite) {
              await exitAllWorkers(true)
            }
            break

          // when error occurs, stop & exit all worker process
          case 'toMasterExitAll':
            await exitAllWorkers(true)
            break

          default:
            log.error(`undefined cmd: ${msg.cmd}`)
            throw new Error(`undefined cmd: ${msg.cmd}`)
        }
      })

      numStart += 1
      worker.send({cmd: 'toWorkerStart'})
      await sleepPromise(options.aliceInterval * 1000)
    }

    cluster.on('exit', (worker, code) => {
      const message = `Worker ${worker.process.pid} exits ` + (!code ? 'successfully' : `with error ${code}`)
      log.verbose(message)
    })

    // register Ctrl-C handler to shutdown VCX with deleting wallet
    process.on('SIGINT', async () => {
      report.print(report.getReport())
      process.exit(0)
    })
  }
  // worker process
  else {
    process.on('message', async (msg) => {
      switch (msg.cmd) {
        case 'toWorkerStart':
          log.verbose(`Alice[${cluster.worker.id}] starts`)
          try {
            await runAlice(options, cluster.worker.id)
          } catch (err) {
            log.error(`runAlice error: ${util.inspect(err)}`)
            process.send({cmd: 'toMasterExitAll'})
          }
          break

        case 'toWorkerExit':
          process.exit(0)
          break

        case 'toWorkerMsg':
          try {
            await handleMessage(msg.body, cluster.worker.id, options)
          } catch (err) {
            log.error(`handleMessage error: ${util.inspect(err)}`)
            process.send({cmd: 'toMasterExitAll'})
          }
          break

        default:
          log.error(`Alice[${cluster.worker.id}] unknown master command`)
          throw new Error(`Alice[${cluster.worker.id}] unknown master command`)
      }
    })

    // register Ctrl-C handler to shutdown VCX with deleting wallet
    process.on('SIGINT', async (signal) => {
      log.verbose(`${signal} worker [${cluster.worker.id}] -> shutdown VCX with deleting wallet`)
      await shutdownVcx(true)
      process.exit(0)
    })
  }

  return 'Waiting web hook event from agent...'
}

async function exitAllWorkers(print) {
  const ids = Object.keys(cluster.workers)
  for (const id of ids) {
    cluster.workers[id].send({cmd: 'toWorkerExit'})
  }

  while (cluster.workers[1]) {
    await sleepPromise(100)
  }

  if (print) {
    report.print(report.getReport())
  }

  process.exit(0)
}

function runWebHookServer() {
  const app = express()
  const port = url.parse(webHookUrl).port
  const asyncHandler = fn => (req, res, next) => {
    return Promise
        .resolve(fn(req, res, next))
        .catch(async function (err) {
          log.error(`${util.inspect(err)}`)
          res.status(500).send({ message: `${util.inspect(err)}` })
          await exitAllWorkers(true)
          process.exit(1)
        })
  }

  app.use(bodyParser.json())
  app.use(morgan('dev'))

  app.post('/notifications/:aliceId', asyncHandler(async (req, res) => {
    const { aliceId } = req.params

    // push web hook message to corresponding worker
    cluster.workers[aliceId].send({ cmd: 'toWorkerMsg', body: req.body })
    res.status(200).send()
  }))

  app.use(asyncHandler(async (req) => {
    throw new Error(`Your request: '${req.originalUrl}' didn't reach any handler.`)
  }))

  app.listen(port, () => log.verbose(`Server listening on port ${port}...`))
}

async function runAlice(options, aliceId) {
  report.clearRecords()

  if (initVCX === false) {
    log.info(`Alice[${aliceId}] #0 Initialize`)
    initVCX = true
    await common.initLibNullPay()

    const vcxLogLevel = process.env.VCX_LOG_LEVEL ? process.env.VCX_LOG_LEVEL : config.vcxLogLevel
    await common.initRustApiAndLogger(vcxLogLevel)

    const libVcxVersion = await getVersion()
    log.info(`LibVCX Version: ${libVcxVersion}`)
    if (libVcxVersion.substr(0, 3) < 0.8) {
      log.error(`LibVCX version must be higher than 0.8`)
      process.send({cmd: 'toMasterExitAll'})
      process.exit(1)
    }

    // Communication method. aries.
    if (options.comm === 'aries') {
      provisionConfig.protocol_type = '4.0'
      provisionConfig.communication_method = 'aries'
      log.info('Running with Aries VCX Enabled! Make sure VCX agency is configured to use protocol_type 4.0')
    }

    if (config.postgresql) {
      await common.loadPostgresPlugin(provisionConfig)
      provisionConfig.wallet_type = 'postgres_storage'
      provisionConfig.storage_config = '{"url":"localhost:5432"}'
      provisionConfig.storage_credentials = '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}'
      log.info(`Running with PostreSQL wallet enabled! Config = ${provisionConfig.storage_config}`)
    } else {
      log.info('Running with builtin wallet.')
    }

    // add webhook url to config
    provisionConfig.webhook_url = `${webHookUrl}/${aliceId}`
    log.info(`Alice[${aliceId}] Running with webhook notifications enabled! Webhook url = ${webHookUrl}`)
  }

  if (verifyCount === options.verifyRatio) {
    report.setStartTime(PhaseType.Onboard)

    log.info(`Alice[${aliceId}] #8 Provision an agent and wallet, get back configuration details`)
    const utime = Math.floor(new Date() / 1000)
    provisionConfig.wallet_name = `node_vcx_demo_alice_wallet_${utime}_${aliceId}`

    const vcxConfig = await common.provisionAgentInAgency(provisionConfig)
    vcxConfig.institution_name = 'alice'
    vcxConfig.institution_logo_url = 'http://robohash.org/234'
    vcxConfig.protocol_version = '2'
    vcxConfig.genesis_path = `${__dirname}/genesis.txn`

    log.info(`Alice[${aliceId}] #9 Initialize libvcx with new configuration`)

    // await common.initVcxWithProvisionedAgentConfig(vcxConfig)
    // avoiding error: Can not open Pool Ledger Pool 'pool1' does not exist ==>
    await common.retryRun(maxRetry, common.initVcxWithProvisionedAgentConfig, vcxConfig)

    report.addRecord(aliceId, PhaseType.Onboard)

    log.silly(`walletAddRecord (vcxConfig, defaultVcxConfig, ${JSON.stringify(vcxConfig, null, 2)})`)
    await walletAddRecord('vcxConfig', 'defaultVcxConfig', JSON.stringify(vcxConfig), {})
  }

  // proceed to issue
  if (!isValidJson(options.issuerInvite) && options.issuerInvite !== 'auto') {
    log.verbose(`Alice[${aliceId}] shutdown VCX with deleting wallet`)
    await shutdownVcx(true)
    process.send({cmd: 'toMasterDone', report: report.getRecords()})
    return
  }

  let inviteUrl, inviteMessgae
  if (verifyCount === options.verifyRatio) {
    // Do issue
    verifyCount = 0
    inviteUrl = inviteIssuerUrl
    inviteMessgae = options.issuerInvite
    report.setStartTime(PhaseType.Issue)
  } else {
    // Do verify
    inviteUrl = inviteVerifierUrl
    inviteMessgae = options.verifierInvite
    report.setStartTime(PhaseType.Verify)
  }

  await receiveInvitation(inviteMessgae, inviteUrl, aliceId)
}

async function receiveInvitation(inviteMessgae, inviteUrl, aliceId) {
  // STEP.2 - receive invitation & request connection
  log.info(`Alice[${aliceId}] #10 Convert to valid json and string and create a connection to faber`)
  if (inviteMessgae === 'auto') {
    try {
      const response = await axios.get(inviteUrl)
      inviteMessgae = JSON.stringify(response.data)
    } catch (err) {
      throw new Error(`error response from issuer: ${err.message}`)
    }
  }

  const connection = await Connection.createWithInvite({id: 'faber', invite: inviteMessgae})
  await connection.connect({data: '{"use_public_did": true}'})
  await connection.updateState()

  const serialConnection = await connection.serialize()
  const pwDid = await connection.getPwDid()

  await connection.release()

  log.silly(`walletAddRecord (connection, ${pwDid}, ${JSON.stringify(serialConnection, null, 2)})`)
  await walletAddRecord('connection', pwDid, JSON.stringify(serialConnection), {})
}

async function handleMessage(message, aliceId, options) {
  const downloadMessagesParam = {
    //status: message.msgStatusCode,
    uids: message.msgUid,
    pairwiseDids: message.pwDid,
  }
  const dlMessages = JSON.parse(await downloadMessages(downloadMessagesParam))
  log.silly(`Alice[${aliceId}] dlMessages: ${JSON.stringify(dlMessages, null, 2)}`)

  for (const message of dlMessages) {
    if (message.msgs.length < 1) {
      log.error(`Alice[${aliceId}] message: ${JSON.stringify(message, null, 2)}`)
      throw new Error(`Alice[${aliceId}] message: ${JSON.stringify(message, null, 2)}`)
    }

    const pwDid = message.pairwiseDID
    const record = await walletGetRecord('connection', pwDid, {})
    const connection = await Connection.deserialize(JSON.parse(JSON.parse(record).value))

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
          if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/response') {
            log.info('- Case(aries ,connections/1.0/response) -> sendConnectionAck')
            log.verbose(`Alice[${aliceId}] aries: spec/connections/1.0/response [${++numResponse}]`)
            await sendConnectionAck(connection, pwDid, aliceId)
          }
          // STEP.14 - receive proof ACK
          else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/present-proof/1.0/ack') {
            log.info('- Case(aries ,present-proof/1.0/ack) -> receiveProofAck')
            log.verbose(`Alice[${aliceId}] aries: spec/present-proof/1.0/ack [${++numAck}]`)
            await receiveProofAck(connection, payloadMsg, aliceId)

            report.addRecord(aliceId, PhaseType.Verify)
            log.verbose(`Alice[${aliceId}] Alice demo is completed`)

            verifyCount += 1
            if (verifyCount === options.verifyRatio) {
              log.verbose(`Alice[${aliceId}] shutdown VCX with deleting wallet`)
              await shutdownVcx(true)
            }
            process.send({ cmd: 'toMasterDone', report: report.getRecords() })
          }
          // SETP.14-1 - receive problem-report (possibly the credential has been revoked)
          else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/report-problem/1.0/problem-report') {
            log.error(`- Alice[${aliceId}] Case(aries ,report-problem/1.0/problem-report) -> printProblem`)
            throw new Error(`Alice[${aliceId}] comment: ${payloadMsg.comment}`)
          }
          else {
            log.error(`Alice[${aliceId}] msg: ${JSON.stringify(msg, null, 2)}`)
            throw new Error(`Alice[${aliceId}] unknown payload message type name: ${payloadMsgType}`)
          }
          break
        }

        // STEP.7 - check credential offer & request credential
        case 'credential-offer': {
          log.info('- Case(credential-offer) -> sendCredentialRequest')
          log.verbose(`Alice[${aliceId}] credential-offer: / [${++numCredOffer}]`)
          await sendCredentialRequest(connection, pwDid, msg.uid, aliceId)
          break
        }

        // STEP.9 - accept credential
        case 'credential': {
          log.info('- Case(credential) -> acceptCredential')
          log.verbose(`Alice[${aliceId}] credential: / [${++numCredential}]`)

          await acceptCredential(connection, payloadMsg, aliceId)
          report.addRecord(aliceId, PhaseType.Issue)
          log.verbose(`Alice[${aliceId}] End of issue credential`)

          // proceed to verify
          if (!isValidJson(options.verifierInvite) && options.verifierInvite !== 'auto') {
            log.verbose(`Alice[${aliceId}] shutdown VCX with deleting wallet`)
            await shutdownVcx(true)
            process.send({cmd: 'toMasterDone', report: report.getRecords()})
          } else {
            report.setStartTime(PhaseType.Verify)
            await receiveInvitation(options.verifierInvite, inviteVerifierUrl, aliceId)
          }

          break
        }

        // STEP.11 - receive request & send proof
        case 'presentation-request': {
          log.info('- Case(presentation-request) -> sendProof')
          log.verbose(`Alice[${aliceId}] presentation-request: / [${++numPresent}]`)

          await sendProof(connection, pwDid, msg.uid, aliceId)
          break
        }

        default: {
          log.error(`Alice[${aliceId}] msg: ${JSON.stringify(msg, null, 2)}`)
          log.error(`Alice[${aliceId}] unknown payload type name: ${payloadTypeName}`)
          throw new Error(`Alice[${aliceId}] unknown payload type name: ${payloadTypeName}`)
        }
      } //switch (payloadTypeName)
    } //for (const msg of message.msgs)

    await connection.release()
  } //for (const message of dlMessages)
}

async function sendConnectionAck(connection, pwDid) {
  await connection.updateState()
  const connectionState = await connection.getState()

  if (connectionState === StateType.Accepted) {
    const serialConnection = await connection.serialize()

    log.silly(`walletUpdateRecordValue (connection, ${pwDid}, ${JSON.stringify(serialConnection, null, 2)})`)
    await walletUpdateRecordValue('connection', pwDid, JSON.stringify(serialConnection))
  } else {
    throw new Error(`Alice[${aliceId}] unexpected connection state: ${connectionState}`)
  }
}

async function sendCredentialRequest(connection, pwDid, msgUid, aliceId) {
  let offers = await Credential.getOffers(connection)
  while (offers === undefined || offers.length < 1) {
    offers = await Credential.getOffers(connection)
  }
  log.info(`credential offer: ${JSON.stringify(offers[0], null, 2)}`)

  // Update agency message status manually (xxxUpdateState automatically update message status, but not here)
  const msgJsonData = {
    msgJson: JSON.stringify([{ pairwiseDID: pwDid, uids: [msgUid] }])
  }
  await updateMessages(msgJsonData)

  // Create a credential object from the credential offer
  const credential = await Credential.create({ sourceId: 'credential', offer: JSON.stringify(offers[0]) })

  log.info(`Alice[${aliceId}] #15 After receiving credential offer, send credential request`)
  await credential.sendRequest({ connection: connection, payment: 0 })

  const serialCredential = await credential.serialize()
  const threadId = serialCredential.data.holder_sm.thread_id

  log.silly(`walletAddRecord (credential, ${threadId}, ${JSON.stringify(serialCredential, null, 2)})`)
  await walletAddRecord('credential', threadId, JSON.stringify(serialCredential), {})

  await credential.release()
}

async function acceptCredential(connection, payloadMsg, aliceId) {
  const threadId = payloadMsg['~thread'].thid
  const credentialRecord = await walletGetRecord('credential', threadId, {})

  // TODO: Must replace connection_handle in credential - Need to consider better way
  let serialCredential = JSON.parse(JSON.parse(credentialRecord).value)
  serialCredential.data.holder_sm.state.RequestSent.connection_handle = connection.handle
  const credential = await Credential.deserialize(serialCredential)

  await credential.updateState()
  const credentialState = await credential.getState()

  if (credentialState === StateType.Accepted) {
    log.info(`Alice[${aliceId}] #16 Accepted credential from faber`)

    // download tails file if not exist
    const serialCredential = await credential.serialize()
    const revRegDefJson = JSON.parse(serialCredential.data.holder_sm.state.Finished.rev_reg_def_json)
    const tailsFileDir = `${tailsFileRoot}/${revRegDefJson.id}`
    const tailsFilePath = `${tailsFileDir}/${revRegDefJson.value.tailsHash}`
    if(!fs.existsSync(tailsFilePath)) {
      // get tails file from tails file server
      const httpConfig = {
        responseType: 'arraybuffer',
      }
      const response = await axios.get(revRegDefJson.value.tailsLocation, httpConfig)
      if (!fs.existsSync(tailsFileDir)){
        fs.mkdirSync(tailsFileDir)
      }
      fs.writeFileSync(tailsFilePath, response.data)
    }
  } else {
    throw new Error(`Alice[${aliceId}] unexpected credential state: ${credentialState}`)
  }

  // Serialize the object
  serialCredential = await credential.serialize()
  log.silly(`walletUpdateRecordValue (credential, ${threadId}, ${JSON.stringify(serialCredential, null, 2)})`)
  await walletUpdateRecordValue('credential', threadId, JSON.stringify(serialCredential))

  await credential.release()
}

async function sendProof(connection, pwDid, msgUid, aliceId) {
  let requests = await DisclosedProof.getRequests(connection)
  while (requests === undefined || requests.length < 1) {
    requests = await DisclosedProof.getRequests(connection)
  }
  log.info(`proof request:: ${JSON.stringify(requests[0], null, 2)}`)

  // Update agency message status manually (xxxUpdateState automatically update message status, but not here)
  const msgJsonData = {
    msgJson: JSON.stringify([{ pairwiseDID: pwDid, uids: [msgUid] }])
  }
  await updateMessages(msgJsonData)

  log.info(`Alice[${aliceId}] #23 Create a Disclosed proof object from proof request`)
  const proof = await DisclosedProof.create({ sourceId: 'proof', request: JSON.stringify(requests[0]) })

  log.info(`Alice[${aliceId}] #24 Query for credentials in the wallet that satisfy the proof request`)
  const credentials = await proof.getCredentials()

  log.verbose(`credentials: ${JSON.stringify(credentials, null, 2)}`)

  // Use the first available credentials to satisfy the proof request
  for (let i = 0; i < Object.keys(credentials.attrs).length; i++) {
    const attr = Object.keys(credentials.attrs)[i]
    const tailsFileDir = `${tailsFileRoot}/${credentials.attrs[attr][0].cred_info.rev_reg_id}`
    credentials.attrs[attr] = {
      credential: credentials.attrs[attr][0],
      // add tails file attribute
      tails_file: tailsFileDir
    }
  }

  log.verbose(`credentials: ${JSON.stringify(credentials, null, 2)}`)

  log.info(`Alice[${aliceId}] #25 Generate the proof`)
  await proof.generateProof({ selectedCreds: credentials, selfAttestedAttrs: {} })

  log.info(`Alice[${aliceId}] #26 Send the proof to faber`)
  await proof.sendProof(connection)

  // Serialize the object
  const serialProof = await proof.serialize()
  const threadId = serialProof.data.prover_sm.thread_id
  log.silly(`walletAddRecord (serialProof, ${threadId}, ${JSON.stringify(serialProof, null, 2)})`)
  await walletAddRecord('proof', threadId, JSON.stringify(serialProof), {})

  await proof.release()
}

async function receiveProofAck(connection, payloadMsg, aliceId) {
  const threadId = payloadMsg['~thread'].thid
  const proofRecord = await walletGetRecord('proof', threadId, {})

  // TODO: Must replace connection_handle in credential - Need to consider better way
  let serialProof = JSON.parse(JSON.parse(proofRecord).value)
  serialProof.data.prover_sm.state.PresentationSent.connection_handle = connection.handle
  const proof = await DisclosedProof.deserialize(serialProof)

  await proof.updateState()
  const proofState = await proof.getState()

  if (proofState === StateType.Accepted) {
    log.info(`Alice[${aliceId}] Faber received & verified the proof`)
  } else if (proofState === StateType.None) {
    log.info(`Alice[${aliceId}] Faber denied the proof (possibly the credential has been revoked)`)
  } else {
    log.error(`Alice[${aliceId}] unexpected proof state: ${proofState}`)
    throw new Error(`Alice[${aliceId}] unexpected proof state: ${proofState}`)
  }

  serialProof = await proof.serialize()
  log.silly(`walletUpdateRecordValue (proof, ${threadId}, ${JSON.stringify(serialProof, null, 2)})`)
  await walletUpdateRecordValue('proof', threadId, JSON.stringify(serialProof))

  await proof.release()
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
    name: 'numCycles',
    alias: 'c',
    type: Number,
    description: 'Total number of Alice\'s running cycles (1 cycle = onboard/issue/verify)',
    defaultValue: 1
  },
  {
    name: 'startInterval',
    alias: 'l',
    type: Number,
    description: 'Interval between each alice starts (seconds)',
    defaultValue: 0
  },
  {
    name: 'infinite',
    alias: 'f',
    type: Boolean,
    description: 'If specified, run infinitely',
    defaultValue: false
  },
  {
    name: 'verifyRatio',
    alias: 'r',
    type: Number,
    description: 'Verify ratio by onboard and issue ->  verify / (onboard & issue)',
    defaultValue: 1
  }
]

const usage = [
  {
    header: 'Options',
    optionList: optionDefinitions
  },
  {
    content: 'Project home: {underline https://github.com/sktston/vcx-demo-node}'
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

function areOptionsValid(options) {
  const allowedCommMethods = ['aries', 'legacy']
  if (!(allowedCommMethods.includes(options.comm))) {
    log.error(`Unknown communication method ${options.comm}. Only ${JSON.stringify(allowedCommMethods)} are allowed.`)
    return false
  }

  // init verifyCount to run 1st issue
  verifyCount = options.verifyRatio

  // adjust numCycles according to verifyRatio
  if (options.numCycles < options.verifyRatio) {
    options.numCycles = options.verifyRatio
  }

  return true
}

runScript(optionDefinitions, usage, areOptionsValid, startUp)
  .catch(function(err) {
    log.error(`${util.inspect(err)}`)
  })