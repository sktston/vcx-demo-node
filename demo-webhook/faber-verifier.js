'use strict'

const { Proof } = require('../dist/src/api/proof')
const { Connection } = require('../dist/src/api/connection')
const { StateType, ProofState } = require('../dist/src')
const { setActiveTxnAuthorAgreementMeta, getLedgerAuthorAgreement } = require('./../dist/src/api/utils')
const demoCommon = require('./common')
const logger = require('./logger')
const config = require('./faber-config.json')
const morgan = require('morgan')
const url = require('url')
const ip = require('ip')
const util = require('util')
const isPortReachable = require('is-port-reachable')
const { runScript } = require('./script-comon')
const { shutdownVcx, downloadMessages, getVersion } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')

const express = require('express')
const bodyParser = require('body-parser')

const app = express()
const utime = Math.floor(new Date() / 1000)

const TAA_ACCEPT = process.env.TAA_ACCEPT === 'true' || false

const provisionConfig = {
  agency_url: process.env.AGENCY_URL ? process.env.AGENCY_URL : config.agencyURL,
  agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
  agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  wallet_name: `node_vcx_demo_faber_verifier_wallet_${utime}`,
  wallet_key: '123',
  payment_method: 'null',
  enterprise_seed: '000000000000000000000000Trustee1'
}

const appLogLevel = process.env.APP_LOG_LEVEL ? process.env.APP_LOG_LEVEL : config.appLogLevel
const vcxLogLevel = process.env.VCX_LOG_LEVEL ? process.env.VCX_LOG_LEVEL : config.vcxLogLevel

const ariesProtocolType = '4.0'
const webHookUrl = 'http://' + ip.address() + ':7202/notifications/'
const autoSendProofRequest = true
let serverReady = false
let numRequest = 0, numAck = 0, numPresent = 0, numVerify = 0

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

async function runFaber(options) {
  logger.level = appLogLevel

  runWebHookServer()

  await demoCommon.initLibNullPay()

  logger.info('#0 Initialize rust API from NodeJS')
  await demoCommon.initRustApiAndLogger(vcxLogLevel)

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
    logger.info('Running with Aries VCX Enabled! Make sure VCX agency is configured to use protocol_type 2.0')
  }

  if (options.postgresql) {
    await demoCommon.loadPostgresPlugin(provisionConfig)
    provisionConfig.wallet_type = 'postgres_storage'
    provisionConfig.storage_config = '{"url":"localhost:5432"}'
    provisionConfig.storage_credentials = '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}'
    logger.info(`Running with PostreSQL wallet enabled! Config = ${provisionConfig.storage_config}`)
  } else {
    logger.info('Running with builtin wallet.')
  }

  if (await isPortReachable(url.parse(webHookUrl).port, {host: url.parse(webHookUrl).hostname})) { // eslint-disable-line
    provisionConfig.webhook_url = webHookUrl
    logger.info(`Running with webhook notifications enabled! Webhook url = ${webHookUrl}`)
  } else {
    logger.info('Webhook url will not be used')
  }

  logger.info(`#1 Config used to provision agent in agency: ${JSON.stringify(provisionConfig, null, 2)}`)
  const agentProvision = await demoCommon.provisionAgentInAgency(provisionConfig)
  agentProvision.institution_name = 'faber'
  agentProvision.institution_logo_url = 'http://robohash.org/234'
  agentProvision.genesis_path = `${__dirname}/docker.txn`

  logger.info(`#2 Using following agent provision to initialize VCX ${JSON.stringify(agentProvision, null, 2)}`)
  await demoCommon.initVcxWithProvisionedAgentConfig(agentProvision)

  logger.verbose('#2-1 Register Ctrl-C handler to shutdown VCX with deleting wallet')
  process.on('SIGINT', async (signal) => {
    logger.verbose(`${signal} process [${process.pid}] -> shutdown VCX with deleting wallet`)
    await shutdownVcx(true)
    process.exit(0)
  })

  logger.verbose('#2-2 Store agentProvision to Faber\'s local wallet')
  await walletAddRecord('vcxConfig', 'defaultVcxConfig', JSON.stringify(agentProvision), {})

  if (TAA_ACCEPT) {
    logger.info('#2.1 Accept transaction author agreement')
    const taa = await getLedgerAuthorAgreement()
    const taa_json = JSON.parse(taa)
    await setActiveTxnAuthorAgreementMeta(taa_json.text, taa_json.version, null, Object.keys(taa_json.aml)[0], utime)
  }

  logger.info('#5 Create a connection to alice and print out the invite details')
  let connectionToAlice = await Connection.create({id: 'alice'})
  await connectionToAlice.connect('{}')
  await connectionToAlice.updateState()

  const details = await connectionToAlice.inviteDetails(false)
  logger.info('\n\n**invite details**')
  logger.info("**You'll ge queried to paste this data to alice side of the demo. This is invitation to connect.**")
  logger.info("**It's assumed this is obtained by Alice from Faber by some existing secure channel.**")
  logger.info('**Could be on website via HTTPS, QR code scanned at Faber institution, ...**')
  logger.info('\n******************\n\n')
  logger.info(JSON.stringify(JSON.parse(details)))
  logger.info('\n\n******************\n\n')

  logger.verbose('#5-1 Store invite details to Faber\'s local wallet')
  await walletAddRecord('invite', 'defaultInvite', details, {})

  // store created connectionToAlice connection for using repeated invitation
  logger.verbose('#5-2 Store invite connection to Faber\'s local wallet')
  const serialConnectionToAlice = JSON.stringify(await connectionToAlice.serialize())
  const connectionToAlicePwDid = await connectionToAlice.getPwDid()

  await walletAddRecord('connection', connectionToAlicePwDid, serialConnectionToAlice, {})
  await connectionToAlice.release()

  logger.verbose('#5-3 Web hook server can response here')
  serverReady = true
}

function runWebHookServer() {
  const port = url.parse(webHookUrl).port
  const asyncHandler = fn => (req, res, next) => {
    return Promise
        .resolve(fn(req, res, next))
        .catch(function (err) {
          logger.error(`${util.inspect(err)}`)
          res.status(500).send({ message: `${util.inspect(err)}` })
          process.exit(1)
        })
  }

  app.use(bodyParser.json())
  app.use(morgan('dev'))

  app.use((req, res, next) => {
    if (!serverReady) {
      logger.error('Server is not ready')
      res.status(500).send({ message: 'Server is not ready' })
    } else {
      next()
    }
  })

  app.post('/notifications', asyncHandler(async (req, res) => {
    const downloadMessagesParam = {
      //status: req.body.msgStatusCode,
      uids: req.body.msgUid,
      pairwiseDids: req.body.pwDid,
    }
    const dlMessages = JSON.parse(await downloadMessages(downloadMessagesParam))
    logger.silly(`dlMessages: ${JSON.stringify(dlMessages, null, 2)}`)

    for (const message of dlMessages) {
      if (message.msgs.length < 1) {
        throw new Error(`empty message: ${JSON.stringify(message, null, 2)}`)
      }

      try {
        await processMessage(message)
      } catch (err) {
        logger.error(`message: ${JSON.stringify(message, null, 2)}`)
        throw new Error(`processMessage error: ${err.message}`)
      }
    }

    res.status(200).send()
  }))

  app.get('/invitations', asyncHandler(async (req, res) => {
    const record = await walletGetRecord('invite', 'defaultInvite', {})
    const inviteDetails = JSON.parse(JSON.parse(record).value)
    logger.debug(`inviteDetails: ${JSON.stringify(inviteDetails)}`)
    res.status(200).json(inviteDetails)
  }))

  app.use(asyncHandler(async (req) => {
    throw new Error(`Your request: '${req.originalUrl}' didn't reach any handler.`)
  }))

  app.listen(port, () => logger.verbose(`Server listening on port ${port}...`))
}

async function processMessage(message) {
  const pwDid = message.pairwiseDID
  const record = await walletGetRecord('connection', pwDid, {})
  const connectionToAlice = await Connection.deserialize(JSON.parse(JSON.parse(record).value))

  for (const msg of message.msgs) {
    // 'decryptedPayload' consists of 'payloadType' and 'payloadMsg'
    const payload = JSON.parse(msg.decryptedPayload)  // JSON Object
    const payloadType = payload['@type']              // JSON Object
    const payloadTypeName = payloadType.name          // String
    const payloadMsg = JSON.parse(payload['@msg'])    // JSON Object
    const payloadMsgType = payloadMsg['@type']        // String

    //logger.verbose(`payloadMsg: ${JSON.stringify(payloadMsg, null, 2)}`)

    switch (payloadTypeName) {
      case 'aries':
        // STEP.3 - update connection from F to F2A
        // connection request - At Inviter: after receiving invitation from Invitee
        if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/request') {
          logger.verbose(`aries: spec/connections/1.0/request [${++numRequest}]`)

          await connectionToAlice.updateState()
          const  connectionState = await connectionToAlice.getState()

          if (connectionState === StateType.RequestReceived) {
            const newPwDid = await connectionToAlice.getPwDid()
            const serialConnectionToAlice = JSON.stringify(await connectionToAlice.serialize())
            await walletAddRecord('connection', newPwDid, serialConnectionToAlice, {})
/*
            const msgJsonData = {
              msgJson: JSON.stringify([ { pairwiseDID: pwDid, uids: [msg.uid] } ])
            }
            await updateMessages(msgJsonData)
*/
          } else {
            logger.error(`unexpected request connection state[${numRequest}]: ${connectionState}`)
            throw new Error(`unexpected request connection state[${numRequest}]: ${connectionState}`)
          }
        }
        // STEP.5 - receive connection created ACK
        // notification ack - At Inviter: after connection request from Invitee
        else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/notification/1.0/ack') {
          logger.verbose(`aries: spec/notification/1.0/ack [${++numAck}]`)
          await connectionToAlice.updateState()
          const connectionState = await connectionToAlice.getState()

          if (connectionState === StateType.Accepted) {
            const updateConnection = JSON.stringify(await connectionToAlice.serialize())
            await walletUpdateRecordValue('connection', pwDid, updateConnection)
          } else {
            logger.error(`unexpected ack connection state[${numAck}]: ${connectionState}`)
            throw new Error(`unexpected ack connection state[${numAck}]: ${connectionState}`)
          }
          // STEP.10 - request proof
          // After issuing credential, issuer does not receive Ack for that
          // We send proof request here
          if (autoSendProofRequest) {
            const record = await walletGetRecord('vcxConfig', 'defaultVcxConfig', {})
            const agentProvision = JSON.parse(JSON.parse(record).value)
            const proofAttributes = [
              {
                names: ['name', 'last_name', 'sex'],
                restrictions: [{ issuer_did: agentProvision.institution_did }]
              },
              {
                name: 'date',
                restrictions: { issuer_did: agentProvision.institution_did }
              },
              {
                name: 'degree',
                restrictions: { 'attr::degree::value': 'maths' }
              }
            ]

            const proofPredicates = [
              { name: 'age', p_type: '>=', p_value: 20, restrictions: [{ issuer_did: agentProvision.institution_did }] }
            ]

            logger.info('#19 Create a Proof object')
            const proof = await Proof.create({
              sourceId: '213',
              attrs: proofAttributes,
              preds: proofPredicates,
              name: 'proofForAlice',
              revocationInterval: {}
            })

            logger.info('#20 Request proof of degree from alice')
            await proof.requestProof(connectionToAlice)
            const serialProof = JSON.stringify(await proof.serialize())
            const threadId = JSON.parse(serialProof).data.verifier_sm.state.PresentationRequestSent.presentation_request['@id']

            await walletAddRecord('proof', threadId, serialProof, {})
            await proof.release()
          } // if (autoSendProofRequest)
        } // else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/notification/1.0/ack')
        else {
          logger.error(`msg: ${JSON.stringify(msg, null, 2)}`)
          logger.error(`unknown payload message type name: ${payloadMsgType}`)
          throw new Error(`unknown payload message type name: ${payloadMsgType}`)
        }
        break

      case 'presentation':
        // STEP.12 - receive & verify proof
        // present-proof presentation - At Issuer: After proofSendRequest
        logger.verbose(`presentation: / [${++numPresent}]`)

        const threadId = payloadMsg['~thread'].thid
        const record = await walletGetRecord('proof', threadId, {})

        // TODO: Must replace connection_handle in proof - Need to consider better way
        const serialProof = JSON.parse(JSON.parse(record).value)
        serialProof.data.verifier_sm.state.PresentationRequestSent.connection_handle = connectionToAlice.handle

        const proof = await Proof.deserialize(serialProof)
        await proof.updateState()
        const proofState = await proof.getState()

        if (proofState === StateType.Accepted) {
          logger.info('#27 Process the proof provided by alice')
          await proof.getProof(connectionToAlice)

          logger.info('#28 Check if proof is valid')
          if (proof.proofState === ProofState.Verified) {
            logger.info('Proof is verified')
          } else {
            logger.info('Could not verify proof')
          }

          const serialProof = JSON.stringify(await proof.serialize())
          await walletUpdateRecordValue('proof', threadId, serialProof)
        } else {
          logger.error(`unexpected proof state: ${proofState}`)
          throw new Error(`unexpected proof state: ${proofState}`)
        }

        await proof.release()
        logger.verbose(`End of verify: ${++numVerify}`)
        break

      default:
        logger.error(`msg: ${JSON.stringify(msg, null, 2)}`)
        logger.error(`unknown payload type name: ${payloadTypeName}`)
        throw new Error(`unknown payload type name: ${payloadTypeName}`)
    } //switch (payloadTypeName)
  } //for (const msg of message.msgs)

  await connectionToAlice.release()
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

function areOptionsValid (options) {
  const allowedCommMethods = ['aries', 'legacy']
  if (!(allowedCommMethods.includes(options.comm))) {
    console.error(`Unknown communication method ${options.comm}. Only ${JSON.stringify(allowedCommMethods)} are allowed.`)
    return false
  }
  return true
}

runScript(optionDefinitions, usage, areOptionsValid, runFaber)
  .catch(function(err) {
    logger.error(`${util.inspect(err)}`)
  })