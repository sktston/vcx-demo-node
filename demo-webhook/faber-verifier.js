/**************************************************
 * Author  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since August 10, 2020                          *
 **************************************************/

'use strict'

const { Proof } = require('../dist/src/api/proof')
const { Connection } = require('../dist/src/api/connection')
const { StateType, ProofState } = require('../dist/src')
const common = require('./common')
const log = require('./logger')
const config = require('./faber-config.json')
const { runScript } = require('./script-comon')
const { shutdownVcx, downloadMessages, getVersion } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')

const express = require('express')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const url = require('url')
const ip = require('ip')
const util = require('util')

const webHookUrl = 'http://' + ip.address() + ':7202/notifications/'
let numRequest = 0, numAck = 0, numPresent = 0, numVerify = 0

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

  await initialize(options)
  runWebHookServer()
}

async function initialize(options) {
  log.info('#0 Initialize')

  await common.initLibNullPay()

  const vcxLogLevel = process.env.VCX_LOG_LEVEL ? process.env.VCX_LOG_LEVEL : config.vcxLogLevel
  await common.initRustApiAndLogger(vcxLogLevel)

  const libVcxVersion = await getVersion()
  log.info(`LibVCX Version: ${libVcxVersion}`)
  if (libVcxVersion.substr(0, 3) < 0.8) {
    log.error(`LibVCX version must be higher than 0.8`)
    process.exit(1)
  }

  const utime = Math.floor(new Date() / 1000)
  const provisionConfig = {
    agency_url: process.env.AGENCY_URL ? process.env.AGENCY_URL : config.agencyURL,
    agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
    agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
    wallet_name: `node_vcx_demo_faber_issuer_wallet_${utime}`,
    wallet_key: '123',
    payment_method: 'null',
    // SEED of faber's DID already registered in the ledger
    // It is recommended to use VON Network and you must register following seed
    enterprise_seed: '00000000000000000000000Endorser1'
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
  provisionConfig.webhook_url = webHookUrl
  log.info(`Running with webhook notifications enabled! Webhook url = ${webHookUrl}`)

  log.info(`#1 Config used to provision agent in agency: ${JSON.stringify(provisionConfig, null, 2)}`)
  const vcxConfig = await common.provisionAgentInAgency(provisionConfig)
  vcxConfig.institution_name = 'faber'
  vcxConfig.institution_logo_url = 'http://robohash.org/234'
  vcxConfig.protocol_version = '2'
  vcxConfig.genesis_path = `${__dirname}/genesis.txn`

  log.info(`#2 Using following agent provision to initialize VCX ${JSON.stringify(vcxConfig, null, 2)}`)
  await common.initVcxWithProvisionedAgentConfig(vcxConfig)

  log.silly(`walletAddRecord (vcxConfig, defaultVcxConfig, ${JSON.stringify(vcxConfig, null, 2)})`)
  await walletAddRecord('vcxConfig', 'defaultVcxConfig', JSON.stringify(vcxConfig), {})

  log.verbose('#2-1 Register Ctrl-C handler to shutdown VCX with deleting wallet')
  process.on('SIGINT', async (signal) => {
    log.verbose(`${signal} process [${process.pid}] -> shutdown VCX with deleting wallet`)
    await shutdownVcx(true)
    process.exit(0)
  })

  await createInviation()

  log.info('Run alice now.')
}

async function createInviation() {
  //STEP.1 - create invitation(connection) & send invitation
  log.info('#5 Create a connection to alice and return the invite details')
  const connection = await Connection.create({id: 'alice'})
  await connection.connect('{}')
  await connection.updateState()

  const details = await connection.inviteDetails(false)
  log.info('**invite details**')
  log.info(details)

  log.silly(`walletAddRecord (invitation, defaultInvitation, ${JSON.stringify(JSON.parse(details), null, 2)})`)
  await walletAddRecord('invitation', 'defaultInvitation', details, {})

  const serialConnection = await connection.serialize()
  const pwDid = await connection.getPwDid()

  log.silly(`walletAddRecord (connection, ${pwDid}, ${JSON.stringify(serialConnection, null, 2)})`)
  await walletAddRecord('connection', pwDid, JSON.stringify(serialConnection), {})

  await connection.release()
}

async function getInvitation() {
  log.info('getInvitation >>>')
  const invitationRecord = await walletGetRecord('invitation', 'defaultInvitation', {})
  const invitation = JSON.parse(invitationRecord).value
  log.info(`getInvitation <<< invitation:${invitation}`)

  return JSON.parse(invitation)
}

async function handleMessage(message) {
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

    //log.debug(`payloadMsg: ${JSON.stringify(payloadMsg, null, 2)}`)

    switch (payloadTypeName) {
      case 'aries':
        // STEP.3 - accept connection request
        if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/request') {
          log.info('- Case(aries, connections/1.0/request) -> acceptConnectionRequest')
          log.verbose(`aries: spec/connections/1.0/request [${++numRequest}]`)
          await acceptConnectionRequest(connection)
        }
        // STEP.5 - receive connection ACK
        else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/notification/1.0/ack') {
          log.info('- Case(aries, notification/1.0/ack) -> receiveConnectionAck & sendCredentialOffer')
          log.verbose(`aries: spec/notification/1.0/ack [${++numAck}]`)
          await receiveConnectionAck(connection, pwDid)

          // STEP.11 - request proof
          await sendProofRequest(connection)
        }
        else {
          log.error(`msg: ${JSON.stringify(msg, null, 2)}`)
          throw new Error(`unknown payload message type name: ${payloadMsgType}`)
        }
        break

      case 'presentation':
        // STEP.13 - receive & verify proof
        log.info('- Case(presentation) -> verifyProof')
        log.verbose(`presentation: / [${++numPresent}]`)
        await verifyProof(connection, payloadMsg)
        log.verbose(`End of verify: ${++numVerify}`)
        break

      default:
        log.error(`msg: ${JSON.stringify(msg, null, 2)}`)
        log.error(`unknown payload type name: ${payloadTypeName}`)
        throw new Error(`unknown payload type name: ${payloadTypeName}`)
    } //switch (payloadTypeName)
  } //for (const msg of message.msgs)

  await connection.release()
}

async function acceptConnectionRequest(connection) {
  await connection.updateState()
  const connectionState = await connection.getState()

  if (connectionState === StateType.RequestReceived) {
    const newPwDid = await connection.getPwDid()
    const serialConnection = await connection.serialize()
    log.silly(`walletAddRecord (connection, ${newPwDid}, ${JSON.stringify(serialConnection, null, 2)})`)
    await walletAddRecord('connection', newPwDid, JSON.stringify(serialConnection), {})
  } else {
    throw new Error(`unexpected connection state: ${connectionState}`)
  }
}

async function receiveConnectionAck(connection, pwDid) {
  await connection.updateState()
  const connectionState = await connection.getState()

  if (connectionState === StateType.Accepted) {
    const updateConnection = await connection.serialize()
    log.silly(`walletUpdateRecordValue (connection, ${pwDid}, ${JSON.stringify(updateConnection, null, 2)})`)
    await walletUpdateRecordValue('connection', pwDid, JSON.stringify(updateConnection))
  } else {
    throw new Error(`unexpected connection state: ${connectionState}`)
  }
}

async function sendProofRequest(connection) {
  const vcxConfigRecord = await walletGetRecord('vcxConfig', 'defaultVcxConfig', {})
  const vcxConfig = JSON.parse(JSON.parse(vcxConfigRecord).value)
  const proofAttributes = [
    {
      names: ['name', 'last_name', 'sex'],
      restrictions: [{ issuer_did: vcxConfig.institution_did }]
    },
    {
      name: 'date',
      restrictions: { issuer_did: vcxConfig.institution_did }
    },
    {
      name: 'degree',
      restrictions: { 'attr::degree::value': 'maths' }
    }
  ]

  const proofPredicates = [
    { name: 'age',
      p_type: '>=',
      p_value: 20,
      restrictions: [{ issuer_did: vcxConfig.institution_did }] }
  ]

  log.info('#19 Create a Proof object')
  const proof = await Proof.create({
    sourceId: 'proof_uuid',
    attrs: proofAttributes,
    preds: proofPredicates,
    name: 'proofForAlice',
    revocationInterval: { to: Math.floor(new Date() / 1000) }
  })

  log.info('#20 Request proof of degree from alice')
  await proof.requestProof(connection)
  const serialProof = await proof.serialize()
  const threadId = serialProof.data.verifier_sm.state.PresentationRequestSent.presentation_request['@id']

  log.silly(`walletAddRecord (proof, ${threadId}, ${JSON.stringify(serialProof, null, 2)})`)
  await walletAddRecord('proof', threadId, JSON.stringify(serialProof), {})

  await proof.release()
}

async function verifyProof(connection, payloadMsg) {
  const threadId = payloadMsg['~thread'].thid
  const proofRecord = await walletGetRecord('proof', threadId, {})

  // TODO: Must replace connection_handle in proof - Need to consider better way
  let serialProof = JSON.parse(JSON.parse(proofRecord).value)
  serialProof.data.verifier_sm.state.PresentationRequestSent.connection_handle = connection.handle

  const proof = await Proof.deserialize(serialProof)
  await proof.updateState()
  const proofState = await proof.getState()

  if (proofState === StateType.Accepted) {
    log.info('#27 Process the proof provided by alice')
    const proofResult = await proof.getProof(connection)

    log.info('#28 Check if proof is valid')
    if (proofResult.proofState === ProofState.Verified) {
      const encodedProof = JSON.parse(proofResult.proof)['presentations~attach'][0].data.base64
      const decodedProof = Buffer.from(encodedProof, 'base64')
      const requestedProof = decodedProof.requested_proof
      log.info(`Requested proof: ${JSON.stringify(requestedProof, null, 2)}`)
      log.info('Proof is verified')
    } else if (proofResult.proofState === ProofState.Invalid) {
      log.info('Proof verification failed. credential has been revoked')
    } else {
      throw new Error(`unknown proof state: ${proof.proofState}`)
    }
  } else if (proofState === StateType.None) {
    log.info('Incorrect proof is received')
  } else {
    throw new Error(`unexpected proof type: ${proofState}`)
  }

  serialProof = await proof.serialize()

  log.silly(`walletUpdateRecordValue (proof, ${threadId}, ${JSON.stringify(serialProof, null, 2)})`)
  await walletUpdateRecordValue('proof', threadId, JSON.stringify(serialProof))

  await proof.release()
}

function runWebHookServer() {
  const app = express()
  const port = url.parse(webHookUrl).port
  const asyncHandler = fn => (req, res, next) => {
    return Promise
      .resolve(fn(req, res, next))
      .catch(function (err) {
        log.error(`${util.inspect(err)}`)
        res.status(500).send({ message: `${util.inspect(err)}` })
        process.exit(1)
      })
  }

  app.use(bodyParser.json())
  app.use(morgan('dev'))

  app.post('/notifications', asyncHandler(async (req, res) => {
    const downloadMessagesParam = {
      //status: req.body.msgStatusCode,
      uids: req.body.msgUid,
      pairwiseDids: req.body.pwDid,
    }
    const dlMessages = JSON.parse(await downloadMessages(downloadMessagesParam))
    log.silly(`dlMessages: ${JSON.stringify(dlMessages, null, 2)}`)

    for (const message of dlMessages) {
      if (message.msgs.length < 1) {
        throw new Error(`empty message: ${JSON.stringify(message, null, 2)}`)
      }

      try {
        await handleMessage(message)
      } catch (err) {
        log.error(`message: ${JSON.stringify(message, null, 2)}`)
        throw new Error(`handleMessage error: ${err.message}`)
      }
    }

    res.status(200).send()
  }))

  // STEP.1 - create connection & send invitation
  app.get('/invitations', asyncHandler(async (req, res) => {
    const invitation = await getInvitation()
    res.status(200).json(invitation)
  }))

  app.use(asyncHandler(async (req) => {
    throw new Error(`Your request: '${req.originalUrl}' didn't reach any handler.`)
  }))

  app.listen(port, () => log.verbose(`Server listening on port ${port}...`))
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

function areOptionsValid (options) {
  const allowedCommMethods = ['aries', 'legacy']
  if (!(allowedCommMethods.includes(options.comm))) {
    console.error(`Unknown communication method ${options.comm}. Only ${JSON.stringify(allowedCommMethods)} are allowed.`)
    return false
  }
  return true
}

runScript(optionDefinitions, usage, areOptionsValid, startUp)
  .catch(function(err) {
    log.error(`${util.inspect(err)}`)
  })