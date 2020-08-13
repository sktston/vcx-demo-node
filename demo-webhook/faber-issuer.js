/**************************************************
 * Author  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since August 10, 2020                          *
 **************************************************/

'use strict'

const { CredentialDef } = require('../dist/src/api/credential-def')
const { IssuerCredential } = require('../dist/src/api/issuer-credential')
const { Connection } = require('../dist/src/api/connection')
const { Schema } = require('./../dist/src/api/schema')
const { StateType } = require('../dist/src')
const common = require('./common')
const { getRandomInt } = require('./common')
const log = require('./logger')
const config = require('./faber-config.json')
const { runScript } = require('./script-comon')
const { shutdownVcx, downloadMessages, getVersion, endorseTransaction } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')

const express = require('express')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const url = require('url')
const ip = require('ip')
const util = require('util')
const os = require('os')
const axios = require('axios')
const FormData = require('form-data')
const fs = require('fs')

const webHookUrl = 'http://' + ip.address() + ':7201/notifications/'
const tailsFileRoot = os.homedir() + '/.indy_client/tails'
let numRequest = 0, numAck = 0, numReqCred = 0, numIssues = 0

/***
 "@" symbol specifies  web hook received step -> total 10-step which receives corresponding agency message
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

  await createSchema()
  await createCredentialDefinition()
  await createInviation()

  log.info('Setting of schema and credential definition is done. Run alice now.')
}

async function createSchema() {
  // define schema with actually needed
  const version = `${getRandomInt(1, 99)}.${getRandomInt(1, 99)}.${getRandomInt(1, 99)}`
  const schemaData = {
    data: {
      attrNames: ['name', 'last_name', 'sex', 'date', 'degree', 'age'],
      name: 'FaberVcx',
      version
    },
    paymentHandle: 0,
    sourceId: `your-identifier-fabervcx-${version}`
  }
  log.info(`#3 Create a new schema on the ledger: ${JSON.stringify(schemaData, null, 2)}`)

  const schema = await Schema.create(schemaData)
  const schemaId = await schema.getSchemaId()
  log.info(`Created schema with id ${schemaId}`)

  const serialSchema = await schema.serialize()

  log.silly(`walletAddRecord (schema, defaultSchema, ${JSON.stringify(serialSchema, null, 2)})`)
  await walletAddRecord('schema', 'defaultSchema', JSON.stringify(serialSchema), {})

  await schema.release()
}

async function createCredentialDefinition() {
  const schemaRecord = await walletGetRecord('schema', 'defaultSchema', {})
  const schema = JSON.parse(JSON.parse(schemaRecord).value)
  const schemaId = schema.data.schema_id
  const version = schema.data.version // not need same with schema version

  const vcxConfigRecord = await walletGetRecord('vcxConfig', 'defaultVcxConfig', {})
  const vcxConfig = JSON.parse(JSON.parse(vcxConfigRecord).value)
  const faberDid = vcxConfig.institution_did

  // define credential definition with actually needed
  const credDefData = {
    name: `CredentialDefName`,
    endorser: faberDid,
    revocationDetails: {
      supportRevocation: true,
      // tails file is created here when prepareForEndorser
      tailsFile: tailsFileRoot,
      maxCreds: config.maxCrdes
    },
    schemaId: schemaId,
    sourceId: `CredentialDefSourceId`,
    // add by dr.jhyun
    tag: `tag.${version}`
  }

  log.info(`#4-1 Create a new credential definition object: \n${JSON.stringify(credDefData, null, 2)}`)
  const credDef = await CredentialDef.prepareForEndorser(credDefData)

  const credDefHandle = credDef.handle
  const credDefTrx = credDef.credentialDefTransaction
  let   revRegDefTrx = credDef.revocRegDefTransaction
  const revRegId = JSON.parse(revRegDefTrx).operation.id
  const tailsFileHash = JSON.parse(revRegDefTrx).operation.value.tailsHash
  const revRegEntryTrx = credDef.revocRegEntryTransaction

  log.info('#4-2 Publish credential definition and revocation registry on the ledger')
  await endorseTransaction(credDefTrx)
  // we replace tails file location from local to tails server url
  revRegDefTrx = JSON.parse(revRegDefTrx)
  revRegDefTrx.operation.value.tailsLocation = config.tailsServerURL + '/' + revRegId
  revRegDefTrx = JSON.stringify(revRegDefTrx)
  await endorseTransaction(revRegDefTrx)
  await endorseTransaction(revRegEntryTrx)

  await credDef.updateState()
  const credentialDefState = await credDef.getState()

  if (credentialDefState === StateType.Initialized) {
    log.info('Published successfully')
  } else {
    throw new Error(`Publishing is failed: ${credentialDefState}`)
  }

  log.info(`#4-3 Upload tails file to tails filer server: ${config.tailsServerURL}/${revRegId}`)

  const formData = new FormData()
  formData.append('genesis', fs.createReadStream(`${__dirname}/genesis.txn`))
  formData.append('tails', fs.createReadStream(`${tailsFileRoot}/${tailsFileHash}`))

  const httpConfig = {
    headers: {
      ...formData.getHeaders()
    }
  }
  const response = await axios.put(`${config.tailsServerURL}/${revRegId}`, formData, httpConfig)

  if (response.data === tailsFileHash) {
    log.info(`Uploaded successfully - tails file: ${tailsFileRoot}/${tailsFileHash}`)
  } else {
    throw new Error(`Uploading is failed - tails file: ${tailsFileRoot}/${tailsFileHash}`)
  }

  const credDefId = await credDef.getCredDefId()
  log.info(`Created credential with id ${credDefId} and handle ${credDefHandle}`)

  const serialCredDef = await credDef.serialize()

  log.silly(`walletAddRecord (credentialDef, defaultCredentialDef, ${JSON.stringify(serialCredDef, null, 2)})`)
  await walletAddRecord('credentialDef', 'defaultCredentialDef', JSON.stringify(serialCredDef), {})

  await credDef.release()
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

    if (payloadTypeName !== 'aries') {
      log.error(`msg: ${JSON.stringify(msg, null, 2)}`)
      throw new Error(`unknown payload type name: ${payloadTypeName}`)
    }

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

      // STEP.6 - send credential offer
      await sendCredentialOffer(connection)
    }
    // STEP.8 - send credential
    else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/request-credential') {
      log.info('- Case(aries ,issue-credential/1.0/request-credential) -> sendCredential')
      log.verbose(`aries: spec/issue-credential/1.0/request-credential[${++numReqCred}]`)
      await sendCredential(connection, payloadMsg)
      if (config.enableRevoke) {
        log.info('#8-1 (Revoke enabled) Revoke the credential')
        await revokeCredential(payloadMsg);
      }
    }
    // STEP.10 - receive credential ACK
    else if(payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/ack') {
        log.info('- Case(aries ,issue-credential/1.0/ack) -> receiveCredentialAck')
        // no logic for receiveCredentialAck in demo
        log.verbose(`End of credential issue: ${++numIssues}`)
    } else {
      log.error(`msg: ${JSON.stringify(msg, null, 2)}`)
      throw new Error(`unknown payload message type name: ${payloadMsgType}`)
    }
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

async function sendCredentialOffer(connection) {
  const schemaAttrs = {
    name: 'alice',
    last_name: 'clark',
    sex: 'female',
    date: '05-2018',
    degree: 'maths',
    age: '25'
  }

  log.info('#12 Create an IssuerCredential object using the schema and credential definition')

  const record = await walletGetRecord('credentialDef', 'defaultCredentialDef', {})
  const credDef = await CredentialDef.deserialize(JSON.parse(JSON.parse(record).value))
  const credDefHandle = credDef.handle
  const credential = await IssuerCredential.create({
    attr: schemaAttrs,
    sourceId: 'alice_degree',
    credDefHandle,
    credentialName: 'cred',
    price: '0'
  })

  log.info('#13 Issue credential offer to alice')
  await credential.sendOffer(connection)

  const serialCredential = await credential.serialize()
  const threadId = serialCredential.data.issuer_sm.state.OfferSent.thread_id

  log.silly(`walletAddRecord (credential, ${threadId}, ${JSON.stringify(serialCredential, null, 2)})`)
  await walletAddRecord('credential', threadId, JSON.stringify(serialCredential), {})

  await credential.release()
  await credDef.release()
}

async function sendCredential(connection, payloadMsg) {
  const threadId = payloadMsg['~thread'].thid
  const credentialRecord = await walletGetRecord('credential', threadId, {})

  // TODO: Must replace connection_handle in credential - Need to consider better way
  const serialCredential = JSON.parse(JSON.parse(credentialRecord).value)
  serialCredential.data.issuer_sm.state.OfferSent.connection_handle = connection.handle
  const credential = await IssuerCredential.deserialize(serialCredential)

  await credential.updateState()
  const credentialState = await credential.getState()

  if (credentialState === StateType.RequestReceived) {
    log.info('#17 Issue credential to alice')

    await credential.sendCredential(connection)

    const serialCredential = await credential.serialize()
    log.silly(`walletUpdateRecordValue (credential, ${threadId}, ${JSON.stringify(serialCredential, null, 2)})`)
    await walletUpdateRecordValue('credential', threadId, JSON.stringify(serialCredential))
  } else {
    throw new Error(`unexpected credential state: ${connectionState}`)
  }

  await credential.release()
}

async function revokeCredential(payloadMsg) {
  const threadId = payloadMsg['~thread'].thid
  const credentialRecord = await walletGetRecord('credential', threadId, {})
  const serialCredential = JSON.parse(JSON.parse(credentialRecord).value)

  const credential = await IssuerCredential.deserialize(serialCredential)

  await credential.updateState()
  const credentialState = await credential.getState()

  if (credentialState === StateType.Accepted) {
    await credential.revokeCredential()

    const serialCredential = await credential.serialize()
    log.silly(`walletUpdateRecordValue (credential, ${threadId}, ${JSON.stringify(serialCredential, null, 2)})`)
    await walletUpdateRecordValue('credential', threadId, JSON.stringify(serialCredential))
  } else {
    throw new Error(`unexpected credential state: ${connectionState}`)
  }

  await credential.release()
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