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
const { StateType } = require('../dist/src/api/common')
const { endorseTransaction } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')
const common = require('./common')
const log = require('./logger')
const faber = require('./faber-common')
const config = require('./faber-config.json')

const ip = require('ip')
const util = require('util')
const os = require('os')
const axios = require('axios')
const FormData = require('form-data')
const fs = require('fs')

const webHookUrl = 'http://' + ip.address() + ':7201/notifications/'
const tailsFileRoot = os.homedir() + '/.indy_client/tails'
let numRequest = 0, numAck = 0, numReqCred = 0, numIssues = 0

log.level = process.env.APP_LOG_LEVEL ? process.env.APP_LOG_LEVEL : config.appLogLevel

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

async function startUp() {
  await faber.initialize(webHookUrl)

  await createSchema()
  await createCredentialDefinition()
  await faber.createInviation()
  log.info('Setting of schema and credential definition is done. Run alice now.')

  faber.runWebHookServer(webHookUrl, handleMessage)
  return 'Waiting web hook event from agent...'
}

async function createSchema() {
  // define schema with actually needed
  const version = `${common.getRandomInt(1, 99)}.${common.getRandomInt(1, 99)}.${common.getRandomInt(1, 99)}`
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
      supportRevocation: config.supportRevoke,
      // tails file is created here when prepareForEndorser
      tailsFile: config.supportRevoke ? tailsFileRoot : 'tails.txt',
      maxCreds: config.supportRevoke ? config.maxCrdes : 0
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

  log.info('#4-2 Publish credential definition and revocation registry on the ledger')
  await endorseTransaction(credDefTrx)

  let revRegDefTrx, revRegId, tailsFileHash, revRegEntryTrx
  if (config.supportRevoke) {
    revRegDefTrx = credDef.revocRegDefTransaction
    revRegId = JSON.parse(revRegDefTrx).operation.id
    tailsFileHash = JSON.parse(revRegDefTrx).operation.value.tailsHash
    revRegEntryTrx = credDef.revocRegEntryTransaction

    // we replace tails file location from local to tails server url
    revRegDefTrx = JSON.parse(revRegDefTrx)
    revRegDefTrx.operation.value.tailsLocation = config.tailsServerURL + '/' + revRegId
    revRegDefTrx = JSON.stringify(revRegDefTrx)
    await endorseTransaction(revRegDefTrx)
    await endorseTransaction(revRegEntryTrx)
  }

  await credDef.updateState()
  const credentialDefState = await credDef.getState()

  if (credentialDefState === StateType.Initialized) {
    log.info('Published successfully')
  } else {
    throw new Error(`Publishing is failed: ${credentialDefState}`)
  }

  if (config.supportRevoke) {
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
  }

  const credDefId = await credDef.getCredDefId()
  log.info(`Created credential with id ${credDefId} and handle ${credDefHandle}`)

  const serialCredDef = await credDef.serialize()

  log.silly(`walletAddRecord (credentialDef, defaultCredentialDef, ${JSON.stringify(serialCredDef, null, 2)})`)
  await walletAddRecord('credentialDef', 'defaultCredentialDef', JSON.stringify(serialCredDef), {})

  await credDef.release()
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
      await faber.acceptConnectionRequest(connection)
    }
    // STEP.5 - receive connection ACK
    else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/notification/1.0/ack') {
      log.info('- Case(aries, notification/1.0/ack) -> receiveConnectionAck & sendCredentialOffer')
      log.verbose(`aries: spec/notification/1.0/ack [${++numAck}]`)
      await faber.receiveConnectionAck(connection, pwDid)

      // STEP.6 - send credential offer
      await sendCredentialOffer(connection)
    }
    // STEP.8 - send credential
    else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/request-credential') {
      log.info('- Case(aries ,issue-credential/1.0/request-credential) -> sendCredential')
      log.verbose(`aries: spec/issue-credential/1.0/request-credential[${++numReqCred}]`)
      await sendCredential(connection, payloadMsg)
      if (config.revokeAfterIssue) {
        log.info('#8-1 (Revoke enabled) Revoke the credential')
        await revokeCredential(payloadMsg);
      }
    }
    // STEP.10 - receive credential ACK
    else if(payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/ack') {
      log.info('- Case(aries ,issue-credential/1.0/ack) -> receiveCredentialAck')
      // no logic for receiveCredentialAck in demo
      log.verbose(`End of credential issue: ${++numIssues}`)
    }
    // receive problem-report
    else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/report-problem/1.0/problem-report') {
        log.error(`- Case(aries ,report-problem/1.0/problem-report) -> printProblem`)
        throw new Error(`comment: ${payloadMsg.comment}`)
    }
    else {
      log.error(`msg: ${JSON.stringify(msg, null, 2)}`)
      throw new Error(`unknown payload message type name: ${payloadMsgType}`)
    }
  } //for (const msg of message.msgs)

  await connection.release()
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

startUp()
  .then(msg => log.info(msg))
  .catch(err => {
    log.error(`${util.inspect(err)}`)
  })