/**************************************************
 * Author  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since August 10, 2020                          *
 **************************************************/

'use strict'

const { Connection } = require('../dist/src/api/connection')
const { Proof, ProofState } = require('../dist/src/api/proof')
const { StateType } = require('../dist/src/api/common')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')
const log = require('./logger')
const faber = require('./faber-common')
const config = require('./faber-config.json')

const ip = require('ip')
const util = require('util')

const webHookUrl = 'http://' + ip.address() + ':7202/notifications/'
let numRequest = 0, numAck = 0, numPresent = 0, numVerify = 0

log.level = process.env.APP_LOG_LEVEL ? process.env.APP_LOG_LEVEL : config.appLogLevel

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

async function startUp() {
  await faber.initialize(webHookUrl)
  await faber.createInviation()
  log.info('Setting of schema and credential definition is done. Run alice now.')

  faber.runWebHookServer(webHookUrl, handleMessage)
  return 'Waiting web hook event from agent...'
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
          await faber.acceptConnectionRequest(connection)
        }
        // STEP.5 - receive connection ACK
        else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/notification/1.0/ack') {
          log.info('- Case(aries, notification/1.0/ack) -> receiveConnectionAck & sendCredentialOffer')
          log.verbose(`aries: spec/notification/1.0/ack [${++numAck}]`)
          await faber.receiveConnectionAck(connection, pwDid)

          // STEP.11 - request proof
          await sendProofRequest(connection)
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
      const decodedProof = Buffer.from(encodedProof, 'base64').toString('utf8')
      const requestedProof = JSON.parse(decodedProof).requested_proof
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

startUp()
  .then(msg => log.info(msg))
  .catch(err => {
    log.error(`${util.inspect(err)}`)
  })
