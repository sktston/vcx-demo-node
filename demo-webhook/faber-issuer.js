const { CredentialDef } = require('../dist/src/api/credential-def')
const { IssuerCredential } = require('../dist/src/api/issuer-credential')
const { Connection } = require('../dist/src/api/connection')
const { Schema } = require('./../dist/src/api/schema')
const { StateType } = require('../dist/src')
const { setActiveTxnAuthorAgreementMeta, getLedgerAuthorAgreement } = require('./../dist/src/api/utils')
const demoCommon = require('./common')
const { getRandomInt } = require('./common')
const logger = require('./logger')
const url = require('url')
const ip = require('ip');
const isPortReachable = require('is-port-reachable')
const { runScript } = require('./script-comon')
const { shutdownVcx, downloadMessages, updateMessages, getVersion } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')

const express = require('express')
const bodyParser = require('body-parser')

const utime = Math.floor(new Date() / 1000)
const TAA_ACCEPT = process.env.TAA_ACCEPT === 'true' || false

const provisionConfig = {
  agency_url: process.env.AGENCY_URL ? process.env.AGENCY_URL : 'http://localhost:8080',
  agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
  agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  wallet_name: `node_vcx_demo_faber_issuer_wallet_${utime}`,
  wallet_key: '123',
  payment_method: 'null',
  enterprise_seed: '000000000000000000000000Trustee1'
}

const logLevel = process.env.VCX_LOG_LEVEL ? process.env.VCX_LOG_LEVEL : 'error'

const ariesProtocolType = '4.0'
const webHookUrl = 'http://' + ip.address() + ':7201/notifications/'
const autoSendOffer = true
let serverReady = false
let numRequest = 0, numAck = 0, numReqCred = 0, numIssues = 0

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

async function runFaber (options) {
  await runWebHookServer()

  await demoCommon.initLibNullPay()

  logger.info('#0 Initialize rust API from NodeJS')
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
  agentProvision.pool_config = '{"timeout":60}'

  logger.info(`#2 Using following agent provision to initialize VCX ${JSON.stringify(agentProvision, null, 2)}`)
  await demoCommon.initVcxWithProvisionedAgentConfig(agentProvision)

  logger.verbose('#2-1 Register Ctrl-C handler to shutdown VCX with deleting wallet')
  process.on('SIGINT', async (signal) => {
    logger.verbose(`${signal} process [${process.pid}] -> shutdown VCX with deleting wallet`)
    await shutdownVcx(true)
    process.exit(0)
  })

  if (TAA_ACCEPT) {
    logger.info('#2.1 Accept transaction author agreement')
    const taa = await getLedgerAuthorAgreement()
    const taa_json = JSON.parse(taa)
    await setActiveTxnAuthorAgreementMeta(taa_json.text, taa_json.version, null, Object.keys(taa_json.aml)[0], utime)
  }

  const version = `${getRandomInt(1, 101)}.${getRandomInt(1, 101)}.${getRandomInt(1, 101)}`
  const schemaData = {
    data: {
      attrNames: ['name', 'last_name', 'sex', 'date', 'degree', 'age'],
      name: 'FaberVcx',
      version
    },
    paymentHandle: 0,
    sourceId: `your-identifier-fabervcx-${version}`
  }
  logger.info(`#3 Create a new schema on the ledger: ${JSON.stringify(schemaData, null, 2)}`)

  const schema = await Schema.create(schemaData)
  const schemaId = await schema.getSchemaId()
  logger.info(`Created schema with id ${schemaId}`)

  logger.verbose('#3-1 Store schema to Faber\'s local wallet')
  const  serialSchema = JSON.stringify(await schema.serialize())
  await walletAddRecord('schema', 'defaultSchema', serialSchema, {})
  await schema.release()

  logger.info('#4 Create a new credential definition on the ledger')
  const data = {
    name: `DemoCredential_${utime}`,
    paymentHandle: 0,
    revocation: false,
    revocationDetails: {
      tailsFile: 'tails.txt'
    },
    schemaId: schemaId,
    sourceId: `CredentialDefSourceId_${utime}`
  }
  const credDef = await CredentialDef.create(data)
  const credDefId = await credDef.getCredDefId()
  const credDefHandle = credDef.handle
  logger.info(`Created credential with id ${credDefId} and handle ${credDefHandle}`)

  logger.verbose('#4-1 Store credential definition to Faber\'s local wallet')
  const  serialCredDef = JSON.stringify(await credDef.serialize())
  await walletAddRecord('credentialDef', 'defaultCredentialDef', serialCredDef, {})
  await credDef.release()

  //STEP.1 - create connection F & send invitation
  logger.info('#5 Create a connection to alice and print out the invite details')
  const connectionToAlice = await Connection.create({id: 'alice'})
  await connectionToAlice.connect('{}')
  await connectionToAlice.updateState()

  const details = await connectionToAlice.inviteDetails(false)
  logger.info('\n\n**invite details**')
  logger.info("**You'll ge queried to paste this data to alice side of the demo. This is invitation to connect.**")
  logger.info("**It's assumed this is obtained by Alice from Faber by some existing secure channel.**")
  logger.info('**Could be on website via HTTPS, QR code scanned at Faber institution, ...**')
  logger.info('\n******************\n\n')
  logger.info(details)
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

async function runWebHookServer() {
  const app = express()
  const port = url.parse(webHookUrl).port

  app.use(bodyParser.json())

  app.post('/notifications', async (req, res) => {
    if (serverReady) {
      const downloadMessagesParam = {
        //status: req.body.msgStatusCode,
        uids: req.body.msgUid,
        pairwiseDids: req.body.pwDid,
      }
      const dlMessages = JSON.parse(await downloadMessages(downloadMessagesParam))
      logger.debug(`dlMessages: ${JSON.stringify(dlMessages, null, 2)}`)

      for (const message of dlMessages) {
        if (message.msgs.length < 1) {
          logger.error(`empty message: ${JSON.stringify(message, null, 2)}`)
          throw new Error(`empty message: ${JSON.stringify(message, null, 2)}`)
        }

        try {
          await processMessage(message)
        } catch (err) {
          logger.error(`processMessage error: ${err.message}`)
          process.exit(1)
        }
      }

      res.status(200).send()
    } else {
      logger.error('Server is not ready')
      res.status(500).send({ message: 'Server is not ready' })
    }
  })

  app.get('/invitations', async function (req, res) {
    if (serverReady) {
      const record = await walletGetRecord('invite', 'defaultInvite', {})
      const inviteDetails = JSON.parse(JSON.parse(record).value)
      logger.debug(`inviteDetails: ${JSON.stringify(inviteDetails)}`)
      res.status(200).json(inviteDetails)
    } else {
      logger.error('Server is not ready')
      res.status(500).send({ message: 'Server is not ready' })
    }
  })

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

    //logger.debug(`payloadMsg: ${JSON.stringify(payloadMsg, null, 2)}`)

    if (payloadTypeName !== 'aries') {
      logger.error(`unknown payload type name: ${payloadTypeName}`)
      throw new Error(`unknown payload type name: ${payloadTypeName}`)
    }

    // STEP.3 - update connection from F to F2A
    // connection request - At Inviter: after receiving invitation from Invitee
    if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/request') {
      logger.verbose(`aries: spec/connections/1.0/request [${++numRequest}]`)
      await connectionToAlice.updateState()
      const connectionState = await connectionToAlice.getState()

      if (connectionState === StateType.RequestReceived) {
        const newPwDid = await connectionToAlice.getPwDid()
        const serialConnectionToAlice = JSON.stringify(await connectionToAlice.serialize())
        await walletAddRecord('connection', newPwDid, serialConnectionToAlice, {})
      } else {
        logger.error(`unexpected connection state: ${connectionState}`)
        throw new Error(`unexpected connection state: ${connectionState}`)
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
        logger.error(`unexpected connection state: ${connectionState}`)
        throw new Error(`unexpected connection state: ${connectionState}`)
      }
      // STEP.6 - send credential offer
      // After issuing credential, issuer does not receive Ack for that
      // We send proof request here
      if (autoSendOffer) {
        const schemaAttrs = {
          name: 'alice',
          last_name: 'clark',
          sex: 'female',
          date: '05-2018',
          degree: 'maths',
          age: '25'
        }

        logger.info('#12 Create an IssuerCredential object using the schema and credential definition')

        const record = await walletGetRecord('credentialDef', 'defaultCredentialDef', {})
        const credDef = await CredentialDef.deserialize(JSON.parse(JSON.parse(record).value))
        const credDefHandle = credDef.handle
        const credentialForAlice = await IssuerCredential.create({
          attr: schemaAttrs,
          sourceId: 'alice_degree',
          credDefHandle,
          credentialName: 'cred',
          price: '0'
        })

        logger.info('#13 Issue credential offer to alice')
        await credentialForAlice.sendOffer(connectionToAlice)

        const serialCredentialForAlice = JSON.stringify(await credentialForAlice.serialize())
        const threadId = JSON.parse(serialCredentialForAlice).data.issuer_sm.state.OfferSent.thread_id
        await walletAddRecord('credential', threadId, serialCredentialForAlice, {})

        await credentialForAlice.release()
        await credDef.release()
      } //if (autoSendOffer)
    } //else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/notification/1.0/ack')

    // STEP.8 - receive request & send credential
    // connection response - At Issuer: After issuerSendCredentialOffer
    else if (payloadMsgType === 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/request-credential') {
      logger.verbose(`aries: spec/issue-credential/1.0/request-credential[${++numReqCred}]`)
      const threadId = payloadMsg['~thread'].thid
      const record = await walletGetRecord('credential', threadId, {})

      // TODO: Must replace connection_handle in credential - Need to consider better way
      const serialCredential = JSON.parse(JSON.parse(record).value)
      serialCredential.data.issuer_sm.state.OfferSent.connection_handle = connectionToAlice.handle
      const credentialForAlice = await IssuerCredential.deserialize(serialCredential)

      await credentialForAlice.updateState()
      const credentialState = await credentialForAlice.getState()

      if (credentialState === StateType.RequestReceived) {
        logger.info('#17 Issue credential to alice')

        await credentialForAlice.sendCredential(connectionToAlice)

        const serialCredential = JSON.stringify(await credentialForAlice.serialize())
        await walletUpdateRecordValue('credential', threadId, serialCredential)
      } else {
        logger.error(`unexpected credential state: ${connectionState}`)
        throw new Error(`unexpected credential state: ${connectionState}`)
      }

      await credentialForAlice.release()
      logger.verbose(`End of credential issue: ${++numIssues}`)
    } else {
      logger.error(`msg: ${JSON.stringify(msg, null, 2)}`)
      logger.error(`unknown payload message type name: ${payloadMsgType}`)
      throw new Error(`unknown payload message type name: ${payloadMsgType}`)
    }
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