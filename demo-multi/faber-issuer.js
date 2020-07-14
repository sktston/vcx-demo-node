const { CredentialDef } = require('../dist/src/api/credential-def')
const { IssuerCredential } = require('../dist/src/api/issuer-credential')
const { Connection } = require('../dist/src/api/connection')
const { Schema } = require('./../dist/src/api/schema')
const { StateType } = require('../dist/src')
const { setActiveTxnAuthorAgreementMeta, getLedgerAuthorAgreement } = require('./../dist/src/api/utils')
const sleepPromise = require('sleep-promise')
const demoCommon = require('./common')
const { getRandomInt } = require('./common')
const logger = require('./logger')
const url = require('url')
const isPortReachable = require('is-port-reachable')
const { runScript } = require('./script-comon')
const axios = require('axios')
const { shutdownVcx } = require('../dist/src')

const utime = Math.floor(new Date() / 1000)
const optionalWebhook = 'http://localhost:7209/notifications/faber-issuer'

const TAA_ACCEPT = process.env.TAA_ACCEPT === 'true' || false

const provisionConfig = {
  agency_url: 'http://localhost:8080',
  agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
  agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  wallet_name: `node_vcx_demo_faber_issuer_wallet_${utime}`,
  wallet_key: '123',
  payment_method: 'null',
  enterprise_seed: '000000000000000000000000Trustee1'
}

const logLevel = 'error'

async function runFaber (options) {
  await demoCommon.initLibNullPay()

  logger.info('#0 Initialize rust API from NodeJS')
  await demoCommon.initRustApiAndLogger(logLevel)

  if (options.comm === 'aries') {
    provisionConfig.protocol_type = '2.0'
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

  if (await isPortReachable(url.parse(optionalWebhook).port, {host: url.parse(optionalWebhook).hostname})) { // eslint-disable-line
    provisionConfig.webhook_url = optionalWebhook
    logger.info(`Running with webhook notifications enabled! Webhook url = ${optionalWebhook}`)
  } else {
    logger.info('Webhook url will not be used')
  }

  logger.info(`#1 Config used to provision agent in agency: ${JSON.stringify(provisionConfig, null, 2)}`)
  const agentProvision = await demoCommon.provisionAgentInAgency(provisionConfig)

  logger.info(`#2 Using following agent provision to initialize VCX ${JSON.stringify(agentProvision, null, 2)}`)
  await demoCommon.initVcxWithProvisionedAgentConfig(agentProvision)

  logger.verbose('#2-1 Register Ctrl-C handler to shutdown VCX with deleting wallet')
  process.on('SIGINT', async (signal) => {
    logger.verbose(`${signal} process [${process.pid}] -> shutdown VCX with deleting wallet`)
    await shutdownVcx(true)
    process.exit(0)
  })

  if (agentProvision.webhook_url) {
    logger.info(`#2-2 Register webhook in agency`)
    const webHookRegData = {
      webhookUrl: agentProvision.webhook_url
    }
    webHookRegEndPoint = agentProvision.agency_endpoint + '/agent/' + agentProvision.remote_to_sdk_did
    await axios.post(webHookRegEndPoint, webHookRegData)
  }

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

  logger.info('#4 Create a new credential definition on the ledger')
  const data = {
    name: 'DemoCredential123',
    paymentHandle: 0,
    revocation: false,
    revocationDetails: {
      tailsFile: 'tails.txt'
    },
    schemaId: schemaId,
    sourceId: 'testCredentialDefSourceId123'
  }
  const credDef = await CredentialDef.create(data)
  const credDefId = await credDef.getCredDefId()
  const credDefHandle = credDef.handle
  logger.info(`Created credential with id ${credDefId} and handle ${credDefHandle}`)

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

  logger.info('#6 Polling agency and waiting for alice to accept the invitation. (start alice.py now)')

  // store created connectionToAlice connection for using repeated invitation
  const inviteConnectionToAlice = await connectionToAlice.serialize()

  let aliceId = 0

  while (true) {
    let connectionState = await connectionToAlice.getState()
    while (connectionState !== StateType.Accepted) {
      await sleepPromise(options.pollInterval)
      await connectionToAlice.updateState()
      connectionState = await connectionToAlice.getState()
    }
    logger.info(`Connection to alice [${++aliceId}] was Accepted!`)

    serveAlice(connectionToAlice, credDefHandle, agentProvision, aliceId, options)

    connectionToAlice = await Connection.deserialize(inviteConnectionToAlice)
  }

  logger.error('Never reach here')
  process.exit(1)
}

async function serveAlice(connectionToAlice, credDefHandle, agentProvision, aliceId, options) {
  const schemaAttrs = {
    name: 'alice',
    last_name: 'clark',
    sex: 'female',
    date: '05-2018',
    degree: 'maths',
    age: '25'
  }

  logger.info('#12 Create an IssuerCredential object using the schema and credential definition')

  const credentialForAlice = await IssuerCredential.create({
    attr: schemaAttrs,
    sourceId: 'alice_degree',
    credDefHandle,
    credentialName: 'cred',
    price: '0'
  })

  logger.info('#13 Issue credential offer to alice')
  await credentialForAlice.sendOffer(connectionToAlice)
  await credentialForAlice.updateState()

  logger.info('#14 Poll agency and wait for alice to send a credential request')
  let credentialState = await credentialForAlice.getState()
  while (credentialState !== StateType.RequestReceived) {
    await sleepPromise(options.pollInterval)
    await credentialForAlice.updateState()
    credentialState = await credentialForAlice.getState()
  }

  logger.info('#17 Issue credential to alice')
  await credentialForAlice.sendCredential(connectionToAlice)

  logger.info('#18 Wait for alice to accept credential')
  await credentialForAlice.updateState()
  credentialState = await credentialForAlice.getState()
  while (credentialState !== StateType.Accepted) {
    await sleepPromise(options.pollInterval)
    await credentialForAlice.updateState()
    credentialState = await credentialForAlice.getState()
  }

  logger.verbose(`End of credential issue --> Release connection to Alice[${aliceId}]`)
  connectionToAlice.release()
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
    name: 'pollInterval',
    alias: 'p',
    type: Number,
    description: 'Agency polling interval for message checking',
    defaultValue: 2000
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
