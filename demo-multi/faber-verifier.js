//const { CredentialDef } = require('../dist/src/api/credential-def')
//const { IssuerCredential } = require('../dist/src/api/issuer-credential')
const { Proof } = require('../dist/src/api/proof')
const { Connection } = require('../dist/src/api/connection')
//const { Schema } = require('./../dist/src/api/schema')
const { StateType, ProofState } = require('../dist/src')
const { setActiveTxnAuthorAgreementMeta, getLedgerAuthorAgreement } = require('./../dist/src/api/utils')
const sleepPromise = require('sleep-promise')
const demoCommon = require('./common')
const { getRandomInt } = require('./common')
const logger = require('./logger')
const url = require('url')
const isPortReachable = require('is-port-reachable')
const { runScript } = require('./script-comon')
const axios = require('axios')
const readlineSync = require('readline-sync')
const { shutdownVcx } = require('../dist/src')

const utime = Math.floor(new Date() / 1000)
const optionalWebhook = 'http://localhost:7209/notifications/faber-verifier'

const TAA_ACCEPT = process.env.TAA_ACCEPT === 'true' || false

const provisionConfig = {
  agency_url: 'http://localhost:8080',
  agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
  agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  wallet_name: `node_vcx_demo_faber_verifier_wallet_${utime}`,
  wallet_key: '123',
  payment_method: 'null',
  enterprise_seed: '000000000000000000000000Trustee1'
}

const logLevel = process.env.VCX_LOG_LEVEL ? process.env.VCX_LOG_LEVEL : 'error'

function waitEnter() {
  if (process.env.STEP == 'true') {
    readlineSync.question('Wait Enter-key...')
  }
}

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

  // register Ctrl-C handler to shutdown VCX with deleting wallet
  process.on('SIGINT', async (signal) => {
    logger.verbose(`${signal} process [${process.pid}] -> shutdown VCX with deleting wallet`)
    await shutdownVcx(true)
    process.exit(0)
  })

  logger.info(`#2 Using following agent provision to initialize VCX ${JSON.stringify(agentProvision, null, 2)}`)
  await demoCommon.initVcxWithProvisionedAgentConfig(agentProvision)

  if (agentProvision.webhook_url) {
    logger.info(`#2-1 Register webhook in agency`)
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

    serveAlice(connectionToAlice, agentProvision, aliceId, options)

    connectionToAlice = await Connection.deserialize(inviteConnectionToAlice)
  }

  logger.error('Never reach here')
  process.exit(1)
}

async function serveAlice(connectionToAlice, agentProvision, aliceId, options) {
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

  logger.info('#21 Poll agency and wait for alice to provide proof')
  let proofState = await proof.getState()
  while (proofState !== StateType.Accepted) {
    await sleepPromise(options.pollInterval)
    await proof.updateState()
    proofState = await proof.getState()
  }

  logger.info('#27 Process the proof provided by alice')
  await proof.getProof(connectionToAlice)

  logger.info('#28 Check if proof is valid')
  if (proof.proofState === ProofState.Verified) {
    logger.info('Proof is verified')
  } else {
    logger.info('Could not verify proof')
  }

  logger.verbose(`End of credential verification --> Release connection to Alice[${aliceId}]`)
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
