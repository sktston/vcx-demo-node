/**************************************************
 * Author  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since August 10, 2020                          *
 **************************************************/

'use strict'

const { Connection } = require('../dist/src/api/connection')
const { StateType } = require('../dist/src/api/common')
const { downloadMessages } = require('../dist/src/api/utils')
const { shutdownVcx, getVersion } = require('../dist/src/api/utils')
const { walletAddRecord, walletGetRecord, walletUpdateRecordValue } = require('./wallet')
const log = require('./logger')
const common = require('./common')
const config = require('./faber-config.json')

const express = require('express')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const url = require('url')
const util = require('util')

log.level = process.env.APP_LOG_LEVEL ? process.env.APP_LOG_LEVEL : config.appLogLevel

async function initialize(webHookUrl) {
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
  if (config.commMethod === 'aries') {
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

function runWebHookServer(webHookUrl, handleMessage) {
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
  app.get('/invitation', asyncHandler(async (req, res) => {
    const invitation = await getInvitation()
    res.status(200).json(invitation)
  }))

  app.use(asyncHandler(async (req) => {
    throw new Error(`Your request: '${req.originalUrl}' didn't reach any handler.`)
  }))

  app.listen(port, () => log.info(`Server listening on port ${port}...`))
}

module.exports = {
  runWebHookServer, initialize, createInviation,
  acceptConnectionRequest, receiveConnectionAck
}