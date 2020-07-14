const { DisclosedProof } = require('../dist/src/api/disclosed-proof')
const { Connection } = require('../dist/src/api/connection')
const { Credential } = require('../dist/src/api/credential')
const { StateType } = require('../dist/src')
const sleepPromise = require('sleep-promise')
const demoCommon = require('./common')
const logger = require('./logger')
const url = require('url')
const isPortReachable = require('is-port-reachable')
const { runScript } = require('./script-comon')
const { performance } = require('perf_hooks')

const { downloadMessages } = require('../dist/src/api/utils')
const { shutdownVcx } = require('../dist/src')

const express = require('express')
const bodyParser = require('body-parser')
const cluster = require('cluster')
const os = require('os')

const utime = Math.floor(new Date() / 1000)
const optionalWebhook = 'http://localhost:7209/notifications/alice'

let initVCX = false
let provisionConfig = {
  agency_url: 'http://localhost:8080',
  agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
  agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  wallet_name: `node_vcx_demo_alice_wallet_${utime}`,
  wallet_key: '123',
  payment_method: 'null',
  enterprise_seed: '000000000000000000000000Trustee1'
}

const logLevel = 'error'

function printResult(tStart, tFinish, numTrans) {
  const durationSec = (tFinish - tStart) / 1000
  const transPerSec = numTrans / durationSec
  const transPerMinute = transPerSec * 60

  logger.verbose()
  logger.verbose('----- Performance -----')
  logger.verbose(`Duration ${durationSec.toFixed(1)} secs to ${numTrans} issue & verify.`)
  logger.verbose(`PerSec ${transPerSec.toFixed(1)}  PerMinute ${transPerMinute.toFixed(1)}`)
  logger.verbose('-----------------------')
}

async function runAliceMultiple (options) {
  if (cluster.isMaster) {
    let numStart = 0
    let numDone = 0
    let numTrans = options.numTransactions
    const numAlice = options.numAlice
    const tStart = performance.now()

    if (numTrans < numAlice) {
      numTrans = numAlice
    }

    logger.verbose(`Num CPUS: ${os.cpus().length}`)

    cluster.schedulingPolicy = cluster.SCHED_RR
    for (let i = 0; i < options.numAlice; i++) {
      const worker = cluster.fork()

      worker.on('message', async (msg) => {
        if (msg.cmd && msg.cmd === 'aliceDone') {
          numDone += 1

          // start next transaction
          if (numStart < numTrans) {
            numStart += 1
            worker.send({cmd: 'aliceStart'})
          }

          // all transactions are done
          if (numDone >= numTrans) {
            for (const id in cluster.workers) {
              cluster.workers[id].send({cmd: 'aliceExit'})
            }

            // wait all workers exit
            await sleepPromise(1000)
            printResult(tStart, performance.now(), numTrans)
            process.exit(0)
          }
        }
      })

      numStart += 1
      worker.send({cmd: 'aliceStart'})
      await sleepPromise(options.aliceInterval * 1000)
    }

    cluster.on('exit', (worker, code, signal) => {
      const message = `Worker ${worker.process.pid} exits ` + (!code ? 'successfully' : `with error ${code}`)
      logger.verbose(message)
    })
  }
  else { // worker
    process.on('message', async (msg) => {
      if (msg.cmd) {
        switch (msg.cmd) {
          case 'aliceStart':
            logger.verbose(`Alice[${cluster.worker.id}] starts`)
            await runAlice(cluster.worker.id, options)
            process.send({cmd: 'aliceDone'});
            break

          case 'aliceExit':
            logger.verbose(`Alice[${cluster.worker.id}] shutdown VCX with deleting wallet`)
            await shutdownVcx(true)
            process.exit(0)
            break

          default:
            logger.error(`Alice[${cluster.worker.id}] unknown master command`)
        }
      }
    });

    // register Ctrl-C handler to shutdown VCX with deleting wallet
    process.on('SIGINT', async (signal) => {
      logger.verbose(`${signal} worker [${cluster.worker.id}] -> shutdown VCX with deleting wallet`)
      await shutdownVcx(true)
      process.exit(0)
    })
  }
}

async function runAlice (aliceId, options) {
  if (initVCX === false) {
    initVCX = true
    await demoCommon.initLibNullPay()

    logger.info(`Alice[${aliceId}] #0 Initialize rust API from NodeJS`)
    await demoCommon.initRustApiAndLogger(logLevel)

    if (options.comm === 'aries') {
      provisionConfig.protocol_type = '2.0'
      provisionConfig.communication_method = 'aries'
      logger.info(`Alice[${aliceId}] Running with Aries VCX Enabled! Make sure VCX agency is configured to use protocol_type 2.0`)
    }
    if (options.postgresql) {
      await demoCommon.loadPostgresPlugin(provisionConfig)
      provisionConfig.wallet_type = 'postgres_storage'
      provisionConfig.storage_config = '{"url":"localhost:5432"}'
      provisionConfig.storage_credentials = '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}'
      logger.info(`Alice[${aliceId}] Running with PostreSQL wallet enabled! Config = ${provisionConfig.storage_config}`)
    } else {
      logger.info(`Alice[${aliceId}] Running with builtin wallet.`)
    }
    if (await isPortReachable(url.parse(optionalWebhook).port, {host: url.parse(optionalWebhook).hostname})) { // eslint-disable-line
      provisionConfig.webhook_url = optionalWebhook
      logger.info(`Alice[${aliceId}] Running with webhook notifications enabled! Webhook url = ${optionalWebhook}`)
    } else {
      logger.info(`Alice[${aliceId}] Webhook url will not be used`)
    }

    logger.info(`Alice[${aliceId}] #8 Provision an agent and wallet, get back configuration details`)
    provisionConfig.wallet_name = provisionConfig.wallet_name + `_${aliceId}`
    const config = await demoCommon.provisionAgentInAgency(provisionConfig)

    logger.info(`Alice[${aliceId}] #9 Initialize libvcx with new configuration`)

    await demoCommon.initVcxWithProvisionedAgentConfig(config)
  }

  logger.info(`Alice[${aliceId}] #10 Convert to valid json and string and create a connection to faber`)
  let connectionToFaber = await Connection.createWithInvite({ id: 'faber', invite: options.issuerInvite })
  await connectionToFaber.connect({ data: '{"use_public_did": true}' })
  let connectionstate = await connectionToFaber.getState()
  while (connectionstate !== StateType.Accepted) {
    await sleepPromise(options.pollInterval)
    await connectionToFaber.updateState()
    connectionstate = await connectionToFaber.getState()
  }

  logger.info(`Alice[${aliceId}] #11 Wait for faber.py to issue a credential offer`)
  let offers = await Credential.getOffers(connectionToFaber)
  while (offers === undefined || offers.length < 1) {
    await sleepPromise(options.pollInterval)
    offers = await Credential.getOffers(connectionToFaber)
  }
  logger.verbose(`Alice[${aliceId}] found ${offers.length} credential offers.`)

  // Create a credential object from the credential offer
  const credential = await Credential.create({ sourceId: 'credential', offer: JSON.stringify(offers[0]) })

  logger.info(`Alice[${aliceId}] #15 After receiving credential offer, send credential request`)
  await credential.sendRequest({ connection: connectionToFaber, payment: 0 })

  logger.info(`Alice[${aliceId}] #16 Poll agency and accept credential from faber`)
  let credentialState = await credential.getState()
  while (credentialState !== StateType.Accepted) {
    await sleepPromise(options.pollInterval)
    await credential.updateState()
    credentialState = await credential.getState()
  }

  logger.verbose(`Alice [${aliceId}] End of issue credential --> Release connection to Faber issuer`)
  await connectionToFaber.release()

  // issue only case
  if (!options.verifierInvite) {
    return
  }

  logger.verbose(`Alice [${aliceId}] starts credential verification`)

  logger.info(`Alice[${aliceId}] #10(verify) Convert to valid json and string and create a connection to faber`)
  connectionToFaber = await Connection.createWithInvite({ id: 'faber', invite: options.verifierInvite })
  await connectionToFaber.connect({ data: '{"use_public_did": true}' })
  connectionstate = await connectionToFaber.getState()
  while (connectionstate !== StateType.Accepted) {
    await sleepPromise(options.pollInterval)
    await connectionToFaber.updateState()
    connectionstate = await connectionToFaber.getState()
  }

  logger.info(`Alice[${aliceId}] #22 Poll agency for a proof request`)
  let requests = await DisclosedProof.getRequests(connectionToFaber)
  while (requests === undefined || requests.length < 1) {
    await sleepPromise(options.pollInterval)
    requests = await DisclosedProof.getRequests(connectionToFaber)
  }
  logger.verbose(`Alice [${aliceId}] found ${requests.length} proof request.`)
  //logger.debug(`request: ${JSON.stringify(requests, null, 2)}`)

  logger.info(`Alice[${aliceId}] #23 Create a Disclosed proof object from proof request`)
  const proof = await DisclosedProof.create({ sourceId: 'proof', request: JSON.stringify(requests[0]) })

  logger.info(`Alice[${aliceId}] #24 Query for credentials in the wallet that satisfy the proof request`)
  const credentials = await proof.getCredentials()

  // Use the first available credentials to satisfy the proof request
  for (let i = 0; i < Object.keys(credentials.attrs).length; i++) {
    const attr = Object.keys(credentials.attrs)[i]
    credentials.attrs[attr] = {
      credential: credentials.attrs[attr][0]
    }
  }

  logger.info(`Alice[${aliceId}] #25 Generate the proof`)
  await proof.generateProof({ selectedCreds: credentials, selfAttestedAttrs: {} })

  logger.info(`Alice[${aliceId}] #26 Send the proof to faber`)
  await proof.sendProof(connectionToFaber)

  let proofState = await proof.getState()
  while (proofState !== StateType.Accepted) {
    await sleepPromise(options.pollInterval)
    await proof.updateState()
    proofState = await proof.getState()
  }

  logger.verbose(`Alice [${aliceId}] proof is verified --> Release connection to Faber verifier`)
  await connectionToFaber.release()
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
    name: 'issuerInvite',
    alias: 'i',
    type: String,
    description: 'Issuer invitation message',
    defaultValue: ''
  },
  {
    name: 'verifierInvite',
    alias: 'v',
    type: String,
    description: 'Verifier invitation message',
    defaultValue: ''
  },
  {
    name: 'numAlice',
    alias: 'n',
    type: Number,
    description: 'Number of alice',
    defaultValue: 1
  },
  {
    name: 'aliceInterval',
    alias: 'l',
    type: Number,
    description: 'Interval between each alice starts (seconds)',
    defaultValue: 0
  },
  {
    name: 'pollInterval',
    alias: 'p',
    type: Number,
    description: 'Agency polling interval for message checking',
    defaultValue: 2000
  },
  {
    name: 'numTransactions',
    alias: 't',
    type: Number,
    description: 'Number of Alice\'s issue/verify',
    defaultValue: 1
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

  if (!options.issuerInvite) {
    console.error(`Issuer invitation string is required to connect with issuer`)
    return false
  }

  return true
}

runScript(optionDefinitions, usage, areOptionsValid, runAliceMultiple)
