const { initRustAPI, initVcxWithConfig, provisionAgent } = require('./../dist/src')
const ffi = require('ffi')
const os = require('os')

const extension = { darwin: '.dylib', linux: '.so', win32: '.dll' }
const libPath = { darwin: '/usr/local/lib/', linux: '/usr/lib/', win32: 'c:\\windows\\system32\\' }

function getLibraryPath (libraryName) {
  const platform = os.platform()
  const postfix = extension[platform.toLowerCase()] || extension.linux
  const libDir = libPath[platform.toLowerCase()] || libPath.linux
  return `${libDir}${libraryName}${postfix}`
}

async function loadPostgresPlugin (provisionConfig) {
  const myffi = ffi.Library(getLibraryPath('libindystrgpostgres'), { postgresstorage_init: ['void', []] })
  await myffi.postgresstorage_init()
}

async function initLibNullPay () {
  const myffi = ffi.Library(getLibraryPath('libnullpay'), { nullpay_init: ['void', []] })
  await myffi.nullpay_init()
}

async function initRustApiAndLogger (logLevel) {
  const rustApi = initRustAPI()
  await rustApi.vcx_set_default_logger(logLevel)
}

async function provisionAgentInAgency (config) {
  return JSON.parse(await provisionAgent(JSON.stringify(config)))
}

async function initVcxWithProvisionedAgentConfig (config) {
 /*
  // remove by dr.jhyun
  config.institution_name = 'faber'
  config.institution_logo_url = 'http://robohash.org/234'
  config.genesis_path = `${__dirname}/genesis.txn`
 */
  await initVcxWithConfig(JSON.stringify(config))
}

function getRandomInt (min, max) {
  min = Math.ceil(min)
  max = Math.floor(max)
  return Math.floor(Math.random() * (max - min)) + min
}

async function retryRun(retry = 0, func, argument) {
  let result, trial = retry + 1

  do {
    try {
      result = await func(argument)
      trial = -1
    } catch (err) {
      log.warn(`${func.name}: ${err.message}: ${trial}`)
      await sleepPromise(1000 * Math.pow(2, retry+1-trial))
      trial -= 1
    }
  } while(trial > 0)

  if (trial === 0) {
    throw new Error(`${func.name} exceeds retry number`)
  }

  return result
}

function isValidJson(str) {
  if (!str) {
    return false
  }

  try {
    JSON.parse(str)
  } catch (e) {
    return false
  }
  return true
}

module.exports = {
  loadPostgresPlugin, initLibNullPay, initRustApiAndLogger,
  provisionAgentInAgency, initVcxWithProvisionedAgentConfig, getRandomInt,
  retryRun, isValidJson
}