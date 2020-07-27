'use strict'

const { Wallet } = require('../dist/src/api/wallet')
const { performance } = require('perf_hooks')
const logger = require('./logger')
const sleepPromise = require('sleep-promise')

const maxRetry = 5

async function walletAddRecord(type, id, value, tags, msg='') {
    const recordParam = {
        type_: type,
        id: id,
        value: value,
        tags: tags
    }

    //logger.silly(`Wallet.addRecord(${msg}): ${JSON.stringify(recordParam, null, 2)}`)
    const tStart = performance.now()
    await Wallet.addRecord(recordParam)
    logger.debug(`Wallet.addRecord: ${(performance.now()-tStart).toFixed(1)}ms`)
}

async function walletGetRecord(type, id, options, msg='') {
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

    const recordParam = {
        type: type,
        id: id,
        options: options
    }
    let record = undefined, trial = maxRetry+1, tStart, duration

    do {
        try {
            tStart = performance.now()
            record = await Wallet.getRecord(recordParam)
            duration = performance.now() - tStart
            trial = 0
        } catch (err) {
            logger.warn(`walletGetRecord(${msg}): ${JSON.stringify(recordParam, null, 2)} --> ${err.message}`)
            await sleepPromise(1000 * Math.pow(2, maxRetry+1-trial))
            trial -= 1
        }
    } while(trial > 0)

    if (record === undefined || !isValidJson(record)) {
        throw new Error('walletGetRecord error')
    }

    //logger.silly(`walletGetRecord(${msg}): ${JSON.stringify(recordParam, null, 2)}`)
    logger.debug(`Wallet.getRecord: ${duration.toFixed(1)}ms`)
    return record
}

async function walletUpdateRecordValue(type, id, value, msg='') {
    const recordParam = {
        type_: type,
        id: id,
        value: value
    }

    //logger.silly(`Wallet.updateRecordValue(${msg}): ${JSON.stringify(recordParam, null, 2)}`)
    const tStart = performance.now()
    await Wallet.updateRecordValue(recordParam)
    logger.debug(`Wallet.updateRecordValue: ${(performance.now()-tStart).toFixed(1)}ms`)
}

module.exports = {
    walletAddRecord,
    walletGetRecord,
    walletUpdateRecordValue
}