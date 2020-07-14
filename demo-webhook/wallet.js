'use strict'

const { Wallet } = require('../dist/src/api/wallet')
const logger = require('./logger')
const sleepPromise = require('sleep-promise')

const maxRetry = 8

async function walletAddRecord(type, id, value, tags, msg='') {
    const recordParam = {
        type_: type,
        id: id,
        value: value,
        tags: tags
    }

    logger.debug(`walletAddRecord(${msg}): ${JSON.stringify(recordParam, null, 2)}`)
    await Wallet.addRecord(recordParam)
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
    let record = undefined, retry = maxRetry

    do {
        try {
            record = await Wallet.getRecord(recordParam)
            retry = 0
        } catch (err) {
            logger.warn(`walletGetRecord(${msg}): ${JSON.stringify(recordParam, null, 2)} --> ${err.message}`)
            await sleepPromise(1000 * Math.pow(2, maxRetry - retry))
            retry -= 1
        }
    } while(retry > 0)

    if (record === undefined || !isValidJson(record)) {
        throw new Error('walletGetRecord error')
    }

    logger.debug(`walletGetRecord(${msg}): ${JSON.stringify(recordParam, null, 2)}`)
    return record
}

async function walletUpdateRecordValue(type, id, value, msg='') {
    const recordParam = {
        type_: type,
        id: id,
        value: value
    }

    logger.debug(`walletUpdateRecordValue(${msg}): ${JSON.stringify(recordParam, null, 2)}`)
    await Wallet.updateRecordValue(recordParam)
}

module.exports = {
    walletAddRecord,
    walletGetRecord,
    walletUpdateRecordValue
}