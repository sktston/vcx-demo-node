'use strict'

const { performance } = require('perf_hooks')
const logger = require('./logger')

const PhaseType = {
    Onboard: 'Onboard',
    Issue: 'Issue',
    Verify: 'Verify',
    None: 'Total'
}

class Report {
    constructor() {
        this.clearRecords()
    }

    clearRecords() {
        // _records is array of '{workerId, phase, startTime, endTime, duration}'
        this._records = []

        // startTime of each phase (onboard, issue, verify)
        this._startTime = {}

        // final report
        this._report = {}
    }

    setStartTime(phase) {
        this._startTime[phase] = performance.now()
    }

    filterRecords(phaseFilter) {
        return this._records.filter(record => phaseFilter.includes(record.phase))
    }

    static sortRecords(recordArray = this._records, sortingField = 'startTime') {
        recordArray.sort((a, b) => { // ascending order
            return a[sortingField] - b[sortingField];
        })

        return recordArray
    }

    addRecord(workerId, phase, startTime = this._startTime[phase], endTime = performance.now()) {
        const duration = endTime - startTime
        this._records.push({workerId, phase, startTime, endTime, duration})
    }

    addRecordArray(recordArray) {
        this._records.push(recordArray)
        // flat into depth-1 array
        this._records = [].concat(...this._records)
    }

    getRecords(phaseFilter = [PhaseType.Onboard, PhaseType.Issue, PhaseType.Verify]) {
        const records = []
        this._records.forEach(element => {
            if (phaseFilter.includes(element.phase)) {
                records.push(element)
            }
        })

        return records
    }

    static transRecordTime(recordArray, multiplier) {
        const records = []
        recordArray.forEach(element => {
            records.push({
                workerId: element.workerId,
                phase: element.phase,
                startTime: element.startTime * multiplier,
                endTime: element.endTime * multiplier,
                duration: element.duration * multiplier
            })
        })

        return records
    }

    getReport() {
        // recordArray -> array of '{workerId, phase, startTime, endTime, duration}'
        function getPhaseAnalysis(recordArray, phaseName) {
            const startMin = recordArray.map(el => el.startTime).reduce((min, cur) => Math.min(min, cur))
            const endMax = recordArray.map(el => el.endTime).reduce((max, cur) => Math.max(max, cur))
            const durationSec = endMax - startMin
            const numTrans = recordArray.length
            const meanAndVar = getMeanAndVar(recordArray, 'duration')

            return {
                phaseName,
                durationSec,
                numTrans,
                transPerSec: numTrans / durationSec,
                transPerMinute: numTrans / durationSec * 60,
                transMinSec: recordArray.map(el => el.duration).reduce((min, cur) => Math.min(min, cur)),
                transMaxSec: recordArray.map(el => el.duration).reduce((max, cur) => Math.max(max, cur)),
                transAvgSec: meanAndVar.mean,
                transVariance: meanAndVar.variance,
            }
        }

        function getMeanAndVar(recordArray, field) {
            const arr = []
            for (const record of recordArray) {
                arr.push(record[field])
            }

            function getVariance(arr, mean) {
                return arr.reduce(function(pre, cur) {
                    pre = pre + Math.pow((cur - mean), 2)
                    return pre
                }, 0)
            }

            const meanTot = arr.reduce(function(pre, cur) {
                return pre + cur
            })
            const total = getVariance(arr, meanTot / arr.length)

            const res = {
                mean: meanTot / arr.length,
                variance: total / arr.length
            }

            return res
        }

        // sort by startTime
        this._records = Report.sortRecords(this._records, 'startTime')

        // array of '{workerId, phase, startTime, endTime, duration}'
        const onBoardRecords = this.filterRecords([PhaseType.Onboard])
        const issueRecords = this.filterRecords([PhaseType.Issue])
        const verifyRecords = this.filterRecords([PhaseType.Verify])

        const totalRecordsSec = Report.transRecordTime(this._records, 0.001)
        const onBoardRecordsSec = Report.transRecordTime(onBoardRecords, 0.001)
        const issueRecordsSec = Report.transRecordTime(issueRecords, 0.001)
        const verifyRecordsSec = Report.transRecordTime(verifyRecords, 0.001)

        const totalAnalysis = getPhaseAnalysis(totalRecordsSec, PhaseType.None)
        const onBoardAnalysis = getPhaseAnalysis(onBoardRecordsSec, PhaseType.Onboard)
        const issueAnalysis = getPhaseAnalysis(issueRecordsSec, PhaseType.Issue)
        const verifyAnalysis = getPhaseAnalysis(verifyRecordsSec, PhaseType.Verify)

        this._report = {totalAnalysis, onBoardAnalysis, issueAnalysis, verifyAnalysis}
        return this._report
    }

    print(report = this._report) {
        for (const phase in report) {
            const phaseAnalysis = report[phase]
            logger.verbose()
            logger.verbose(`------ ${phaseAnalysis.phaseName} Performance ------`)
            logger.verbose(`Duration ${phaseAnalysis.durationSec.toFixed(1)} secs to ${phaseAnalysis.numTrans} transactions.`)
            logger.verbose(`PerSec ${phaseAnalysis.transPerSec.toFixed(1)}  PerMinute ${phaseAnalysis.transPerMinute.toFixed(1)}`)
            logger.verbose(`TransMinSec ${phaseAnalysis.transMinSec.toFixed(1)}  TransMaxSec ${phaseAnalysis.transMaxSec.toFixed(1)}`)
            logger.verbose(`TransAvgSec ${phaseAnalysis.transAvgSec.toFixed(1)}  TransVariance ${phaseAnalysis.transVariance.toFixed(2)}`)
            logger.verbose('------------------------------------')
        }
    }
}

module.exports = {
    PhaseType,
    Report
}