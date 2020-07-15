'use strict'

const { performance } = require('perf_hooks')
const logger = require('./logger')
const { median, variance, quantile } = require('simple-statistics')

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
        this._records.push({ workerId, phase, startTime, endTime, duration })
    }

    addRecordArray(recordArray) {
        this._records.push(recordArray)
        // flat into depth-1 array
        this._records = [].concat(...this._records)
    }

    getRecords(phaseFilter = [PhaseType.Onboard, PhaseType.Issue, PhaseType.Verify]) {
        return this._records.reduce((accumArray, current) => {
                if (phaseFilter.includes(current.phase)) {
                    accumArray.push(current)
                }
                return accumArray
            }, []
        )
    }

    static transRecordTime(recordArray, multiplier) {
        return recordArray.reduce((accumArray, current) => {
                accumArray.push({
                    workerId: current.workerId,
                    phase: current.phase,
                    startTime: current.startTime * multiplier,
                    endTime: current.endTime * multiplier,
                    duration: current.duration * multiplier
                })
                return accumArray
            }, []
        )
    }

    getReport() {
        // recordArray -> array of '{workerId, phase, startTime, endTime, duration}'
        function getPhaseAnalysis(recordArray, phaseName) {
            const startMin = recordArray.map(el => el.startTime).reduce((min, current) => Math.min(min, current))
            const endMax = recordArray.map(el => el.endTime).reduce((max, current) => Math.max(max, current))
            const durationSec = endMax - startMin
            const numTrans = recordArray.length
            const durationArray = recordArray.map(el => el.duration).reduce((accumArray, current) => {
                    accumArray.push(current)
                    return accumArray
                },
                []
            )

            return {
                phaseName,
                durationSec,
                numTrans,
                transPerSec: numTrans / durationSec,
                transPerMinute: numTrans / durationSec * 60,
                transMin: recordArray.map(el => el.duration).reduce((min, cur) => Math.min(min, cur)),
                transMax: recordArray.map(el => el.duration).reduce((max, cur) => Math.max(max, cur)),
                transMedian: median(durationArray),
                transVariance: variance(durationArray),
                transQuantile: quantile(durationArray, [0.95, 0.99]),
            }
        }

        // sort by startTime
        this._records = Report.sortRecords(this._records, 'startTime')

        // array of '{workerId, phase, startTime, endTime, duration}'
        const onBoardRecords = this.filterRecords([PhaseType.Onboard])
        const issueRecords = this.filterRecords([PhaseType.Issue])
        const verifyRecords = this.filterRecords([PhaseType.Verify])

        const onBoardRecordsSec = Report.transRecordTime(onBoardRecords, 0.001)
        const issueRecordsSec = Report.transRecordTime(issueRecords, 0.001)
        const verifyRecordsSec = Report.transRecordTime(verifyRecords, 0.001)
        const totalRecordsSec = Report.transRecordTime(this._records, 0.001)

        const onBoardAnalysis = getPhaseAnalysis(onBoardRecordsSec, PhaseType.Onboard)
        const issueAnalysis = getPhaseAnalysis(issueRecordsSec, PhaseType.Issue)
        const verifyAnalysis = getPhaseAnalysis(verifyRecordsSec, PhaseType.Verify)
        const totalAnalysis = getPhaseAnalysis(totalRecordsSec, PhaseType.None)

        this._report = { onBoardAnalysis, issueAnalysis, verifyAnalysis, totalAnalysis }
        return this._report
    }

    print(report = this._report) {
        for (const phase in report) {
            const phaseAnalysis = report[phase]
            logger.verbose()
            logger.verbose(`------ ${phaseAnalysis.phaseName} Performance ------`)
            logger.verbose(`*** Throughput ***`)
            logger.verbose(`Duration ${phaseAnalysis.durationSec.toFixed(1)} secs to ${phaseAnalysis.numTrans} transactions.`)
            logger.verbose(`PerSec ${phaseAnalysis.transPerSec.toFixed(1)}  PerMinute ${phaseAnalysis.transPerMinute.toFixed(1)}`)
            logger.verbose()
            logger.verbose(`*** Transaction time (sec) ***`)
            logger.verbose(`Min ${phaseAnalysis.transMin.toFixed(1)}  Max ${phaseAnalysis.transMax.toFixed(1)}`)
            logger.verbose(`Median ${phaseAnalysis.transMedian.toFixed(1)}  Variance ${phaseAnalysis.transVariance.toFixed(2)}`)
            logger.verbose(`Quantile[0.95, 0.99]=[${phaseAnalysis.transQuantile.map(el => el.toFixed(1))}]`)
            logger.verbose('------------------------------------')
        }
    }
}

module.exports = {
    PhaseType,
    Report
}