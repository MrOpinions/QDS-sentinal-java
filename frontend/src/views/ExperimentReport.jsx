import { useState } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ReferenceLine, ResponsiveContainer
} from 'recharts'
import { runAttackSimulate } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'
import styles from './ExperimentReport.module.css'

const PRELOADED_CSV = [
  { intensity_q: 0.00, mismatch_rate: 0.0000, threat_level: 'CLEAN',      security_decision_verdict: 'ACCEPT', findings_count: 0, source: 'csv' },
  { intensity_q: 0.05, mismatch_rate: 0.0500, threat_level: 'CLEAN',      security_decision_verdict: 'ACCEPT', findings_count: 0, source: 'csv' },
  { intensity_q: 0.10, mismatch_rate: 0.1000, threat_level: 'ADVISORY',   security_decision_verdict: 'REJECT', findings_count: 1, source: 'csv' },
  { intensity_q: 0.15, mismatch_rate: 0.1500, threat_level: 'SUSPICIOUS', security_decision_verdict: 'REJECT', findings_count: 2, source: 'csv' },
  { intensity_q: 0.20, mismatch_rate: 0.2000, threat_level: 'SUSPICIOUS', security_decision_verdict: 'REJECT', findings_count: 2, source: 'csv' },
  { intensity_q: 0.25, mismatch_rate: 0.2500, threat_level: 'SUSPICIOUS', security_decision_verdict: 'REJECT', findings_count: 2, source: 'csv' },
  { intensity_q: 0.30, mismatch_rate: 0.3000, threat_level: 'SUSPICIOUS', security_decision_verdict: 'REJECT', findings_count: 2, source: 'csv' },
]

const SWEEP_INTENSITIES = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50]

const LEVEL_COLOR = {
  CLEAN: 'var(--color-accept)',
  ADVISORY: 'var(--color-advisory)',
  SUSPICIOUS: 'var(--color-suspicious)',
  CRITICAL: 'var(--color-critical)',
}

function mergeForChart(csvData, liveData) {
  const byQ = {}
  for (const row of csvData) {
    byQ[row.intensity_q] = { intensity_q: row.intensity_q, csv_rate: row.mismatch_rate }
  }
  for (const row of liveData) {
    if (!byQ[row.intensity_q]) {
      byQ[row.intensity_q] = { intensity_q: row.intensity_q }
    }
    byQ[row.intensity_q].live_rate = row.mismatch_rate
  }
  return Object.values(byQ).sort((a, b) => a.intensity_q - b.intensity_q)
}

function exportData(data, format) {
  if (format === 'csv') {
    const headers = ['intensity_q', 'mismatch_rate', 'threat_level', 'security_decision_verdict', 'findings_count', 'source']
    const rows = data.map(r => headers.map(h => r[h] ?? '').join(','))
    const content = [headers.join(','), ...rows].join('\n')
    downloadFile(content, 'qds-sweep.csv', 'text/csv')
  } else {
    downloadFile(JSON.stringify(data, null, 2), 'qds-sweep.json', 'application/json')
  }
}

function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function CsvDot(props) {
  const { cx, cy } = props
  if (cx == null || cy == null) return null
  return <circle cx={cx} cy={cy} r={4} fill="var(--basis-x)" stroke="var(--bg-base)" strokeWidth={1} />
}

function LiveDot(props) {
  const { cx, cy } = props
  if (cx == null || cy == null) return null
  return <rect x={cx - 4} y={cy - 4} width={8} height={8} fill="var(--color-suspicious)" stroke="var(--bg-base)" strokeWidth={1} />
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null
  return (
    <div className={styles.tooltip}>
      <div className="mono">q = {Number(label).toFixed(2)}</div>
      {payload.map(p => (
        <div key={p.dataKey} className="mono" style={{ color: p.color }}>
          {p.name}: {p.value != null ? p.value.toFixed(4) : '—'}
        </div>
      ))}
    </div>
  )
}

export default function ExperimentReport() {
  const [liveData, setLiveData] = useState([])
  const [sweeping, setSweeping] = useState(false)
  const [sweepProgress, setSweepProgress] = useState(0)
  const [sweepError, setSweepError] = useState(null)
  const [sweepMessage, setSweepMessage] = useState('PARTIAL_FORGERY_SWEEP_LIVE')

  const allData = [...PRELOADED_CSV, ...liveData].sort((a, b) => a.intensity_q - b.intensity_q)
  const chartData = mergeForChart(PRELOADED_CSV, liveData)

  async function runSweep() {
    setSweeping(true)
    setSweepError(null)
    setSweepProgress(0)
    const newPoints = []

    for (let i = 0; i < SWEEP_INTENSITIES.length; i++) {
      const q = SWEEP_INTENSITIES[i]
      setSweepProgress(Math.round((i / SWEEP_INTENSITIES.length) * 100))

      const result = await runAttackSimulate({
        simulation: {
          message: sweepMessage,
          sender_id: 'alice',
          recipient_id: 'bob',
          signature_length: 16,
          seed: 42,
          bell_state: 'PHI_PLUS',
          bases_allowed: ['X', 'Y', 'Z'],
          sequence_number: i + 100,
        },
        attack_type: 'PARTIAL_FORGERY',
        intensity: q,
        verification_mode: 'direct',
        s_a: 0.10,
        s_v: 0.20,
      })

      if (result.error) {
        setSweepError(result.error)
        setSweeping(false)
        return
      }

      const assessment = result.data.assessment
      newPoints.push({
        intensity_q: q,
        mismatch_rate: assessment.qber_analysis.global_mismatch_rate,
        threat_level: assessment.threat_level,
        security_decision_verdict: assessment.security_decision.startsWith('ACCEPT') ? 'ACCEPT' : 'REJECT',
        findings_count: assessment.findings.length,
        source: 'live',
      })

      setLiveData([...newPoints])
    }

    setSweepProgress(100)
    setSweeping(false)
  }

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <div>
          <h2>Experiment Report — Partial Forgery Detection Sweep</h2>
          <p className={styles.subtitle}>
            Pre-loaded from <span className="mono">partial_forgery_sweep.csv</span>.
            Run a live sweep to append real-time results.
          </p>
        </div>
        <div className={styles.exportButtons}>
          <button id="export-csv-btn" onClick={() => exportData(allData, 'csv')}>Export CSV</button>
          <button id="export-json-btn" onClick={() => exportData(allData, 'json')}>Export JSON</button>
        </div>
      </div>

      <ErrorBanner error={sweepError} />

      <div className={styles.chartContainer}>
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={chartData} margin={{ top: 8, right: 24, left: 0, bottom: 24 }}>
            <CartesianGrid strokeDasharray="2 4" stroke="var(--bg-chrome)" />
            <XAxis
              dataKey="intensity_q"
              tickFormatter={v => Number(v).toFixed(2)}
              label={{ value: 'Attack Intensity (q)', position: 'insideBottom', offset: -12, style: { fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }}
              tick={{ fontSize: 10, fontFamily: 'var(--font-mono)', fill: 'var(--text-muted)' }}
            />
            <YAxis
              tickFormatter={v => v.toFixed(2)}
              label={{ value: 'Mismatch Rate', angle: -90, position: 'insideLeft', offset: 12, style: { fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }}
              tick={{ fontSize: 10, fontFamily: 'var(--font-mono)', fill: 'var(--text-muted)' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine y={0.10} stroke="var(--color-advisory)" strokeDasharray="4 3" label={{ value: 's_a=0.10 (direct auth)', position: 'right', fontSize: 9, fontFamily: 'var(--font-mono)', fill: 'var(--color-advisory)' }} />
            <ReferenceLine y={0.20} stroke="var(--color-suspicious)" strokeDasharray="4 3" label={{ value: 's_v=0.20 (forwarded verif)', position: 'right', fontSize: 9, fontFamily: 'var(--font-mono)', fill: 'var(--color-suspicious)' }} />
            <Line
              type="monotone"
              dataKey="csv_rate"
              name="CSV (pre-loaded)"
              stroke="var(--basis-x)"
              strokeWidth={1.5}
              dot={<CsvDot />}
              connectNulls
            />
            <Line
              type="monotone"
              dataKey="live_rate"
              name="Live (run)"
              stroke="var(--color-suspicious)"
              strokeWidth={1.5}
              dot={<LiveDot />}
              strokeDasharray="5 3"
              connectNulls
            />
          </LineChart>
        </ResponsiveContainer>

        <div className={styles.legend}>
          <span className={styles.legendItem}>
            <span className={styles.dotCircle} /> CSV pre-loaded
          </span>
          <span className={styles.legendItem}>
            <span className={styles.dotSquare} /> Live run
          </span>
          <span className={styles.legendItem}>
            <span className={styles.lineAdvisory} /> s_a=0.10 (direct authentication threshold)
          </span>
          <span className={styles.legendItem}>
            <span className={styles.lineSuspicious} /> s_v=0.20 (forwarded verification threshold)
          </span>
        </div>

        <div className={styles.chartScientificNote}>
          Points show simulated telemetry under a fixed seed; they are not measured physical-channel results.
        </div>
      </div>

      <div className={styles.sweepControls}>
        <div className={styles.formGroup}>
          <label htmlFor="sweep-message">Sweep message payload</label>
          <input
            id="sweep-message"
            value={sweepMessage}
            onChange={e => setSweepMessage(e.target.value)}
            style={{ maxWidth: 320 }}
          />
        </div>
        <div className={styles.sweepActions}>
          <button
            id="run-sweep-btn"
            className="primary"
            onClick={runSweep}
            disabled={sweeping}
          >
            {sweeping ? <span className="pulse">Sweeping… {sweepProgress}%</span> : 'Run New Sweep'}
          </button>
          {liveData.length > 0 && (
            <button id="clear-live-btn" onClick={() => setLiveData([])}>
              Clear live data
            </button>
          )}
        </div>
        <p className="text-muted text-small">
          Sweeps PARTIAL_FORGERY at intensities: {SWEEP_INTENSITIES.map(q => q.toFixed(2)).join(', ')}
        </p>
      </div>

      <div className={styles.dataTable}>
        <div className="panel-title">Data Table — {allData.length} rows</div>
        <div className="scrollable" style={{ maxHeight: 240 }}>
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th className="right">intensity_q</th>
                <th className="right">mismatch_rate</th>
                <th>threat_level</th>
                <th>verdict</th>
                <th className="right">findings_count</th>
              </tr>
            </thead>
            <tbody>
              {allData.map((row, i) => (
                <tr key={i} className={row.source === 'live' ? styles.liveRow : ''}>
                  <td className={`mono ${row.source === 'csv' ? styles.sourcecsv : styles.sourcelive}`}>{row.source}</td>
                  <td className="mono right">{row.intensity_q.toFixed(2)}</td>
                  <td className="mono right">{row.mismatch_rate.toFixed(4)}</td>
                  <td>
                    <span style={{ color: LEVEL_COLOR[row.threat_level] || 'inherit', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      {row.threat_level}
                    </span>
                  </td>
                  <td className={`mono ${row.security_decision_verdict === 'ACCEPT' ? styles.accept : styles.reject}`}>
                    {row.security_decision_verdict}
                  </td>
                  <td className="mono right">{row.findings_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
