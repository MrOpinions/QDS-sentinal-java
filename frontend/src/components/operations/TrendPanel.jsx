import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Cell,
} from 'recharts'
import styles from './operations.module.css'

const COLOR_SAFE = 'hsl(152, 48%, 60%)'
const COLOR_CRITICAL = 'hsl(6, 80%, 68%)'
const COLOR_SUSPICIOUS = 'hsl(28, 82%, 64%)'
const COLOR_GRID = 'hsl(222, 18%, 24%)'
const COLOR_AXIS = 'hsl(40, 8%, 56%)'

const CRITICAL_TYPES = new Set([
  'CORRECTION_TAMPERING',
  'REPLAY_ATTACK',
  'PAYLOAD_DIGEST_MISMATCH',
  'IMPERSONATION',
  'UNAUTHORIZED_VERIFICATION',
  'CONFIGURATION_WARNING',
])

function formatTimeAxis(key) {
  if (!key) return ''
  if (typeof key === 'string' && key.includes('T')) {
    const parts = key.split('T')
    if (parts[1]) {
      const timeParts = parts[1].split(':')
      const hourNum = parseInt(timeParts[0], 10)
      if (!isNaN(hourNum)) {
        const ampm = hourNum >= 12 ? 'pm' : 'am'
        const hour12 = hourNum % 12 || 12
        return `${hour12}${ampm}`
      }
    }
  }
  if (typeof key === 'string' && key.length === 10 && key.includes('-')) {
    const [y, m, d] = key.split('-').map(Number)
    if (!isNaN(y) && !isNaN(m) && !isNaN(d)) {
      const date = new Date(y, m - 1, d)
      return date.toLocaleDateString([], { weekday: 'short' })
    }
  }
  return key
}

function formatTooltipLabel(key) {
  if (!key) return ''
  if (typeof key === 'string' && key.includes('T')) {
    const parts = key.split('T')
    if (parts[1]) {
      const timeParts = parts[1].split(':')
      const hourNum = parseInt(timeParts[0], 10)
      if (!isNaN(hourNum)) {
        const ampm = hourNum >= 12 ? 'PM' : 'AM'
        const hour12 = hourNum % 12 || 12
        return `${parts[0]} at ${hour12}:00 ${ampm}`
      }
    }
  }
  return key
}

export default function TrendPanel({ trendsData }) {
  const timeSeries = trendsData?.time_series || []
  const breakdown = trendsData?.threat_breakdown || []
  const granularity = trendsData?.time_granularity || 'hourly'

  const hasTimeSeries = timeSeries.length > 0
  const hasBreakdown = breakdown.length > 0

  return (
    <div className={styles.sectionBlock}>
      <div className={styles.sectionHeader}>
        <div>
          <h2 className={styles.sectionTitle}>Trends</h2>
          <p className={styles.sectionSubtitle}>Historical traffic security and issue distribution</p>
        </div>
      </div>

      <div className={styles.trendGrid}>
        <div className={styles.chartCard}>
          <div className={styles.chartHeader}>
            <span className={styles.chartTitle}>Activity over time</span>
            <span className={styles.chartSubtitle}>
              {granularity === 'hourly' ? 'Hourly sessions (last 24h)' : 'Daily sessions (last 7d)'}
            </span>
          </div>

          <div className={styles.chartArea}>
            {!hasTimeSeries ? (
              <div className={styles.chartEmpty}>
                No session traffic recorded in this period.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={timeSeries} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={COLOR_GRID} vertical={false} />
                  <XAxis
                    dataKey="hour"
                    tickFormatter={formatTimeAxis}
                    tick={{ fontSize: 10, fill: COLOR_AXIS }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fontSize: 10, fill: COLOR_AXIS }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      fontSize: 11,
                      background: 'hsl(222, 30%, 11%)',
                      border: '1px solid hsl(222, 20%, 20%)',
                      borderRadius: 2,
                      padding: '6px 10px',
                    }}
                    labelFormatter={formatTooltipLabel}
                  />
                  <Bar dataKey="accepted" name="Safe" stackId="a" fill={COLOR_SAFE} radius={0} />
                  <Bar dataKey="rejected" name="Flagged / Rejected" stackId="a" fill={COLOR_CRITICAL} radius={0} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className={styles.chartCard}>
          <div className={styles.chartHeader}>
            <span className={styles.chartTitle}>What kind of issues occurred</span>
            <span className={styles.chartSubtitle}>Distribution of recorded incidents</span>
          </div>

          <div className={styles.chartArea}>
            {!hasBreakdown ? (
              <div className={styles.chartEmpty}>
                No security issues recorded yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart
                  layout="vertical"
                  data={breakdown}
                  margin={{ top: 8, right: 16, left: 12, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke={COLOR_GRID} horizontal={false} />
                  <XAxis
                    type="number"
                    allowDecimals={false}
                    tick={{ fontSize: 10, fill: COLOR_AXIS }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    type="category"
                    dataKey="type"
                    width={150}
                    tick={{ fontSize: 10, fill: COLOR_AXIS }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      fontSize: 11,
                      background: 'hsl(222, 30%, 11%)',
                      border: '1px solid hsl(222, 20%, 20%)',
                      borderRadius: 2,
                      padding: '6px 10px',
                    }}
                  />
                  <Bar dataKey="count" name="Incidents" radius={0}>
                    {breakdown.map((entry, index) => {
                      const isCritical = CRITICAL_TYPES.has(entry.raw_type)
                      return (
                        <Cell
                          key={`cell-${index}`}
                          fill={isCritical ? COLOR_CRITICAL : COLOR_SUSPICIOUS}
                        />
                      )
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
