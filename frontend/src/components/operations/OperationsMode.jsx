import { useState, useEffect, useCallback } from 'react'
import { getOpsOverview, getOpsThreatFeed, getOpsTrends } from '../../api/ops'
import HeroStatus from './HeroStatus'
import InfiltrationMap from './InfiltrationMap'
import ActivityFeed from './ActivityFeed'
import ExposureSummary from './ExposureSummary'
import TrendPanel from './TrendPanel'
import styles from './operations.module.css'

const POLL_INTERVAL_MS = 8000

export default function OperationsMode() {
  const [overview, setOverview] = useState(null)
  const [feedData, setFeedData] = useState(null)
  const [trendsData, setTrendsData] = useState(null)
  const [lastRefreshed, setLastRefreshed] = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchAll = useCallback(async () => {
    const [overviewRes, feedRes, trendsRes] = await Promise.all([
      getOpsOverview(),
      getOpsThreatFeed(),
      getOpsTrends(),
    ])
    if (overviewRes.data) setOverview(overviewRes.data)
    if (feedRes.data) setFeedData(feedRes.data)
    if (trendsRes.data) setTrendsData(trendsRes.data)
    setLastRefreshed(new Date())
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchAll()
    const interval = setInterval(fetchAll, POLL_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [fetchAll])

  function formatRefreshed(date) {
    if (!date) return ''
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  return (
    <div className={styles.opsContainer}>
      <div className={styles.opsHeaderRow}>
        <div className={styles.opsHeaderTitleGroup}>
          <span className={styles.opsModeLabel}>OPERATIONS DASHBOARD</span>
          <span className={styles.opsModeDesc}>Layman Threat &amp; Risk Overview</span>
        </div>
        <div className={styles.refreshControl}>
          <span className={styles.refreshTime}>
            {loading ? 'Checking status...' : lastRefreshed ? `Updated ${formatRefreshed(lastRefreshed)}` : ''}
          </span>
          <button className={styles.refreshButton} onClick={fetchAll} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {/* SECTION 1: THE HEADLINE ANSWER (Dominant visual weight) */}
      <HeroStatus overview={loading ? null : overview} />

      {/* SECTION 2: WHERE IT LANDED ON THE PROTOCOL */}
      <InfiltrationMap feedData={loading ? null : feedData} />

      {/* SECTIONS 3 & 4: WHAT HAPPENED + HOW EXPOSED AM I */}
      <div className={styles.middleGrid}>
        <div className={styles.middleColLeft}>
          <ActivityFeed feedData={loading ? null : feedData} />
        </div>
        <div className={styles.middleColRight}>
          <ExposureSummary trendsData={loading ? null : trendsData} />
        </div>
      </div>

      {/* SECTION 4: TRENDS, SIMPLIFIED */}
      <TrendPanel trendsData={loading ? null : trendsData} />
    </div>
  )
}
