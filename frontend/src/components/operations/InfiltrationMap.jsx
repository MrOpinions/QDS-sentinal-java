import { useMemo } from 'react'
import styles from './operations.module.css'

/**
 * Where the attacks landed.
 *
 * "UNDER ATTACK, 72% flagged" says that something happened but not where, and
 * where is the interesting part. This maps every recorded threat type onto the
 * stage of the protocol it compromises, so the pipeline itself shows which
 * links held and which did not.
 */

const STAGES = [
  {
    id: 'entangle',
    label: 'Entanglement',
    short: 'Bell pair',
    types: ['BELL_INTEGRITY_VIOLATION', 'ENTANGLEMENT_FAILURE'],
    clean: 'Alice and Bob share a clean Bell pair. The entanglement is intact, so teleportation starts from a known state.',
    breached:
      'The entangled pair was disturbed before use. Someone touched the channel while the pair was being distributed, which is what an eavesdropper looks like at this stage.',
  },
  {
    id: 'transit',
    label: 'Channel transit',
    short: 'Carriers in flight',
    types: ['QBER_THRESHOLD_BREACH', 'CHANNEL_MANIPULATION', 'INTERCEPT_RESEND', 'FIDELITY_DEGRADATION'],
    clean: 'Carriers arrived with fidelity at baseline. No measurement happened in transit.',
    breached:
      'Carriers arrived disturbed. Measuring a quantum state collapses it, so an interceptor cannot read the channel and leave it unchanged — the error rate is the fingerprint they leave behind.',
  },
  {
    id: 'correct',
    label: 'Pauli correction',
    short: 'Classical bits',
    types: ['CORRECTION_TAMPERING', 'CORRECTION_INCONSISTENCY'],
    clean: 'Every correction Bob applied matched the one Alice sent.',
    breached:
      'The classical correction bits were altered in flight. This half of teleportation travels over an ordinary channel, so it is the cheapest part of the protocol to attack.',
  },
  {
    id: 'bind',
    label: 'Payload binding',
    short: 'Digest + ledger',
    types: ['PAYLOAD_DIGEST_MISMATCH', 'DIGEST_FORGERY', 'REPLAY_DETECTED'],
    clean: 'The signature block matches its payload digest, and the fingerprint is new to the ledger.',
    breached:
      'The packet does not bind to the message it claims, or it has been seen before. This check is arithmetic rather than statistical, so a failure here is proof and not suspicion.',
  },
  {
    id: 'verify',
    label: 'Verification',
    short: 'Bob and Charlie',
    types: ['BOB_THRESHOLD_BREACH', 'CHARLIE_THRESHOLD_BREACH', 'BOB_REPUDIATION', 'ARBITRATION_DISAGREEMENT'],
    clean: 'Both recipients measured mismatch rates under their thresholds and agreed.',
    breached:
      'A recipient crossed its threshold. When Bob and Charlie disagree, the disagreement itself is the signal: it is what separates a noisy channel from a repudiating recipient.',
  },
]

const OTHER = {
  id: 'other',
  label: 'Unclassified',
  short: 'Other findings',
  clean: '',
  breached: 'Findings that do not map to a single protocol stage.',
}

export default function InfiltrationMap({ feedData }) {
  const { stages, other, total, worst } = useMemo(() => {
    const events = feedData?.events ?? []
    const counts = new Map()
    const severities = new Map()

    for (const ev of events) {
      const stage = STAGES.find((s) => s.types.includes(ev.threat_type))
      const key = stage ? stage.id : OTHER.id
      counts.set(key, (counts.get(key) ?? 0) + 1)
      // Critical outranks suspicious outranks advisory for how a stage is drawn.
      const rank = ev.severity === 'critical' ? 3 : ev.severity === 'suspicious' ? 2 : 1
      severities.set(key, Math.max(severities.get(key) ?? 0, rank))
    }

    const resolved = STAGES.map((s) => ({
      ...s,
      count: counts.get(s.id) ?? 0,
      rank: severities.get(s.id) ?? 0,
    }))

    return {
      stages: resolved,
      other: counts.get(OTHER.id) ?? 0,
      total: events.length,
      worst: Math.max(0, ...resolved.map((s) => s.rank)),
    }
  }, [feedData])

  const breachedCount = stages.filter((s) => s.count > 0).length

  function severityClass(rank) {
    if (rank >= 3) return styles.mapNodeCritical
    if (rank === 2) return styles.mapNodeSuspicious
    if (rank === 1) return styles.mapNodeAdvisory
    return styles.mapNodeClean
  }

  return (
    <section className={styles.mapPanel} aria-labelledby="infiltration-heading">
      <div className={styles.mapHead}>
        <div>
          <h2 id="infiltration-heading" className={styles.mapTitle}>
            Where the attacks landed
          </h2>
          <p className={styles.mapLede}>
            Alice signs, the carriers cross the channel, Bob verifies. Every finding below is
            attributed to the stage it compromises, so you can see which links held.
          </p>
        </div>
        <div className={styles.mapSummary}>
          <span className={styles.mapSummaryNum}>
            {breachedCount}<span className={styles.mapSummaryOf}>/{STAGES.length}</span>
          </span>
          <span className={styles.mapSummaryLabel}>
            {breachedCount === 0 ? 'stages clean' : 'stages with findings'}
          </span>
        </div>
      </div>

      <div className={styles.mapRail} role="img" aria-label={
        breachedCount === 0
          ? 'Protocol pipeline: all five stages clean'
          : `Protocol pipeline: findings at ${stages.filter(s => s.count > 0).map(s => s.label).join(', ')}`
      }>
        <div className={styles.mapEndpoint}>
          <span className={styles.mapEndpointName}>Alice</span>
          <span className={styles.mapEndpointRole}>signer</span>
        </div>

        <div className={styles.mapChain}>
          {stages.map((s) => (
            <div className={styles.mapCell} key={s.id}>
              <div className={`${styles.mapNode} ${severityClass(s.rank)}`}>
                {s.count > 0 && <span className={styles.mapCount}>{s.count}</span>}
              </div>
              <span className={styles.mapNodeLabel}>{s.label}</span>
              <span className={styles.mapNodeShort}>{s.short}</span>
            </div>
          ))}
        </div>

        <div className={styles.mapEndpoint}>
          <span className={styles.mapEndpointName}>Bob</span>
          <span className={styles.mapEndpointRole}>verifier</span>
        </div>
      </div>

      <ol className={styles.mapNotes}>
        {stages.map((s) => (
          <li
            className={`${styles.mapNote} ${s.count > 0 ? styles.mapNoteBreached : ''}`}
            key={s.id}
          >
            <div className={styles.mapNoteHead}>
              <span className={styles.mapNoteLabel}>{s.label}</span>
              <span className={`${styles.mapNoteState} ${s.count > 0 ? styles.mapStateBad : styles.mapStateOk}`}>
                {s.count > 0 ? `${s.count} finding${s.count === 1 ? '' : 's'}` : 'clean'}
              </span>
            </div>
            <p className={styles.mapNoteBody}>{s.count > 0 ? s.breached : s.clean}</p>
          </li>
        ))}
        {other > 0 && (
          <li className={`${styles.mapNote} ${styles.mapNoteBreached}`}>
            <div className={styles.mapNoteHead}>
              <span className={styles.mapNoteLabel}>{OTHER.label}</span>
              <span className={`${styles.mapNoteState} ${styles.mapStateBad}`}>
                {other} finding{other === 1 ? '' : 's'}
              </span>
            </div>
            <p className={styles.mapNoteBody}>{OTHER.breached}</p>
          </li>
        )}
      </ol>

      <p className={styles.mapFoot}>
        {total === 0
          ? 'No findings recorded. Run an assessment to populate this view.'
          : `${total} finding${total === 1 ? '' : 's'} across the last 24 hours. ` +
            (worst >= 3
              ? 'At least one is deterministic: the engine can prove it rather than infer it.'
              : 'All statistical or advisory: the engine is reporting suspicion, not proof.')}
      </p>
    </section>
  )
}
