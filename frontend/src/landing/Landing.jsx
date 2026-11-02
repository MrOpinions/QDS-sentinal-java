import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import QuantumField from './QuantumField'
import styles from './Landing.module.css'

gsap.registerPlugin(ScrollTrigger)

const FACTS = [
  ['3', 'layers, protocol to dashboard'],
  ['148', 'backend tests'],
  ['8', 'attack types modelled'],
  ['4', 'Bell states simulated'],
]

const LAYERS = [
  {
    tag: 'Layer 1',
    name: 'Protocol simulation',
    body: 'Exact statevector simulation in NumPy with normalisation checks. Pauli eigenstates, all four Bell pairs, the full three-qubit teleportation circuit, Born-rule measurement, and structured telemetry for everything above it.',
    does: ['Statevectors', 'Teleportation', 'Noise models', 'Telemetry'],
    not: 'Makes no security decisions.',
  },
  {
    tag: 'Layer 2',
    name: 'Threat detection',
    body: 'Consumes Layer 1 telemetry and decides. Digest binding and replay checks are deterministic and authoritative; mismatch-rate analysis is statistical and advisory. The distinction is kept explicit in every assessment.',
    does: ['Thresholds', 'Replay ledger', 'Classification', 'Bob/Charlie'],
    not: 'Never overrides a deterministic check with a statistical one.',
  },
  {
    tag: 'Layer 3',
    name: 'Console',
    body: 'The dashboard you can open from here. Runs a scenario, shows the circuit trace position by position, the Bloch sphere for each carrier, the threat feed with evidence, and the SQLite audit log behind it.',
    does: ['Circuit trace', 'Bloch sphere', 'Threat feed', 'Audit log'],
    not: 'Reads the engine; it does not re-implement it.',
  },
]

const PROTOCOL = [
  {
    step: '01',
    name: 'Entangle',
    detail:
      'Alice and Bob share a Bell pair. All four maximally entangled states are built as exact statevectors with normalisation asserted, so every later step has a known ground truth to check against.',
    formula: '|Φ+⟩ = (|00⟩ + |11⟩) / √2',
    note: 'Φ+, Φ−, Ψ+, Ψ− all available as the channel state.',
  },
  {
    step: '02',
    name: 'Teleport',
    detail:
      'Each signature carrier rides a three-qubit teleportation circuit. Alice measures in the Bell basis and sends two classical bits; Bob applies the matching Pauli correction and the carrier arrives.',
    formula: 'I · X · Z · XZ',
    note: 'Expected and actual corrections are both recorded, so tampering shows.',
  },
  {
    step: '03',
    name: 'Sign',
    detail:
      'The teleported eigenstates become a signature block bound to the SHA-256 payload digest, the sender, the recipient, a sequence number and a nonce. That binding is what makes a replayed packet detectable at all.',
    formula: 'session|block|nonce|seq',
    note: 'The fingerprint goes into the replay ledger.',
  },
  {
    step: '04',
    name: 'Verify',
    detail:
      'Bob measures in the allowed bases and counts mismatches. The rate is compared against thresholds derived from the honest error rate rather than a hand-picked constant, and Charlie can verify the forwarded copy independently.',
    formula: 'mismatch / positions ≶ s_a',
    note: 'Disagreement between Bob and Charlie is itself a signal.',
  },
]

const ATTACKS = [
  {
    name: 'Intercept and resend',
    actor: 'Eve',
    attack: 'Measures qubits mid-channel, collapsing them, then re-sends reconstructed states.',
    tell: 'Mismatch rate climbs above the honest baseline.',
    detector: 'QBERAnalysisResult',
    authority: 'Statistical',
  },
  {
    name: 'Forgery',
    actor: 'Third party',
    attack: 'Builds a plausible signature packet for a message Alice never signed.',
    tell: 'SHA-256 digest does not match the payload.',
    detector: 'DigestCheckResult',
    authority: 'Deterministic',
  },
  {
    name: 'Replay',
    actor: 'Captured traffic',
    attack: 'Resubmits a valid past packet to impersonate a fresh transaction.',
    tell: 'Fingerprint already present in the ledger.',
    detector: 'ReplayDetectionResult',
    authority: 'Deterministic',
  },
  {
    name: 'Repudiation',
    actor: 'Bob',
    attack: 'Denies sending what he sent, or claims Alice forged it.',
    tell: "Bob's rate crosses s_a while Charlie's stays under s_v.",
    detector: 'BobCharlieMetrics',
    authority: 'Advisory',
  },
  {
    name: 'Partial forgery',
    actor: 'Third party',
    attack: 'Guesses a fraction of the carriers and copies the rest.',
    tell: 'Mismatch rate scales with the guessed fraction.',
    detector: 'Threshold sweep',
    authority: 'Statistical',
  },
  {
    name: 'Correction tampering',
    actor: 'In-flight',
    attack: 'Alters the classical Pauli correction bits between Alice and Bob.',
    tell: 'Expected and actual corrections diverge.',
    detector: 'Correction consistency',
    authority: 'Deterministic',
  },
  {
    name: 'Channel manipulation',
    actor: 'Eve',
    attack: 'Biases the quantum channel itself rather than reading it.',
    tell: 'Per-basis mismatch distribution skews.',
    detector: 'Basis distribution',
    authority: 'Statistical',
  },
  {
    name: 'Fidelity degradation',
    actor: 'Channel',
    attack: 'Slow drift pulling teleportation fidelity down over time.',
    tell: 'Mean fidelity falls below the configured floor.',
    detector: 'Fidelity monitor',
    authority: 'Advisory',
  },
]

const LIMITS = [
  'No quantum hardware. Every result is a software simulation of protocol mechanics.',
  'No composable security proof. The engine approximates results from Amiri et al. (2016) and Gottesman-Chuang (2001); it does not reproduce them.',
  'Digest binding is classical. The quantum key binding that makes real QDS information-theoretically secure is modelled, not proven.',
  'The replay ledger is in memory. It does not survive a restart, and distributed replay prevention is out of scope.',
  'Detection is not exhaustive. Attack variants outside the modelled eight may pass.',
]

export default function Landing() {
  const root = useRef(null)
  const pinRef = useRef(null)
  const trackRef = useRef(null)

  // global.css pins html/body/#root to height:100% so the dashboard can own its
  // own scroll areas. The landing page is a document that scrolls, and without
  // this the window never moves - which also leaves ScrollTrigger inert.
  useEffect(() => {
    const rootEl = document.getElementById('root')
    const saved = [
      [document.documentElement, document.documentElement.style.cssText],
      [document.body, document.body.style.cssText],
      [rootEl, rootEl.style.cssText],
    ]

    document.documentElement.style.height = 'auto'
    document.body.style.height = 'auto'
    rootEl.style.height = 'auto'
    rootEl.style.display = 'block'

    return () => saved.forEach(([el, css]) => { el.style.cssText = css })
  }, [])

  useEffect(() => {
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduceMotion) return

    const ctx = gsap.context(() => {
      gsap.from(`.${styles.heroLine}`, {
        yPercent: 110,
        duration: 1.1,
        ease: 'power3.out',
        stagger: 0.09,
      })

      gsap.from(`.${styles.heroMeta}`, {
        opacity: 0,
        y: 14,
        duration: 0.8,
        delay: 0.55,
        ease: 'power2.out',
      })

      gsap.from(`.${styles.fact}`, {
        opacity: 0,
        y: 18,
        duration: 0.5,
        stagger: 0.08,
        ease: 'power2.out',
        scrollTrigger: { trigger: `.${styles.facts}`, start: 'top 88%' },
      })

      gsap.utils.toArray(`.${styles.layer}`).forEach((el) => {
        gsap.from(el, {
          opacity: 0,
          y: 44,
          duration: 0.65,
          ease: 'power2.out',
          scrollTrigger: { trigger: el, start: 'top 86%' },
        })
      })

      // The protocol is a sequence, so it reads along the horizontal axis:
      // the section pins and the track slides as you scroll. Only where there
      // is room - a narrow screen gets the same panels stacked.
      const mm = gsap.matchMedia()
      mm.add('(min-width: 900px)', () => {
        const track = trackRef.current
        const distance = () => Math.max(0, track.scrollWidth - window.innerWidth)

        const tween = gsap.to(track, {
          x: () => -distance(),
          ease: 'none',
          scrollTrigger: {
            trigger: pinRef.current,
            pin: true,
            scrub: 0.8,
            start: 'top top',
            end: () => `+=${distance()}`,
            invalidateOnRefresh: true,
          },
        })

        return () => tween.kill()
      })

      gsap.from(`.${styles.chainFill}`, {
        scaleX: 0,
        transformOrigin: 'left center',
        ease: 'none',
        scrollTrigger: {
          trigger: `.${styles.chain}`,
          start: 'top 80%',
          end: 'bottom 60%',
          scrub: 0.6,
        },
      })

      gsap.from(`.${styles.chainStop}`, {
        opacity: 0,
        y: 10,
        duration: 0.5,
        stagger: 0.12,
        ease: 'power2.out',
        scrollTrigger: { trigger: `.${styles.chain}`, start: 'top 75%' },
      })

      gsap.from(`.${styles.card}`, {
        opacity: 0,
        y: 24,
        duration: 0.5,
        stagger: 0.06,
        ease: 'power2.out',
        scrollTrigger: { trigger: `.${styles.rail}`, start: 'top 88%' },
      })

      gsap.from(`.${styles.limit}`, {
        opacity: 0,
        x: -16,
        duration: 0.5,
        stagger: 0.08,
        ease: 'power2.out',
        scrollTrigger: { trigger: `.${styles.limits}`, start: 'top 85%' },
      })

      gsap.from(`.${styles.closingInner}`, {
        opacity: 0,
        y: 30,
        duration: 0.8,
        ease: 'power2.out',
        scrollTrigger: { trigger: `.${styles.closing}`, start: 'top 80%' },
      })

      // Triggers are measured at mount, before the webfonts land. Once they do,
      // every section has shifted and the start positions are stale.
      ScrollTrigger.refresh()
      if (document.fonts?.ready) {
        document.fonts.ready.then(() => ScrollTrigger.refresh())
      }
    }, root)

    return () => ctx.revert()
  }, [])

  return (
    <div className={styles.page} ref={root}>
      <QuantumField />

      <header className={styles.topBar}>
        <span className={styles.wordmark}>QDS Sentinel</span>
        <Link to="/dashboard" className={styles.topLink}>
          Open the dashboard
        </Link>
      </header>

      <section className={styles.hero}>
        <p className={styles.eyebrow}>Teleportation-based quantum digital signatures</p>
        <h1 className={styles.heroTitle}>
          <span className={styles.heroMask}>
            <span className={styles.heroLine}>Observation</span>
          </span>
          <span className={styles.heroMask}>
            <span className={styles.heroLine}>leaves a mark.</span>
          </span>
        </h1>
        <div className={styles.heroMeta}>
          <p className={styles.heroBody}>
            A forger cannot copy a quantum state without disturbing it. QDS Sentinel simulates
            the protocol end to end, measures that disturbance, and decides whether a signature
            holds — separating what it can prove from what it can only suggest.
          </p>
          <p className={styles.heroHint}>Move your cursor — the channel bends around it.</p>
        </div>

        <ul className={styles.facts}>
          {FACTS.map(([n, label]) => (
            <li className={styles.fact} key={label}>
              <span className={styles.factNum}>{n}</span>
              <span className={styles.factLabel}>{label}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className={styles.section} aria-labelledby="layers-heading">
        <h2 id="layers-heading" className={styles.sectionTitle}>
          Three layers, and each one knows its limits
        </h2>
        <p className={styles.sectionLede}>
          The boundaries are enforced, not aspirational. Layer 1 refuses to make security
          decisions; Layer 2 refuses to dress a statistical signal as a proof.
        </p>
        <div className={styles.layers}>
          {LAYERS.map(({ tag, name, body, does, not }) => (
            <article className={styles.layer} key={tag}>
              <span className={styles.layerTag}>{tag}</span>
              <h3 className={styles.layerName}>{name}</h3>
              <p className={styles.layerBody}>{body}</p>
              <ul className={styles.chips}>
                {does.map((d) => (
                  <li className={styles.chip} key={d}>{d}</li>
                ))}
              </ul>
              <p className={styles.layerNot}>{not}</p>
            </article>
          ))}
        </div>
      </section>

      <section className={styles.pinSection} ref={pinRef} aria-labelledby="protocol-heading">
        <div className={styles.pinInner}>
          <div className={styles.pinHead}>
            <h2 id="protocol-heading" className={styles.sectionTitle}>
              How a signature is made and checked
            </h2>
            <p className={styles.scrollCue}>Keep scrolling — this one runs sideways</p>
          </div>
          <div className={styles.track} ref={trackRef}>
            {PROTOCOL.map(({ step, name, detail, formula, note }) => (
              <article className={styles.panel} key={step}>
                <div className={styles.panelHead}>
                  <span className={styles.panelNum}>{step}</span>
                  <h3 className={styles.panelName}>{name}</h3>
                </div>
                <p className={styles.panelDetail}>{detail}</p>
                <code className={styles.panelFormula}>{formula}</code>
                <p className={styles.panelNote}>{note}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.section} aria-labelledby="chain-heading">
        <h2 id="chain-heading" className={styles.sectionTitle}>
          The decision is a chain, not a guess
        </h2>
        <p className={styles.sectionLede}>
          Four quantities have to stay in order. If they ever cross, the configuration itself is
          unsound and the engine raises a ConfigurationWarning before it judges a single packet.
        </p>
        <div className={styles.chain}>
          <div className={styles.chainTrack} aria-hidden="true">
            <span className={styles.chainFill} />
          </div>
          <ol className={styles.chainStops}>
            <li className={styles.chainStop}>
              <code className={styles.chainSym}>e_upper</code>
              <span className={styles.chainWhat}>honest error ceiling</span>
            </li>
            <li className={styles.chainStop}>
              <code className={styles.chainSym}>s_a</code>
              <span className={styles.chainWhat}>authentication threshold</span>
            </li>
            <li className={styles.chainStop}>
              <code className={styles.chainSym}>s_v</code>
              <span className={styles.chainWhat}>verification threshold</span>
            </li>
            <li className={styles.chainStop}>
              <code className={styles.chainSym}>p_E</code>
              <span className={styles.chainWhat}>best a forger can do</span>
            </li>
          </ol>
        </div>
      </section>

      <section className={styles.section} aria-labelledby="attacks-heading">
        <div className={styles.railHead}>
          <div>
            <h2 id="attacks-heading" className={styles.sectionTitle}>
              Eight ways to cheat, each with a tell
            </h2>
            <p className={styles.sectionLede}>
              Every detector declares its own authority. Deterministic checks decide; statistical
              ones only ever advise.
            </p>
          </div>
          <p className={styles.scrollCue}>Scroll the row sideways, or use arrow keys</p>
        </div>
        <div
          className={styles.rail}
          tabIndex={0}
          role="group"
          aria-label="Attack types, horizontally scrollable"
        >
          {ATTACKS.map((a) => (
            <article className={styles.card} key={a.name}>
              <div className={styles.cardTop}>
                <h3 className={styles.cardName}>{a.name}</h3>
                <span className={styles.cardActor}>{a.actor}</span>
              </div>
              <p className={styles.cardAttack}>{a.attack}</p>
              <dl className={styles.cardMeta}>
                <dt className={styles.cardKey}>Tell</dt>
                <dd className={styles.cardVal}>{a.tell}</dd>
                <dt className={styles.cardKey}>Detector</dt>
                <dd className={`${styles.cardVal} ${styles.cardMono}`}>{a.detector}</dd>
              </dl>
              <span
                className={`${styles.authority} ${
                  a.authority === 'Deterministic' ? styles.authHard : styles.authSoft
                }`}
              >
                {a.authority}
              </span>
            </article>
          ))}
        </div>
      </section>

      <section className={styles.section} aria-labelledby="limits-heading">
        <h2 id="limits-heading" className={styles.sectionTitle}>
          What this does not claim
        </h2>
        <p className={styles.sectionLede}>
          Taken from the project's own security-claims document, which is required reading before
          interpreting any assessment.
        </p>
        <ul className={styles.limits}>
          {LIMITS.map((l) => (
            <li className={styles.limit} key={l}>
              {l}
            </li>
          ))}
        </ul>
      </section>

      <section className={styles.closing}>
        <div className={styles.closingInner}>
          <h2 className={styles.closingTitle}>Run it against a live packet.</h2>
          <p className={styles.closingBody}>
            The dashboard drives the same engine: pick a scenario, fire an attack, read the
            verdict and the evidence behind it.
          </p>
          <Link to="/dashboard" className={styles.cta}>
            Open the dashboard
          </Link>
          <p className={styles.stack}>
            FastAPI · NumPy · Pydantic · SQLAlchemy · React · Vite
          </p>
        </div>
        <p className={styles.disclaimer}>
          Software simulation of QDS protocol mechanics. No quantum hardware is involved.
        </p>
      </section>
    </div>
  )
}
