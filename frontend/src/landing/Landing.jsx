import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import QuantumField from './QuantumField'
import styles from './Landing.module.css'

gsap.registerPlugin(ScrollTrigger)

const PROTOCOL = [
  {
    step: '01',
    name: 'Entangle',
    detail:
      'Alice and Bob share a Bell pair. The simulator builds all four maximally entangled states as exact statevectors, so every later step has a known ground truth to check against.',
    formula: '|Φ+⟩ = (|00⟩ + |11⟩) / √2',
  },
  {
    step: '02',
    name: 'Teleport',
    detail:
      'Each signature carrier rides a three-qubit teleportation circuit. Alice measures in the Bell basis and sends two classical bits; Bob applies the matching Pauli correction.',
    formula: 'I · X · Z · XZ',
  },
  {
    step: '03',
    name: 'Sign',
    detail:
      'The teleported eigenstates become a signature block bound to the payload digest, the sender, the recipient and a sequence number. Binding is what makes a replayed packet detectable.',
    formula: 'SHA-256(payload) ⊕ carriers',
  },
  {
    step: '04',
    name: 'Verify',
    detail:
      'Bob measures in the allowed bases and counts mismatches. The rate is compared against thresholds derived from the honest error rate, not against a hand-picked constant.',
    formula: 'mismatch / positions ≶ s_a',
  },
]

const ATTACKS = [
  ['Replay', 'A previously valid packet, sent again'],
  ['Partial forgery', 'Some carriers guessed, the rest copied'],
  ['Correction tampering', 'Pauli corrections altered in flight'],
  ['Full forgery', 'A signature built without the key'],
  ['Intercept and resend', 'Measured mid-channel, then reinjected'],
  ['Channel manipulation', 'The quantum channel itself biased'],
  ['Fidelity degradation', 'Slow drift below the honest baseline'],
  ['Repudiation', 'A verifier denying what it accepted'],
]

export default function Landing() {
  const root = useRef(null)

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
    document.body.style.background = 'hsl(222, 38%, 7%)'
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

      // Each protocol step rises as it enters, and the rule beside it draws itself.
      gsap.utils.toArray(`.${styles.step}`).forEach((el) => {
        gsap.from(el, {
          opacity: 0,
          y: 48,
          duration: 0.7,
          ease: 'power2.out',
          scrollTrigger: { trigger: el, start: 'top 85%' },
        })
        gsap.from(el.querySelector(`.${styles.stepRule}`), {
          scaleX: 0,
          transformOrigin: 'left center',
          duration: 0.9,
          ease: 'power2.inOut',
          scrollTrigger: { trigger: el, start: 'top 85%' },
        })
      })

      // The threshold chain fills left to right as you scroll through it.
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

      gsap.from(`.${styles.attack}`, {
        opacity: 0,
        y: 22,
        duration: 0.5,
        stagger: 0.05,
        ease: 'power2.out',
        scrollTrigger: { trigger: `.${styles.attackGrid}`, start: 'top 85%' },
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
            the protocol end to end, then measures that disturbance and decides whether a
            signature holds.
          </p>
          <p className={styles.heroHint}>Move your cursor — the channel bends around it.</p>
        </div>
      </section>

      <section className={styles.section} aria-labelledby="protocol-heading">
        <h2 id="protocol-heading" className={styles.sectionTitle}>
          How a signature is made and checked
        </h2>
        <div className={styles.steps}>
          {PROTOCOL.map(({ step, name, detail, formula }) => (
            <article className={styles.step} key={step}>
              <div className={styles.stepHead}>
                <span className={styles.stepNum}>{step}</span>
                <h3 className={styles.stepName}>{name}</h3>
              </div>
              <span className={styles.stepRule} aria-hidden="true" />
              <p className={styles.stepDetail}>{detail}</p>
              <code className={styles.stepFormula}>{formula}</code>
            </article>
          ))}
        </div>
      </section>

      <section className={styles.section} aria-labelledby="chain-heading">
        <h2 id="chain-heading" className={styles.sectionTitle}>
          The decision is a chain, not a guess
        </h2>
        <p className={styles.sectionLede}>
          Four quantities have to stay in order. If they ever cross, the configuration itself is
          unsound and the engine says so before it judges a single packet.
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
        <h2 id="attacks-heading" className={styles.sectionTitle}>
          Eight ways to cheat, each with a tell
        </h2>
        <div className={styles.attackGrid}>
          {ATTACKS.map(([name, line]) => (
            <div className={styles.attack} key={name}>
              <h3 className={styles.attackName}>{name}</h3>
              <p className={styles.attackLine}>{line}</p>
            </div>
          ))}
        </div>
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
        </div>
        <p className={styles.disclaimer}>
          Software simulation of QDS protocol mechanics. No quantum hardware is involved.
        </p>
      </section>
    </div>
  )
}
