# QDS Sentinel

**QDS Sentinel** simulates teleportation-based Quantum Digital Signatures (QDS) and detects forgery, replay, impersonation and quantum-channel tampering using quantum measurement statistics and deterministic mathematical rules.

A forger cannot copy a quantum state without disturbing it. QDS Sentinel models the protocol end to end, measures that disturbance, and decides whether a signature holds — separating what it can prove from what it can only suggest.

> **Simulation only.** No quantum hardware is involved. See [What this does not claim](#what-this-does-not-claim).

![The landing page: the headline "Observation leaves a mark" over a dot lattice bending toward the cursor](docs/images/landing-hero.jpg)

---

## Architecture

All three layers are implemented.

| Layer | Name | Responsibility | Will not do |
|---|---|---|---|
| **1** | Protocol simulation | Exact statevector simulation, Bell pairs, 3-qubit teleportation, Pauli corrections, Born-rule measurement, telemetry | Make security decisions |
| **2** | Threat detection | Threshold analysis, replay ledger, attack classification, Bob/Charlie arbitration | Dress a statistical signal as a proof |
| **3** | Console | Circuit trace, Bloch sphere, threat feed, metrics, audit log | Re-implement the engine |

### Layer 1 — protocol simulation

| Capability | Detail |
|---|---|
| Statevectors | Complex `double[]` pairs in plain Java, normalisation asserted (‖v‖ ≈ 1.0) |
| Pauli eigenstates | Exact basis states in X, Y and Z |
| Bell states | Φ⁺, Φ⁻, Ψ⁺, Ψ⁻ |
| Teleportation | Full 3-qubit circuit with feedforward correction (I, X, Z, XZ) |
| Measurement | Exact Born-rule probabilities, deterministic or sampled |
| Noise | `NoNoise`, `DepolarizingNoise`, `PauliFlipNoise` |
| Telemetry | Teleportation events, measurement events, position records, mismatch summaries |

### Layer 2 — threat detection

Every detector declares its own authority. Deterministic checks decide; statistical ones only advise.

| Attack | Actor | Indicator | Detector | Authority |
|---|---|---|---|---|
| Intercept and resend | Eve | Mismatch rate above honest baseline | `QBERAnalysisResult` | Statistical |
| Forgery | Third party | SHA-256 digest mismatch | `DigestCheckResult` | Deterministic |
| Replay | Captured traffic | Fingerprint already in ledger | `ReplayDetectionResult` | Deterministic |
| Repudiation | Bob | Bob crosses `s_a` while Charlie stays under `s_v` | `BobCharlieMetrics` | Advisory |
| Partial forgery | Third party | Mismatch scales with guessed fraction | Threshold sweep | Statistical |
| Correction tampering | In-flight | Expected and actual corrections diverge | Correction consistency | Deterministic |
| Channel manipulation | Eve | Per-basis mismatch distribution skews | Basis distribution | Statistical |
| Fidelity degradation | Channel | Mean fidelity below configured floor | Fidelity monitor | Advisory |

### The threshold chain

Four quantities must stay in order. If they cross, the configuration is unsound and the engine raises a `ConfigurationWarning` before judging any packet.

| Symbol | Meaning | Default |
|---|---|---|
| `e_upper` | Honest error ceiling | 0.00 |
| `s_a` | Authentication threshold | 0.10 |
| `s_v` | Verification threshold | 0.20 |
| `p_E` | Best a forger can do | 0.25 |

Required ordering: `e_upper < s_a < s_v < p_E`

---

## Getting started

### Requirements

| Component | Version |
|---|---|
| JDK | 17+ (the backend uses only the JDK: no Maven, Gradle or third-party jars) |
| Node.js | 18+ |

### Backend

```bash
javac -d backend/out -sourcepath backend/src backend/src/qds/Server.java
```

```bash
java -cp backend/out qds.Server
```

The server listens on port 8000 (set `PORT` to change it). Sessions are stored in `qds_sentinel.jsonl.db` in the working directory; set `QDS_DB_PATH=memory` for a store that is discarded on exit.

### Frontend

```bash
npm install --prefix frontend
```

```bash
npm run dev --prefix frontend
```

| Route | Page |
|---|---|
| `/` | Landing page — what the protocol does and how it is checked |
| `/dashboard` | The console |

The Vite dev server proxies `/api` and `/health` to port 8000, so the backend must be running.

---

## Stack

| Part | Built with | Why |
|---|---|---|
| Simulation | Plain Java (`java.util`, `java.security`) | Exact complex statevectors; normalisation asserted every step |
| API | `com.sun.net.httpserver` (`jdk.httpserver`) | Built into the JDK; request validation is hand-written and mirrors the old Pydantic rules |
| Primary store | In-memory tables + append-only JSON-lines file | What the dashboard reads; zero setup |
| Audit store | Append-only file, `javax.crypto` AES-GCM, SHA-256 chain | Encrypted and hash-chained (see [Audit log](#audit-log)) |
| Console | React 18 + Vite | Seven tabs over one assessment payload |
| Charts | plotly (Bloch sphere), recharts (2D) | 3D state projection vs. ordinary series |
| Motion | GSAP + ScrollTrigger | Landing scroll narrative, dashboard entrance |
| Type | Syne · Work Sans · Azeret Mono | Display, body, and data |

---

## The console

### Landing page — `/`

Explains the protocol before showing any numbers: the three layers, the four
protocol steps (pinned and scrolling sideways, because a protocol is a
sequence), the threshold chain, the eight attacks, and what the project does
not claim. The dot lattice behind it bends toward the cursor — observing the
channel disturbs it, which is the premise the whole system rests on.

![The protocol section pinned, showing panels 01 Entangle and 02 Teleport with 03 entering from the right](docs/images/landing-protocol.jpg)

### Dashboard — `/dashboard`

Two modes. **Simulation** is the engineer's view, seven tabs over one
assessment:

| Tab | Shows |
|---|---|
| Control Panel | Compose a session: message, parties, signature length, Bell state, bases, seed, attack type, threshold overrides |
| Circuit Trace | Every signature position: basis, prepared state, Bell outcome, expected vs. actual correction, fidelity, match |
| Quantum State | Bloch sphere per position, with prepared state and measurement collapse, and the telemetry behind it |
| Threat Feed | Findings with observed evidence, protocol impact, and which authority raised them |
| Security Metrics | Digest consistency, replay check, thresholds in use, mismatch rate, correction consistency, fidelity monitor |
| Experiment Report | Partial-forgery sweep: mismatch rate against attack intensity, with `s_a` and `s_v` drawn in |
| Database Logs | The stored session as persisted, queried back from the store |

![Threat Feed after a digest forgery: a red REJECT banner, with recorded and recomputed SHA-256 shown side by side](docs/images/dashboard-threat-feed.jpg)

*Threat Feed. The evidence is the recorded digest against the recomputed one — the engine shows its working rather than asserting a verdict.*

![Quantum State: a Bloch sphere with the prepared state and its measurement collapse, beside per-position telemetry](docs/images/dashboard-bloch.jpg)

*Quantum State. Each of the 16 carriers, its prepared eigenstate, where measurement collapsed it, and the fidelity that came out.*

**Operations** is the same data for a non-specialist:

| Panel | Answers |
|---|---|
| Threat status | Is anything wrong right now |
| Where the attacks landed | Which protocol stage each finding compromises, drawn as a pipeline from Alice to Bob |
| What happened | Recent flagged events in plain language |
| How exposed am I | Which vulnerability recurs most |
| Trends | Hourly traffic and incident distribution |

![Where the attacks landed: a pipeline from Alice to Bob with findings counted at four of five protocol stages](docs/images/operations-infiltration.jpg)

*Where the attacks landed. Every finding attributed to the stage of the protocol it compromises, so the pipeline shows which links held.*

---

## Demo walkthrough

With both servers running, open `/dashboard`. Three buttons in the Control
Panel cover the interesting cases.

| Step | Click | Expect | The point |
|---|---|---|---|
| 1 | **Clean session** | `ACCEPT` · 0/16 mismatch · fidelity 1.0000 | The honest baseline. Everything downstream is measured against this. |
| 2 | **Digest forgery** | `REJECT` · `PAYLOAD_DIGEST_MISMATCH [CRITICAL]` | Recorded and recomputed SHA-256 shown side by side. Arithmetic, not statistics — the engine can prove this one. |
| 3 | **Replay attack** | `REJECT` · `REPLAY_DETECTED` | The fingerprint was already in the ledger. Also deterministic. |
| 4 | Attack type → any, then **Run Assessment** | Varies by intensity | Statistical detectors. The verdict is a threshold judgement, and the engine labels it as such. |

Then switch to **Operations** and read *Where the attacks landed*: the same
findings, attributed to the stage of the protocol each one breaks.

Worth noticing in step 2: the header still reports `0 / 16` mismatch and
fidelity `1.0000` next to a red `REJECT`. That is correct — the rejection came
from the deterministic digest check, not from the statistics — and it is the
clearest illustration of why the two kinds of detector are kept apart.

---

## API

### Layer 1 — `/api/v1/layer1`

| Method | Path | Does |
|---|---|---|
| `POST` | `/simulate` | Run a full QDS protocol session |
| `GET` | `/example-session` | Deterministic 8-position clean session, seed 42 |
| `GET` | `/bloch-state/{basis}/{bit}` | Bloch coordinates for a bare Pauli eigenstate |
| `POST` | `/bloch-trace` | Bloch coordinates for every position in a session |

### Layer 2 — `/api/v1/layer2`

| Method | Path | Does |
|---|---|---|
| `POST` | `/assess` | Simulate and assess, with optional identity checks |
| `POST` | `/assess-existing` | Assess a session without re-running Layer 1 |
| `POST` | `/attack-simulate` | Inject an attack, then assess |
| `GET` | `/example-clean` | Clean session — expect ACCEPT |
| `GET` | `/example-replay` | Replay detection — expect REJECT |
| `GET` | `/example-forgery` | Digest mismatch — expect REJECT |

### Operations — `/api/ops`

| Method | Path | Does |
|---|---|---|
| `GET` | `/overview` | Today's traffic and verdict summary |
| `GET` | `/threat-feed` | Recent flagged events |
| `GET` | `/trends` | Hourly activity and incident distribution |
| `GET` | `/sessions` | Stored sessions |
| `GET` | `/logs` | Telemetry across sessions |
| `GET` | `/logs/{session_id}` | Telemetry for one session |
| `GET` | `/audit/verify` | Whether the audit chain is intact |

---

## Tests

```bash
javac -d backend/out -sourcepath backend/src backend/src/qds/SelfTest.java
```

```bash
java -cp backend/out qds.SelfTest
```

`SelfTest` is a dependency-free check that exits non-zero on failure. It covers:

| Area | Checks |
|---|---|
| Quantum core | Eigenstate norms, Bloch coordinates, teleportation fidelity for every Bell state × eigenstate over 40 seeds each, Born-rule measurement, Pauli corrections |
| Protocol | SHA-256 digest, seed reproducibility, clean-session invariants, JSON round-trip |
| Bounds | Hoeffding upper bound and tail, threshold-chain validation |
| Replay ledger | Exact repeat, reused nonce, non-increasing sequence, eviction |
| Engine | Clean accept, replay, digest forgery, impersonation, broken threshold chain, forwarded mode |
| Attacks | All eight attack types, original session left untouched |
| Audit log | Chain intact, field encryption, edit detected at the right record, disabled no-op |
| JSON | Parse / write round-trip, canonical key order |

---

## Audit log

Sessions go to the primary store, which is what the dashboard reads. They can
also be mirrored to an append-only audit file that exists to prove afterwards
that nothing was altered.

Two protections, doing different jobs:

| | Mechanism | Protects against | Reversible |
|---|---|---|---|
| **Confidentiality** | AES-256-GCM on `message`, `sender_id`, `recipient_id`, `raw_assessment_string` | Anyone reading the file directly | Yes — the app decrypts |
| **Integrity** | SHA-256 chain: each record hashes its own content plus the previous record's hash | Silent edits or deletions by anyone with write access | No — one-way by design |

Hashing alone would make the log unreadable, including to the dashboard.
Encryption alone would leave it silently editable. Together the log is
confidential and provably unaltered: changing any record breaks every hash
after it, which `GET /api/ops/audit/verify` reports with the sequence number
where the chain first fails.

Verdicts, rates and thresholds stay in plaintext, so the operations endpoints
can still aggregate over them.

### Configuration

| Variable | Effect |
|---|---|
| `AUDIT_LOG_PATH` | Enables the sink and names the JSON-lines file. Unset, the sink is disabled |
| `AUDIT_ENCRYPTION_KEY` | Any passphrase (stretched to an AES key with SHA-256). Unset, records are chained but not encrypted |
| `QDS_DB_PATH` | Primary store file (default `qds_sentinel.jsonl.db`); `memory` keeps it in RAM only |
| `PORT` | HTTP port (default `8000`) |

```bash
export AUDIT_LOG_PATH=qds_audit.jsonl
```

```bash
export AUDIT_ENCRYPTION_KEY="a long passphrase"
```

A failed audit write is logged and swallowed: losing the audit mirror must
never cost the primary record.

> The JDK ships no MongoDB or SQL driver, so both stores are plain files.
> Swapping either for a real database means adding a driver jar.

---

## Layout

```
backend/src/qds/
  Quantum.java       statevectors, gates, Bell states, teleportation, measurement, noise, Bloch
  Protocol.java      key material, signature packet, session, shared data model
  Layer2.java        bounds, replay ledger, detectors, engine, attack injection, calibration
  Store.java         primary store and the hash-chained audit log
  Server.java        HTTP routes, request validation, persistence glue
  Ops.java           operations-mode endpoints
  Json / Req / Fmt   JSON reader and writer, typed request access, formatting helpers
  SelfTest.java      dependency-free test run
backend/data/        partial_forgery_sweep.csv
frontend/src/
  landing/           landing page, GSAP scroll, cursor-warp canvas
  views/             dashboard tabs
  components/        badges, banners, Bloch sphere, operations mode
  styles/            tokens.css drives the whole palette
docs/                protocol spec, threat model, security claims, audits
```

---

## What this does not claim

Taken from [`docs/layer2-security-claims.md`](docs/layer2-security-claims.md), which is required reading before interpreting any assessment.

| Limitation | Detail |
|---|---|
| No quantum hardware | Every result is a software simulation of protocol mechanics |
| No composable security proof | Approximates Amiri et al. (2016) and Gottesman-Chuang (2001); does not reproduce them |
| Classical digest binding | The quantum key binding that makes real QDS information-theoretically secure is modelled, not proven |
| In-memory replay ledger | Does not survive a restart; distributed replay prevention is out of scope |
| Detection is not exhaustive | Attack variants outside the modelled eight may pass |

---

## Documentation

| Document | Covers |
|---|---|
| [`protocol-spec.md`](docs/protocol-spec.md) | The protocol as implemented |
| [`threat-model.md`](docs/threat-model.md) | Actors, attacks, detectors, limitations |
| [`layer2-security-claims.md`](docs/layer2-security-claims.md) | What is and is not proven |
| [`layer1-assumptions.md`](docs/layer1-assumptions.md) | Layer 1 scope boundaries |
| [`layer1-api.md`](docs/layer1-api.md) · [`layer2-api.md`](docs/layer2-api.md) | Endpoint reference |
| [`layer2-detection-spec.md`](docs/layer2-detection-spec.md) | Detector definitions |
| [`demo-script.md`](docs/demo-script.md) · [`layer3-demo-script.md`](docs/layer3-demo-script.md) | Walkthroughs |
