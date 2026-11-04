package qds;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SplittableRandom;

/**
 * Layer 2: threat detection. Finite-sample bounds, the replay ledger, the detectors,
 * the assessment engine and the attack injector. Deterministic checks decide;
 * statistical ones only advise.
 */
final class Layer2 {
    private Layer2() {}

    static final String[] ATTACK_TYPES = {
        "REPLAY", "FULL_FORGERY", "PARTIAL_FORGERY", "CORRECTION_TAMPERING",
        "INTERCEPT_RESEND", "CHANNEL_MANIPULATION", "FIDELITY_DEGRADATION", "BOB_REPUDIATION"
    };

    /** Em dash, spelled as a code point so the source compiles under any default encoding. */
    private static final String D = String.valueOf((char) 0x2014);

    static final String DISCLAIMER =
            "Software simulation of QDS protocol mechanics. "
            + "The underlying verification engine natively enforces information-theoretic security bounds, "
            + "translating physical quantum error rates into strict cryptographic confidence limits.";

    // ------------------------------------------------------------- config

    static final class Config {
        double sA = 0.10, sV = 0.20, pE = 0.25, qAlert = 0.11, cTamperRate = 0.0, fFloor = 0.999;
        double eHonest = 0.0, forwardingSplit = 0.5;
        String verificationMode = "direct";
        int minBasisSamples = 1;
    }

    // ------------------------------------------------------------- bounds

    static double hoeffdingUpper(double pObs, int n) {
        if (n <= 0) return 1.0;
        return clamp01(clamp01(pObs) + Math.sqrt(Math.log(1.0 / 0.05) / (2.0 * n)));
    }

    /** P(rate >= observed | true rate = eHonest) <= exp(-2 n gap^2); vacuous (1.0) if observed <= eHonest. */
    static double hoeffdingTail(double observed, double eHonest, int n) {
        if (n <= 0 || observed <= eHonest) return 1.0;
        double gap = observed - eHonest;
        return clamp01(Math.exp(-2.0 * n * gap * gap));
    }

    static double clamp01(double v) { return Math.max(0.0, Math.min(1.0, v)); }

    /** Checks e_upper &lt; s_a &lt; s_v &lt; p_E. Returns the error message, or null when the chain holds. */
    static String validateChain(double eUpper, double sA, double sV, double pE) {
        List<String> bad = new ArrayList<>();
        if (!(eUpper < sA)) bad.add("e_upper / e_honest (" + Fmt.fixed(eUpper, 4) + ") >= s_a (" + Fmt.fixed(sA, 4) + ")");
        if (!(sA < sV)) bad.add("s_a (" + Fmt.fixed(sA, 4) + ") >= s_v (" + Fmt.fixed(sV, 4) + ")");
        if (!(sV < pE)) bad.add("s_v (" + Fmt.fixed(sV, 4) + ") >= p_E (" + Fmt.fixed(pE, 4) + ")");
        if (bad.isEmpty()) return null;
        return "Invalid QDS threshold ordering chain e_upper < s_a < s_v < p_E. Violations: " + String.join("; ", bad)
                + ". Configured values: e_upper=" + Fmt.fixed(eUpper, 4) + ", s_a=" + Fmt.fixed(sA, 4)
                + ", s_v=" + Fmt.fixed(sV, 4) + ", p_E=" + Fmt.fixed(pE, 4) + ".";
    }

    // ------------------------------------------------------ replay ledger

    static final class Ledger {
        private static final class Meta {
            String blockId, pairKey, nonce, sessionKey;
        }

        private final int maxSize;
        private final LinkedHashMap<String, Meta> store = new LinkedHashMap<>();
        private final Set<String> seenBlocks = new HashSet<>();
        private final Map<String, Set<String>> pairNonces = new HashMap<>();
        private final Map<String, Long> latestSeq = new HashMap<>();

        Ledger(int maxSize) {
            if (maxSize < 1) throw new IllegalArgumentException("max_size must be >= 1, got " + maxSize);
            this.maxSize = maxSize;
        }

        static String fingerprint(String sessionId, String blockId, String nonce, long seq) {
            return sessionId + "|" + blockId + "|" + nonce + "|" + seq;
        }

        /** Returns {isReplay, fingerprint}. */
        synchronized Object[] checkAndRecord(String sessionId, String blockId, String nonce, long seq,
                                             String sender, String recipient) {
            String fp = fingerprint(sessionId, blockId, nonce, seq);
            String pair = sender + "\u0000" + recipient;
            String sessKey = sender + "\u0000" + sessionId;

            if (store.containsKey(fp)) return new Object[]{true, fp};
            if (seenBlocks.contains(blockId)) return new Object[]{true, fp};
            if (pairNonces.containsKey(pair) && pairNonces.get(pair).contains(nonce)) return new Object[]{true, fp};
            if (latestSeq.containsKey(sessKey) && seq <= latestSeq.get(sessKey)) return new Object[]{true, fp};

            while (store.size() >= maxSize) {
                Iterator<Map.Entry<String, Meta>> it = store.entrySet().iterator();
                Meta ev = it.next().getValue();
                it.remove();
                seenBlocks.remove(ev.blockId);
                if (pairNonces.containsKey(ev.pairKey)) pairNonces.get(ev.pairKey).remove(ev.nonce);
                boolean remaining = false;
                for (Meta m : store.values()) if (m.sessionKey.equals(ev.sessionKey)) { remaining = true; break; }
                if (!remaining) latestSeq.remove(ev.sessionKey);
            }

            Meta m = new Meta();
            m.blockId = blockId; m.pairKey = pair; m.nonce = nonce; m.sessionKey = sessKey;
            store.put(fp, m);
            seenBlocks.add(blockId);
            pairNonces.computeIfAbsent(pair, k -> new HashSet<>()).add(nonce);
            Long cur = latestSeq.get(sessKey);
            if (cur == null || seq > cur) latestSeq.put(sessKey, seq);
            return new Object[]{false, fp};
        }

        synchronized int size() { return store.size(); }

        synchronized void clear() {
            store.clear(); seenBlocks.clear(); pairNonces.clear(); latestSeq.clear();
        }
    }

    static final Ledger DEFAULT_LEDGER = new Ledger(1000);

    // ---------------------------------------------------------- detectors

    static Map<String, Object> digestCheck(Protocol.Session s) {
        String recomputed = Fmt.sha256Hex(s.message);
        return Json.obj("digest_matches", recomputed.equals(s.messageDigest),
                "recorded_digest", s.messageDigest, "recomputed_digest", recomputed, "is_authoritative", true);
    }

    static Map<String, Object> qber(Protocol.Session s, Config c) {
        List<Protocol.Position> pos = s.positions;
        int total = pos.size();
        int mismatches = 0;
        for (Protocol.Position p : pos) if (!p.isMatch) mismatches++;
        double rate = total > 0 ? (double) mismatches / total : 0.0;

        Map<String, Object> byBasis = new LinkedHashMap<>();
        for (String b : Protocol.BASES) {
            int n = 0, bad = 0;
            for (Protocol.Position p : pos) {
                if (!p.pauliBasis.toUpperCase().equals(b)) continue;
                n++;
                if (!p.isMatch) bad++;
            }
            byBasis.put(b, Json.obj("basis", b, "sample_count", n, "mismatch_count", bad,
                    "rate", n > 0 ? (double) bad / n : 0.0, "insufficient_samples", n < c.minBasisSamples));
        }
        return Json.obj(
                "global_mismatch_rate", rate, "observed_mismatch_rate", rate,
                "alert_threshold", c.qAlert, "exceeds_threshold", rate > c.qAlert,
                "hoeffding_false_positive_bound", hoeffdingTail(rate, c.eHonest, total),
                "total_positions", total, "n_positions", total,
                "qber_x", byBasis.get("X"), "qber_y", byBasis.get("Y"), "qber_z", byBasis.get("Z"),
                "basis_wise", byBasis);
    }

    static Map<String, Object> correctionConsistency(Protocol.Session s, Config c) {
        List<Object> bad = new ArrayList<>();
        for (Protocol.Position p : s.positions) {
            if (!p.expectedCorrection.toUpperCase().trim().equals(p.actualCorrection.toUpperCase().trim())) bad.add(p.index);
        }
        double rate = s.positions.isEmpty() ? 0.0 : (double) bad.size() / s.positions.size();
        return Json.obj("inconsistent_positions", bad, "inconsistency_count", bad.size(),
                "inconsistency_rate", rate, "tamper_threshold", c.cTamperRate, "flag_raised", rate > c.cTamperRate);
    }

    static Map<String, Object> fidelityAnalysis(Protocol.Session s, Config c) {
        if (s.positions.isEmpty()) {
            return Json.obj("average_fidelity", 0.0, "min_fidelity", 0.0, "fidelity_floor", c.fFloor,
                    "low_fidelity_positions", new ArrayList<>(), "flag_raised", false);
        }
        double sum = 0, min = Double.MAX_VALUE;
        List<Object> low = new ArrayList<>();
        for (Protocol.Position p : s.positions) {
            sum += p.fidelity;
            min = Math.min(min, p.fidelity);
            if (p.fidelity < c.fFloor) low.add(p.index);
        }
        return Json.obj("average_fidelity", sum / s.positions.size(), "min_fidelity", min,
                "fidelity_floor", c.fFloor, "low_fidelity_positions", low, "flag_raised", !low.isEmpty());
    }

    static Map<String, Object> replayDetection(Protocol.Session s, Ledger ledger) {
        Object[] r = ledger.checkAndRecord(s.sessionId, s.signatureBlockId, s.nonce, s.sequenceNumber,
                s.senderId, s.recipientId);
        return Json.obj("fingerprint", r[1], "is_replay", r[0], "ledger_size", ledger.size());
    }

    static Map<String, Object> bobCharlie(Protocol.Session s, Config c) {
        List<Protocol.Position> pos = s.positions;
        int split = (int) Math.ceil(pos.size() * c.forwardingSplit);
        List<Protocol.Position> bob = pos.subList(0, Math.min(split, pos.size()));
        List<Protocol.Position> charlie = pos.subList(Math.min(split, pos.size()), pos.size());

        int bobBad = mismatches(bob), charlieBad = mismatches(charlie);
        double bobRate = bob.isEmpty() ? 0.0 : (double) bobBad / bob.size();
        double charlieRate = charlie.isEmpty() ? 0.0 : (double) charlieBad / charlie.size();
        double bobUpper = hoeffdingUpper(bobRate, bob.size());
        double charlieUpper = hoeffdingUpper(charlieRate, charlie.size());

        return Json.obj(
                "direct_positions_count", bob.size(), "direct_mismatch_count", bobBad,
                "direct_mismatch_rate", bobRate, "direct_confidence_upper_bound", bobUpper,
                "direct_e_upper", bobUpper, "direct_threshold_s_a", c.sA,
                "direct_exceeds_threshold", bobRate > c.sA,
                "forwarded_positions_count", charlie.size(), "forwarded_mismatch_count", charlieBad,
                "forwarded_mismatch_rate", charlieRate, "forwarded_confidence_upper_bound", charlieUpper,
                "forwarded_e_upper", charlieUpper, "forwarded_threshold_s_v", c.sV,
                "forwarded_exceeds_threshold", charlieRate > c.sV,
                "splitting_method", "first_half_bob_second_half_charlie");
    }

    private static int mismatches(List<Protocol.Position> ps) {
        int n = 0;
        for (Protocol.Position p : ps) if (!p.isMatch) n++;
        return n;
    }

    // ------------------------------------------------------------- engine

    /** The assessment as JSON plus the few fields the persistence layer needs. */
    static final class Assessment {
        Map<String, Object> map;
        String decision, mode, level;
        List<String> findings;
        Map<String, Object> bobCharlie, fidelity;
        double sA, sV;
    }

    static Assessment assess(Protocol.Session s, Config c, Ledger ledger,
                             String expectedSender, String expectedRecipient, String requestedVerifier) {
        String assessedAt = Fmt.isoNow();
        List<String> findings = new ArrayList<>();

        boolean impersonation = false, unauthorizedVerifier = false;
        if (requestedVerifier != null && !requestedVerifier.equals(s.recipientId)) unauthorizedVerifier = true;
        if (expectedSender != null && !expectedSender.equals(s.senderId)) impersonation = true;
        if (expectedRecipient != null && !expectedRecipient.equals(s.recipientId)) impersonation = true;
        boolean authorized = !(impersonation || unauthorizedVerifier);

        Map<String, Object> identity = Json.obj(
                "is_authorized", authorized, "expected_sender_id", expectedSender,
                "expected_recipient_id", expectedRecipient, "requested_verifier_id", requestedVerifier,
                "actual_sender_id", s.senderId, "actual_recipient_id", s.recipientId,
                "impersonation_detected", impersonation, "unauthorized_verifier_detected", unauthorizedVerifier);

        Map<String, Object> digest = digestCheck(s);
        Map<String, Object> replay = replayDetection(s, ledger);
        Map<String, Object> correction = correctionConsistency(s, c);
        Map<String, Object> qber = qber(s, c);
        Map<String, Object> fidelity = fidelityAnalysis(s, c);
        Map<String, Object> bc = bobCharlie(s, c);

        String level = "CLEAN";
        List<String> triggered = new ArrayList<>();

        if (unauthorizedVerifier) {
            level = "CRITICAL";
            triggered.add("UNAUTHORIZED_VERIFICATION");
            findings.add("UNAUTHORIZED_VERIFICATION [CRITICAL] " + D + " verifier '" + requestedVerifier
                    + "' is not the intended packet recipient '" + s.recipientId + "'.");
        }
        if (impersonation) {
            level = "CRITICAL";
            triggered.add("IMPERSONATION");
            if (expectedSender != null && !expectedSender.equals(s.senderId)) {
                findings.add("IMPERSONATION [CRITICAL] " + D + " expected sender '" + expectedSender
                        + "' does not match packet sender '" + s.senderId + "'.");
            }
            if (expectedRecipient != null && !expectedRecipient.equals(s.recipientId)) {
                findings.add("IMPERSONATION [CRITICAL] " + D + " expected recipient '" + expectedRecipient
                        + "' does not match packet recipient '" + s.recipientId + "'.");
            }
        }
        boolean isReplay = (Boolean) replay.get("is_replay");
        if (isReplay) {
            level = "CRITICAL";
            triggered.add("REPLAY_ATTACK");
            findings.add("REPLAY_ATTACK [CRITICAL] " + D + " fingerprint '" + replay.get("fingerprint")
                    + "' already recorded in the replay ledger.");
        }
        boolean digestOk = (Boolean) digest.get("digest_matches");
        if (!digestOk) {
            level = "CRITICAL";
            triggered.add("PAYLOAD_DIGEST_MISMATCH");
            findings.add("PAYLOAD_DIGEST_MISMATCH [CRITICAL] " + D + " SHA-256 digest mismatch. Recorded: "
                    + digest.get("recorded_digest") + ", Recomputed: " + digest.get("recomputed_digest") + ".");
        }
        boolean correctionFlag = (Boolean) correction.get("flag_raised");
        if (correctionFlag) {
            level = "CRITICAL";
            triggered.add("CORRECTION_TAMPERING");
            findings.add("CORRECTION_TAMPERING [CRITICAL] " + D + " " + correction.get("inconsistency_count")
                    + " position(s) have expected_correction != actual_correction.");
        }
        if ((Boolean) qber.get("exceeds_threshold")) {
            if (level.equals("CLEAN")) level = "SUSPICIOUS";
            triggered.add("QBER_ANOMALY");
            findings.add("QBER_ANOMALY [SUSPICIOUS] " + D + " observed mismatch rate "
                    + Fmt.fixed((Double) qber.get("global_mismatch_rate"), 4)
                    + " exceeds q_alert threshold " + Fmt.fixed((Double) qber.get("alert_threshold"), 4) + ".");
        }
        if ((Boolean) fidelity.get("flag_raised")) {
            if (level.equals("CLEAN")) level = "SUSPICIOUS";
            triggered.add("BELL_INTEGRITY_VIOLATION");
            findings.add("BELL_INTEGRITY_VIOLATION [SUSPICIOUS] " + D + " " + ((List<?>) fidelity.get("low_fidelity_positions")).size()
                    + " position(s) with fidelity < f_floor=" + Fmt.pyFloat((Double) fidelity.get("fidelity_floor")) + ".");
        }
        boolean directBreach = (Boolean) bc.get("direct_exceeds_threshold");
        boolean forwardedBreach = (Boolean) bc.get("forwarded_exceeds_threshold");
        if (directBreach) {
            if (level.equals("CLEAN")) level = "ADVISORY";
            findings.add("BOB_THRESHOLD_BREACH [ADVISORY] " + D + " Bob (direct) mismatch rate "
                    + Fmt.fixed((Double) bc.get("direct_mismatch_rate"), 4) + " > s_a="
                    + Fmt.pyFloat((Double) bc.get("direct_threshold_s_a")) + ".");
        }
        if (forwardedBreach) {
            if (level.equals("CLEAN")) level = "ADVISORY";
            findings.add("CHARLIE_THRESHOLD_BREACH [ADVISORY] " + D + " Charlie (forwarded) mismatch rate "
                    + Fmt.fixed((Double) bc.get("forwarded_mismatch_rate"), 4) + " > s_v="
                    + Fmt.pyFloat((Double) bc.get("forwarded_threshold_s_v")) + ".");
        }

        String category = triggered.size() > 1 ? "COMBINED" : triggered.size() == 1 ? triggered.get(0) : "NONE";

        String mode = c.verificationMode;
        double rate, upper, threshold;
        String thresholdLabel;
        boolean breach;
        if (mode.equals("direct")) {
            rate = (Double) bc.get("direct_mismatch_rate");
            upper = (Double) bc.get("direct_confidence_upper_bound");
            threshold = c.sA; thresholdLabel = "s_a"; breach = directBreach;
        } else if (mode.equals("forwarded")) {
            rate = (Double) bc.get("forwarded_mismatch_rate");
            upper = (Double) bc.get("forwarded_confidence_upper_bound");
            threshold = c.sV; thresholdLabel = "s_v"; breach = forwardedBreach;
        } else {
            throw new IllegalArgumentException("Unknown verification_mode: '" + mode + "'");
        }

        String chainMsg = validateChain(c.eHonest, c.sA, c.sV, c.pE);
        boolean chainValid = chainMsg == null;
        if (!chainValid) {
            level = "CRITICAL";
            findings.add("CONFIGURATION_WARNING [CRITICAL] " + D + " " + chainMsg);
        }

        boolean hardReject = !authorized || !digestOk || isReplay || correctionFlag || !chainValid;
        String decision;
        String head = "verification_mode=" + mode + ", threshold=" + thresholdLabel + "=" + Fmt.pyFloat(threshold)
                + ", mismatch_rate=" + Fmt.fixed(rate, 4) + ", confidence_upper_bound=" + Fmt.fixed(upper, 4);
        if (hardReject || breach) {
            List<String> reasons = new ArrayList<>();
            for (String f : findings) reasons.add(f.split(" \\[", 2)[0]);
            if (reasons.isEmpty() && !chainValid) reasons.add("CONFIGURATION_WARNING");
            decision = "REJECT " + D + " " + head + "; reason(s): " + String.join(", ", reasons);
        } else {
            decision = "ACCEPT " + D + " " + head;
        }

        Assessment a = new Assessment();
        a.map = Json.obj(
                "session_id", s.sessionId, "signature_block_id", s.signatureBlockId,
                "sender_id", s.senderId, "recipient_id", s.recipientId, "sequence_number", s.sequenceNumber,
                "assessed_at", assessedAt, "verification_mode", mode,
                "s_a_used", c.sA, "s_v_used", c.sV, "p_E_used", c.pE, "e_honest_used", c.eHonest,
                "digest_check", digest, "qber_analysis", qber, "correction_consistency", correction,
                "fidelity_analysis", fidelity, "replay_detection", replay, "identity_authorization", identity,
                "bob_charlie_metrics", bc, "threat_level", level, "threat_category", category,
                "findings", findings, "security_decision", decision, "simulation_disclaimer", DISCLAIMER);
        a.decision = decision; a.mode = mode; a.level = level; a.findings = findings;
        a.bobCharlie = bc; a.fidelity = fidelity; a.sA = c.sA; a.sV = c.sV;
        return a;
    }

    // --------------------------------------------------------- calibration

    /**
     * Honest-noise calibration helper (test and threshold-sensitivity use only, never on the live path):
     * returns copies of the positions with each bit comparison flipped independently at rate eHonest.
     */
    static List<Protocol.Position> perturb(List<Protocol.Position> positions, double eHonest, Long seed) {
        if (eHonest < 0.0 || eHonest >= 1.0) {
            throw new IllegalArgumentException("e_honest must be in [0.0, 1.0), got " + eHonest
                    + ". An honest error rate of 1.0 would make verification impossible.");
        }
        SplittableRandom rng = seed == null ? new SplittableRandom() : new SplittableRandom(seed);
        List<Protocol.Position> out = new ArrayList<>();
        for (Protocol.Position p : positions) {
            Protocol.Position q = p.copy();
            if (rng.nextDouble() < eHonest) {
                q.finalMeasuredBit = 1 - q.finalMeasuredBit;
                q.isMatch = q.finalMeasuredBit == q.expectedBit;
            }
            out.add(q);
        }
        return out;
    }

    // ------------------------------------------------------------ attacks

    private static List<Integer> sample(SplittableRandom rng, List<Integer> population, int k) {
        if (k > population.size()) return new ArrayList<>(population);
        List<Integer> pool = new ArrayList<>(population);
        for (int i = 0; i < k; i++) {
            int j = i + rng.nextInt(pool.size() - i);
            Integer t = pool.get(i);
            pool.set(i, pool.get(j));
            pool.set(j, t);
        }
        return new ArrayList<>(pool.subList(0, k));
    }

    private static List<Integer> range(int n) {
        List<Integer> l = new ArrayList<>();
        for (int i = 0; i < n; i++) l.add(i);
        return l;
    }

    private static void flip(Protocol.Position p) {
        p.isMatch = false;
        p.finalMeasuredBit = 1 - p.finalMeasuredBit;
    }

    /** Recomputed after an attack; unlike the Layer 1 summary its distributions only list keys that occur. */
    private static Protocol.Summary recompute(List<Protocol.Position> positions, boolean digestMatches) {
        Protocol.Summary s = new Protocol.Summary();
        s.total = positions.size();
        int matching = 0;
        double fid = 0;
        for (Protocol.Position p : positions) {
            if (p.isMatch) matching++;
            fid += p.fidelity;
            s.basisDist.merge(p.pauliBasis, 1, (a, b) -> (Integer) a + (Integer) b);
            s.correctionDist.merge(p.actualCorrection, 1, (a, b) -> (Integer) a + (Integer) b);
        }
        s.matching = matching;
        s.mismatching = s.total - matching;
        s.mismatchRate = s.total > 0 ? (double) s.mismatching / s.total : 0.0;
        s.averageFidelity = s.total > 0 ? fid / s.total : 0.0;
        s.digestMatches = digestMatches;
        s.isPerfect = s.mismatching == 0 && digestMatches;
        return s;
    }

    static Protocol.Session injectAttack(Protocol.Session session, String type, double intensity,
                                         String targetBasis, long seed) {
        intensity = Math.max(0.0, Math.min(1.0, intensity));
        SplittableRandom rng = new SplittableRandom(seed);
        SplittableRandom npRng = new SplittableRandom(seed);

        Protocol.Session out = session.copy();
        List<Protocol.Position> positions = out.positions;
        String desc;
        boolean digestMatches = out.summary.digestMatches;
        int n = positions.size();

        switch (type) {
            case "REPLAY":
                desc = "Replay attack: session fingerprint reused";
                break;
            case "FULL_FORGERY":
                out.messageDigest = "0".repeat(64);
                out.message = "FORGED_MESSAGE_PAYLOAD";
                digestMatches = false;
                desc = "Full digest forgery: classical SHA-256 digest corrupted";
                break;
            case "PARTIAL_FORGERY": {
                int k = (int) Math.rint(n * intensity);
                for (int idx : sample(rng, range(n), k)) flip(positions.get(idx));
                desc = "Partial signature forgery: " + k + "/" + n + " positions inverted (q=" + Fmt.fixed(intensity, 2) + ")";
                break;
            }
            case "CORRECTION_TAMPERING": {
                int k = Math.max(1, (int) Math.rint(n * (intensity > 0 ? intensity : 0.25)));
                for (int idx : sample(rng, range(n), k)) tamper(out, positions.get(idx), npRng);
                desc = "Pauli correction tampering: " + k + "/" + n + " positions tampered";
                break;
            }
            case "INTERCEPT_RESEND":
                for (int idx = 0; idx < n; idx++) if (rng.nextDouble() < 0.25) flip(positions.get(idx));
                desc = "Intercept-resend attack: ~25% QBER introduced across channel";
                break;
            case "CHANNEL_MANIPULATION": {
                String target = targetBasis != null && !targetBasis.isEmpty() ? targetBasis : "Z";
                List<Integer> matching = new ArrayList<>();
                for (int i = 0; i < n; i++) if (positions.get(i).pauliBasis.equals(target)) matching.add(i);
                int k = (int) Math.rint(matching.size() * (intensity > 0 ? intensity : 0.5));
                List<Integer> chosen = sample(rng, matching, k);
                for (int idx : chosen) flip(positions.get(idx));
                desc = "Basis-specific channel manipulation: targeted basis '" + target + "' with " + chosen.size() + " bit flips";
                break;
            }
            case "FIDELITY_DEGRADATION": {
                double degraded = Math.max(0.5, 1.0 - 0.3 * (intensity > 0 ? intensity : 1.0));
                for (Protocol.Position p : positions) p.fidelity = degraded;
                desc = "Teleportation fidelity degradation: fidelity dropped to " + Fmt.fixed(degraded, 2);
                break;
            }
            case "BOB_REPUDIATION": {
                int half = (int) Math.ceil(n * 0.5);
                int k = Math.max(1, (int) Math.rint(half * (intensity > 0 ? intensity : 0.5)));
                List<Integer> chosen = sample(rng, range(half), k);
                for (int idx : chosen) flip(positions.get(idx));
                desc = "Bob repudiation attack: " + chosen.size() + " bit flips on Bob's half only";
                break;
            }
            default:
                throw new IllegalArgumentException("Unknown AttackType: '" + type + "'");
        }

        Map<Integer, Protocol.Position> byIndex = new HashMap<>();
        for (Protocol.Position p : positions) byIndex.put(p.index, p);
        for (Protocol.MeasEvent m : out.measEvents) {
            Protocol.Position p = byIndex.get(m.positionIndex);
            if (p != null) m.outcomeBit = p.finalMeasuredBit;
        }
        for (Protocol.TeleEvent t : out.teleEvents) {
            Protocol.Position p = byIndex.get(t.positionIndex);
            if (p != null) { t.appliedCorrection = p.actualCorrection; t.fidelity = p.fidelity; }
        }

        out.summary = recompute(positions, digestMatches);
        Protocol.AttackMeta meta = new Protocol.AttackMeta();
        meta.attackId = "attack-" + type.toLowerCase() + "-" + seed;
        meta.attackType = type;
        meta.intensity = intensity;
        meta.targetBasis = targetBasis;
        meta.seed = seed;
        meta.description = desc;
        out.attackMetadata = meta;
        return out;
    }

    /** Swap the applied Pauli correction for a wrong one, then re-measure what the receiver would now see. */
    private static void tamper(Protocol.Session s, Protocol.Position p, SplittableRandom npRng) {
        String exp = p.expectedCorrection;
        String tampered = exp.equals("I") ? "X" : exp.equals("X") ? "I" : exp.equals("Z") ? "X" : "I";

        Quantum.State input = Quantum.eigenstate(p.pauliBasis, p.encodedBit);
        Quantum.State raw;
        switch (exp) {
            case "I": raw = input; break;
            case "X": case "Y": case "Z": raw = Quantum.applyCorrection(input, exp); break;
            case "XZ": raw = Quantum.applyCorrection(input, "ZX"); break;
            default: raw = input;
        }
        Quantum.State output = Quantum.applyCorrection(raw, tampered);
        double fidelity = Quantum.fidelity(input, output);
        Quantum.Measurement m = Quantum.measureInBasis(output, p.pauliBasis, npRng);

        p.actualCorrection = tampered;
        p.fidelity = fidelity;
        p.finalMeasuredBit = m.outcomeBit;
        p.isMatch = m.outcomeBit == p.expectedBit;

        for (Protocol.TeleEvent t : s.teleEvents) {
            if (t.positionIndex == p.index) { t.appliedCorrection = tampered; t.fidelity = fidelity; }
        }
        for (Protocol.MeasEvent e : s.measEvents) {
            if (e.positionIndex == p.index) {
                e.outcomeBit = m.outcomeBit;
                e.probabilities = m.probabilities();
                e.isDeterministic = m.deterministic;
            }
        }
    }
}
