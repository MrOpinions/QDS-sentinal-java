package qds;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;

/**
 * Dependency-free self-check: java -cp backend/out qds.SelfTest
 * Exits non-zero if any check fails.
 */
public final class SelfTest {
    private static int passed, failed;

    private static void check(boolean ok, String what) {
        if (ok) { passed++; } else { failed++; System.out.println("FAIL: " + what); }
    }

    private static boolean near(double a, double b) { return Math.abs(a - b) < 1e-9; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static Protocol.Session session(String msg, int n, long seed, String id) {
        return Protocol.runSession(msg, "alice", "bob", n, seed, "PHI_PLUS", null, id, "nonce-" + id, 1, null);
    }

    public static void main(String[] args) throws Exception {
        quantum();
        protocol();
        bounds();
        ledger();
        engine();
        attacks();
        audit();
        json();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }

    static void quantum() {
        for (String b : Protocol.BASES) {
            for (int bit = 0; bit < 2; bit++) check(near(Quantum.norm(Quantum.eigenstate(b, bit).re, Quantum.eigenstate(b, bit).im), 1.0), "norm " + b + bit);
        }
        double[] plusI = Quantum.blochForBasisBit("Y", 0);
        check(plusI[0] == 0.0 && near(plusI[1], 1.0) && plusI[2] == 0.0, "|+i> sits on +Y");
        check(Quantum.blochForBasisBit("Z", 1)[2] == -1.0, "|1> sits on -Z");

        // every Bell state x every eigenstate x many seeds must teleport perfectly (validates the correction table)
        SplittableRandom rng = new SplittableRandom(7);
        double worst = 1.0;
        for (String bell : Protocol.BELL_STATES) {
            for (String b : Protocol.BASES) {
                for (int bit = 0; bit < 2; bit++) {
                    for (int i = 0; i < 40; i++) {
                        Quantum.Teleportation t = Quantum.teleport(Quantum.eigenstate(b, bit), bell, null, rng);
                        worst = Math.min(worst, t.fidelity);
                    }
                }
            }
        }
        check(worst > 1 - 1e-9, "teleportation fidelity ~1 for all Bell states (worst " + worst + ")");

        Quantum.Measurement m = Quantum.measureInBasis(Quantum.eigenstate("X", 1), "X", rng);
        check(m.outcomeBit == 1 && m.deterministic, "eigenstate measured in own basis is deterministic");
        Quantum.Measurement m2 = Quantum.measureInBasis(Quantum.eigenstate("X", 0), "Z", rng);
        check(near(m2.p0, 0.5) && !m2.deterministic, "|+> in Z basis is 50/50");

        Quantum.State s = Quantum.applyCorrection(Quantum.eigenstate("Z", 0), "X");
        check(s.re[1] == 1.0, "X|0> = |1>");
        boolean threw = false;
        try { Quantum.expectedCorrection("22", "PHI_PLUS"); } catch (IllegalArgumentException e) { threw = true; }
        check(threw, "bad Bell bits rejected");
    }

    static void protocol() {
        check(Fmt.sha256Hex("abc").equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256(abc)");

        Protocol.Session a = session("HELLO", 16, 42, "t1"), b = session("HELLO", 16, 42, "t1");
        boolean same = true;
        for (int i = 0; i < 16; i++) {
            Protocol.Position p = a.positions.get(i), q = b.positions.get(i);
            same &= p.pauliBasis.equals(q.pauliBasis) && p.encodedBit == q.encodedBit && p.bellMeasurementBits.equals(q.bellMeasurementBits);
        }
        check(same, "same seed reproduces the session");
        check(a.summary.mismatching == 0 && a.summary.isPerfect && near(a.summary.averageFidelity, 1.0), "clean session has no mismatches");
        check(a.positions.size() == 16 && a.teleEvents.size() == 16 && a.measEvents.size() == 16, "event counts");
        check(a.summary.basisDist.size() == 3 && a.summary.correctionDist.size() == 4, "summary distributions pre-populated");

        Protocol.Session z = Protocol.runSession("M", "a", "b", 20, 1L, "PSI_MINUS", Arrays.asList("Z"), null, null, 1, null);
        boolean allZ = true;
        for (Protocol.Position p : z.positions) allZ &= p.pauliBasis.equals("Z");
        check(allZ, "bases_allowed respected");

        boolean threw = false;
        try { Protocol.runSession("M", "a", "b", 0, 1L, "PHI_PLUS", null, null, null, 1, null); } catch (IllegalArgumentException e) { threw = true; }
        check(threw, "zero signature length rejected");

        // round-trip through JSON, as assess-existing does
        Protocol.Session back = Protocol.Session.from(new Req(Json.parse(Json.write(a.toMap())), "body"));
        check(back.positions.size() == 16 && back.messageDigest.equals(a.messageDigest) && back.summary.isPerfect, "session JSON round-trip");
    }

    static void bounds() {
        check(near(Layer2.hoeffdingUpper(0.0, 16), Math.sqrt(Math.log(20.0) / 32.0)), "hoeffding upper n=16");
        check(Layer2.hoeffdingUpper(0.9, 4) == 1.0 && Layer2.hoeffdingUpper(0.1, 0) == 1.0, "hoeffding clamps");
        check(Layer2.hoeffdingTail(0.1, 0.2, 10) == 1.0, "tail vacuous when observed <= honest");
        check(near(Layer2.hoeffdingTail(0.3, 0.0, 10), Math.exp(-2 * 10 * 0.09)), "hoeffding tail");
        check(Layer2.validateChain(0.0, 0.10, 0.20, 0.25) == null, "default chain valid");
        check(Layer2.validateChain(0.0, 0.30, 0.20, 0.25) != null, "inverted chain flagged");

        Protocol.Session base = session("CAL", 400, 3, "cal");
        check(Layer2.perturb(base.positions, 0.0, 1L).stream().allMatch(p -> p.isMatch), "calibrator at 0.0 changes nothing");
        long flipped = Layer2.perturb(base.positions, 0.25, 1L).stream().filter(p -> !p.isMatch).count();
        check(flipped > 60 && flipped < 140, "calibrator flips about e_honest of positions: " + flipped);
        check(base.positions.stream().allMatch(p -> p.isMatch), "calibrator leaves originals untouched");
    }

    static void ledger() {
        Layer2.Ledger l = new Layer2.Ledger(3);
        check(!(Boolean) l.checkAndRecord("s1", "b1", "n1", 1, "a", "b")[0], "first packet is fresh");
        check((Boolean) l.checkAndRecord("s1", "b1", "n1", 1, "a", "b")[0], "exact repeat is a replay");
        check((Boolean) l.checkAndRecord("s2", "b2", "n1", 1, "a", "b")[0], "reused nonce is a replay");
        check((Boolean) l.checkAndRecord("s1", "b9", "n9", 1, "a", "b")[0], "non-increasing sequence is a replay");
        check(!(Boolean) l.checkAndRecord("s1", "b3", "n3", 2, "a", "b")[0], "higher sequence is fresh");
        for (int i = 0; i < 6; i++) l.checkAndRecord("x" + i, "bx" + i, "nx" + i, 1, "a", "b");
        check(l.size() == 3, "ledger evicts beyond max size");
        boolean threw = false;
        try { new Layer2.Ledger(0); } catch (IllegalArgumentException e) { threw = true; }
        check(threw, "ledger size must be >= 1");
    }

    static void engine() {
        Layer2.Config cfg = new Layer2.Config();
        Layer2.Ledger l = new Layer2.Ledger(100);

        Protocol.Session clean = session("CLEAN_MSG", 16, 42, "e1");
        Layer2.Assessment a = Layer2.assess(clean, cfg, l, null, null, null);
        check(a.decision.startsWith("ACCEPT") && a.level.equals("CLEAN") && a.findings.isEmpty(), "clean session accepted");

        Layer2.Assessment again = Layer2.assess(clean, cfg, l, null, null, null);
        check(again.decision.startsWith("REJECT") && again.map.get("threat_category").equals("REPLAY_ATTACK"), "replay rejected");

        Protocol.Session forged = session("AUTHENTIC", 16, 77, "e2");
        forged.messageDigest = "0".repeat(64);
        Layer2.Assessment f = Layer2.assess(forged, cfg, l, null, null, null);
        check(f.decision.startsWith("REJECT") && f.map.get("threat_category").equals("PAYLOAD_DIGEST_MISMATCH"), "digest forgery rejected");

        Layer2.Assessment id = Layer2.assess(session("ID", 8, 5, "e3"), cfg, l, "mallory", null, "eve");
        check(id.level.equals("CRITICAL") && id.map.get("threat_category").equals("COMBINED"), "impersonation + unauthorized verifier");

        Layer2.Config bad = new Layer2.Config();
        bad.sV = 0.30;
        Layer2.Assessment cw = Layer2.assess(session("CFG", 8, 6, "e4"), bad, l, null, null, null);
        check(cw.decision.startsWith("REJECT") && cw.findings.get(0).startsWith("CONFIGURATION_WARNING"), "broken threshold chain rejected");

        Layer2.Config fwd = new Layer2.Config();
        fwd.verificationMode = "forwarded";
        Layer2.Assessment fa = Layer2.assess(session("FWD", 8, 8, "e5"), fwd, l, null, null, null);
        check(fa.decision.contains("threshold=s_v=0.2"), "forwarded mode uses s_v: " + fa.decision);

        check(near((Double) a.map.get("s_a_used"), 0.10) && a.map.get("simulation_disclaimer") != null, "assessment carries config + disclaimer");
        check(Fmt.fixed(0.12345, 4).equals("0.1235") || Fmt.fixed(0.12345, 4).equals("0.1234"), "fixed formatting");
    }

    static void attacks() {
        Layer2.Config cfg = new Layer2.Config();
        Protocol.Session base = session("ATTACK_BASE", 20, 42, "a0");

        Protocol.Session pf = Layer2.injectAttack(base, "PARTIAL_FORGERY", 0.25, null, 42);
        check(pf.summary.mismatching == 5 && near(pf.summary.mismatchRate, 0.25), "partial forgery flips round(n*q) positions");
        check(pf.attackMetadata.attackId.equals("attack-partial_forgery-42"), "attack id");
        check(base.summary.mismatching == 0, "original session untouched");
        Layer2.Assessment pa = Layer2.assess(pf, cfg, new Layer2.Ledger(10), null, null, null);
        check(pa.decision.startsWith("REJECT") && pa.level.equals("SUSPICIOUS"), "25% forgery rejected as suspicious: " + pa.decision);

        Protocol.Session ct = Layer2.injectAttack(base, "CORRECTION_TAMPERING", 1.0, null, 42);
        Layer2.Assessment ca = Layer2.assess(ct, cfg, new Layer2.Ledger(10), null, null, null);
        check(ca.level.equals("CRITICAL") && ca.findings.get(0).startsWith("CORRECTION_TAMPERING"), "correction tampering is critical");

        Protocol.Session ff = Layer2.injectAttack(base, "FULL_FORGERY", 1.0, null, 42);
        check(!ff.summary.digestMatches && ff.message.equals("FORGED_MESSAGE_PAYLOAD"), "full forgery");

        Protocol.Session fd = Layer2.injectAttack(base, "FIDELITY_DEGRADATION", 1.0, null, 42);
        check(near(fd.positions.get(0).fidelity, 0.7), "fidelity degraded to 0.7");
        check(Layer2.assess(fd, cfg, new Layer2.Ledger(10), null, null, null).map.get("threat_category").equals("BELL_INTEGRITY_VIOLATION"), "degradation raises bell integrity finding");

        Protocol.Session bob = Layer2.injectAttack(base, "BOB_REPUDIATION", 1.0, null, 42);
        boolean onlyBob = true;
        for (int i = 10; i < 20; i++) onlyBob &= bob.positions.get(i).isMatch;
        check(onlyBob && bob.summary.mismatching == 10, "repudiation touches only Bob's half");

        Protocol.Session cm = Layer2.injectAttack(base, "CHANNEL_MANIPULATION", 1.0, "X", 42);
        boolean onlyX = true;
        for (Protocol.Position p : cm.positions) onlyX &= p.pauliBasis.equals("X") || p.isMatch;
        check(onlyX, "channel manipulation targets one basis");

        Protocol.Session ir = Layer2.injectAttack(base, "INTERCEPT_RESEND", 1.0, null, 42);
        check(ir.summary.mismatching > 0 && ir.summary.mismatching < 20, "intercept-resend introduces partial QBER");
    }

    static void audit() throws Exception {
        Path f = Files.createTempFile("qds-audit", ".jsonl");
        Files.delete(f);
        Store.Audit audit = new Store.Audit(f.toString(), "passphrase");
        audit.append("session", "s1", Json.obj("message", "secret payload", "sender_id", "alice", "verdict", "ACCEPT"));
        audit.append("session", "s2", Json.obj("message", "other", "verdict", "REJECT"));
        check((Boolean) audit.verifyChain().get("intact"), "fresh chain intact");

        String raw = Files.readString(f);
        check(!raw.contains("secret payload") && raw.contains("ACCEPT"), "sensitive fields encrypted, verdicts readable");
        Map<String, Object> rec = audit.read("s1").get(0);
        check(map(rec.get("body")).get("message").equals("secret payload"), "decrypts back");

        Files.writeString(f, raw.replace("ACCEPT", "REJECT"));
        Map<String, Object> v = new Store.Audit(f.toString(), "passphrase").verifyChain();
        check(!(Boolean) v.get("intact") && ((Long) v.get("broken_at")) == 0L, "edit detected at the right record");
        check((Boolean) new Store.Audit(null, null).verifyChain().get("intact") && !new Store.Audit(null, null).enabled(), "disabled sink is a no-op");
        Files.delete(f);
    }

    static void json() {
        Object o = Json.parse("{\"a\":[1,2.5,\"x\\n\\u0041\",true,null],\"b\":{\"c\":-3e2}}");
        check(Json.write(o).equals("{\"a\":[1,2.5,\"x\\nA\",true,null],\"b\":{\"c\":-300.0}}"), "json round-trip: " + Json.write(o));
        check(Json.canonical(Json.obj("b", 1, "a", Arrays.asList(1, 2))).equals("{\"a\":[1,2],\"b\":1}"), "canonical sorts keys");
        boolean threw = false;
        try { Json.parse("{\"a\":"); } catch (Json.ParseException e) { threw = true; }
        check(threw, "truncated json rejected");
        List<Object> empty = new ArrayList<>();
        check(Json.write(empty).equals("[]"), "empty list");
    }
}
