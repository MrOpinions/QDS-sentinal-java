package qds;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * QDS Sentinel HTTP API on the JDK's built-in server. Serves exactly the routes and JSON shapes
 * the React console expects: /health, /api/v1/layer1, /api/v1/layer2 and /api/ops.
 */
public final class Server {
    private Server() {}

    static final String APP_NAME = "QDS Sentinel";
    static final String VERSION = "0.1.0";
    static final String LAYER = "Layer 1: Protocol Simulation + Layer 2: Threat Detection";

    private static final Layer2.Ledger EXAMPLE_LEDGER = new Layer2.Ledger(100);

    public static void main(String[] args) throws IOException {
        try {
            Store.DEFAULT.listSessions(0);   // opens the database now, so a bad MySQL setting fails at startup
        } catch (Throwable t) {
            Throwable root = t instanceof ExceptionInInitializerError && t.getCause() != null ? t.getCause() : t;
            System.err.println("Could not start the database layer: " + root.getMessage());
            if (root.getCause() instanceof java.sql.SQLException || String.valueOf(root.getMessage()).contains("No suitable driver")) {
                System.err.println("Check MYSQL_URL / MYSQL_USER / MYSQL_PASSWORD and that the Connector/J jar is on the classpath.");
            }
            System.exit(1);
        }
        int port = Integer.parseInt(Store.env("PORT", "8000"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", Server::handle);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println(APP_NAME + " " + VERSION + " (Java) listening on http://localhost:" + port + " | store: "
                + (Store.DEFAULT instanceof JdbcStore ? "MySQL" : "file"));
    }

    // ------------------------------------------------------------ plumbing

    private static final class Reply {
        final int status;
        final Object body;
        Reply(int status, Object body) { this.status = status; this.body = body; }
    }

    private static Reply ok(Object body) { return new Reply(200, body); }

    private static void handle(HttpExchange ex) throws IOException {
        Reply reply;
        try {
            addCors(ex);
            if (ex.getRequestMethod().equals("OPTIONS")) {
                ex.sendResponseHeaders(200, -1);
                ex.close();
                return;
            }
            reply = route(ex);
        } catch (HttpError e) {
            reply = new Reply(e.status, Json.obj("detail", e.getMessage()));
        } catch (Json.ParseException e) {
            reply = new Reply(422, Json.obj("detail", "body: JSON decode error: " + e.getMessage()));
        } catch (RuntimeException e) {
            e.printStackTrace();
            reply = new Reply(500, Json.obj("detail", "Internal Server Error"));
        }
        byte[] bytes = Json.write(reply.body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(reply.status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private static void addCors(HttpExchange ex) {
        Headers in = ex.getRequestHeaders(), out = ex.getResponseHeaders();
        String origin = in.getFirst("Origin");
        out.set("Access-Control-Allow-Origin", origin != null ? origin : "*");
        out.set("Access-Control-Allow-Credentials", "true");
        out.set("Vary", "Origin");
        out.set("Access-Control-Allow-Methods", "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT");
        String reqHeaders = in.getFirst("Access-Control-Request-Headers");
        out.set("Access-Control-Allow-Headers", reqHeaders != null ? reqHeaders : "*");
    }

    private static Reply route(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        if (path.length() > 1 && path.endsWith("/")) path = path.substring(0, path.length() - 1);
        Map<String, String> query = query(ex.getRequestURI().getRawQuery());
        String[] seg = path.split("/");   // "", "api", "v1", "layer1", ...

        if (path.equals("/health")) return only(method, "GET", () -> ok(health()));

        if (path.startsWith("/api/v1/layer1/")) {
            String tail = path.substring("/api/v1/layer1/".length());
            if (tail.equals("simulate")) return only(method, "POST", () -> ok(simulate(body(ex))));
            if (tail.equals("example-session")) return only(method, "GET", () -> ok(exampleSession()));
            if (tail.equals("bloch-trace")) return only(method, "POST", () -> ok(blochTrace(body(ex))));
            if (seg.length == 7 && seg[4].equals("bloch-state")) {
                return only(method, "GET", () -> ok(blochState(seg[5], intParam("path.bit", seg[6]))));
            }
        } else if (path.startsWith("/api/v1/layer2/")) {
            switch (path.substring("/api/v1/layer2/".length())) {
                case "assess": return only(method, "POST", () -> ok(assess(body(ex))));
                case "assess-existing": return only(method, "POST", () -> ok(assessExisting(body(ex))));
                case "attack-simulate": return only(method, "POST", () -> ok(attackSimulate(body(ex))));
                case "example-clean": return only(method, "GET", () -> ok(exampleClean()));
                case "example-replay": return only(method, "GET", () -> ok(exampleReplay()));
                case "example-forgery": return only(method, "GET", () -> ok(exampleForgery()));
                default: break;
            }
        } else if (path.startsWith("/api/ops/")) {
            String tail = path.substring("/api/ops/".length());
            switch (tail) {
                case "overview": return only(method, "GET", () -> ok(Ops.overview()));
                case "threat-feed": return only(method, "GET", () -> ok(Ops.threatFeed(limit(query, 30))));
                case "trends": return only(method, "GET", () -> ok(Ops.trends()));
                case "sessions": return only(method, "GET", () -> ok(Ops.sessions(limit(query, 50))));
                case "logs": return only(method, "GET", () -> ok(Ops.recentLogs(limit(query, 100))));
                case "audit/verify": return only(method, "GET", () -> ok(Store.Audit.DEFAULT.verifyChain()));
                default:
                    if (tail.startsWith("logs/") && seg.length == 5) {
                        return only(method, "GET", () -> ok(Ops.sessionLogs(URLDecoder.decode(seg[4], "UTF-8"))));
                    }
            }
        }
        return new Reply(404, Json.obj("detail", "Not Found"));
    }

    private interface Handler { Reply run() throws IOException; }

    private static Reply only(String method, String allowed, Handler h) throws IOException {
        if (!method.equals(allowed)) return new Reply(405, Json.obj("detail", "Method Not Allowed"));
        return h.run();
    }

    private static Object body(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            if (text.trim().isEmpty()) throw new HttpError(422, "body: Field required");
            return Json.parse(text);
        }
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> q = new LinkedHashMap<>();
        if (raw == null) return q;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            int i = pair.indexOf('=');
            try {
                q.put(URLDecoder.decode(i < 0 ? pair : pair.substring(0, i), "UTF-8"),
                      i < 0 ? "" : URLDecoder.decode(pair.substring(i + 1), "UTF-8"));
            } catch (java.io.UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
        return q;
    }

    private static int limit(Map<String, String> q, int dflt) {
        return q.containsKey("limit") ? intParam("query.limit", q.get("limit")) : dflt;
    }

    private static int intParam(String name, String raw) {
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new HttpError(422, name + ": Input should be a valid integer, unable to parse string as an integer");
        }
    }

    // ------------------------------------------------------------- health

    private static Map<String, Object> health() {
        return Json.obj("status", "ok", "app_name", APP_NAME, "version", VERSION, "layer", LAYER);
    }

    // ------------------------------------------------------------- layer 1

    private static Map<String, Object> simulate(Object raw) {
        Protocol.Sim sim = Protocol.Sim.from(new Req(raw, "body"));
        try {
            return Protocol.run(sim).toMap();
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        } catch (RuntimeException e) {
            throw new HttpError(500, "Internal simulation error: " + e.getMessage());
        }
    }

    private static Map<String, Object> exampleSession() {
        return Protocol.runSession("AUTHENTICATED_TRANSACTION_PAYLOAD_001", "alice", "bob", 8, 42L, "PHI_PLUS",
                null, "example-session-001", "nonce-deterministic-42", 1, null).toMap();
    }

    private static Map<String, Object> blochState(String basis, int bit) {
        try {
            double[] c = Quantum.blochForBasisBit(basis, bit);
            return Json.obj("basis", basis.toUpperCase(), "bit", bit,
                    "prepared_label", Quantum.eigenstate(basis, bit).name,
                    "coordinates", Quantum.coord(c), "is_collapsed", false, "collapsed_coordinates", null);
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        }
    }

    private static List<Object> blochTrace(Object raw) {
        Protocol.Sim sim = Protocol.Sim.from(new Req(raw, "body"));
        try {
            Protocol.Session s = Protocol.run(sim);
            List<Object> trace = new ArrayList<>();
            for (Protocol.Position p : s.positions) {
                trace.add(Quantum.measurementCollapse(p.pauliBasis, p.encodedBit, p.finalMeasuredBit));
            }
            return trace;
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        } catch (RuntimeException e) {
            throw new HttpError(500, "Internal Bloch trace computation error: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------- layer 2

    /** Fields shared by assess, assess-existing and attack-simulate. */
    private static final class Ctx {
        Layer2.Config config;
        String expectedSender, expectedRecipient, requestedVerifier;

        Ctx(Req r) {
            String mode = r.enumOr("verification_mode", "direct", "direct", "forwarded");
            Double sA = r.dblOpt("s_a", 0.0, 1.0, false);
            Double sV = r.dblOpt("s_v", 0.0, 1.0, false);
            Double eHonest = r.dblOpt("e_honest", 0.0, 1.0, true);
            expectedSender = r.strOpt("expected_sender_id");
            expectedRecipient = r.strOpt("expected_recipient_id");
            requestedVerifier = r.strOpt("requested_verifier_id");
            config = buildConfig(mode, sA, sV, eHonest);
        }
    }

    static Layer2.Config buildConfig(String mode, Double sA, Double sV, Double eHonest) {
        Layer2.Config c = new Layer2.Config();
        c.verificationMode = mode;
        if (sA != null) c.sA = sA;
        if (sV != null) c.sV = sV;
        if (eHonest != null) c.eHonest = eHonest;
        if (c.sA >= c.sV) {
            throw new HttpError(422, "Threshold ordering violated: s_a=" + Fmt.pyFloat(c.sA)
                    + " must be strictly less than s_v=" + Fmt.pyFloat(c.sV) + " (Amiri et al. 2016 Eq. 19). "
                    + "Repudiation exponential hardness requires s_a < s_v.");
        }
        if (c.eHonest >= c.sA) {
            throw new HttpError(422, "Threshold ordering violated: e_honest=" + Fmt.pyFloat(c.eHonest)
                    + " must be strictly less than s_a=" + Fmt.pyFloat(c.sA)
                    + ". Recalibrate e_honest or increase s_a.");
        }
        return c;
    }

    private static Protocol.Session runLayer1(Protocol.Sim sim, String errorPrefix) {
        try {
            return Protocol.run(sim);
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, errorPrefix + e.getMessage());
        } catch (RuntimeException e) {
            throw new HttpError(500, "Layer 1 simulation error: " + e.getMessage());
        }
    }

    private static Layer2.Assessment layer2(Protocol.Session s, Ctx ctx, Layer2.Ledger ledger) {
        try {
            return Layer2.assess(s, ctx.config, ledger, ctx.expectedSender, ctx.expectedRecipient, ctx.requestedVerifier);
        } catch (RuntimeException e) {
            throw new HttpError(500, "Layer 2 assessment error: " + e.getMessage());
        }
    }

    private static Map<String, Object> assess(Object raw) {
        Req r = new Req(raw, "body");
        Protocol.Sim sim = Protocol.Sim.from(r.obj("simulation"));
        Ctx ctx = new Ctx(r);
        Protocol.Session session = runLayer1(sim, "");
        Layer2.Assessment a = layer2(session, ctx, Layer2.DEFAULT_LEDGER);
        persist(session, a, null);
        return Json.obj("session", session.toMap(), "assessment", a.map);
    }

    private static Map<String, Object> assessExisting(Object raw) {
        Req r = new Req(raw, "body");
        Protocol.Session session = Protocol.Session.from(r.obj("session"));
        Ctx ctx = new Ctx(r);
        Layer2.Assessment a = layer2(session, ctx, Layer2.DEFAULT_LEDGER);
        persist(session, a, null);
        return Json.obj("session", session.toMap(), "assessment", a.map);
    }

    private static Map<String, Object> attackSimulate(Object raw) {
        Req r = new Req(raw, "body");
        Protocol.Sim sim = Protocol.Sim.from(r.obj("simulation"));
        String type = r.enumStr("attack_type", Layer2.ATTACK_TYPES);
        double intensity = r.dblRange("intensity", 1.0, 0.0, 1.0);
        String targetBasis = r.strOpt("target_basis");
        Ctx ctx = new Ctx(r);
        long seed = sim.seed != null ? sim.seed : 42L;

        Protocol.Session session = runLayer1(sim, "Layer 1 simulation error: ");

        Protocol.Session injected;
        Protocol.AttackMeta meta;
        if (type.equals("REPLAY")) {
            injected = session;
            meta = new Protocol.AttackMeta();
            meta.attackId = UUID.randomUUID().toString();
            meta.attackType = "REPLAY";
            meta.intensity = 1.0;
            meta.seed = seed;
            meta.description = "Stateful replay: exact packet re-submitted (session=" + py(sim.sessionId)
                    + ", nonce=" + py(sim.nonce) + ", seq=" + sim.sequenceNumber + ")";
            layer2(injected, ctx, Layer2.DEFAULT_LEDGER);   // first submission records the fingerprint
        } else {
            injected = Layer2.injectAttack(session, type, intensity, targetBasis, seed);
            meta = injected.attackMetadata;
        }
        Layer2.Assessment a = layer2(injected, ctx, Layer2.DEFAULT_LEDGER);
        persist(injected, a, type);
        return Json.obj("attack_metadata", meta.toMap(), "injected_session", injected.toMap(), "assessment", a.map);
    }

    private static String py(String s) { return s == null ? "None" : s; }

    private static Map<String, Object> exampleClean() {
        EXAMPLE_LEDGER.clear();
        Protocol.Session s = Protocol.runSession("AUTHENTICATED_TRANSACTION_PAYLOAD_CLEAN", "alice", "bob", 16, 42L,
                "PHI_PLUS", null, "example-clean-001", "nonce-clean-42", 1, null);
        Layer2.Assessment a = Layer2.assess(s, new Layer2.Config(), EXAMPLE_LEDGER, null, null, null);
        persist(s, a, null);
        return Json.obj("session", s.toMap(), "assessment", a.map);
    }

    private static Map<String, Object> exampleReplay() {
        EXAMPLE_LEDGER.clear();
        Protocol.Session s = Protocol.runSession("AUTHENTICATED_TRANSACTION_REPLAY_TEST", "alice", "bob", 16, 99L,
                "PHI_PLUS", null, "example-replay-001", "nonce-replay-99", 1, null);
        Layer2.Config c = new Layer2.Config();
        Layer2.assess(s, c, EXAMPLE_LEDGER, null, null, null);
        Layer2.Assessment a = Layer2.assess(s, c, EXAMPLE_LEDGER, null, null, null);
        persist(s, a, "REPLAY");
        return Json.obj("session", s.toMap(), "assessment", a.map);
    }

    private static Map<String, Object> exampleForgery() {
        EXAMPLE_LEDGER.clear();
        Protocol.Session s = Protocol.runSession("AUTHENTIC_MESSAGE", "alice", "bob", 16, 77L, "PHI_PLUS", null,
                "example-forgery-001", "nonce-forgery-77", 1, null);
        s.messageDigest = "0".repeat(64);
        s.summary.digestMatches = false;
        s.summary.isPerfect = false;
        Layer2.Assessment a = Layer2.assess(s, new Layer2.Config(), EXAMPLE_LEDGER, null, null, null);
        persist(s, a, "PAYLOAD_DIGEST_MISMATCH");
        return Json.obj("session", s.toMap(), "assessment", a.map);
    }

    // --------------------------------------------------------- persistence

    private static final Map<String, String> FINDING_TO_IMPACT = new TreeMap<>();
    static {
        FINDING_TO_IMPACT.put("CORRECTION_TAMPERING", "The quantum correction instructions were altered. The message integrity cannot be guaranteed.");
        FINDING_TO_IMPACT.put("BELL_INTEGRITY_VIOLATION", "Low entanglement fidelity detected. The quantum channel may have been interfered with.");
        FINDING_TO_IMPACT.put("QBER_ANOMALY", "Error rate exceeded advisory threshold. Possible eavesdropping on the quantum channel.");
        FINDING_TO_IMPACT.put("REPLAY_ATTACK", "This packet fingerprint was already seen. The message is a replay of a captured session.");
        FINDING_TO_IMPACT.put("PAYLOAD_DIGEST_MISMATCH", "The message hash does not match. The payload was modified after signing.");
        FINDING_TO_IMPACT.put("IMPERSONATION", "Sender or recipient identity does not match expected values.");
        FINDING_TO_IMPACT.put("UNAUTHORIZED_VERIFICATION", "An unauthorized party attempted to verify this message.");
        FINDING_TO_IMPACT.put("BOB_THRESHOLD_BREACH", "Direct verification mismatch rate exceeded the accept threshold.");
        FINDING_TO_IMPACT.put("CHARLIE_THRESHOLD_BREACH", "Forwarded verification mismatch rate exceeded the accept threshold.");
        FINDING_TO_IMPACT.put("CONFIGURATION_WARNING", "Security configuration ordering violation detected.");
    }

    /** Stores the assessed session for the dashboard and mirrors it to the audit log. Never fails a request. */
    private static void persist(Protocol.Session s, Layer2.Assessment a, String attackLabel) {
        try {
            boolean direct = a.mode.equals("direct");
            Store.SessionRow row = new Store.SessionRow();
            row.id = s.sessionId;
            row.timestamp = Instant.now().truncatedTo(ChronoUnit.MICROS);
            row.senderId = s.senderId;
            row.recipientId = s.recipientId;
            row.message = s.message;
            row.verificationMode = a.mode;
            row.threatLevel = a.level.toLowerCase();
            row.verdict = a.decision.startsWith("ACCEPT") ? "ACCEPT" : "REJECT";
            row.mismatchRate = (Double) a.bobCharlie.get(direct ? "direct_mismatch_rate" : "forwarded_mismatch_rate");
            row.threshold = direct ? a.sA : a.sV;
            row.confidenceUpperBound = (Double) a.bobCharlie.get(direct ? "direct_confidence_upper_bound" : "forwarded_confidence_upper_bound");
            row.meanFidelity = (Double) a.fidelity.get("average_fidelity");
            row.attackType = attackLabel;
            row.rawAssessment = a.decision;
            Store.DEFAULT.upsertSession(row);

            List<Store.LogRow> logs = new ArrayList<>();
            List<Map<String, Object>> auditLogs = new ArrayList<>();
            for (Protocol.Position p : s.positions) {
                Store.LogRow l = new Store.LogRow();
                l.sessionId = s.sessionId;
                l.positionIndex = p.index;
                l.basis = p.pauliBasis;
                l.bellOutcome = p.bellMeasurementBits == null ? "" : p.bellMeasurementBits;
                l.expectedCorrection = p.expectedCorrection;
                l.actualCorrection = p.actualCorrection;
                l.fidelity = p.fidelity;
                l.match = p.isMatch;
                logs.add(l);
                auditLogs.add(Json.obj("position_index", l.positionIndex, "basis", l.basis,
                        "bell_outcome", l.bellOutcome, "expected_correction", l.expectedCorrection,
                        "actual_correction", l.actualCorrection, "fidelity", l.fidelity, "match", l.match));
            }
            Store.DEFAULT.addLogs(logs);

            for (String finding : a.findings) {
                String rawType = finding.split(" \\[", 2)[0].trim();
                Store.EventRow e = new Store.EventRow();
                e.sessionId = s.sessionId;
                e.threatType = rawType;
                e.severity = finding.contains("CRITICAL") ? "critical" : "suspicious";
                e.observedEvidence = finding;
                e.protocolImpact = FINDING_TO_IMPACT.getOrDefault(rawType, finding);
                e.timestamp = Instant.now().truncatedTo(ChronoUnit.MICROS);
                Store.DEFAULT.addEvent(e);
            }

            mirrorToAudit(row, auditLogs, a);
        } catch (RuntimeException e) {
            System.err.println("persist failed (request unaffected): " + e);
        }
    }

    private static void mirrorToAudit(Store.SessionRow row, List<Map<String, Object>> logs, Layer2.Assessment a) {
        Store.Audit audit = Store.Audit.DEFAULT;
        if (!audit.enabled()) return;
        audit.append("session", row.id, Json.obj(
                "id", row.id, "timestamp", Fmt.isoZ(row.timestamp), "sender_id", row.senderId,
                "recipient_id", row.recipientId, "message", row.message, "verification_mode", row.verificationMode,
                "threat_level", row.threatLevel, "verdict", row.verdict, "mismatch_rate", row.mismatchRate,
                "threshold", row.threshold, "confidence_upper_bound", row.confidenceUpperBound,
                "mean_fidelity", row.meanFidelity, "attack_type", row.attackType,
                "raw_assessment_string", row.rawAssessment));
        audit.appendMany("telemetry", row.id, logs);
        List<Map<String, Object>> findings = new ArrayList<>();
        for (String f : a.findings) findings.add(Json.obj("finding", f));
        audit.appendMany("finding", row.id, findings);
    }
}
