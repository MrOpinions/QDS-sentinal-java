package qds;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Primary store (what the dashboard reads): sessions, telemetry logs and threat events,
 * held in memory and appended to a JSON-lines file so they survive a restart.
 * Replaces the SQLAlchemy/SQLite layer, since the JDK ships no embedded database.
 */
final class Store {
    static final class SessionRow {
        String id, senderId, recipientId, message, verificationMode, threatLevel, verdict, attackType, rawAssessment;
        Instant timestamp;
        double mismatchRate, threshold, confidenceUpperBound, meanFidelity;
    }

    static final class LogRow {
        long id;
        String sessionId, basis, bellOutcome, expectedCorrection, actualCorrection;
        int positionIndex;
        double fidelity;
        boolean match;
    }

    static final class EventRow {
        long id;
        String sessionId, threatType, severity, observedEvidence, protocolImpact;
        Instant timestamp;
    }

    private final List<SessionRow> sessions = new ArrayList<>();
    private final Map<String, SessionRow> sessionById = new HashMap<>();
    private final List<LogRow> logs = new ArrayList<>();
    private final List<EventRow> events = new ArrayList<>();
    private final Path file;

    Store(String path) {
        this.file = (path == null || path.equals("memory")) ? null : Paths.get(path);
        if (file != null && Files.exists(file)) load();
    }

    static final Store DEFAULT = new Store(env("QDS_DB_PATH", "qds_sentinel.jsonl.db"));

    static String env(String name, String dflt) {
        String v = System.getenv(name);
        return v == null || v.isEmpty() ? dflt : v;
    }

    // ------------------------------------------------------------- writes

    synchronized void upsertSession(SessionRow r) {
        SessionRow old = sessionById.get(r.id);
        if (old == null) {
            sessions.add(r);
        } else {
            sessions.set(sessions.indexOf(old), r);
        }
        sessionById.put(r.id, r);
        append(Json.obj("t", "session", "id", r.id, "ts", r.timestamp.toString(), "sender", r.senderId,
                "recipient", r.recipientId, "message", r.message, "mode", r.verificationMode,
                "level", r.threatLevel, "verdict", r.verdict, "mismatch", r.mismatchRate,
                "threshold", r.threshold, "upper", r.confidenceUpperBound, "fidelity", r.meanFidelity,
                "attack", r.attackType, "raw", r.rawAssessment));
    }

    synchronized void addLogs(List<LogRow> rows) {
        for (LogRow r : rows) {
            r.id = logs.size() + 1;
            logs.add(r);
            append(Json.obj("t", "log", "sid", r.sessionId, "pos", r.positionIndex, "basis", r.basis,
                    "bell", r.bellOutcome, "exp", r.expectedCorrection, "act", r.actualCorrection,
                    "fid", r.fidelity, "match", r.match));
        }
    }

    synchronized void addEvent(EventRow r) {
        r.id = events.size() + 1;
        events.add(r);
        append(Json.obj("t", "event", "sid", r.sessionId, "type", r.threatType, "sev", r.severity,
                "evidence", r.observedEvidence, "impact", r.protocolImpact, "ts", r.timestamp.toString()));
    }

    // -------------------------------------------------------------- reads

    synchronized SessionRow getSession(String id) { return sessionById.get(id); }

    /** Newest first. A negative limit means no limit, as in SQL. */
    synchronized List<SessionRow> listSessions(int limit) {
        List<SessionRow> out = new ArrayList<>(sessions);
        Collections.reverse(out);
        out.sort(Comparator.comparing((SessionRow s) -> s.timestamp).reversed());
        return cap(out, limit);
    }

    synchronized List<SessionRow> sessionsSince(Instant since) {
        List<SessionRow> out = new ArrayList<>();
        for (SessionRow s : listSessions(-1)) if (!s.timestamp.isBefore(since)) out.add(s);
        return out;
    }

    synchronized List<EventRow> listEvents(int limit) {
        List<EventRow> out = new ArrayList<>(events);
        Collections.reverse(out);
        out.sort(Comparator.comparing((EventRow e) -> e.timestamp).reversed());
        return cap(out, limit);
    }

    synchronized Map<String, Integer> countEvents(Instant since, boolean bySeverity) {
        Map<String, Integer> out = new java.util.TreeMap<>();
        for (EventRow e : events) {
            if (e.timestamp.isBefore(since)) continue;
            out.merge(bySeverity ? e.severity : e.threatType, 1, Integer::sum);
        }
        return out;
    }

    synchronized List<LogRow> logsForSession(String sessionId) {
        List<LogRow> out = new ArrayList<>();
        for (LogRow l : logs) if (l.sessionId.equals(sessionId)) out.add(l);
        out.sort(Comparator.comparingInt((LogRow l) -> l.positionIndex));
        return out;
    }

    synchronized List<LogRow> recentLogs(int limit) {
        List<LogRow> out = new ArrayList<>(logs);
        Collections.reverse(out);
        return cap(out, limit);
    }

    private static <T> List<T> cap(List<T> l, int limit) {
        return limit < 0 || limit >= l.size() ? l : new ArrayList<>(l.subList(0, limit));
    }

    // -------------------------------------------------------- persistence

    private void append(Map<String, Object> line) {
        if (file == null) return;
        try {
            Files.write(file, (Json.write(line) + "\n").getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("store: could not write " + file + ": " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void load() {
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.trim().isEmpty()) continue;
                Req r = new Req(Json.parse(line), "row");
                switch (r.str("t")) {
                    case "session": {
                        SessionRow s = new SessionRow();
                        s.id = r.str("id");
                        s.timestamp = Instant.parse(r.str("ts"));
                        s.senderId = r.str("sender"); s.recipientId = r.str("recipient"); s.message = r.str("message");
                        s.verificationMode = r.str("mode"); s.threatLevel = r.str("level"); s.verdict = r.str("verdict");
                        s.mismatchRate = r.dbl("mismatch"); s.threshold = r.dbl("threshold");
                        s.confidenceUpperBound = r.dbl("upper"); s.meanFidelity = r.dbl("fidelity");
                        s.attackType = r.strOpt("attack"); s.rawAssessment = r.str("raw");
                        SessionRow old = sessionById.get(s.id);
                        if (old == null) sessions.add(s); else sessions.set(sessions.indexOf(old), s);
                        sessionById.put(s.id, s);
                        break;
                    }
                    case "log": {
                        LogRow l = new LogRow();
                        l.id = logs.size() + 1;
                        l.sessionId = r.str("sid"); l.positionIndex = (int) r.lng("pos"); l.basis = r.str("basis");
                        l.bellOutcome = r.str("bell"); l.expectedCorrection = r.str("exp");
                        l.actualCorrection = r.str("act"); l.fidelity = r.dbl("fid"); l.match = r.bool("match");
                        logs.add(l);
                        break;
                    }
                    case "event": {
                        EventRow e = new EventRow();
                        e.id = events.size() + 1;
                        e.sessionId = r.str("sid"); e.threatType = r.str("type"); e.severity = r.str("sev");
                        e.observedEvidence = r.str("evidence"); e.protocolImpact = r.str("impact");
                        e.timestamp = Instant.parse(r.str("ts"));
                        events.add(e);
                        break;
                    }
                    default:
                        break;
                }
            }
        } catch (IOException | RuntimeException e) {
            System.err.println("store: could not fully load " + file + ": " + e.getMessage());
        }
    }

    // ===================================================================== audit

    /**
     * Tamper-evident audit sink: an append-only JSON-lines file where every record stores the SHA-256
     * of its own canonical content chained to the previous record's hash. Sensitive fields are
     * additionally AES-GCM encrypted. Disabled (every call a no-op) unless AUDIT_LOG_PATH is set.
     */
    static final class Audit {
        static final String[] ENCRYPTED_FIELDS = {"message", "sender_id", "recipient_id", "raw_assessment_string"};
        static final String GENESIS = "0".repeat(64);

        private final Path path;
        private final SecretKeySpec key;
        private final SecureRandom random = new SecureRandom();
        private String lastHash = GENESIS;
        private long nextSeq = 0;

        Audit(String path, String passphrase) {
            this.path = path == null ? null : Paths.get(path);
            this.key = passphrase == null ? null : new SecretKeySpec(Fmt.sha256(passphrase.getBytes(StandardCharsets.UTF_8)), "AES");
            if (this.path != null && Files.exists(this.path)) {
                try {
                    for (String line : Files.readAllLines(this.path, StandardCharsets.UTF_8)) {
                        if (line.trim().isEmpty()) continue;
                        Req r = new Req(Json.parse(line), "audit");
                        lastHash = r.str("hash");
                        nextSeq = r.lng("seq") + 1;
                    }
                } catch (IOException | RuntimeException e) {
                    System.err.println("audit: could not read " + path + ": " + e.getMessage());
                }
            }
        }

        static final Audit DEFAULT = new Audit(System.getenv("AUDIT_LOG_PATH"), System.getenv("AUDIT_ENCRYPTION_KEY"));

        boolean enabled() { return path != null; }

        static String chainHash(Map<String, Object> core, String prev) {
            return Fmt.sha256Hex(prev + Json.canonical(core));
        }

        private String encrypt(String v) {
            if (key == null) return v;
            try {
                byte[] iv = new byte[12];
                random.nextBytes(iv);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
                byte[] ct = c.doFinal(v.getBytes(StandardCharsets.UTF_8));
                byte[] all = new byte[iv.length + ct.length];
                System.arraycopy(iv, 0, all, 0, iv.length);
                System.arraycopy(ct, 0, all, iv.length, ct.length);
                return Base64.getEncoder().encodeToString(all);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private String decrypt(String v) {
            if (key == null) return v;
            try {
                byte[] all = Base64.getDecoder().decode(v);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, all, 0, 12));
                return new String(c.doFinal(all, 12, all.length - 12), StandardCharsets.UTF_8);
            } catch (Exception e) {
                return "<undecryptable>";
            }
        }

        synchronized String append(String kind, String sessionId, Map<String, Object> body) {
            if (!enabled()) return null;
            Map<String, Object> stored = new LinkedHashMap<>(body);
            List<Object> encrypted = new ArrayList<>();
            for (String f : ENCRYPTED_FIELDS) {
                if (stored.get(f) != null) {
                    stored.put(f, encrypt(String.valueOf(stored.get(f))));
                    encrypted.add(f);
                }
            }
            Map<String, Object> core = Json.obj("seq", nextSeq, "kind", kind, "session_id", sessionId, "body", stored);
            String hash = chainHash(core, lastHash);
            Map<String, Object> rec = new LinkedHashMap<>(core);
            rec.put("recorded_at", Fmt.isoNow());
            rec.put("encrypted_fields", key == null ? new ArrayList<>() : encrypted);
            rec.put("prev_hash", lastHash);
            rec.put("hash", hash);
            try {
                Files.write(path, (Json.write(rec) + "\n").getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            lastHash = hash;
            nextSeq++;
            return hash;
        }

        int appendMany(String kind, String sessionId, List<Map<String, Object>> bodies) {
            if (!enabled()) return 0;
            for (Map<String, Object> b : bodies) append(kind, sessionId, b);
            return bodies.size();
        }

        /** Records of one session with their sensitive fields decrypted. */
        synchronized List<Map<String, Object>> read(String sessionId) {
            List<Map<String, Object>> out = new ArrayList<>();
            if (!enabled() || !Files.exists(path)) return out;
            try {
                for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                    if (line.trim().isEmpty()) continue;
                    Req r = new Req(Json.parse(line), "audit");
                    if (!r.str("session_id").equals(sessionId)) continue;
                    Map<String, Object> body = new LinkedHashMap<>(r.map("body"));
                    for (Object f : r.list("encrypted_fields")) body.put((String) f, decrypt((String) body.get(f)));
                    out.add(Json.obj("seq", r.lng("seq"), "kind", r.str("kind"), "hash", r.str("hash"), "body", body));
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return out;
        }

        /** Walks the whole log and reports the first break, if any. */
        synchronized Map<String, Object> verifyChain() {
            if (!enabled()) return Json.obj("enabled", false, "intact", true, "records", 0, "broken_at", null);
            String prev = GENESIS;
            long count = 0;
            if (Files.exists(path)) {
                try {
                    for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                        if (line.trim().isEmpty()) continue;
                        Req r = new Req(Json.parse(line), "audit");
                        Map<String, Object> core = Json.obj("seq", r.lng("seq"), "kind", r.str("kind"),
                                "session_id", r.str("session_id"), "body", r.map("body"));
                        if (!prev.equals(r.str("prev_hash")) || !chainHash(core, prev).equals(r.str("hash"))) {
                            return Json.obj("enabled", true, "intact", false, "records", count, "broken_at", r.lng("seq"));
                        }
                        prev = r.str("hash");
                        count++;
                    }
                } catch (IOException | RuntimeException e) {
                    return Json.obj("enabled", true, "intact", false, "records", count, "broken_at", count);
                }
            }
            return Json.obj("enabled", true, "intact", true, "records", count, "broken_at", null);
        }
    }
}
