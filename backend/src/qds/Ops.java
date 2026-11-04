package qds;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Operations-mode endpoints: the stored sessions and threat events, summarised for non-specialists. */
final class Ops {
    private Ops() {}

    static final Map<String, String> LABELS = new LinkedHashMap<>();
    static final Map<String, String> IMPACT = new LinkedHashMap<>();
    static {
        LABELS.put("CORRECTION_TAMPERING", "Message tampered in transit");
        LABELS.put("BELL_INTEGRITY_VIOLATION", "Quantum channel interference detected");
        LABELS.put("QBER_ANOMALY", "Unusually high error rate observed");
        LABELS.put("REPLAY_ATTACK", "Previously seen message re-submitted");
        LABELS.put("PAYLOAD_DIGEST_MISMATCH", "Message contents altered after signing");
        LABELS.put("IMPERSONATION", "Sender or recipient identity mismatch");
        LABELS.put("UNAUTHORIZED_VERIFICATION", "Unauthorized party attempted to verify");
        LABELS.put("BOB_THRESHOLD_BREACH", "Error rate exceeded acceptance limit");
        LABELS.put("CHARLIE_THRESHOLD_BREACH", "Forwarded error rate exceeded limit");
        LABELS.put("CONFIGURATION_WARNING", "Security configuration problem detected");

        IMPACT.put("CORRECTION_TAMPERING", "The message cannot be trusted. A third party likely intercepted and modified the quantum correction instructions.");
        IMPACT.put("BELL_INTEGRITY_VIOLATION", "The quantum entanglement used to secure this message showed signs of interference. The channel may be monitored.");
        IMPACT.put("QBER_ANOMALY", "More errors than expected were found in the transmission. This can indicate eavesdropping.");
        IMPACT.put("REPLAY_ATTACK", "This exact message was already received before. Someone is trying to re-use a captured packet.");
        IMPACT.put("PAYLOAD_DIGEST_MISMATCH", "The message was changed after it was signed. It no longer matches the original.");
        IMPACT.put("IMPERSONATION", "The claimed sender or recipient does not match who sent this message.");
        IMPACT.put("UNAUTHORIZED_VERIFICATION", "Someone who was not the intended recipient tried to read this message.");
        IMPACT.put("BOB_THRESHOLD_BREACH", "The direct verification check failed. The message is rejected.");
        IMPACT.put("CHARLIE_THRESHOLD_BREACH", "The forwarded verification check failed. The message is rejected.");
        IMPACT.put("CONFIGURATION_WARNING", "The security settings are misconfigured. Verification cannot be trusted until fixed.");
    }

    private static Instant ago(long amount, ChronoUnit unit) { return Instant.now().minus(amount, unit); }

    private static Map<String, Object> plainEvent(Store.EventRow e, Store.SessionRow s) {
        String label = LABELS.getOrDefault(e.threatType, e.threatType);
        String impact = IMPACT.getOrDefault(e.threatType, e.observedEvidence);
        String sender = s != null ? s.senderId : "unknown";
        String recipient = s != null ? s.recipientId : "unknown";
        String preview = "";
        if (s != null && s.message != null && !s.message.isEmpty()) {
            preview = s.message.length() > 40 ? s.message.substring(0, 40) + "..." : s.message;
        }
        return Json.obj(
                "id", e.id, "timestamp", Fmt.isoZ(e.timestamp), "severity", e.severity,
                "threat_type", e.threatType, "headline", label,
                "sentence", "A message from " + sender + " to " + recipient + " was flagged: " + label.toLowerCase() + ".",
                "detail", impact, "message_preview", preview, "sender", sender, "recipient", recipient);
    }

    static Map<String, Object> overview() {
        Store db = Store.DEFAULT;
        Instant since = ago(24, ChronoUnit.HOURS);
        Map<String, Integer> counts = db.countEvents(since, true);
        int critical = counts.getOrDefault("critical", 0), suspicious = counts.getOrDefault("suspicious", 0);

        String status = "clean", lastAt = null, lastVerdict = null;
        List<Store.SessionRow> recent = db.listSessions(1);
        if (!recent.isEmpty()) {
            Store.SessionRow latest = recent.get(0);
            status = latest.threatLevel;
            lastAt = Fmt.isoZ(latest.timestamp);
            lastVerdict = latest.verdict;
        }
        List<Store.SessionRow> today = db.sessionsSince(since);
        int rejected = 0;
        for (Store.SessionRow s : today) if (s.verdict.equals("REJECT")) rejected++;

        return Json.obj(
                "current_status", status, "last_assessed_at", lastAt, "last_verdict", lastVerdict,
                "threat_counts_24h", Json.obj("critical", critical, "suspicious", suspicious,
                        "total_threats", critical + suspicious),
                "sessions_24h", Json.obj("total", today.size(), "rejected", rejected, "accepted", today.size() - rejected));
    }

    static Map<String, Object> threatFeed(int limit) {
        List<Object> out = new ArrayList<>();
        for (Store.EventRow e : Store.DEFAULT.listEvents(limit)) {
            out.add(plainEvent(e, Store.DEFAULT.getSession(e.sessionId)));
        }
        return Json.obj("events", out, "total", out.size());
    }

    static Map<String, Object> trends() {
        Store db = Store.DEFAULT;
        Instant since24 = ago(24, ChronoUnit.HOURS), since7d = ago(7, ChronoUnit.DAYS);
        List<Store.SessionRow> hourly = db.sessionsSince(since24);
        boolean useHourly = !hourly.isEmpty();
        List<Store.SessionRow> rows = useHourly ? hourly : db.sessionsSince(since7d);

        Map<String, Map<String, Object>> buckets = new java.util.TreeMap<>();
        for (Store.SessionRow s : rows) {
            String key = useHourly ? Fmt.hourKey(s.timestamp) : Fmt.dayKey(s.timestamp);
            Map<String, Object> b = buckets.computeIfAbsent(key,
                    k -> Json.obj("hour", k, "total", 0, "rejected", 0, "accepted", 0));
            bump(b, "total");
            bump(b, s.verdict.equals("REJECT") ? "rejected" : "accepted");
        }

        List<Map.Entry<String, Integer>> entries = new ArrayList<>(db.countEvents(since7d, false).entrySet());
        entries.sort(Comparator.comparingInt((Map.Entry<String, Integer> e) -> e.getValue()).reversed());
        List<Object> breakdown = new ArrayList<>();
        for (Map.Entry<String, Integer> e : entries) {
            breakdown.add(Json.obj("type", LABELS.getOrDefault(e.getKey(), e.getKey()), "raw_type", e.getKey(),
                    "count", e.getValue()));
        }
        return Json.obj("time_series", new ArrayList<Object>(buckets.values()),
                "time_granularity", useHourly ? "hourly" : "daily", "threat_breakdown", breakdown);
    }

    private static void bump(Map<String, Object> m, String key) { m.put(key, (Integer) m.get(key) + 1); }

    static Map<String, Object> sessions(int limit) {
        List<Object> out = new ArrayList<>();
        for (Store.SessionRow s : Store.DEFAULT.listSessions(limit)) {
            out.add(Json.obj(
                    "id", s.id, "timestamp", Fmt.isoZ(s.timestamp), "sender_id", s.senderId,
                    "recipient_id", s.recipientId, "message", s.message, "verification_mode", s.verificationMode,
                    "threat_level", s.threatLevel, "verdict", s.verdict, "mismatch_rate", s.mismatchRate,
                    "threshold", s.threshold, "confidence_upper_bound", s.confidenceUpperBound,
                    "mean_fidelity", s.meanFidelity, "attack_type", s.attackType,
                    "raw_assessment_string", s.rawAssessment));
        }
        return Json.obj("sessions", out, "total", out.size());
    }

    private static Map<String, Object> logMap(Store.LogRow l) {
        return Json.obj("id", l.id, "session_id", l.sessionId, "position_index", l.positionIndex,
                "basis", l.basis, "bell_outcome", l.bellOutcome, "expected_correction", l.expectedCorrection,
                "actual_correction", l.actualCorrection, "fidelity", l.fidelity, "match", l.match);
    }

    static Map<String, Object> sessionLogs(String sessionId) {
        Store.SessionRow s = Store.DEFAULT.getSession(sessionId);
        List<Object> logs = new ArrayList<>();
        for (Store.LogRow l : Store.DEFAULT.logsForSession(sessionId)) logs.add(logMap(l));
        Map<String, Object> info = null;
        if (s != null) {
            info = Json.obj("id", s.id, "timestamp", Fmt.isoZ(s.timestamp), "sender_id", s.senderId,
                    "recipient_id", s.recipientId, "message", s.message, "verification_mode", s.verificationMode,
                    "threat_level", s.threatLevel, "verdict", s.verdict, "attack_type", s.attackType);
        }
        return Json.obj("session", info, "logs", logs, "total", logs.size());
    }

    static Map<String, Object> recentLogs(int limit) {
        List<Object> logs = new ArrayList<>();
        for (Store.LogRow l : Store.DEFAULT.recentLogs(limit)) logs.add(logMap(l));
        return Json.obj("logs", logs, "total", logs.size());
    }
}
