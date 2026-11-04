package qds;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * MySQL-backed primary store, used when MYSQL_URL is set. Same tables as the original SQLAlchemy
 * schema: sessions, telemetry_logs and threat_events. Needs the MySQL Connector/J jar on the
 * classpath at run time; compiling needs nothing beyond the JDK (java.sql).
 */
final class JdbcStore extends Store {
    private final String url, user, password;
    private Connection conn;

    JdbcStore(String url, String user, String password) {
        super("memory");
        this.url = url;
        this.user = user;
        this.password = password;
        try (Statement st = connection().createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS sessions ("
                    + "id VARCHAR(255) PRIMARY KEY, `timestamp` DATETIME(6) NOT NULL, "
                    + "sender_id VARCHAR(255) NOT NULL, recipient_id VARCHAR(255) NOT NULL, message TEXT NOT NULL, "
                    + "verification_mode VARCHAR(16) NOT NULL, threat_level VARCHAR(16) NOT NULL, "
                    + "verdict VARCHAR(16) NOT NULL, mismatch_rate DOUBLE NOT NULL, threshold DOUBLE NOT NULL, "
                    + "confidence_upper_bound DOUBLE NOT NULL, mean_fidelity DOUBLE NOT NULL, "
                    + "attack_type VARCHAR(64) NULL, raw_assessment_string TEXT NOT NULL, "
                    + "INDEX idx_sessions_ts (`timestamp`))");
            st.execute("CREATE TABLE IF NOT EXISTS telemetry_logs ("
                    + "id BIGINT AUTO_INCREMENT PRIMARY KEY, session_id VARCHAR(255) NOT NULL, "
                    + "position_index INT NOT NULL, basis VARCHAR(8) NOT NULL, bell_outcome VARCHAR(8) NOT NULL, "
                    + "expected_correction VARCHAR(8) NOT NULL, actual_correction VARCHAR(8) NOT NULL, "
                    + "fidelity DOUBLE NOT NULL, is_match BOOLEAN NOT NULL, INDEX idx_logs_session (session_id), "
                    + "FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE)");
            st.execute("CREATE TABLE IF NOT EXISTS threat_events ("
                    + "id BIGINT AUTO_INCREMENT PRIMARY KEY, session_id VARCHAR(255) NOT NULL, "
                    + "threat_type VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL, "
                    + "observed_evidence TEXT NOT NULL, protocol_impact TEXT NOT NULL, "
                    + "`timestamp` DATETIME(6) NOT NULL, INDEX idx_events_ts (`timestamp`), "
                    + "FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE)");
        } catch (SQLException e) {
            throw new IllegalStateException("MySQL setup failed: " + e.getMessage(), e);
        }
    }

    /** Re-opens the connection if the server dropped it (MySQL closes idle connections). */
    private Connection connection() throws SQLException {
        if (conn == null || !conn.isValid(2)) conn = DriverManager.getConnection(url, user, password);
        return conn;
    }

    private static LocalDateTime utc(Instant t) { return LocalDateTime.ofInstant(t, ZoneOffset.UTC); }

    private static Instant instant(ResultSet rs, String col) throws SQLException {
        return rs.getObject(col, LocalDateTime.class).toInstant(ZoneOffset.UTC);
    }

    private static IllegalStateException fail(SQLException e) {
        return new IllegalStateException("MySQL error: " + e.getMessage(), e);
    }

    // ------------------------------------------------------------- writes

    @Override
    synchronized void upsertSession(SessionRow r) {
        String sql = "INSERT INTO sessions (id, `timestamp`, sender_id, recipient_id, message, verification_mode, "
                + "threat_level, verdict, mismatch_rate, threshold, confidence_upper_bound, mean_fidelity, "
                + "attack_type, raw_assessment_string) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                + "ON DUPLICATE KEY UPDATE `timestamp`=VALUES(`timestamp`), sender_id=VALUES(sender_id), "
                + "recipient_id=VALUES(recipient_id), message=VALUES(message), "
                + "verification_mode=VALUES(verification_mode), threat_level=VALUES(threat_level), "
                + "verdict=VALUES(verdict), mismatch_rate=VALUES(mismatch_rate), threshold=VALUES(threshold), "
                + "confidence_upper_bound=VALUES(confidence_upper_bound), mean_fidelity=VALUES(mean_fidelity), "
                + "attack_type=VALUES(attack_type), raw_assessment_string=VALUES(raw_assessment_string)";
        try (PreparedStatement ps = connection().prepareStatement(sql)) {
            ps.setString(1, r.id);
            ps.setObject(2, utc(r.timestamp));
            ps.setString(3, r.senderId);
            ps.setString(4, r.recipientId);
            ps.setString(5, r.message);
            ps.setString(6, r.verificationMode);
            ps.setString(7, r.threatLevel);
            ps.setString(8, r.verdict);
            ps.setDouble(9, r.mismatchRate);
            ps.setDouble(10, r.threshold);
            ps.setDouble(11, r.confidenceUpperBound);
            ps.setDouble(12, r.meanFidelity);
            ps.setString(13, r.attackType);
            ps.setString(14, r.rawAssessment);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail(e);
        }
    }

    @Override
    synchronized void addLogs(List<LogRow> rows) {
        String sql = "INSERT INTO telemetry_logs (session_id, position_index, basis, bell_outcome, "
                + "expected_correction, actual_correction, fidelity, is_match) VALUES (?,?,?,?,?,?,?,?)";
        try (PreparedStatement ps = connection().prepareStatement(sql)) {
            for (LogRow r : rows) {
                ps.setString(1, r.sessionId);
                ps.setInt(2, r.positionIndex);
                ps.setString(3, r.basis);
                ps.setString(4, r.bellOutcome);
                ps.setString(5, r.expectedCorrection);
                ps.setString(6, r.actualCorrection);
                ps.setDouble(7, r.fidelity);
                ps.setBoolean(8, r.match);
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (SQLException e) {
            throw fail(e);
        }
    }

    @Override
    synchronized void addEvent(EventRow r) {
        String sql = "INSERT INTO threat_events (session_id, threat_type, severity, observed_evidence, "
                + "protocol_impact, `timestamp`) VALUES (?,?,?,?,?,?)";
        try (PreparedStatement ps = connection().prepareStatement(sql)) {
            ps.setString(1, r.sessionId);
            ps.setString(2, r.threatType);
            ps.setString(3, r.severity);
            ps.setString(4, r.observedEvidence);
            ps.setString(5, r.protocolImpact);
            ps.setObject(6, utc(r.timestamp));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw fail(e);
        }
    }

    // -------------------------------------------------------------- reads

    private static final String SESSION_COLS = "id, `timestamp`, sender_id, recipient_id, message, "
            + "verification_mode, threat_level, verdict, mismatch_rate, threshold, confidence_upper_bound, "
            + "mean_fidelity, attack_type, raw_assessment_string";

    private static SessionRow session(ResultSet rs) throws SQLException {
        SessionRow s = new SessionRow();
        s.id = rs.getString("id");
        s.timestamp = instant(rs, "timestamp");
        s.senderId = rs.getString("sender_id");
        s.recipientId = rs.getString("recipient_id");
        s.message = rs.getString("message");
        s.verificationMode = rs.getString("verification_mode");
        s.threatLevel = rs.getString("threat_level");
        s.verdict = rs.getString("verdict");
        s.mismatchRate = rs.getDouble("mismatch_rate");
        s.threshold = rs.getDouble("threshold");
        s.confidenceUpperBound = rs.getDouble("confidence_upper_bound");
        s.meanFidelity = rs.getDouble("mean_fidelity");
        s.attackType = rs.getString("attack_type");
        s.rawAssessment = rs.getString("raw_assessment_string");
        return s;
    }

    private static String limitClause(int limit) { return limit < 0 ? "" : " LIMIT " + limit; }

    @Override
    synchronized SessionRow getSession(String id) {
        try (PreparedStatement ps = connection().prepareStatement("SELECT " + SESSION_COLS + " FROM sessions WHERE id=?")) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? session(rs) : null;
            }
        } catch (SQLException e) {
            throw fail(e);
        }
    }

    @Override
    synchronized List<SessionRow> listSessions(int limit) {
        List<SessionRow> out = new ArrayList<>();
        try (Statement st = connection().createStatement();
             ResultSet rs = st.executeQuery("SELECT " + SESSION_COLS + " FROM sessions ORDER BY `timestamp` DESC"
                     + limitClause(limit))) {
            while (rs.next()) out.add(session(rs));
        } catch (SQLException e) {
            throw fail(e);
        }
        return out;
    }

    @Override
    synchronized List<SessionRow> sessionsSince(Instant since) {
        List<SessionRow> out = new ArrayList<>();
        try (PreparedStatement ps = connection().prepareStatement("SELECT " + SESSION_COLS
                + " FROM sessions WHERE `timestamp` >= ? ORDER BY `timestamp` DESC")) {
            ps.setObject(1, utc(since));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(session(rs));
            }
        } catch (SQLException e) {
            throw fail(e);
        }
        return out;
    }

    @Override
    synchronized List<EventRow> listEvents(int limit) {
        List<EventRow> out = new ArrayList<>();
        try (Statement st = connection().createStatement();
             ResultSet rs = st.executeQuery("SELECT id, session_id, threat_type, severity, observed_evidence, "
                     + "protocol_impact, `timestamp` FROM threat_events ORDER BY `timestamp` DESC, id DESC"
                     + limitClause(limit))) {
            while (rs.next()) {
                EventRow e = new EventRow();
                e.id = rs.getLong("id");
                e.sessionId = rs.getString("session_id");
                e.threatType = rs.getString("threat_type");
                e.severity = rs.getString("severity");
                e.observedEvidence = rs.getString("observed_evidence");
                e.protocolImpact = rs.getString("protocol_impact");
                e.timestamp = instant(rs, "timestamp");
                out.add(e);
            }
        } catch (SQLException e) {
            throw fail(e);
        }
        return out;
    }

    @Override
    synchronized Map<String, Integer> countEvents(Instant since, boolean bySeverity) {
        String col = bySeverity ? "severity" : "threat_type";
        Map<String, Integer> out = new TreeMap<>();
        try (PreparedStatement ps = connection().prepareStatement("SELECT " + col
                + ", COUNT(*) AS n FROM threat_events WHERE `timestamp` >= ? GROUP BY " + col)) {
            ps.setObject(1, utc(since));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.put(rs.getString(1), rs.getInt("n"));
            }
        } catch (SQLException e) {
            throw fail(e);
        }
        return out;
    }

    private static LogRow log(ResultSet rs) throws SQLException {
        LogRow l = new LogRow();
        l.id = rs.getLong("id");
        l.sessionId = rs.getString("session_id");
        l.positionIndex = rs.getInt("position_index");
        l.basis = rs.getString("basis");
        l.bellOutcome = rs.getString("bell_outcome");
        l.expectedCorrection = rs.getString("expected_correction");
        l.actualCorrection = rs.getString("actual_correction");
        l.fidelity = rs.getDouble("fidelity");
        l.match = rs.getBoolean("is_match");
        return l;
    }

    @Override
    synchronized List<LogRow> logsForSession(String sessionId) {
        List<LogRow> out = new ArrayList<>();
        try (PreparedStatement ps = connection().prepareStatement(
                "SELECT * FROM telemetry_logs WHERE session_id=? ORDER BY position_index, id")) {
            ps.setString(1, sessionId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(log(rs));
            }
        } catch (SQLException e) {
            throw fail(e);
        }
        return out;
    }

    @Override
    synchronized List<LogRow> recentLogs(int limit) {
        List<LogRow> out = new ArrayList<>();
        try (Statement st = connection().createStatement();
             ResultSet rs = st.executeQuery("SELECT * FROM telemetry_logs ORDER BY id DESC" + limitClause(limit))) {
            while (rs.next()) out.add(log(rs));
        } catch (SQLException e) {
            throw fail(e);
        }
        return out;
    }
}
