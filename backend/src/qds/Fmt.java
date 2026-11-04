package qds;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/** Small formatting and hashing helpers shared across the backend. */
final class Fmt {
    private Fmt() {}

    private static final DateTimeFormatter MICROS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter HOUR =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH':00'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    /** Like Python f"{x:.{digits}f}": exact binary value, round half to even. */
    static String fixed(double x, int digits) {
        return new BigDecimal(x).setScale(digits, RoundingMode.HALF_EVEN).toPlainString();
    }

    /** Like Python str(float) for ordinary magnitudes: 0.1 -> "0.1", 1 -> "1.0". */
    static String pyFloat(double d) {
        String s = new BigDecimal(Double.toString(d)).toPlainString();
        return s.indexOf('.') < 0 ? s + ".0" : s;
    }

    /** now(UTC).isoformat(), e.g. 2026-11-04T12:00:00.123456+00:00 */
    static String isoNow() {
        return MICROS.format(Instant.now().truncatedTo(ChronoUnit.MICROS)) + "+00:00";
    }

    /** Naive-UTC isoformat plus "Z", as the operations endpoints emit it. */
    static String isoZ(Instant t) {
        return MICROS.format(t) + "Z";
    }

    static String hourKey(Instant t) { return HOUR.format(t); }

    static String dayKey(Instant t) { return DAY.format(t); }

    static String sha256Hex(String s) {
        return hex(sha256(s.getBytes(StandardCharsets.UTF_8)));
    }

    static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
