package qds;

import java.util.List;
import java.util.Map;

/**
 * Typed access to a parsed JSON object with Pydantic-style validation errors.
 * Every failure is a 422 whose detail names the field, e.g. "body.simulation.message: Field required".
 */
final class Req {
    final Map<String, Object> m;
    final String path;

    @SuppressWarnings("unchecked")
    Req(Object o, String path) {
        if (!(o instanceof Map)) throw new HttpError(422, path + ": Input should be a valid dictionary or object");
        this.m = (Map<String, Object>) o;
        this.path = path;
    }

    private HttpError err(String key, String msg) {
        return new HttpError(422, path + "." + key + ": " + msg);
    }

    boolean present(String key) { return m.get(key) != null; }

    Req obj(String key) {
        if (!present(key)) throw err(key, "Field required");
        return new Req(m.get(key), path + "." + key);
    }

    String str(String key) {
        if (!present(key)) throw err(key, "Field required");
        Object v = m.get(key);
        if (!(v instanceof String)) throw err(key, "Input should be a valid string");
        return (String) v;
    }

    String strMin1(String key) {
        String s = str(key);
        if (s.isEmpty()) throw err(key, "String should have at least 1 character");
        return s;
    }

    String strMin1(String key, String dflt) {
        return present(key) ? strMin1(key) : dflt;
    }

    String strOpt(String key) {
        if (!present(key)) return null;
        return str(key);
    }

    long lng(String key) {
        if (!present(key)) throw err(key, "Field required");
        return asLong(key, m.get(key));
    }

    Long lngOpt(String key) {
        return present(key) ? asLong(key, m.get(key)) : null;
    }

    private long asLong(String key, Object v) {
        if (v instanceof Long) return (Long) v;
        if (v instanceof Double && ((Double) v) == Math.rint((Double) v) && !Double.isInfinite((Double) v)) {
            return ((Double) v).longValue();
        }
        if (v instanceof String) {
            try { return Long.parseLong(((String) v).trim()); } catch (NumberFormatException ignored) { /* fall through */ }
        }
        throw err(key, "Input should be a valid integer");
    }

    long lngRange(String key, long dflt, long min, long max) {
        if (!present(key)) return dflt;
        long v = asLong(key, m.get(key));
        if (v < min) throw err(key, "Input should be greater than or equal to " + min);
        if (v > max) throw err(key, "Input should be less than or equal to " + max);
        return v;
    }

    double dbl(String key) {
        if (!present(key)) throw err(key, "Field required");
        return asDouble(key, m.get(key));
    }

    private double asDouble(String key, Object v) {
        if (v instanceof Number) return ((Number) v).doubleValue();
        if (v instanceof String) {
            try { return Double.parseDouble(((String) v).trim()); } catch (NumberFormatException ignored) { /* fall through */ }
        }
        throw err(key, "Input should be a valid number");
    }

    /** Optional double in [min, max]; maxExclusive turns the upper bound into "<". */
    Double dblOpt(String key, double min, double max, boolean maxExclusive) {
        if (!present(key)) return null;
        double v = asDouble(key, m.get(key));
        if (v < min) throw err(key, "Input should be greater than or equal to " + Fmt.pyFloat(min));
        if (maxExclusive ? v >= max : v > max) {
            throw err(key, "Input should be " + (maxExclusive ? "less than " : "less than or equal to ") + Fmt.pyFloat(max));
        }
        return v;
    }

    double dblRange(String key, double dflt, double min, double max) {
        Double v = dblOpt(key, min, max, false);
        return v == null ? dflt : v;
    }

    double dblOr(String key, double dflt) {
        return present(key) ? dbl(key) : dflt;
    }

    boolean bool(String key) {
        if (!present(key)) throw err(key, "Field required");
        Object v = m.get(key);
        if (v instanceof Boolean) return (Boolean) v;
        throw err(key, "Input should be a valid boolean");
    }

    boolean boolOr(String key, boolean dflt) {
        return present(key) ? bool(key) : dflt;
    }

    @SuppressWarnings("unchecked")
    List<Object> list(String key) {
        if (!present(key)) throw err(key, "Field required");
        Object v = m.get(key);
        if (!(v instanceof List)) throw err(key, "Input should be a valid list");
        return (List<Object>) v;
    }

    /** Required string restricted to the given values (case-sensitive, like a Pydantic Enum). */
    String enumStr(String key, String... allowed) {
        String s = str(key);
        return checkEnum(key, s, allowed);
    }

    String enumOr(String key, String dflt, String... allowed) {
        return present(key) ? enumStr(key, allowed) : dflt;
    }

    String checkEnum(String key, String s, String... allowed) {
        for (String a : allowed) if (a.equals(s)) return s;
        throw err(key, "Input should be " + String.join(", ", allowed));
    }

    /** Required map-of-int field (e.g. basis_distribution). */
    Map<String, Object> map(String key) {
        if (!present(key)) throw err(key, "Field required");
        if (!(m.get(key) instanceof Map)) throw err(key, "Input should be a valid dictionary");
        @SuppressWarnings("unchecked")
        Map<String, Object> out = (Map<String, Object>) m.get(key);
        return out;
    }

    Req item(List<Object> list, String key, int i) {
        return new Req(list.get(i), path + "." + key + "[" + i + "]");
    }
}
