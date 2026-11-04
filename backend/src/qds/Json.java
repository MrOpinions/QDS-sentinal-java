package qds;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal JSON reader/writer (the JDK ships none).
 * Objects are Map, arrays are List, numbers are Long or Double, plus String/Boolean/null.
 */
final class Json {
    private Json() {}

    static final class ParseException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        ParseException(String m) { super(m); }
    }

    // ---------------------------------------------------------------- parse

    static Object parse(String text) {
        Parser p = new Parser(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != text.length()) throw new ParseException("Unexpected trailing data at " + p.i);
        return v;
    }

    private static final class Parser {
        final String s;
        int i;

        Parser(String s) { this.s = s; }

        void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        Object value() {
            if (i >= s.length()) throw new ParseException("Unexpected end of JSON");
            char c = s.charAt(i);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': return literal("true", Boolean.TRUE);
                case 'f': return literal("false", Boolean.FALSE);
                case 'n': return literal("null", null);
                default: return number();
            }
        }

        Object literal(String word, Object v) {
            if (!s.startsWith(word, i)) throw new ParseException("Invalid literal at " + i);
            i += word.length();
            return v;
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (peek() == '}') { i++; return m; }
            while (true) {
                ws();
                if (peek() != '"') throw new ParseException("Expected string key at " + i);
                String k = string();
                ws();
                if (peek() != ':') throw new ParseException("Expected ':' at " + i);
                i++;
                ws();
                m.put(k, value());
                ws();
                char c = peek();
                i++;
                if (c == '}') return m;
                if (c != ',') throw new ParseException("Expected ',' or '}' at " + (i - 1));
            }
        }

        List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++;
            ws();
            if (peek() == ']') { i++; return l; }
            while (true) {
                ws();
                l.add(value());
                ws();
                char c = peek();
                i++;
                if (c == ']') return l;
                if (c != ',') throw new ParseException("Expected ',' or ']' at " + (i - 1));
            }
        }

        char peek() {
            if (i >= s.length()) throw new ParseException("Unexpected end of JSON");
            return s.charAt(i);
        }

        String string() {
            StringBuilder b = new StringBuilder();
            i++;
            while (true) {
                if (i >= s.length()) throw new ParseException("Unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c != '\\') { b.append(c); continue; }
                char e = s.charAt(i++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default: throw new ParseException("Bad escape \\" + e);
                }
            }
        }

        Object number() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            String t = s.substring(start, i);
            if (t.isEmpty()) throw new ParseException("Unexpected character '" + s.charAt(start) + "' at " + start);
            try {
                if (t.indexOf('.') < 0 && t.indexOf('e') < 0 && t.indexOf('E') < 0) {
                    try { return Long.parseLong(t); } catch (NumberFormatException big) { return Double.parseDouble(t); }
                }
                return Double.parseDouble(t);
            } catch (NumberFormatException ex) {
                throw new ParseException("Bad number '" + t + "'");
            }
        }
    }

    // ---------------------------------------------------------------- write

    /** Plain output, insertion order. */
    static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v, false);
        return b.toString();
    }

    /** Sorted keys, no whitespace: the same bytes for the same content (used for audit hashing). */
    static String canonical(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v, true);
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder b, Object v, boolean sorted) {
        if (v == null) { b.append("null"); return; }
        if (v instanceof String) { quote(b, (String) v); return; }
        if (v instanceof Boolean) { b.append(v); return; }
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) b.append("null");
            else b.append(d);
            return;
        }
        if (v instanceof Number) { b.append(v); return; }
        if (v instanceof Map) {
            Map<String, Object> m = sorted ? new TreeMap<>((Map<String, Object>) v) : (Map<String, Object>) v;
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : m.entrySet()) {
                if (!first) b.append(',');
                first = false;
                quote(b, e.getKey());
                b.append(':');
                write(b, e.getValue(), sorted);
            }
            b.append('}');
            return;
        }
        if (v instanceof Iterable) {
            b.append('[');
            boolean first = true;
            for (Object o : (Iterable<Object>) v) {
                if (!first) b.append(',');
                first = false;
                write(b, o, sorted);
            }
            b.append(']');
            return;
        }
        quote(b, v.toString());
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
    }

    /** Ordered map literal: Json.obj("a", 1, "b", 2). */
    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
}
