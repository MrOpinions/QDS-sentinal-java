package qds;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;

/**
 * Layer 1 quantum core: exact complex statevectors, gates, Bell pairs,
 * 3-qubit teleportation, Pauli corrections, Born-rule measurement, noise, Bloch coordinates.
 * Pure JDK; qubit 0 is the most significant bit of a basis index.
 */
final class Quantum {
    private Quantum() {}

    static final double S2 = 1.0 / Math.sqrt(2.0);

    // gate = {r00,i00, r01,i01, r10,i10, r11,i11}
    static final double[] GATE_I = {1, 0, 0, 0, 0, 0, 1, 0};
    static final double[] GATE_X = {0, 0, 1, 0, 1, 0, 0, 0};
    static final double[] GATE_Y = {0, 0, 0, -1, 0, 1, 0, 0};
    static final double[] GATE_Z = {1, 0, 0, 0, 0, 0, -1, 0};
    static final double[] GATE_H = {S2, 0, S2, 0, S2, 0, -S2, 0};

    static double[] gateByName(String name) {
        switch (name.toUpperCase()) {
            case "I": return GATE_I;
            case "X": return GATE_X;
            case "Y": return GATE_Y;
            case "Z": return GATE_Z;
            case "H": return GATE_H;
            default: throw new IllegalArgumentException("Unknown gate name '" + name + "'");
        }
    }

    // ------------------------------------------------------------ state

    static final class State {
        final String name;
        final double[] re;
        final double[] im;
        final int numQubits;

        State(String name, double[] re, double[] im, int numQubits) {
            int dim = 1 << numQubits;
            if (re.length != dim || im.length != dim) {
                throw new IllegalArgumentException("State vector dimension (" + re.length
                        + ",) does not match expected dimension " + dim + " for " + numQubits + " qubits");
            }
            double n = norm(re, im);
            if (Math.abs(n - 1.0) > 1e-5) {
                throw new IllegalArgumentException("State vector is not normalized. Calculated norm is " + n);
            }
            this.name = name;
            this.re = re;
            this.im = im;
            this.numQubits = numQubits;
        }

        /** [[re, im], ...] */
        List<Object> toComplexList() {
            List<Object> out = new ArrayList<>();
            for (int i = 0; i < re.length; i++) out.add(java.util.Arrays.asList((Object) re[i], im[i]));
            return out;
        }
    }

    static double norm(double[] re, double[] im) {
        double s = 0;
        for (int i = 0; i < re.length; i++) s += re[i] * re[i] + im[i] * im[i];
        return Math.sqrt(s);
    }

    static State eigenstate(String basis, int bit) {
        String b = basis.toUpperCase();
        if (!b.equals("X") && !b.equals("Y") && !b.equals("Z")) {
            throw new IllegalArgumentException("Invalid basis '" + basis + "'. Allowed bases are 'X', 'Y', 'Z'");
        }
        if (bit != 0 && bit != 1) throw new IllegalArgumentException("Invalid bit '" + bit + "'. Bit must be 0 or 1");
        switch (b) {
            case "Z":
                return bit == 0 ? new State("|0>", new double[]{1, 0}, new double[]{0, 0}, 1)
                                : new State("|1>", new double[]{0, 1}, new double[]{0, 0}, 1);
            case "X":
                return bit == 0 ? new State("|+>", new double[]{S2, S2}, new double[]{0, 0}, 1)
                                : new State("|->", new double[]{S2, -S2}, new double[]{0, 0}, 1);
            default:
                return bit == 0 ? new State("|+i>", new double[]{S2, 0}, new double[]{0, S2}, 1)
                                : new State("|-i>", new double[]{S2, 0}, new double[]{0, -S2}, 1);
        }
    }

    static State bell(String label) {
        double[] re;
        String name;
        switch (label.toUpperCase()) {
            case "PHI_PLUS": re = new double[]{S2, 0, 0, S2}; name = "|Phi+>"; break;
            case "PHI_MINUS": re = new double[]{S2, 0, 0, -S2}; name = "|Phi->"; break;
            case "PSI_PLUS": re = new double[]{0, S2, S2, 0}; name = "|Psi+>"; break;
            case "PSI_MINUS": re = new double[]{0, S2, -S2, 0}; name = "|Psi->"; break;
            default:
                throw new IllegalArgumentException("Invalid Bell state label '" + label
                        + "'. Allowed: 'PHI_PLUS', 'PHI_MINUS', 'PSI_PLUS', 'PSI_MINUS'");
        }
        return new State(name, re, new double[4], 2);
    }

    /** |<a|b>|^2 */
    static double fidelity(State a, State b) {
        if (a.re.length != b.re.length) {
            throw new IllegalArgumentException("State dimensions do not match for fidelity calculation: ("
                    + a.re.length + ",) vs (" + b.re.length + ",)");
        }
        double[] ip = vdot(a.re, a.im, b.re, b.im);
        return ip[0] * ip[0] + ip[1] * ip[1];
    }

    /** conj(a) . b */
    static double[] vdot(double[] ar, double[] ai, double[] br, double[] bi) {
        double r = 0, i = 0;
        for (int k = 0; k < ar.length; k++) {
            r += ar[k] * br[k] + ai[k] * bi[k];
            i += ar[k] * bi[k] - ai[k] * br[k];
        }
        return new double[]{r, i};
    }

    // ------------------------------------------------------------ gates

    /** Applies a 2x2 gate to one qubit of an n-qubit vector; returns {re, im} copies. */
    static double[][] applySingle(double[] re, double[] im, double[] g, int target, int total) {
        if (target < 0 || target >= total) {
            throw new IllegalArgumentException("Target qubit index " + target + " out of range for " + total + " qubits");
        }
        double[] r = re.clone(), m = im.clone();
        int mask = 1 << (total - 1 - target);
        for (int i = 0; i < re.length; i++) {
            if ((i & mask) != 0) continue;
            int j = i | mask;
            double ar = re[i], ai = im[i], br = re[j], bi = im[j];
            r[i] = g[0] * ar - g[1] * ai + g[2] * br - g[3] * bi;
            m[i] = g[0] * ai + g[1] * ar + g[2] * bi + g[3] * br;
            r[j] = g[4] * ar - g[5] * ai + g[6] * br - g[7] * bi;
            m[j] = g[4] * ai + g[5] * ar + g[6] * bi + g[7] * br;
        }
        return new double[][]{r, m};
    }

    static double[][] applyCnot(double[] re, double[] im, int control, int target, int total) {
        if (control < 0 || control >= total) {
            throw new IllegalArgumentException("Control qubit " + control + " out of range for " + total + " qubits");
        }
        if (target < 0 || target >= total) {
            throw new IllegalArgumentException("Target qubit " + target + " out of range for " + total + " qubits");
        }
        if (control == target) throw new IllegalArgumentException("Control and target qubits cannot be the same");
        double[] r = re.clone(), m = im.clone();
        int cm = 1 << (total - 1 - control), tm = 1 << (total - 1 - target);
        for (int i = 0; i < re.length; i++) {
            if ((i & cm) != 0) {
                int j = i ^ tm;
                r[i] = re[j];
                m[i] = im[j];
            }
        }
        return new double[][]{r, m};
    }

    // ------------------------------------------------------- Pauli corrections

    static String expectedCorrection(String bits, String bellLabel) {
        String b = bits.trim();
        String[] map;
        switch (bellLabel.toUpperCase().trim()) {
            case "PHI_PLUS": map = new String[]{"I", "X", "Z", "XZ"}; break;
            case "PHI_MINUS": map = new String[]{"Z", "XZ", "I", "X"}; break;
            case "PSI_PLUS": map = new String[]{"X", "I", "XZ", "Z"}; break;
            case "PSI_MINUS": map = new String[]{"XZ", "Z", "X", "I"}; break;
            default: throw new IllegalArgumentException("Invalid Bell state label '" + bellLabel + "'");
        }
        switch (b) {
            case "00": return map[0];
            case "01": return map[1];
            case "10": return map[2];
            case "11": return map[3];
            default:
                throw new IllegalArgumentException("Invalid measurement bits '" + bits + "'. Expected '00', '01', '10', or '11'");
        }
    }

    /** "XZ" means X first then Z; "ZX" means Z first then X. */
    static State applyCorrection(State s, String correction) {
        if (s.numQubits != 1) {
            throw new IllegalArgumentException("apply_pauli_correction only supports 1-qubit states, got " + s.numQubits);
        }
        String c = correction.toUpperCase().trim();
        double[][] v = {s.re, s.im};
        switch (c) {
            case "I": v = applySingle(v[0], v[1], GATE_I, 0, 1); break;
            case "X": v = applySingle(v[0], v[1], GATE_X, 0, 1); break;
            case "Y": v = applySingle(v[0], v[1], GATE_Y, 0, 1); break;
            case "Z": v = applySingle(v[0], v[1], GATE_Z, 0, 1); break;
            case "XZ":
                v = applySingle(v[0], v[1], GATE_X, 0, 1);
                v = applySingle(v[0], v[1], GATE_Z, 0, 1);
                break;
            case "ZX":
                v = applySingle(v[0], v[1], GATE_Z, 0, 1);
                v = applySingle(v[0], v[1], GATE_X, 0, 1);
                break;
            default:
                throw new IllegalArgumentException("Unknown Pauli correction '" + correction
                        + "'. Allowed: 'I', 'X', 'Y', 'Z', 'XZ', 'ZX'");
        }
        return new State(c + "(" + s.name + ")", v[0], v[1], 1);
    }

    // ------------------------------------------------------------ noise

    interface Noise {
        State apply(State s, SplittableRandom rng);
        String name();
    }

    static final class NoNoise implements Noise {
        public State apply(State s, SplittableRandom rng) {
            return new State(s.name, s.re.clone(), s.im.clone(), s.numQubits);
        }
        public String name() { return "NoNoise"; }
    }

    static final class DepolarizingNoise implements Noise {
        final double p;
        DepolarizingNoise(double p) {
            if (p < 0.0 || p > 1.0) throw new IllegalArgumentException("Error probability must be in [0.0, 1.0], got " + p);
            this.p = p;
        }
        public State apply(State s, SplittableRandom rng) {
            if (p == 0.0 || rng.nextDouble() > p) return new NoNoise().apply(s, rng);
            double[] g = new double[][]{GATE_X, GATE_Y, GATE_Z}[rng.nextInt(3)];
            double[][] v = applySingle(s.re, s.im, g, 0, 1);
            return new State("Noisy(" + s.name + ")", v[0], v[1], s.numQubits);
        }
        public String name() { return "DepolarizingNoise"; }
    }

    static final class PauliFlipNoise implements Noise {
        final double p;
        final String type;
        PauliFlipNoise(double p, String type) {
            if (p < 0.0 || p > 1.0) throw new IllegalArgumentException("Flip probability must be in [0.0, 1.0], got " + p);
            this.p = p;
            this.type = type.toUpperCase();
        }
        public State apply(State s, SplittableRandom rng) {
            if (p == 0.0 || rng.nextDouble() > p) return new NoNoise().apply(s, rng);
            double[][] v = applySingle(s.re, s.im, gateByName(type), 0, 1);
            return new State("Flipped(" + s.name + ")", v[0], v[1], s.numQubits);
        }
        public String name() { return "PauliFlipNoise"; }
    }

    // ------------------------------------------------------- measurement

    static final class Measurement {
        String basis;
        int outcomeBit;
        double p0, p1;
        State post;
        boolean deterministic;

        Map<String, Object> probabilities() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("0", p0);
            m.put("1", p1);
            return m;
        }
    }

    /** Born-rule measurement of a 1-qubit state in the X, Y or Z eigenbasis. */
    static Measurement measureInBasis(State s, String basis, SplittableRandom rng) {
        if (s.numQubits != 1) {
            throw new IllegalArgumentException("measure_in_basis only supports 1-qubit states, got " + s.numQubits + " qubits");
        }
        String b = basis.toUpperCase();
        if (!b.equals("X") && !b.equals("Y") && !b.equals("Z")) {
            throw new IllegalArgumentException("Invalid basis '" + basis + "'. Allowed bases are 'X', 'Y', 'Z'");
        }
        State s0 = eigenstate(b, 0), s1 = eigenstate(b, 1);
        double[] i0 = vdot(s0.re, s0.im, s.re, s.im), i1 = vdot(s1.re, s1.im, s.re, s.im);
        double p0 = i0[0] * i0[0] + i0[1] * i0[1];
        double p1 = i1[0] * i1[0] + i1[1] * i1[1];
        double total = p0 + p1;
        if (total > 0.0) { p0 /= total; p1 /= total; }

        Measurement m = new Measurement();
        m.basis = b;
        m.p0 = p0;
        m.p1 = p1;
        if (rng.nextDouble() < p0) { m.outcomeBit = 0; m.post = s0; } else { m.outcomeBit = 1; m.post = s1; }
        m.deterministic = p0 >= 0.999999 || p1 >= 0.999999;
        return m;
    }

    static final class TwoQubitMeasurement {
        String bits;
        double[] collapsedRe, collapsedIm;
        Map<String, Double> branchProbs;
    }

    /** Computational-basis measurement of qubits a and b of a 3-qubit vector; collapses the remaining qubit. */
    static TwoQubitMeasurement measureTwo(double[] re, double[] im, int qa, int qb, int total, SplittableRandom rng) {
        String[] branches = {"00", "01", "10", "11"};
        double[] probs = new double[4];
        for (int idx = 0; idx < re.length; idx++) {
            int ba = (idx >> (total - 1 - qa)) & 1, bb = (idx >> (total - 1 - qb)) & 1;
            probs[ba * 2 + bb] += re[idx] * re[idx] + im[idx] * im[idx];
        }
        double sum = probs[0] + probs[1] + probs[2] + probs[3];

        // inverse-CDF draw over the normalised branch probabilities
        double r = rng.nextDouble(), acc = 0;
        int chosen = 3;
        for (int k = 0; k < 4; k++) {
            acc += probs[k] / sum;
            if (r < acc) { chosen = k; break; }
        }
        int selA = chosen >> 1, selB = chosen & 1;

        double[] cr = new double[2], ci = new double[2];
        for (int t = 0; t < 2; t++) {
            int index = 0;
            for (int q = 0; q < total; q++) {
                int bit = q == qa ? selA : q == qb ? selB : t;
                index = (index << 1) | bit;
            }
            cr[t] = re[index];
            ci[t] = im[index];
        }
        double n = norm(cr, ci);
        if (n > 0) for (int t = 0; t < 2; t++) { cr[t] /= n; ci[t] /= n; }

        TwoQubitMeasurement out = new TwoQubitMeasurement();
        out.bits = branches[chosen];
        out.collapsedRe = cr;
        out.collapsedIm = ci;
        out.branchProbs = new LinkedHashMap<>();
        for (int k = 0; k < 4; k++) out.branchProbs.put(branches[k], probs[k]);
        return out;
    }

    // ------------------------------------------------------- teleportation

    static final class Teleportation {
        State input;
        String bellLabel, bits, expectedCorrection, appliedCorrection;
        Map<String, Double> branchProbs;
        State beforeCorrection, afterCorrection;
        double fidelity;
        List<String> trace;
    }

    static Teleportation teleport(State input, String bellLabel, Noise noise, SplittableRandom rng) {
        if (input.numQubits != 1) throw new IllegalArgumentException("Input state must be 1 qubit, got " + input.numQubits);
        if (noise == null) noise = new NoNoise();
        List<String> trace = new ArrayList<>();

        State bell = bell(bellLabel);
        trace.add("Prepared Bell state " + bellLabel + " on qubits (q1, q2)");

        // |q0> (x) |q1 q2>
        double[] re = new double[8], im = new double[8];
        for (int a = 0; a < 2; a++) {
            for (int b = 0; b < 4; b++) {
                re[a * 4 + b] = input.re[a] * bell.re[b] - input.im[a] * bell.im[b];
                im[a * 4 + b] = input.re[a] * bell.im[b] + input.im[a] * bell.re[b];
            }
        }
        trace.add("Formed composite 3-qubit state |q0> (x) |q1,q2> with input " + input.name);

        double[][] v = applyCnot(re, im, 0, 1, 3);
        trace.add("Applied CNOT gate with control q0 and target q1");
        v = applySingle(v[0], v[1], GATE_H, 0, 3);
        trace.add("Applied Hadamard gate on qubit q0");

        TwoQubitMeasurement mm = measureTwo(v[0], v[1], 0, 1, 3, rng);
        trace.add("Measured qubits (q0, q1) in computational basis, outcome bits: '" + mm.bits + "'");

        State raw = new State("q2_collapsed_" + mm.bits, mm.collapsedRe, mm.collapsedIm, 1);
        State noisy = noise.apply(raw, rng);

        String expected = expectedCorrection(mm.bits, bellLabel);
        State corrected = applyCorrection(noisy, expected);
        trace.add("Applied Pauli correction '" + expected + "' to receiver qubit q2");

        double f = fidelity(input, corrected);
        trace.add("Calculated state fidelity: " + Fmt.fixed(f, 8));

        Teleportation t = new Teleportation();
        t.input = input;
        t.bellLabel = bellLabel;
        t.bits = mm.bits;
        t.branchProbs = mm.branchProbs;
        t.expectedCorrection = expected;
        t.appliedCorrection = expected;
        t.beforeCorrection = raw;
        t.afterCorrection = corrected;
        t.fidelity = f;
        t.trace = trace;
        return t;
    }

    // ------------------------------------------------------------ Bloch

    static double[] blochCoordinates(State s) {
        if (s.numQubits != 1) {
            throw new IllegalArgumentException("Bloch coordinates are only defined for 1-qubit states, got " + s.numQubits + " qubits");
        }
        double ar = s.re[0], ai = s.im[0], br = s.re[1], bi = s.im[1];
        double x = 2.0 * (ar * br + ai * bi);
        double y = 2.0 * (ar * bi - ai * br);
        double z = (ar * ar + ai * ai) - (br * br + bi * bi);
        return new double[]{clean(x), clean(y), clean(z)};
    }

    private static double clean(double v) {
        return Math.abs(v) < 1e-12 ? 0.0 : Math.rint(v * 1e10) / 1e10;
    }

    static double[] blochForBasisBit(String basis, int bit) {
        return blochCoordinates(eigenstate(basis, bit));
    }

    static Map<String, Object> coord(double[] c) {
        return Json.obj("x", c[0], "y", c[1], "z", c[2]);
    }

    static Map<String, Object> measurementCollapse(String basis, int bit, int measuredBit) {
        String b = basis.toUpperCase();
        if (!b.equals("X") && !b.equals("Y") && !b.equals("Z")) {
            throw new IllegalArgumentException("Invalid basis '" + basis + "'. Allowed bases are 'X', 'Y', 'Z'");
        }
        if (bit != 0 && bit != 1) throw new IllegalArgumentException("Invalid bit '" + bit + "'. Bit must be 0 or 1");
        if (measuredBit != 0 && measuredBit != 1) {
            throw new IllegalArgumentException("Invalid measured_bit '" + measuredBit + "'. Bit must be 0 or 1");
        }
        State prepared = eigenstate(b, bit);
        double[] pre = blochCoordinates(prepared);
        double[] post = blochCoordinates(eigenstate("Z", measuredBit));
        boolean collapsed = !b.equals("Z") || bit != measuredBit;
        return Json.obj(
                "basis", b,
                "bit", bit,
                "prepared_label", prepared.name,
                "coordinates", coord(pre),
                "is_collapsed", collapsed,
                "collapsed_coordinates", collapsed ? coord(post) : null);
    }
}
