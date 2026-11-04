package qds;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;
import java.util.UUID;

/**
 * Layer 1: signature key material, the teleportation-mediated signature packet,
 * telemetry events and the protocol session. Also holds the shared data model
 * (positions, events, summary, session) with its JSON mapping.
 */
final class Protocol {
    private Protocol() {}

    static final String[] BELL_STATES = {"PHI_PLUS", "PHI_MINUS", "PSI_PLUS", "PSI_MINUS"};
    static final String[] BASES = {"X", "Y", "Z"};

    // ---------------------------------------------------------- data model

    static final class Position {
        int index;
        String pauliBasis;
        int encodedBit;
        String preparedStateLabel, bellState, bellMeasurementBits, expectedCorrection, actualCorrection;
        int finalMeasuredBit, expectedBit;
        double fidelity;
        boolean isMatch;

        Position copy() {
            Position p = new Position();
            p.index = index; p.pauliBasis = pauliBasis; p.encodedBit = encodedBit;
            p.preparedStateLabel = preparedStateLabel; p.bellState = bellState;
            p.bellMeasurementBits = bellMeasurementBits; p.expectedCorrection = expectedCorrection;
            p.actualCorrection = actualCorrection; p.finalMeasuredBit = finalMeasuredBit;
            p.expectedBit = expectedBit; p.fidelity = fidelity; p.isMatch = isMatch;
            return p;
        }

        Map<String, Object> toMap() {
            return Json.obj(
                    "index", index, "pauli_basis", pauliBasis, "encoded_bit", encodedBit,
                    "prepared_state_label", preparedStateLabel, "bell_state", bellState,
                    "bell_measurement_bits", bellMeasurementBits,
                    "expected_correction", expectedCorrection, "actual_correction", actualCorrection,
                    "final_measured_bit", finalMeasuredBit, "expected_bit", expectedBit,
                    "fidelity", fidelity, "is_match", isMatch);
        }

        static Position from(Req r) {
            Position p = new Position();
            p.index = (int) r.lng("index");
            p.pauliBasis = r.str("pauli_basis");
            p.encodedBit = (int) r.lng("encoded_bit");
            p.preparedStateLabel = r.str("prepared_state_label");
            p.bellState = r.str("bell_state");
            p.bellMeasurementBits = r.str("bell_measurement_bits");
            p.expectedCorrection = r.str("expected_correction");
            p.actualCorrection = r.str("actual_correction");
            p.finalMeasuredBit = (int) r.lng("final_measured_bit");
            p.expectedBit = (int) r.lng("expected_bit");
            p.fidelity = r.dbl("fidelity");
            p.isMatch = r.bool("is_match");
            return p;
        }
    }

    static final class TeleEvent {
        String eventId, bellState, bellMeasurementBits, expectedCorrection, appliedCorrection;
        int positionIndex;
        double fidelity;
        List<String> stepTrace = new ArrayList<>();

        TeleEvent copy() {
            TeleEvent t = new TeleEvent();
            t.eventId = eventId; t.bellState = bellState; t.bellMeasurementBits = bellMeasurementBits;
            t.expectedCorrection = expectedCorrection; t.appliedCorrection = appliedCorrection;
            t.positionIndex = positionIndex; t.fidelity = fidelity; t.stepTrace = new ArrayList<>(stepTrace);
            return t;
        }

        Map<String, Object> toMap() {
            return Json.obj(
                    "event_id", eventId, "position_index", positionIndex, "bell_state", bellState,
                    "bell_measurement_bits", bellMeasurementBits, "expected_correction", expectedCorrection,
                    "applied_correction", appliedCorrection, "fidelity", fidelity, "step_trace", stepTrace);
        }

        static TeleEvent from(Req r) {
            TeleEvent t = new TeleEvent();
            t.eventId = r.str("event_id");
            t.positionIndex = (int) r.lng("position_index");
            t.bellState = r.str("bell_state");
            t.bellMeasurementBits = r.str("bell_measurement_bits");
            t.expectedCorrection = r.str("expected_correction");
            t.appliedCorrection = r.str("applied_correction");
            t.fidelity = r.dbl("fidelity");
            if (r.present("step_trace")) for (Object o : r.list("step_trace")) t.stepTrace.add(String.valueOf(o));
            return t;
        }
    }

    static final class MeasEvent {
        String eventId, basis;
        int positionIndex, outcomeBit;
        Map<String, Object> probabilities;
        boolean isDeterministic;

        MeasEvent copy() {
            MeasEvent m = new MeasEvent();
            m.eventId = eventId; m.basis = basis; m.positionIndex = positionIndex; m.outcomeBit = outcomeBit;
            m.probabilities = new LinkedHashMap<>(probabilities); m.isDeterministic = isDeterministic;
            return m;
        }

        Map<String, Object> toMap() {
            return Json.obj(
                    "event_id", eventId, "position_index", positionIndex, "basis", basis,
                    "outcome_bit", outcomeBit, "probabilities", probabilities, "is_deterministic", isDeterministic);
        }

        static MeasEvent from(Req r) {
            MeasEvent m = new MeasEvent();
            m.eventId = r.str("event_id");
            m.positionIndex = (int) r.lng("position_index");
            m.basis = r.str("basis");
            m.outcomeBit = (int) r.lng("outcome_bit");
            m.probabilities = new LinkedHashMap<>(r.map("probabilities"));
            m.isDeterministic = r.bool("is_deterministic");
            return m;
        }
    }

    static final class Summary {
        int total, matching, mismatching;
        double mismatchRate, averageFidelity;
        Map<String, Object> basisDist = new LinkedHashMap<>();
        Map<String, Object> correctionDist = new LinkedHashMap<>();
        boolean digestMatches, isPerfect;

        Summary copy() {
            Summary s = new Summary();
            s.total = total; s.matching = matching; s.mismatching = mismatching;
            s.mismatchRate = mismatchRate; s.averageFidelity = averageFidelity;
            s.basisDist = new LinkedHashMap<>(basisDist); s.correctionDist = new LinkedHashMap<>(correctionDist);
            s.digestMatches = digestMatches; s.isPerfect = isPerfect;
            return s;
        }

        Map<String, Object> toMap() {
            return Json.obj(
                    "total_positions", total, "matching_positions", matching,
                    "mismatching_positions", mismatching, "mismatch_count", mismatching,
                    "mismatch_rate", mismatchRate, "average_fidelity", averageFidelity,
                    "basis_distribution", basisDist, "correction_distribution", correctionDist,
                    "digest_matches", digestMatches, "is_perfect_match", isPerfect);
        }

        static Summary from(Req r) {
            Summary s = new Summary();
            s.total = (int) r.lng("total_positions");
            s.matching = (int) r.lng("matching_positions");
            s.mismatching = (int) r.lng("mismatching_positions");
            s.mismatchRate = r.dbl("mismatch_rate");
            s.averageFidelity = r.dbl("average_fidelity");
            s.basisDist = new LinkedHashMap<>(r.map("basis_distribution"));
            s.correctionDist = new LinkedHashMap<>(r.map("correction_distribution"));
            s.digestMatches = r.boolOr("digest_matches", true);
            s.isPerfect = r.bool("is_perfect_match");
            return s;
        }
    }

    static final class AttackMeta {
        String attackId, attackType, targetBasis, description;
        double intensity = 1.0;
        long seed = 42;

        Map<String, Object> toMap() {
            return Json.obj("attack_id", attackId, "attack_type", attackType, "intensity", intensity,
                    "target_basis", targetBasis, "seed", seed, "description", description);
        }

        static AttackMeta from(Req r) {
            AttackMeta a = new AttackMeta();
            a.attackId = r.str("attack_id");
            a.attackType = r.enumStr("attack_type", Layer2.ATTACK_TYPES);
            a.intensity = r.dblRange("intensity", 1.0, 0.0, 1.0);
            a.targetBasis = r.strOpt("target_basis");
            a.seed = r.lngRange("seed", 42, Long.MIN_VALUE, Long.MAX_VALUE);
            a.description = r.str("description");
            return a;
        }
    }

    static final class Session {
        String protocolVersion = "1.0.0";
        String sessionId, signatureBlockId, senderId, recipientId, message, messageDigest, nonce, createdAt;
        long sequenceNumber;
        Map<String, Object> configuration = new LinkedHashMap<>();
        List<Position> positions = new ArrayList<>();
        List<TeleEvent> teleEvents = new ArrayList<>();
        List<MeasEvent> measEvents = new ArrayList<>();
        Summary summary;
        AttackMeta attackMetadata;

        Session copy() {
            Session s = new Session();
            s.protocolVersion = protocolVersion; s.sessionId = sessionId; s.signatureBlockId = signatureBlockId;
            s.senderId = senderId; s.recipientId = recipientId; s.message = message;
            s.messageDigest = messageDigest; s.nonce = nonce; s.createdAt = createdAt;
            s.sequenceNumber = sequenceNumber; s.configuration = new LinkedHashMap<>(configuration);
            for (Position p : positions) s.positions.add(p.copy());
            for (TeleEvent t : teleEvents) s.teleEvents.add(t.copy());
            for (MeasEvent m : measEvents) s.measEvents.add(m.copy());
            s.summary = summary.copy();
            s.attackMetadata = attackMetadata;
            return s;
        }

        Map<String, Object> toMap() {
            List<Object> pos = new ArrayList<>(), tel = new ArrayList<>(), mea = new ArrayList<>();
            for (Position p : positions) pos.add(p.toMap());
            for (TeleEvent t : teleEvents) tel.add(t.toMap());
            for (MeasEvent m : measEvents) mea.add(m.toMap());
            return Json.obj(
                    "protocol_version", protocolVersion, "session_id", sessionId,
                    "signature_block_id", signatureBlockId, "sender_id", senderId, "recipient_id", recipientId,
                    "message", message, "message_digest", messageDigest, "nonce", nonce,
                    "sequence_number", sequenceNumber, "created_at", createdAt, "configuration", configuration,
                    "signature_positions", pos, "teleportation_events", tel, "measurement_events", mea,
                    "verification_summary", summary.toMap(),
                    "attack_metadata", attackMetadata == null ? null : attackMetadata.toMap());
        }

        static Session from(Req r) {
            Session s = new Session();
            s.protocolVersion = r.strMin1("protocol_version", "1.0.0");
            s.sessionId = r.str("session_id");
            s.signatureBlockId = r.str("signature_block_id");
            s.senderId = r.str("sender_id");
            s.recipientId = r.str("recipient_id");
            s.message = r.str("message");
            s.messageDigest = r.str("message_digest");
            s.nonce = r.str("nonce");
            s.sequenceNumber = r.lng("sequence_number");
            s.createdAt = r.str("created_at");
            if (r.present("configuration")) s.configuration = new LinkedHashMap<>(r.map("configuration"));
            List<Object> pos = r.list("signature_positions");
            for (int i = 0; i < pos.size(); i++) s.positions.add(Position.from(r.item(pos, "signature_positions", i)));
            List<Object> tel = r.list("teleportation_events");
            for (int i = 0; i < tel.size(); i++) s.teleEvents.add(TeleEvent.from(r.item(tel, "teleportation_events", i)));
            List<Object> mea = r.list("measurement_events");
            for (int i = 0; i < mea.size(); i++) s.measEvents.add(MeasEvent.from(r.item(mea, "measurement_events", i)));
            s.summary = Summary.from(r.obj("verification_summary"));
            if (r.present("attack_metadata")) s.attackMetadata = AttackMeta.from(r.obj("attack_metadata"));
            return s;
        }
    }

    // ------------------------------------------------------------ request

    /** Layer 1 simulation parameters (the SimulationRequest body). */
    static final class Sim {
        String message, senderId = "alice", recipientId = "bob", bellState = "PHI_PLUS";
        int signatureLength = 16;
        Long seed;
        List<String> bases = new ArrayList<>(Arrays.asList(BASES));
        String sessionId, nonce;
        long sequenceNumber = 1;

        static Sim from(Req r) {
            Sim s = new Sim();
            s.message = r.strMin1("message");
            s.senderId = r.strMin1("sender_id", "alice");
            s.recipientId = r.strMin1("recipient_id", "bob");
            s.signatureLength = (int) r.lngRange("signature_length", 16, 1, 4096);
            s.seed = r.lngOpt("seed");
            s.bellState = r.enumOr("bell_state", "PHI_PLUS", BELL_STATES);
            if (r.present("bases_allowed")) {
                List<Object> raw = r.list("bases_allowed");
                if (raw.isEmpty()) throw new HttpError(422, r.path + ".bases_allowed: List should have at least 1 item after validation, not 0");
                s.bases = new ArrayList<>();
                for (Object o : raw) s.bases.add(r.checkEnum("bases_allowed", String.valueOf(o), BASES));
            }
            s.sessionId = r.strOpt("session_id");
            s.nonce = r.strOpt("nonce");
            s.sequenceNumber = r.lngRange("sequence_number", 1, 1, Long.MAX_VALUE);
            return s;
        }
    }

    static Session run(Sim s) {
        return runSession(s.message, s.senderId, s.recipientId, s.signatureLength, s.seed, s.bellState,
                s.bases, s.sessionId, s.nonce, s.sequenceNumber, null);
    }

    // ----------------------------------------------------- keygen / digest

    static String digest(String message) {
        return Fmt.sha256Hex(message);
    }

    static final class Element {
        final int position;
        final String basis;
        final int bit;
        Element(int position, String basis, int bit) { this.position = position; this.basis = basis; this.bit = bit; }
    }

    static List<Element> generateElements(String message, int length, List<String> allowedBases, SplittableRandom rng,
                                          String sessionId, String nonce, long sequence) {
        if (length <= 0) throw new IllegalArgumentException("Signature length must be positive, got " + length);
        List<String> bases = new ArrayList<>();
        for (String b : allowedBases) {
            String u = b.toUpperCase();
            if (!u.equals("X") && !u.equals("Y") && !u.equals("Z")) {
                throw new IllegalArgumentException("Invalid basis in allowed_bases: '" + b + "'");
            }
            bases.add(u);
        }
        String msgDigest = digest(message);
        List<Element> out = new ArrayList<>();
        for (int pos = 0; pos < length; pos++) {
            int random = rng.nextInt(1_000_000);
            String binding = msgDigest + "_" + sessionId + "_" + nonce + "_" + sequence + "_" + pos + "_" + random;
            byte[] h = Fmt.sha256(binding.getBytes(StandardCharsets.UTF_8));
            long basisWord = ((h[0] & 0xffL) << 24) | ((h[1] & 0xffL) << 16) | ((h[2] & 0xffL) << 8) | (h[3] & 0xffL);
            long bitWord = ((h[4] & 0xffL) << 24) | ((h[5] & 0xffL) << 16) | ((h[6] & 0xffL) << 8) | (h[7] & 0xffL);
            out.add(new Element(pos, bases.get((int) (basisWord % bases.size())), (int) (bitWord % 2)));
        }
        return out;
    }

    // ------------------------------------------------------------ session

    static SplittableRandom rng(Long seed) {
        if (seed == null) return new SplittableRandom();
        if (seed < 0) throw new IllegalArgumentException("expected non-negative integer");
        return new SplittableRandom(seed);
    }

    static Session runSession(String message, String senderId, String recipientId, int length, Long seed,
                              String bellLabel, List<String> allowedBases, String sessionId, String nonce,
                              long sequence, Quantum.Noise noise) {
        if (sessionId == null) sessionId = UUID.randomUUID().toString();
        if (nonce == null) nonce = UUID.randomUUID().toString();
        if (allowedBases == null) allowedBases = Arrays.asList(BASES);
        if (noise == null) noise = new Quantum.NoNoise();
        SplittableRandom rng = rng(seed);

        String blockId = UUID.randomUUID().toString();
        String timestamp = Fmt.isoNow();
        List<Element> elements = generateElements(message, length, allowedBases, rng, sessionId, nonce, sequence);

        Session s = new Session();
        for (Element e : elements) {
            Quantum.State prepared = Quantum.eigenstate(e.basis, e.bit);
            Quantum.Teleportation tp = Quantum.teleport(prepared, bellLabel, noise, rng);

            TeleEvent te = new TeleEvent();
            te.eventId = UUID.randomUUID().toString();
            te.positionIndex = e.position;
            te.bellState = tp.bellLabel;
            te.bellMeasurementBits = tp.bits;
            te.expectedCorrection = tp.expectedCorrection;
            te.appliedCorrection = tp.appliedCorrection;
            te.fidelity = tp.fidelity;
            te.stepTrace = tp.trace;
            s.teleEvents.add(te);

            Quantum.Measurement mr = Quantum.measureInBasis(tp.afterCorrection, e.basis, rng);
            MeasEvent me = new MeasEvent();
            me.eventId = UUID.randomUUID().toString();
            me.positionIndex = e.position;
            me.basis = mr.basis;
            me.outcomeBit = mr.outcomeBit;
            me.probabilities = mr.probabilities();
            me.isDeterministic = mr.deterministic;
            s.measEvents.add(me);

            Position p = new Position();
            p.index = e.position;
            p.pauliBasis = e.basis;
            p.encodedBit = e.bit;
            p.preparedStateLabel = prepared.name;
            p.bellState = bellLabel;
            p.bellMeasurementBits = tp.bits;
            p.expectedCorrection = tp.expectedCorrection;
            p.actualCorrection = tp.appliedCorrection;
            p.finalMeasuredBit = mr.outcomeBit;
            p.expectedBit = e.bit;
            p.fidelity = tp.fidelity;
            p.isMatch = e.bit == mr.outcomeBit;
            s.positions.add(p);
        }

        String msgDigest = digest(message);
        s.protocolVersion = "1.0.0";
        s.sessionId = sessionId;
        s.signatureBlockId = blockId;
        s.senderId = senderId;
        s.recipientId = recipientId;
        s.message = message;
        s.messageDigest = msgDigest;
        s.nonce = nonce;
        s.sequenceNumber = sequence;
        s.createdAt = timestamp;
        s.configuration = Json.obj(
                "signature_length", length,
                "seed", seed,
                "bell_state", bellLabel,
                "bases_allowed", allowedBases,
                "noise_model", noise.name());
        // the digest was just computed from this message, so it matches by construction
        s.summary = buildSummary(s.positions, true);
        return s;
    }

    static Summary buildSummary(List<Position> positions, boolean digestMatches) {
        Summary s = new Summary();
        s.basisDist.put("X", 0); s.basisDist.put("Y", 0); s.basisDist.put("Z", 0);
        s.correctionDist.put("I", 0); s.correctionDist.put("X", 0); s.correctionDist.put("Z", 0); s.correctionDist.put("XZ", 0);
        s.total = positions.size();
        for (Position p : positions) {
            s.basisDist.merge(p.pauliBasis.toUpperCase(), 1, (a, b) -> (Integer) a + (Integer) b);
            s.correctionDist.merge(p.actualCorrection.toUpperCase(), 1, (a, b) -> (Integer) a + (Integer) b);
        }
        s.digestMatches = digestMatches;
        if (s.total == 0) {
            s.isPerfect = digestMatches;
            return s;
        }
        int matching = 0;
        double fid = 0;
        for (Position p : positions) {
            if (p.isMatch) matching++;
            fid += p.fidelity;
        }
        s.matching = matching;
        s.mismatching = s.total - matching;
        s.mismatchRate = (double) s.mismatching / s.total;
        s.averageFidelity = fid / s.total;
        s.isPerfect = s.mismatching == 0 && digestMatches;
        return s;
    }
}
