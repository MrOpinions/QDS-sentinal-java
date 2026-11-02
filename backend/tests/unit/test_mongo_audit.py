"""Tests for the tamper-evident Mongo audit sink.

Run against mongomock, so they need no MongoDB server.
"""

from __future__ import annotations

import mongomock
import pytest

from app.database.mongo_audit import (
    GENESIS_HASH,
    MongoAuditSink,
    build_cipher,
    compute_hash,
)

KEY = "test-passphrase-not-a-real-key"

SESSION = {
    "id": "sess-1",
    "sender_id": "alice",
    "recipient_id": "bob",
    "message": "PAYLOAD_TRANSFER_AUTHENTIC_001",
    "verdict": "ACCEPT",
    "mismatch_rate": 0.0,
    "raw_assessment_string": "ACCEPT: clean",
}


@pytest.fixture
def sink():
    return MongoAuditSink(client=mongomock.MongoClient(), encryption_key=KEY)


@pytest.fixture
def plain_sink():
    return MongoAuditSink(client=mongomock.MongoClient(), encryption_key=None)


def test_disabled_without_client_or_uri():
    s = MongoAuditSink()
    assert s.enabled is False
    assert s.append("session", "sess-1", SESSION) is None
    assert s.read("sess-1") == []
    assert s.verify_chain()["enabled"] is False


def test_append_returns_hash_and_stores_record(sink):
    digest = sink.append("session", "sess-1", SESSION)
    assert digest and len(digest) == 64
    stored = list(sink.db["audit_log"].find())
    assert len(stored) == 1
    assert stored[0]["seq"] == 0
    assert stored[0]["prev_hash"] == GENESIS_HASH


def test_sensitive_fields_are_encrypted_at_rest(sink):
    sink.append("session", "sess-1", SESSION)
    raw = sink.db["audit_log"].find_one()["body"]

    # The plaintext must not be recoverable by reading the collection.
    assert raw["message"] != SESSION["message"]
    assert raw["sender_id"] != "alice"
    assert "alice" not in str(raw)
    assert "PAYLOAD_TRANSFER_AUTHENTIC_001" not in str(raw)

    # Non-sensitive fields stay queryable.
    assert raw["verdict"] == "ACCEPT"
    assert raw["mismatch_rate"] == 0.0


def test_read_round_trips_the_plaintext(sink):
    sink.append("session", "sess-1", SESSION)
    [rec] = sink.read("sess-1")
    assert rec["body"]["message"] == SESSION["message"]
    assert rec["body"]["sender_id"] == "alice"
    assert rec["body"]["verdict"] == "ACCEPT"


def test_records_chain_to_their_predecessor(sink):
    sink.append("session", "sess-1", SESSION)
    sink.append_many("telemetry", "sess-1", [{"position_index": i} for i in range(3)])

    records = list(sink.db["audit_log"].find().sort("seq", 1))
    assert [r["seq"] for r in records] == [0, 1, 2, 3]
    assert records[0]["prev_hash"] == GENESIS_HASH
    for earlier, later in zip(records, records[1:]):
        assert later["prev_hash"] == earlier["hash"]


def test_verify_chain_accepts_an_untouched_log(sink):
    sink.append("session", "sess-1", SESSION)
    sink.append_many("finding", "sess-1", [{"finding": "PAYLOAD_DIGEST_MISMATCH"}])

    result = sink.verify_chain()
    assert result == {"enabled": True, "intact": True, "records": 2, "broken_at": None}


def test_verify_chain_detects_an_edited_record(sink):
    sink.append("session", "sess-1", SESSION)
    sink.append_many("telemetry", "sess-1", [{"position_index": 0}, {"position_index": 1}])

    # Someone edits a verdict directly in the collection, leaving hashes alone.
    sink.db["audit_log"].update_one({"seq": 0}, {"$set": {"body.verdict": "ACCEPT_FORGED"}})

    result = sink.verify_chain()
    assert result["intact"] is False
    assert result["broken_at"] == 0


def test_verify_chain_detects_a_deleted_record(sink):
    sink.append("session", "sess-1", SESSION)
    sink.append_many("telemetry", "sess-1", [{"position_index": 0}, {"position_index": 1}])

    sink.db["audit_log"].delete_one({"seq": 1})

    result = sink.verify_chain()
    assert result["intact"] is False
    assert result["broken_at"] == 2


def test_chain_survives_a_rewritten_record_only_if_every_later_hash_is_redone(sink):
    """The point of chaining: one edit invalidates everything after it."""
    sink.append("session", "sess-1", SESSION)
    sink.append_many("telemetry", "sess-1", [{"position_index": i} for i in range(4)])

    # Recompute only the edited record's own hash, as a naive tamperer would.
    target = sink.db["audit_log"].find_one({"seq": 2})
    body = dict(target["body"])
    body["position_index"] = 99
    forged = compute_hash(
        {"seq": 2, "kind": target["kind"], "session_id": target["session_id"], "body": body},
        target["prev_hash"],
    )
    sink.db["audit_log"].update_one(
        {"seq": 2}, {"$set": {"body": body, "hash": forged}}
    )

    result = sink.verify_chain()
    assert result["intact"] is False
    assert result["broken_at"] == 3


def test_without_a_key_records_are_chained_but_readable(plain_sink):
    plain_sink.append("session", "sess-1", SESSION)
    raw = plain_sink.db["audit_log"].find_one()["body"]
    assert raw["message"] == SESSION["message"]
    assert plain_sink.verify_chain()["intact"] is True


def test_passphrase_and_fernet_keys_both_produce_a_working_cipher():
    from cryptography.fernet import Fernet

    for key in (KEY, Fernet.generate_key().decode()):
        cipher = build_cipher(key)
        assert cipher.enabled is True
        assert cipher.decrypt(cipher.encrypt("alice")) == "alice"


def test_same_passphrase_decrypts_a_previous_run(sink):
    """A restart with the same key must still read what the last run wrote."""
    sink.append("session", "sess-1", SESSION)
    reopened = MongoAuditSink(client=sink._client, encryption_key=KEY)
    [rec] = reopened.read("sess-1")
    assert rec["body"]["sender_id"] == "alice"


def test_wrong_key_cannot_read_the_payload(sink):
    sink.append("session", "sess-1", SESSION)
    attacker = MongoAuditSink(client=sink._client, encryption_key="a-different-passphrase")
    [rec] = attacker.read("sess-1")
    assert rec["body"]["message"] == "<undecryptable>"
