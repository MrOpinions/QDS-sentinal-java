"""Tamper-evident audit sink in MongoDB.

Two separate protections, because they do different jobs:

* **Encryption** (reversible) hides the sensitive fields of a record - the
  payload, who sent it, who received it - from anyone reading the collection
  directly. The application can still decrypt and display them.
* **Hash chaining** (one-way) makes the log tamper-evident. Each record stores
  the SHA-256 of its own canonical content plus the previous record's hash, so
  altering or deleting any record breaks every hash after it.

Hashing alone would make the log unreadable; encryption alone would leave it
silently editable by anyone with write access. Both together give a log that is
confidential *and* provably unaltered.

The sink is optional. With no ``MONGODB_URI`` configured it is disabled and
every call is a no-op, so the app runs exactly as before.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

# Fields encrypted at rest. Everything else (verdicts, rates, thresholds) stays
# queryable, which is what the operations endpoints aggregate over.
ENCRYPTED_FIELDS = ("message", "sender_id", "recipient_id", "raw_assessment_string")

GENESIS_HASH = "0" * 64


def _canonical(payload: dict[str, Any]) -> bytes:
    """Stable bytes for a document, so the same content always hashes alike."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def compute_hash(payload: dict[str, Any], prev_hash: str) -> str:
    """SHA-256 over the record's content chained to the previous record."""
    digest = hashlib.sha256()
    digest.update(prev_hash.encode())
    digest.update(_canonical(payload))
    return digest.hexdigest()


class _NullCipher:
    """Used when no key is configured: records are chained but not encrypted."""

    enabled = False

    def encrypt(self, value: str) -> str:
        return value

    def decrypt(self, value: str) -> str:
        return value


class _FernetCipher:
    enabled = True

    def __init__(self, key: bytes) -> None:
        from cryptography.fernet import Fernet

        self._fernet = Fernet(key)

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        return self._fernet.decrypt(value.encode()).decode()


def build_cipher(key: Optional[str]) -> _NullCipher | _FernetCipher:
    """A Fernet cipher from ``key``, or a pass-through when none is set.

    ``key`` may be a urlsafe-base64 Fernet key, or any passphrase, which is
    stretched to one with SHA-256 so a human-typed value also works.
    """
    if not key:
        return _NullCipher()
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.warning("cryptography not installed; audit fields stored unencrypted")
        return _NullCipher()

    try:
        Fernet(key.encode())
        material = key.encode()
    except Exception:
        material = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
    return _FernetCipher(material)


class MongoAuditSink:
    """Append-only, hash-chained audit log.

    Instances are cheap and safe to construct when Mongo is absent: ``enabled``
    is then False and every write returns None.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        db_name: str = "qds_sentinel",
        encryption_key: Optional[str] = None,
        client: Any = None,
    ) -> None:
        self.cipher = build_cipher(encryption_key)
        self._client = None
        self.db = None

        if client is not None:
            self._client = client
        elif uri:
            try:
                from pymongo import MongoClient

                self._client = MongoClient(uri, serverSelectionTimeoutMS=2000)
            except ImportError:
                logger.warning("pymongo not installed; Mongo audit sink disabled")
            except Exception as exc:
                logger.warning("Mongo audit sink unavailable: %s", exc)

        if self._client is not None:
            self.db = self._client[db_name]

    @property
    def enabled(self) -> bool:
        return self.db is not None

    # -- internals ---------------------------------------------------------

    def _collection(self):
        return self.db["audit_log"]

    def _last_hash(self) -> str:
        last = self._collection().find_one(sort=[("seq", -1)])
        return last["hash"] if last else GENESIS_HASH

    def _next_seq(self) -> int:
        last = self._collection().find_one(sort=[("seq", -1)])
        return (last["seq"] + 1) if last else 0

    def _encrypt_fields(self, body: dict[str, Any]) -> dict[str, Any]:
        out = dict(body)
        for field in ENCRYPTED_FIELDS:
            if field in out and out[field] is not None:
                out[field] = self.cipher.encrypt(str(out[field]))
        return out

    # -- writes ------------------------------------------------------------

    def append(self, kind: str, session_id: str, body: dict[str, Any]) -> Optional[str]:
        """Append one record. Returns its hash, or None when disabled."""
        if not self.enabled:
            return None

        stored = self._encrypt_fields(body)
        prev_hash = self._last_hash()
        record = {
            "seq": self._next_seq(),
            "kind": kind,
            "session_id": session_id,
            "recorded_at": datetime.now(timezone.utc),
            "encrypted_fields": [f for f in ENCRYPTED_FIELDS if f in stored],
            "body": stored,
        }
        record["prev_hash"] = prev_hash
        record["hash"] = compute_hash(
            {k: record[k] for k in ("seq", "kind", "session_id", "body")}, prev_hash
        )
        self._collection().insert_one(record)
        return record["hash"]

    def append_many(self, kind: str, session_id: str, bodies: Iterable[dict[str, Any]]) -> int:
        """Append a batch one at a time, since each link needs the previous hash."""
        if not self.enabled:
            return 0
        count = 0
        for body in bodies:
            self.append(kind, session_id, body)
            count += 1
        return count

    # -- reads -------------------------------------------------------------

    def read(self, session_id: str) -> list[dict[str, Any]]:
        """Records for one session, decrypted."""
        if not self.enabled:
            return []
        out = []
        for rec in self._collection().find({"session_id": session_id}).sort("seq", 1):
            body = dict(rec["body"])
            for field in rec.get("encrypted_fields", []):
                try:
                    body[field] = self.cipher.decrypt(body[field])
                except Exception:
                    body[field] = "<undecryptable>"
            out.append({
                "seq": rec["seq"],
                "kind": rec["kind"],
                "recorded_at": rec["recorded_at"],
                "hash": rec["hash"],
                "body": body,
            })
        return out

    def verify_chain(self) -> dict[str, Any]:
        """Walk the whole log and report the first break, if any."""
        if not self.enabled:
            return {"enabled": False, "intact": True, "records": 0, "broken_at": None}

        prev_hash = GENESIS_HASH
        count = 0
        for rec in self._collection().find().sort("seq", 1):
            expected = compute_hash(
                {k: rec[k] for k in ("seq", "kind", "session_id", "body")}, prev_hash
            )
            if rec.get("prev_hash") != prev_hash or rec.get("hash") != expected:
                return {
                    "enabled": True,
                    "intact": False,
                    "records": count,
                    "broken_at": rec.get("seq"),
                }
            prev_hash = rec["hash"]
            count += 1
        return {"enabled": True, "intact": True, "records": count, "broken_at": None}


_sink: Optional[MongoAuditSink] = None


def get_audit_sink() -> MongoAuditSink:
    """Process-wide sink, built from the environment on first use."""
    global _sink
    if _sink is None:
        _sink = MongoAuditSink(
            uri=os.environ.get("MONGODB_URI"),
            db_name=os.environ.get("MONGODB_DB", "qds_sentinel"),
            encryption_key=os.environ.get("AUDIT_ENCRYPTION_KEY"),
        )
    return _sink


def reset_audit_sink() -> None:
    """Drop the cached sink. For tests, and for re-reading the environment."""
    global _sink
    _sink = None
