from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session as DBSession

from app.database.session import get_db
from app.database import crud

router = APIRouter(prefix="/api/ops", tags=["Operations Mode"])


THREAT_TYPE_PLAIN_LABELS = {
    "CORRECTION_TAMPERING": "Message tampered in transit",
    "BELL_INTEGRITY_VIOLATION": "Quantum channel interference detected",
    "QBER_ANOMALY": "Unusually high error rate observed",
    "REPLAY_ATTACK": "Previously seen message re-submitted",
    "PAYLOAD_DIGEST_MISMATCH": "Message contents altered after signing",
    "IMPERSONATION": "Sender or recipient identity mismatch",
    "UNAUTHORIZED_VERIFICATION": "Unauthorized party attempted to verify",
    "BOB_THRESHOLD_BREACH": "Error rate exceeded acceptance limit",
    "CHARLIE_THRESHOLD_BREACH": "Forwarded error rate exceeded limit",
    "CONFIGURATION_WARNING": "Security configuration problem detected",
}

THREAT_TYPE_IMPACT = {
    "CORRECTION_TAMPERING": "The message cannot be trusted. A third party likely intercepted and modified the quantum correction instructions.",
    "BELL_INTEGRITY_VIOLATION": "The quantum entanglement used to secure this message showed signs of interference. The channel may be monitored.",
    "QBER_ANOMALY": "More errors than expected were found in the transmission. This can indicate eavesdropping.",
    "REPLAY_ATTACK": "This exact message was already received before. Someone is trying to re-use a captured packet.",
    "PAYLOAD_DIGEST_MISMATCH": "The message was changed after it was signed. It no longer matches the original.",
    "IMPERSONATION": "The claimed sender or recipient does not match who sent this message.",
    "UNAUTHORIZED_VERIFICATION": "Someone who was not the intended recipient tried to read this message.",
    "BOB_THRESHOLD_BREACH": "The direct verification check failed. The message is rejected.",
    "CHARLIE_THRESHOLD_BREACH": "The forwarded verification check failed. The message is rejected.",
    "CONFIGURATION_WARNING": "The security settings are misconfigured. Verification cannot be trusted until fixed.",
}


def _plain_english_event(event, session_row) -> dict:
    label = THREAT_TYPE_PLAIN_LABELS.get(event.threat_type, event.threat_type)
    impact = THREAT_TYPE_IMPACT.get(event.threat_type, event.observed_evidence)
    sender = session_row.sender_id if session_row else "unknown"
    recipient = session_row.recipient_id if session_row else "unknown"
    message_preview = ""
    if session_row and session_row.message:
        raw = session_row.message
        message_preview = raw[:40] + "..." if len(raw) > 40 else raw

    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() + "Z",
        "severity": event.severity,
        "threat_type": event.threat_type,
        "headline": label,
        "sentence": f"A message from {sender} to {recipient} was flagged: {label.lower()}.",
        "detail": impact,
        "message_preview": message_preview,
        "sender": sender,
        "recipient": recipient,
    }


@router.get("/overview")
def get_overview(db: DBSession = Depends(get_db)):
    since_24h = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)

    counts = crud.get_threat_counts_by_severity(db, since=since_24h)
    critical_count = counts.get("critical", 0)
    suspicious_count = counts.get("suspicious", 0)

    recent_sessions = crud.list_sessions(db, limit=1)
    current_status = "clean"
    last_assessed_at = None
    last_verdict = None
    if recent_sessions:
        latest = recent_sessions[0]
        current_status = latest.threat_level
        last_assessed_at = latest.timestamp.isoformat() + "Z"
        last_verdict = latest.verdict

    sessions_today = crud.get_sessions_since(db, since=since_24h)
    total_today = len(sessions_today)
    rejected_today = sum(1 for s in sessions_today if s.verdict == "REJECT")

    return {
        "current_status": current_status,
        "last_assessed_at": last_assessed_at,
        "last_verdict": last_verdict,
        "threat_counts_24h": {
            "critical": critical_count,
            "suspicious": suspicious_count,
            "total_threats": critical_count + suspicious_count,
        },
        "sessions_24h": {
            "total": total_today,
            "rejected": rejected_today,
            "accepted": total_today - rejected_today,
        },
    }


@router.get("/threat-feed")
def get_threat_feed(limit: int = 30, db: DBSession = Depends(get_db)):
    events = crud.list_threat_events(db, limit=limit)
    result = []
    for event in events:
        session_row = crud.get_session(db, event.session_id)
        result.append(_plain_english_event(event, session_row))
    return {"events": result, "total": len(result)}


@router.get("/trends")
def get_trends(db: DBSession = Depends(get_db)):
    since_24h = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    since_7d = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)

    sessions_24h = crud.get_sessions_since(db, since=since_24h)
    sessions_7d = crud.get_sessions_since(db, since=since_7d)

    use_hourly = len(sessions_24h) > 0

    if use_hourly:
        buckets: dict[str, dict] = {}
        for session in sessions_24h:
            hour_key = session.timestamp.strftime("%Y-%m-%dT%H:00")
            if hour_key not in buckets:
                buckets[hour_key] = {"hour": hour_key, "total": 0, "rejected": 0, "accepted": 0}
            buckets[hour_key]["total"] += 1
            if session.verdict == "REJECT":
                buckets[hour_key]["rejected"] += 1
            else:
                buckets[hour_key]["accepted"] += 1
        time_series = sorted(buckets.values(), key=lambda x: x["hour"])
        time_granularity = "hourly"
    else:
        buckets_7d: dict[str, dict] = {}
        for session in sessions_7d:
            day_key = session.timestamp.strftime("%Y-%m-%d")
            if day_key not in buckets_7d:
                buckets_7d[day_key] = {"hour": day_key, "total": 0, "rejected": 0, "accepted": 0}
            buckets_7d[day_key]["total"] += 1
            if session.verdict == "REJECT":
                buckets_7d[day_key]["rejected"] += 1
            else:
                buckets_7d[day_key]["accepted"] += 1
        time_series = sorted(buckets_7d.values(), key=lambda x: x["hour"])
        time_granularity = "daily"

    breakdown = crud.get_threat_type_breakdown(db, since=since_7d)
    threat_breakdown = [
        {"type": THREAT_TYPE_PLAIN_LABELS.get(k, k), "raw_type": k, "count": v}
        for k, v in sorted(breakdown.items(), key=lambda x: x[1], reverse=True)
    ]

    return {
        "time_series": time_series,
        "time_granularity": time_granularity,
        "threat_breakdown": threat_breakdown,
    }


@router.get("/sessions")
def get_sessions(limit: int = 50, db: DBSession = Depends(get_db)):
    session_records = crud.list_sessions(db, limit=limit)
    result = []
    for s in session_records:
        result.append({
            "id": s.id,
            "timestamp": s.timestamp.isoformat() + "Z",
            "sender_id": s.sender_id,
            "recipient_id": s.recipient_id,
            "message": s.message,
            "verification_mode": s.verification_mode,
            "threat_level": s.threat_level,
            "verdict": s.verdict,
            "mismatch_rate": s.mismatch_rate,
            "threshold": s.threshold,
            "confidence_upper_bound": s.confidence_upper_bound,
            "mean_fidelity": s.mean_fidelity,
            "attack_type": s.attack_type,
            "raw_assessment_string": s.raw_assessment_string,
        })
    return {"sessions": result, "total": len(result)}


@router.get("/logs/{session_id}")
def get_session_logs(session_id: str, db: DBSession = Depends(get_db)):
    session_record = crud.get_session(db, session_id)
    log_records = crud.get_telemetry_logs_for_session(db, session_id)
    
    formatted_logs = []
    for log in log_records:
        formatted_logs.append({
            "id": log.id,
            "session_id": log.session_id,
            "position_index": log.position_index,
            "basis": log.basis,
            "bell_outcome": log.bell_outcome,
            "expected_correction": log.expected_correction,
            "actual_correction": log.actual_correction,
            "fidelity": log.fidelity,
            "match": log.match,
        })

    session_info = None
    if session_record:
        session_info = {
            "id": session_record.id,
            "timestamp": session_record.timestamp.isoformat() + "Z",
            "sender_id": session_record.sender_id,
            "recipient_id": session_record.recipient_id,
            "message": session_record.message,
            "verification_mode": session_record.verification_mode,
            "threat_level": session_record.threat_level,
            "verdict": session_record.verdict,
            "attack_type": session_record.attack_type,
        }

    return {
        "session": session_info,
        "logs": formatted_logs,
        "total": len(formatted_logs),
    }


@router.get("/logs")
def get_recent_logs(limit: int = 100, db: DBSession = Depends(get_db)):
    log_records = crud.list_telemetry_logs(db, limit=limit)
    formatted_logs = []
    for log in log_records:
        formatted_logs.append({
            "id": log.id,
            "session_id": log.session_id,
            "position_index": log.position_index,
            "basis": log.basis,
            "bell_outcome": log.bell_outcome,
            "expected_correction": log.expected_correction,
            "actual_correction": log.actual_correction,
            "fidelity": log.fidelity,
            "match": log.match,
        })
    return {"logs": formatted_logs, "total": len(formatted_logs)}



@router.get("/audit/verify")
def verify_audit_chain():
    """Report whether the Mongo audit log is intact.

    `enabled` is false when no MONGODB_URI is configured, in which case the
    app is running on SQLite alone and there is no chain to check.
    """
    from app.database.mongo_audit import get_audit_sink

    return get_audit_sink().verify_chain()
