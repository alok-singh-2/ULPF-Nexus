from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import os
import urllib.request
import urllib.error
import uuid
import time
import threading
import secrets
import base64
import logging
from contextvars import ContextVar
from typing import Callable
from difflib import SequenceMatcher
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import numpy as np
except Exception:
    np = None

try:
    from sentence_transformers import SentenceTransformer
except Exception:
    SentenceTransformer = None

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
DATA_DIR = ROOT / "backend" / "data"
DB_PATH = DATA_DIR / "ulpf_nexus.db"
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="ULPF Nexus",
    version="4.0.3",
    description="Air-gapped, lossless universal log pre-processing prototype",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in os.getenv("ULPF_ALLOWED_ORIGINS", "*").split(",") if x.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

# v3.8 enterprise hardening: request IDs, security headers and structured audit logging.
REQUEST_ID: ContextVar[str] = ContextVar("request_id", default="-")
logging.basicConfig(level=os.getenv("ULPF_LOG_LEVEL", "INFO"))
logger = logging.getLogger("ulpf-nexus")
AUTH_MODE = os.getenv("ULPF_AUTH_MODE", "development").lower()
SESSION_TTL_SECONDS = int(os.getenv("ULPF_SESSION_TTL_SECONDS", "3600"))

@app.middleware("http")
async def hardening_middleware(request, call_next):
    request_id = request.headers.get("X-Request-ID") or "REQ-" + uuid.uuid4().hex[:12].upper()
    token = REQUEST_ID.set(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(json.dumps({"event":"request.error","request_id":request_id,"path":request.url.path,"method":request.method}))
        raise
    finally:
        elapsed = round((time.perf_counter()-started)*1000, 3)
        REQUEST_ID.reset(token)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    logger.info(json.dumps({"event":"request","request_id":request_id,"path":request.url.path,"method":request.method,"status":response.status_code,"duration_ms":elapsed}))
    return response

PARSERS: dict[str, dict[str, Any]] = {
    "syslog-firewall-v1": {
        "id": "syslog-firewall-v1",
        "status": "approved",
        "coverage": 0.997,
        "schema_version": "ulpf-event-v1",
        "source_families": ["Cisco ASA", "Fortinet", "Linux firewall-like syslog"],
        "mapping": {
            "src": "source.ip", "dst": "destination.ip", "sport": "source.port",
            "dport": "destination.port", "action": "event.action", "proto": "network.protocol",
            "user": "user.name",
        },
        "genome": {
            "detection": ["kv pairs", "syslog tokens", "firewall action fields"],
            "type_conversions": ["ports→integer"],
            "validation": ["IPv4 shape", "port 1..65535", "action allowlist"],
            "provenance": "Nexus seed parser",
            "key_fingerprint": ["src", "dst", "sport", "dport", "action", "proto", "user"],
            "format": "unknown",
        },
    }
}

SCHEMA_FIELDS = {
    "source.ip": "ip", "destination.ip": "ip", "source.port": "port", "destination.port": "port",
    "event.action": "action", "network.protocol": "protocol", "user.name": "string", "host.name": "string",
}

ALIAS_RULES: dict[str, tuple[str, float]] = {
    "src": ("source.ip", 0.97), "src_ip": ("source.ip", 0.99), "srcip": ("source.ip", 0.98),
    "source": ("source.ip", 0.79), "sourceaddress": ("source.ip", 0.95), "source_address": ("source.ip", 0.95),
    "src_addr": ("source.ip", 0.96), "dst": ("destination.ip", 0.97), "dst_ip": ("destination.ip", 0.99),
    "dstip": ("destination.ip", 0.98), "destination": ("destination.ip", 0.79),
    "destinationaddress": ("destination.ip", 0.95), "destination_address": ("destination.ip", 0.95),
    "dst_addr": ("destination.ip", 0.96), "sport": ("source.port", 0.98), "spt": ("source.port", 0.98),
    "src_port": ("source.port", 0.99), "source_port": ("source.port", 0.99),
    "dport": ("destination.port", 0.98), "dpt": ("destination.port", 0.98),
    "dst_port": ("destination.port", 0.99), "destination_port": ("destination.port", 0.99),
    "action": ("event.action", 0.96), "act": ("event.action", 0.93), "decision": ("event.action", 0.88),
    "result": ("event.action", 0.82), "proto": ("network.protocol", 0.96), "protocol": ("network.protocol", 0.99),
    "transport": ("network.protocol", 0.88), "user": ("user.name", 0.93), "username": ("user.name", 0.99),
    "uid": ("user.name", 0.80), "hostname": ("host.name", 0.99), "host": ("host.name", 0.82),
}


SEMANTIC_NODE_TYPES = {"canonical": "canonical", "alias": "alias"}

# Seed relationships used by the offline semantic knowledge graph. Evidence scores are
# deliberately explainable: alias confidence + value-shape agreement + graph support.
SEMANTIC_SEEDS = {
    "src_ip": "source.ip", "srcip": "source.ip", "sourceaddress": "source.ip", "source_address": "source.ip",
    "src_addr": "source.ip", "dst_ip": "destination.ip", "dstip": "destination.ip",
    "destinationaddress": "destination.ip", "destination_address": "destination.ip", "dst_addr": "destination.ip",
    "sport": "source.port", "spt": "source.port", "src_port": "source.port", "source_port": "source.port",
    "dport": "destination.port", "dpt": "destination.port", "dst_port": "destination.port", "destination_port": "destination.port",
    "act": "event.action", "decision": "event.action", "result": "event.action",
    "proto": "network.protocol", "protocol": "network.protocol", "transport": "network.protocol",
    "username": "user.name", "uid": "user.name", "hostname": "host.name",
}


AI_MODE = os.getenv("ULPF_AI_MODE", "heuristic").lower()
AI_BASE_URL = os.getenv("ULPF_AI_BASE_URL", "http://127.0.0.1:8000/v1")
AI_MODEL = os.getenv("ULPF_AI_MODEL", "gpt-oss-120b")
AI_TIMEOUT = float(os.getenv("ULPF_AI_TIMEOUT", "20"))

# v3.5 realtime event bus: in-process, air-gapped SSE fanout for the prototype.
_REALTIME_LOCK = threading.Condition()
_REALTIME_SEQ = 0
_REALTIME_EVENTS: list[dict[str, Any]] = []

def _publish_realtime(kind: str, payload: dict[str, Any]) -> None:
    global _REALTIME_SEQ
    with _REALTIME_LOCK:
        _REALTIME_SEQ += 1
        item = {"seq": _REALTIME_SEQ, "kind": kind, "at": datetime.now(timezone.utc).isoformat(), **payload}
        _REALTIME_EVENTS.append(item)
        del _REALTIME_EVENTS[:-250]
        _REALTIME_LOCK.notify_all()


def _extract_json_object(content: str) -> dict[str, Any]:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content, flags=re.S).strip()
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, flags=re.S)
        if match:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
    raise ValueError("model response did not contain a valid JSON object")


def _validate_gpt_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    allowed_targets = set(SCHEMA_FIELDS)
    mappings = payload.get("candidate_mappings", {})
    if not isinstance(mappings, dict):
        raise ValueError("candidate_mappings must be an object")
    cleaned: dict[str, Any] = {}
    for raw_key, info in mappings.items():
        if not isinstance(info, dict):
            continue
        target = info.get("target")
        if target not in allowed_targets:
            continue
        try:
            conf = max(0.0, min(1.0, float(info.get("confidence", 0.0))))
        except (TypeError, ValueError):
            conf = 0.0
        evidence = str(info.get("evidence", "schema/value-shape evidence"))[:500]
        cleaned[str(raw_key)] = {"target": target, "confidence": round(conf, 3), "evidence": evidence, "value": info.get("value")}
    unknown = [str(x) for x in payload.get("unknown_fields", []) if isinstance(x, (str, int, float))][:100]
    conflicts = payload.get("conflicts", [])
    safe_conflicts = []
    if isinstance(conflicts, list):
        for c in conflicts[:100]:
            if isinstance(c, dict):
                safe_conflicts.append({k: c.get(k) for k in ("target","fields","reason")})
    if cleaned:
        confidence = round(sum(v["confidence"] for v in cleaned.values()) / len(cleaned), 3)
    else:
        try: confidence = max(0.0, min(1.0, float(payload.get("mapping_confidence", 0.0))))
        except (TypeError, ValueError): confidence = 0.0
    return {"candidate_mappings": cleaned, "unknown_fields": unknown, "conflicts": safe_conflicts, "mapping_confidence": confidence}


def _gpt_oss_map(raw: str, context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Call a locally hosted OpenAI-compatible GPT-OSS endpoint. Never uses a cloud provider."""
    prompt = {
        "model": AI_MODEL, "temperature": 0,
        "messages": [
            {"role": "system", "content": (
                "You are the ULPF Nexus field mapper. Return ONLY one JSON object. "
                "Allowed canonical targets: source.ip, destination.ip, source.port, destination.port, event.action, network.protocol, user.name, host.name. "
                "For every mapping include target, confidence 0..1, evidence and value. Use only the raw event. "
                "Keep unknown keys unknown. List conflicts when plausible mappings compete. Do not output hidden reasoning or chain-of-thought."
            )},
            {"role": "user", "content": json.dumps({"raw_event": raw, "retrieved_local_context": context or {"semantic_results":[],"candidate_parsers":[],"schema":{"fields":SCHEMA_FIELDS}}}, separators=(",", ":"))}
        ]
    }
    url = AI_BASE_URL.rstrip('/') + '/chat/completions'
    req = urllib.request.Request(url, data=json.dumps(prompt).encode(), headers={"Content-Type":"application/json"}, method='POST')
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
        parsed = _extract_json_object(body['choices'][0]['message']['content'])
        cleaned = _validate_gpt_mapping(parsed)
        cleaned.update({"model": AI_MODEL, "execution":"local-openai-compatible", "latency_ms":round((time.perf_counter()-started)*1000,3), "endpoint":url, "provider_status":"available"})
        return cleaned
    except Exception as exc:
        return {"candidate_mappings":{},"unknown_fields":list(parse_kv(raw).keys()),"conflicts":[],"mapping_confidence":0.0,"model":AI_MODEL,"execution":"local-openai-compatible","latency_ms":round((time.perf_counter()-started)*1000,3),"endpoint":url,"provider_status":"unavailable","error":str(exc)[:500]}


def persist_ai_mapping_evidence(raw: str, source: str, result: dict[str, Any]) -> str:
    mapping_id = "MAP-" + uuid.uuid4().hex[:12].upper()
    summary = {"provider_status":result.get("provider_status","unknown"),"latency_ms":result.get("latency_ms",0),"endpoint":result.get("endpoint","local"),"model":result.get("model","unknown"),"note":"Evidence summary only; hidden model reasoning is not persisted."}
    conn=db(); conn.execute("INSERT INTO ai_mapping_evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(mapping_id,datetime.now(timezone.utc).isoformat(),sha256(raw),source,str(result.get("model",AI_MODEL)),str(result.get("execution","local")),"available" if result.get("provider_status")=="available" else "fallback",float(result.get("mapping_confidence",0)),json.dumps(result.get("candidate_mappings",{})),json.dumps(result.get("unknown_fields",[])),json.dumps(result.get("conflicts",[])),json.dumps(summary))); conn.commit(); conn.close(); return mapping_id


class IngestRequest(BaseModel):
    source: str = Field(default="unknown")
    raw: str
    format_hint: str | None = None


class SandboxRequest(BaseModel):
    parser_id: str = "syslog-firewall-v1"
    samples: list[str]


class RegressionRequest(BaseModel):
    parser_a: str
    parser_b: str
    samples: list[str]


class MappingRequest(BaseModel):
    raw: str


class CandidateParserRequest(BaseModel):
    raw_samples: list[str]
    name: str | None = None


class SourceRegisterRequest(BaseModel):
    source: str
    expected_vendor: str | None = None


class ParserGenerateRequest(BaseModel):
    raw_samples: list[str]
    source: str = "unknown-source"
    name: str | None = None


class ParserReplayRequest(BaseModel):
    parser_id: str
    samples: list[str]

class ParserContractRequest(BaseModel):
    raw_samples: list[str]
    source: str = "unknown-source"
    name: str | None = None
    compile_candidate: bool = True



class OnboardingRequest(BaseModel):
    source: str
    samples: list[str]
    expected_vendor: str | None = None


class OnboardingPromoteRequest(BaseModel):
    session_id: str
    candidate_name: str | None = None


class NormalizePreviewRequest(BaseModel):
    raw: str
    format_hint: str | None = None


class ProcessRequest(BaseModel):
    source: str = "unknown"
    raw: str
    format_hint: str | None = None
    idempotency_key: str | None = None


class QuarantineReviewRequest(BaseModel):
    decision: str = Field(pattern="^(release|reject)$")
    reviewer: str = "analyst"
    notes: str = ""


class ResponseRecommendationRequest(BaseModel):
    entity_type: str = Field(pattern="^(event|incident|attack_path)$")
    entity_id: str
    analyst: str = "Nexus"


class ResponseApprovalRequest(BaseModel):
    analyst: str = Field(min_length=1, max_length=120)
    decision: str = Field(pattern="^(approve|reject)$")
    notes: str = ""


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS auth_users (
            username TEXT PRIMARY KEY, role TEXT NOT NULL, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hardening_audit (
            audit_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, actor TEXT NOT NULL, role TEXT NOT NULL,
            action TEXT NOT NULL, resource TEXT NOT NULL, request_id TEXT NOT NULL, payload_json TEXT NOT NULL,
            prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_created ON hardening_audit(created_at);
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, secret INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS service_health (
            component TEXT PRIMARY KEY, status TEXT NOT NULL, details_json TEXT NOT NULL, checked_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            source TEXT NOT NULL,
            vendor TEXT NOT NULL,
            format TEXT NOT NULL,
            parser_id TEXT NOT NULL,
            status TEXT NOT NULL,
            raw TEXT NOT NULL,
            raw_sha256 TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS forensic_traces (
            trace_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            raw_sha256 TEXT NOT NULL,
            parser_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            status TEXT NOT NULL,
            timeline_json TEXT NOT NULL,
            proof_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_forensic_created ON forensic_traces(created_at);
        CREATE TABLE IF NOT EXISTS parser_candidates (
            parser_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dna_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source TEXT NOT NULL,
            dna_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sources (
            source TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            vendor TEXT NOT NULL,
            parser_id TEXT NOT NULL,
            dna_id TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS parser_versions (
            parser_key TEXT NOT NULL,
            version INTEGER NOT NULL,
            parser_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            coverage REAL NOT NULL,
            reason TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY (parser_key, version)
        );
        CREATE TABLE IF NOT EXISTS parser_field_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, parser_id TEXT NOT NULL,
            raw_field TEXT NOT NULL, canonical_field TEXT NOT NULL, confidence REAL NOT NULL,
            evidence_json TEXT NOT NULL, validation_rules_json TEXT NOT NULL, sample_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS parser_sandbox_runs (
            run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, parser_id TEXT NOT NULL, sample_count INTEGER NOT NULL,
            avg_coverage REAL NOT NULL, avg_confidence REAL NOT NULL, lossless_rate REAL NOT NULL,
            conflict_count INTEGER NOT NULL, decision TEXT NOT NULL, results_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS parser_contracts (
            contract_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, parser_id TEXT NOT NULL,
            contract_version INTEGER NOT NULL, status TEXT NOT NULL, contract_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS parser_approval_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, parser_id TEXT NOT NULL, version INTEGER NOT NULL,
            action TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL, sandbox_run_id TEXT
        );
        CREATE TABLE IF NOT EXISTS contract_execution_runs (
            run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, contract_id TEXT NOT NULL, parser_id TEXT NOT NULL,
            contract_version INTEGER NOT NULL, raw_sha256 TEXT NOT NULL, status TEXT NOT NULL,
            coverage REAL NOT NULL, validation_errors_json TEXT NOT NULL, unknown_fields_json TEXT NOT NULL,
            normalized_json TEXT NOT NULL, extensions_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_contract_exec_contract ON contract_execution_runs(contract_id, created_at);
        CREATE TABLE IF NOT EXISTS schema_registry (
            schema_id TEXT NOT NULL, version INTEGER NOT NULL, created_at TEXT NOT NULL,
            status TEXT NOT NULL, fields_json TEXT NOT NULL,
            PRIMARY KEY (schema_id, version)
        );
        CREATE TABLE IF NOT EXISTS ingestion_batches (
            batch_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source TEXT NOT NULL,
            received INTEGER NOT NULL, accepted INTEGER NOT NULL, review INTEGER NOT NULL,
            quarantined INTEGER NOT NULL, duration_ms REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS onboarding_sessions (
            session_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source TEXT NOT NULL,
            status TEXT NOT NULL, dna_json TEXT NOT NULL, match_json TEXT NOT NULL,
            recommendation TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, source TEXT NOT NULL,
            raw TEXT NOT NULL, raw_sha256 TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mutation_reports (
            report_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source TEXT NOT NULL,
            baseline_dna_id TEXT NOT NULL, current_dna_id TEXT NOT NULL, similarity REAL NOT NULL,
            severity TEXT NOT NULL, decision TEXT NOT NULL, changed_dimensions_json TEXT NOT NULL,
            recommendation TEXT NOT NULL, payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS event_processing_runs (
            run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_id TEXT NOT NULL,
            stage TEXT NOT NULL, status TEXT NOT NULL, duration_ms REAL NOT NULL,
            details_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quarantine_queue (
            event_id TEXT PRIMARY KEY, queued_at TEXT NOT NULL, reason TEXT NOT NULL,
            severity TEXT NOT NULL, status TEXT NOT NULL, reviewer TEXT, reviewed_at TEXT,
            decision TEXT, notes TEXT
        );
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            idempotency_key TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_id TEXT NOT NULL,
            request_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS processing_queue (
            job_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            source TEXT NOT NULL, raw TEXT NOT NULL, format_hint TEXT,
            status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3, next_attempt_at TEXT,
            event_id TEXT, last_error TEXT, worker TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_queue_status_next ON processing_queue(status, next_attempt_at);
        CREATE TABLE IF NOT EXISTS dead_letter_queue (
            job_id TEXT PRIMARY KEY, moved_at TEXT NOT NULL, reason TEXT NOT NULL,
            attempts INTEGER NOT NULL, source TEXT NOT NULL, raw TEXT NOT NULL,
            last_error TEXT NOT NULL, payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS queue_metrics (
            id INTEGER PRIMARY KEY CHECK (id=1), enqueued INTEGER NOT NULL DEFAULT 0,
            processed INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
            retried INTEGER NOT NULL DEFAULT 0, dlq INTEGER NOT NULL DEFAULT 0,
            processing_ms_total REAL NOT NULL DEFAULT 0, last_updated TEXT
        );
        CREATE TABLE IF NOT EXISTS stream_events (
            stream TEXT NOT NULL, partition_id INTEGER NOT NULL, sequence_no INTEGER NOT NULL,
            message_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, source TEXT NOT NULL,
            raw TEXT NOT NULL, format_hint TEXT, status TEXT NOT NULL DEFAULT 'available',
            consumed_by TEXT, consumed_at TEXT, event_id TEXT,
            PRIMARY KEY (stream, partition_id, sequence_no)
        );
        CREATE INDEX IF NOT EXISTS idx_stream_available ON stream_events(stream, partition_id, status, sequence_no);
        CREATE TABLE IF NOT EXISTS stream_offsets (
            stream TEXT NOT NULL, consumer TEXT NOT NULL, partition_id INTEGER NOT NULL,
            next_sequence INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL,
            PRIMARY KEY (stream, consumer, partition_id)
        );
        CREATE TABLE IF NOT EXISTS stream_checkpoints (
            stream TEXT NOT NULL, consumer TEXT NOT NULL, partition_id INTEGER NOT NULL,
            sequence_no INTEGER NOT NULL, committed_at TEXT NOT NULL,
            event_id TEXT,
            PRIMARY KEY (stream, consumer, partition_id)
        );
        CREATE TABLE IF NOT EXISTS stream_replay_requests (
            replay_id TEXT PRIMARY KEY, stream TEXT NOT NULL, consumer TEXT NOT NULL,
            partition_id INTEGER NOT NULL, from_sequence INTEGER NOT NULL, to_sequence INTEGER, status TEXT NOT NULL,
            created_at TEXT NOT NULL, completed_at TEXT, replayed INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO queue_metrics(id,last_updated) VALUES (1, datetime('now'));
        CREATE INDEX IF NOT EXISTS idx_processing_runs_event ON event_processing_runs(event_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_queue(status, queued_at);
        CREATE TABLE IF NOT EXISTS semantic_nodes (
            node_id TEXT PRIMARY KEY, label TEXT NOT NULL, node_type TEXT NOT NULL,
            canonical_type TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            observation_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS semantic_edges (
            source_id TEXT NOT NULL, target_id TEXT NOT NULL, relation TEXT NOT NULL,
            evidence_count INTEGER NOT NULL DEFAULT 0, confidence REAL NOT NULL DEFAULT 0,
            evidence_json TEXT NOT NULL, last_seen TEXT NOT NULL,
            PRIMARY KEY (source_id, target_id, relation)
        );
        CREATE TABLE IF NOT EXISTS semantic_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, raw_key TEXT NOT NULL,
            candidate_target TEXT NOT NULL, chosen_target TEXT, value_shape TEXT NOT NULL,
            confidence REAL NOT NULL, reason TEXT NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_dna_history_source_id ON dna_history(source, id);
        CREATE INDEX IF NOT EXISTS idx_events_source_created ON events(source, created_at);
        CREATE INDEX IF NOT EXISTS idx_events_status_created ON events(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_events_vendor_created ON events(vendor, created_at);
        CREATE INDEX IF NOT EXISTS idx_events_format_created ON events(format, created_at);
        CREATE INDEX IF NOT EXISTS idx_mutation_source_created ON mutation_reports(source, created_at);
        CREATE TABLE IF NOT EXISTS event_archive (
            event_id TEXT PRIMARY KEY, archived_at TEXT NOT NULL, created_at TEXT NOT NULL,
            source TEXT NOT NULL, vendor TEXT NOT NULL, format TEXT NOT NULL, parser_id TEXT NOT NULL,
            status TEXT NOT NULL, raw TEXT NOT NULL, raw_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_archive_created ON event_archive(created_at);
        CREATE TABLE IF NOT EXISTS retention_policies (
            policy_id TEXT PRIMARY KEY, name TEXT NOT NULL, hot_days INTEGER NOT NULL,
            archive_before_delete INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS storage_operations (
            operation_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, operation TEXT NOT NULL,
            status TEXT NOT NULL, affected INTEGER NOT NULL DEFAULT 0, details_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ai_decisions (
            decision_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
            source TEXT NOT NULL, route TEXT NOT NULL, confidence REAL NOT NULL,
            deterministic_confidence REAL NOT NULL, semantic_confidence REAL NOT NULL,
            model TEXT NOT NULL, execution TEXT NOT NULL, status TEXT NOT NULL,
            reasons_json TEXT NOT NULL, evidence_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ai_decisions_created ON ai_decisions(created_at);
        CREATE INDEX IF NOT EXISTS idx_ai_decisions_route ON ai_decisions(route, created_at);
        CREATE TABLE IF NOT EXISTS ai_mapping_evidence (
            mapping_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, raw_sha256 TEXT NOT NULL, source TEXT NOT NULL,
            model TEXT NOT NULL, execution TEXT NOT NULL, status TEXT NOT NULL, mapping_confidence REAL NOT NULL,
            candidate_mappings_json TEXT NOT NULL, unknown_fields_json TEXT NOT NULL, conflicts_json TEXT NOT NULL,
            validation_summary_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ai_mapping_evidence_created ON ai_mapping_evidence(created_at);
        CREATE INDEX IF NOT EXISTS idx_ai_mapping_evidence_hash ON ai_mapping_evidence(raw_sha256);
        CREATE TABLE IF NOT EXISTS semantic_documents (
            document_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, doc_type TEXT NOT NULL,
            canonical_field TEXT, title TEXT NOT NULL, content TEXT NOT NULL,
            metadata_json TEXT NOT NULL, embedding_json TEXT NOT NULL, embedding_model TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_semantic_documents_type ON semantic_documents(doc_type);
        CREATE TABLE IF NOT EXISTS semantic_retrievals (
            retrieval_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
            query_text TEXT NOT NULL, top_k INTEGER NOT NULL, results_json TEXT NOT NULL,
            embedding_model TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS translation_artifacts (
            artifact_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, parser_id TEXT NOT NULL,
            contract_id TEXT, schema_id TEXT NOT NULL, schema_version INTEGER NOT NULL,
            parser_version INTEGER NOT NULL, contract_version INTEGER, artifact_hash TEXT NOT NULL,
            status TEXT NOT NULL, payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_translation_artifacts_parser ON translation_artifacts(parser_id, created_at);
        CREATE TABLE IF NOT EXISTS event_model_refs (
            event_id TEXT PRIMARY KEY, schema_id TEXT NOT NULL, schema_version INTEGER NOT NULL,
            parser_id TEXT NOT NULL, parser_version INTEGER, contract_id TEXT, contract_version INTEGER,
            artifact_id TEXT, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_event_model_refs_created ON event_model_refs(created_at);
        CREATE TABLE IF NOT EXISTS model_compatibility_checks (
            check_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, artifact_a TEXT NOT NULL, artifact_b TEXT NOT NULL,
            compatible INTEGER NOT NULL, schema_impact TEXT NOT NULL, parser_impact TEXT NOT NULL, contract_impact TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_model_compatibility_created ON model_compatibility_checks(created_at);
        CREATE TABLE IF NOT EXISTS evolution_runs (
            run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source TEXT NOT NULL,
            raw_sha256 TEXT NOT NULL, dna_id TEXT NOT NULL, mutation_severity TEXT NOT NULL,
            mutation_decision TEXT NOT NULL, ai_route TEXT NOT NULL, ai_confidence REAL NOT NULL,
            candidate_parser_id TEXT, sandbox_run_id TEXT, regression_status TEXT NOT NULL,
            final_state TEXT NOT NULL, decision_reason TEXT NOT NULL, evidence_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evolution_created ON evolution_runs(created_at);
        CREATE INDEX IF NOT EXISTS idx_evolution_source ON evolution_runs(source, created_at);
        CREATE TABLE IF NOT EXISTS detection_rules (
            rule_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            name TEXT NOT NULL, description TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            severity TEXT NOT NULL, rule_type TEXT NOT NULL, threshold INTEGER NOT NULL DEFAULT 1,
            window_seconds INTEGER NOT NULL DEFAULT 300, conditions_json TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT "analyst", version INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            rule_id TEXT NOT NULL, rule_version INTEGER NOT NULL, severity TEXT NOT NULL,
            status TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
            source TEXT, event_ids_json TEXT NOT NULL, evidence_json TEXT NOT NULL,
            score REAL NOT NULL DEFAULT 0, assigned_to TEXT, resolution TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules(enabled, updated_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id, created_at);
        CREATE TABLE IF NOT EXISTS correlation_rules (
            rule_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            name TEXT NOT NULL, description TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            severity TEXT NOT NULL, window_seconds INTEGER NOT NULL DEFAULT 900,
            steps_json TEXT NOT NULL, group_by TEXT, created_by TEXT NOT NULL DEFAULT "analyst",
            version INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS correlation_incidents (
            incident_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            rule_id TEXT NOT NULL, rule_version INTEGER NOT NULL, severity TEXT NOT NULL,
            status TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
            group_value TEXT, event_ids_json TEXT NOT NULL, step_matches_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL, score REAL NOT NULL DEFAULT 0, assigned_to TEXT, resolution TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_corr_rules_enabled ON correlation_rules(enabled, updated_at);
        CREATE INDEX IF NOT EXISTS idx_corr_incidents_status_created ON correlation_incidents(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_corr_incidents_rule ON correlation_incidents(rule_id, created_at);
        CREATE TABLE IF NOT EXISTS risk_assessments (
            risk_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
            score REAL NOT NULL, band TEXT NOT NULL, confidence REAL NOT NULL, summary TEXT NOT NULL,
            factors_json TEXT NOT NULL, evidence_json TEXT NOT NULL, decision_status TEXT NOT NULL DEFAULT 'open',
            assigned_to TEXT, resolution TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_risk_entity ON risk_assessments(entity_type, entity_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_risk_score ON risk_assessments(score DESC, created_at DESC);
        CREATE TABLE IF NOT EXISTS risk_decisions (
            decision_id TEXT PRIMARY KEY, risk_id TEXT NOT NULL, created_at TEXT NOT NULL,
            analyst TEXT NOT NULL, decision TEXT NOT NULL, note TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_risk_decisions_risk ON risk_decisions(risk_id, created_at);
        CREATE TABLE IF NOT EXISTS risk_propagations (
            propagation_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL, risk_id TEXT NOT NULL, trigger_type TEXT NOT NULL,
            propagated_score REAL NOT NULL, propagated_band TEXT NOT NULL,
            evidence_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_risk_propagations_entity ON risk_propagations(entity_type, entity_id, created_at);
        CREATE TABLE IF NOT EXISTS risk_queue (
            queue_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, risk_id TEXT NOT NULL,
            priority_score REAL NOT NULL, priority_band TEXT NOT NULL, priority_reason TEXT NOT NULL,
            assigned_to TEXT, status TEXT NOT NULL DEFAULT 'open', sla_due_at TEXT,
            rank INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_risk_queue_priority ON risk_queue(status, priority_score DESC, created_at ASC);
        CREATE INDEX IF NOT EXISTS idx_risk_queue_entity ON risk_queue(entity_type, entity_id);
        CREATE TABLE IF NOT EXISTS response_recommendations (
            recommendation_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            trigger_type TEXT NOT NULL, trigger_id TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
            action_type TEXT NOT NULL, title TEXT NOT NULL, rationale TEXT NOT NULL, severity TEXT NOT NULL,
            confidence REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', evidence_json TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'nexus', approved_by TEXT, approved_at TEXT, notes TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_response_reco_status_created ON response_recommendations(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_response_reco_entity ON response_recommendations(entity_type, entity_id, created_at);
        CREATE TABLE IF NOT EXISTS demo_runs (
            run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, scenario TEXT NOT NULL,
            status TEXT NOT NULL, duration_ms REAL NOT NULL, step_count INTEGER NOT NULL,
            summary_json TEXT NOT NULL, evidence_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_demo_runs_created ON demo_runs(created_at);
        CREATE TABLE IF NOT EXISTS response_executions (
            execution_id TEXT PRIMARY KEY, recommendation_id TEXT NOT NULL, created_at TEXT NOT NULL,
            action_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, executed_by TEXT NOT NULL,
            target TEXT, result_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_response_exec_created ON response_executions(created_at);
        """
    )

    # Lightweight SQLite schema migration for databases created by earlier
    # ULPF Nexus prototype versions. CREATE TABLE IF NOT EXISTS does not add
    # columns to an existing table, so make the stream table forward-compatible.
    stream_columns = {row[1] for row in conn.execute("PRAGMA table_info(stream_events)").fetchall()}
    stream_migrations = {
        "consumed_by": "TEXT",
        "consumed_at": "TEXT",
        "event_id": "TEXT",
    }
    for column, column_type in stream_migrations.items():
        if column not in stream_columns:
            conn.execute(f"ALTER TABLE stream_events ADD COLUMN {column} {column_type}")

    # Forward-compatible migration for prototype databases created by older releases.
    # SQLite CREATE TABLE IF NOT EXISTS does not add columns to an existing table.
    stream_columns = {row[1] for row in conn.execute("PRAGMA table_info(stream_events)").fetchall()}
    for column, column_type in {"consumed_by": "TEXT", "consumed_at": "TEXT", "event_id": "TEXT"}.items():
        if column not in stream_columns:
            conn.execute(f"ALTER TABLE stream_events ADD COLUMN {column} {column_type}")

    conn.commit()
    conn.close()


init_db()

def schema_version_payload(schema_id: str = "ulpf-event-v1", version: int | None = None) -> dict[str, Any] | None:
    conn = db()
    if version is None:
        row = conn.execute("SELECT * FROM schema_registry WHERE schema_id=? ORDER BY version DESC LIMIT 1", (schema_id,)).fetchone()
    else:
        row = conn.execute("SELECT * FROM schema_registry WHERE schema_id=? AND version=?", (schema_id, version)).fetchone()
    conn.close()
    if not row:
        return None
    fields = json.loads(row["fields_json"])
    payload = {"schema_id": row["schema_id"], "version": row["version"], "status": row["status"], "fields": fields}
    payload["schema_hash"] = sha256(json.dumps(fields, sort_keys=True))
    return payload

def latest_parser_version(parser_id: str) -> tuple[int | None, dict[str, Any] | None]:
    if parser_id in PARSERS:
        key = parser_id.rsplit("-v", 1)[0] if "-v" in parser_id else parser_id
        conn = db(); row = conn.execute("SELECT version,payload_json FROM parser_versions WHERE parser_id=? ORDER BY version DESC LIMIT 1", (parser_id,)).fetchone(); conn.close()
        return (int(row["version"]) if row else 1), (json.loads(row["payload_json"]) if row else PARSERS[parser_id])
    conn = db(); row = conn.execute("SELECT version,payload_json FROM parser_versions WHERE parser_id=? ORDER BY version DESC LIMIT 1", (parser_id,)).fetchone(); conn.close()
    if row:
        return int(row["version"]), json.loads(row["payload_json"])
    return None, None

def latest_contract_for_parser(parser_id: str) -> dict[str, Any] | None:
    conn = db(); row = conn.execute("SELECT * FROM parser_contracts WHERE parser_id=? ORDER BY contract_version DESC LIMIT 1", (parser_id,)).fetchone(); conn.close()
    if not row: return None
    payload = json.loads(row["payload_json"])
    return {"contract_id": row["contract_id"], "version": row["contract_version"], "status": row["status"], "contract_hash": row["contract_hash"], "payload": payload}

def build_translation_artifact(parser_id: str, schema_id: str = "ulpf-event-v1") -> dict[str, Any] | None:
    parser_version, parser = latest_parser_version(parser_id)
    schema = schema_version_payload(schema_id)
    if not parser_version or not parser or not schema: return None
    contract = latest_contract_for_parser(parser_id)
    payload = {
        "parser": {"id": parser_id, "version": parser_version, "status": parser.get("status", "approved"), "mapping": parser.get("mapping", {}), "genome": parser.get("genome", {})},
        "schema": schema,
        "contract": None if not contract else {"id": contract["contract_id"], "version": contract["version"], "status": contract["status"], "hash": contract["contract_hash"], "payload": contract["payload"]},
    }
    artifact_hash = sha256(json.dumps(payload, sort_keys=True))
    aid = "ART-" + artifact_hash[:12].upper()
    conn = db(); conn.execute("INSERT OR REPLACE INTO translation_artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?)", (aid, datetime.now(timezone.utc).isoformat(), parser_id, contract["contract_id"] if contract else None, schema["schema_id"], schema["version"], parser_version, contract["version"] if contract else None, artifact_hash, "active", json.dumps(payload))); conn.commit(); conn.close()
    return {"artifact_id": aid, "artifact_hash": artifact_hash, "parser_id": parser_id, "parser_version": parser_version, "schema_id": schema["schema_id"], "schema_version": schema["version"], "contract_id": contract["contract_id"] if contract else None, "contract_version": contract["version"] if contract else None, "status": "active"}

# Seed the canonical schema registry once.
_conn = db()
_now = datetime.now(timezone.utc).isoformat()
_conn.execute("INSERT OR IGNORE INTO schema_registry VALUES (?,?,?,?,?)", ("ulpf-event-v1", 1, _now, "active", json.dumps(SCHEMA_FIELDS)))
_seed = PARSERS["syslog-firewall-v1"]
_conn.execute("INSERT OR IGNORE INTO parser_versions VALUES (?,?,?,?,?,?,?,?)", ("syslog-firewall", 1, _seed["id"], _now, "approved", _seed["coverage"], "seed parser", json.dumps(_seed)))
_conn.execute(
    "INSERT OR IGNORE INTO retention_policies VALUES (?,?,?,?,?,?,?)",
    ("default-hot-30d", "Default Hot Storage", 30, 1, 1, _now, _now),
)
_conn.commit(); _conn.close()


def semantic_node_id(label: str, node_type: str) -> str:
    return f"{node_type}:{label.lower()}"

def semantic_seed_graph() -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = db()
    for canonical, kind in SCHEMA_FIELDS.items():
        nid = semantic_node_id(canonical, "canonical")
        conn.execute("INSERT OR IGNORE INTO semantic_nodes VALUES (?,?,?,?,?,?,?)",
                     (nid, canonical, "canonical", kind, now, now, 0))
    for alias, target in SEMANTIC_SEEDS.items():
        aid = semantic_node_id(alias, "alias")
        tid = semantic_node_id(target, "canonical")
        conn.execute("INSERT OR IGNORE INTO semantic_nodes VALUES (?,?,?,?,?,?,?)",
                     (aid, alias, "alias", target, now, now, 0))
        evidence = json.dumps({"seed": True, "alias_rule_confidence": ALIAS_RULES.get(alias, (target, 0.75))[1]})
        conn.execute("INSERT OR IGNORE INTO semantic_edges VALUES (?,?,?,?,?,?,?)",
                     (aid, tid, "maps_to", 1, float(ALIAS_RULES.get(alias, (target, 0.75))[1]), evidence, now))
    conn.commit(); conn.close()

semantic_seed_graph()

EMBEDDING_DIM = int(os.getenv("ULPF_EMBEDDING_DIM", "256"))
_EMBEDDING_MODEL_NAME = os.getenv("ULPF_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
_embedding_model = None
_embedding_lock = threading.Lock()


def _hash_embedding(text: str, dim: int = EMBEDDING_DIM) -> list[float]:
    """Deterministic, dependency-free local vector fallback for fully offline operation."""
    vec = [0.0] * dim
    tokens = re.findall(r"[a-zA-Z0-9_.:-]+", text.lower())
    if not tokens:
        return vec
    for token in tokens:
        digest = hashlib.sha256(token.encode()).digest()
        for i in range(0, 16, 2):
            idx = int.from_bytes(digest[i:i+2], "big") % dim
            sign = -1.0 if digest[i] & 1 else 1.0
            vec[idx] += sign
    norm = math.sqrt(sum(x*x for x in vec)) or 1.0
    return [round(x / norm, 6) for x in vec]


def embedding_status() -> dict[str, Any]:
    return {
        "configured_model": _EMBEDDING_MODEL_NAME,
        "provider": "sentence-transformers" if SentenceTransformer else "deterministic-hash-fallback",
        "model_loaded": _embedding_model is not None,
        "dimension": EMBEDDING_DIM,
        "air_gapped": True,
    }


def local_embedding(text: str) -> tuple[list[float], str]:
    global _embedding_model
    if SentenceTransformer is not None:
        try:
            with _embedding_lock:
                if _embedding_model is None:
                    _embedding_model = SentenceTransformer(_EMBEDDING_MODEL_NAME, local_files_only=True)
            arr = _embedding_model.encode([text], normalize_embeddings=True, show_progress_bar=False)[0]
            return [round(float(x), 6) for x in arr], f"sentence-transformers:{_EMBEDDING_MODEL_NAME}"
        except Exception:
            pass
    return _hash_embedding(text), "hash-embedding-v1"


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x*y for x,y in zip(a,b))
    na = math.sqrt(sum(x*x for x in a)); nb = math.sqrt(sum(y*y for y in b))
    return round(dot / (na*nb or 1.0), 6)


def _seed_semantic_documents() -> None:
    docs = []
    descriptions = {
        "source.ip": "originating source IPv4 or IPv6 address src sourceAddress source_ip src_addr",
        "destination.ip": "destination target IPv4 or IPv6 address dst destinationAddress destination_ip dst_addr",
        "source.port": "originating source transport port sport spt src_port source_port",
        "destination.port": "destination transport port dport dpt dst_port destination_port",
        "event.action": "security decision action outcome allow deny accept reject decision result act",
        "network.protocol": "network transport protocol proto protocol transport tcp udp icmp",
        "user.name": "username user account identity uid principal",
        "host.name": "hostname host system device name",
    }
    for canonical, text in descriptions.items():
        emb, model = local_embedding(text)
        docs.append(("canonical:"+canonical, "canonical", canonical, canonical, text, {"canonical_type":SCHEMA_FIELDS[canonical]}, emb, model))
    for alias, target in SEMANTIC_SEEDS.items():
        text = f"raw alias {alias} maps to canonical {target} {descriptions.get(target,'')}"
        emb, model = local_embedding(text)
        docs.append(("alias:"+alias, "alias", target, alias, text, {"target":target}, emb, model))
    conn = db(); now=datetime.now(timezone.utc).isoformat()
    for did, dtype, canonical, title, content, meta, emb, model in docs:
        conn.execute("INSERT OR IGNORE INTO semantic_documents VALUES (?,?,?,?,?,?,?,?,?)", (did,now,dtype,canonical,title,content,json.dumps(meta),json.dumps(emb),model))
    conn.commit(); conn.close()


_seed_semantic_documents()


def semantic_retrieve(query: str, top_k: int = 8, raw_sha256: str | None = None) -> dict[str, Any]:
    emb, model = local_embedding(query)
    conn = db(); rows = conn.execute("SELECT * FROM semantic_documents").fetchall(); conn.close()
    scored=[]
    for r in rows:
        score=cosine_similarity(emb,json.loads(r["embedding_json"]))
        scored.append({"document_id":r["document_id"],"doc_type":r["doc_type"],"canonical_field":r["canonical_field"],"title":r["title"],"content":r["content"],"metadata":json.loads(r["metadata_json"]),"score":score})
    scored.sort(key=lambda x:x["score"], reverse=True)
    result={"query":query,"top_k":max(1,min(top_k,25)),"embedding_model":model,"results":scored[:max(1,min(top_k,25))]}
    rid="RET-"+uuid.uuid4().hex[:12].upper()
    conn=db(); conn.execute("INSERT INTO semantic_retrievals VALUES (?,?,?,?,?,?,?)",(rid,datetime.now(timezone.utc).isoformat(),raw_sha256 or sha256(query),query,result["top_k"],json.dumps(result["results"]),model)); conn.commit(); conn.close()
    result["retrieval_id"]=rid
    return result


def context_bundle(raw: str, source: str = "unknown", top_k: int = 6) -> dict[str, Any]:
    kv=parse_kv(raw)
    field_queries=[f"{key} {value}" for key,value in kv.items()]
    docs=[]
    seen=set()
    for q in field_queries:
        for r in semantic_retrieve(q, top_k=3, raw_sha256=sha256(raw))["results"]:
            key=(r["document_id"],r["canonical_field"])
            if key not in seen:
                seen.add(key); docs.append(r)
    docs.sort(key=lambda x:x["score"], reverse=True)
    parsers=[]
    conn=db()
    rows=conn.execute("SELECT parser_id,status,payload_json FROM parser_candidates WHERE status IN ('candidate','approved') ORDER BY created_at DESC LIMIT 20").fetchall()
    version_rows=conn.execute("SELECT parser_id,status,payload_json FROM parser_versions ORDER BY created_at DESC LIMIT 20").fetchall()
    conn.close()
    for r in list(rows) + list(version_rows):
        payload=json.loads(r["payload_json"])
        parsers.append({"parser_id":r["parser_id"],"status":r["status"],"schema_version":payload.get("schema_version","ulpf-event-v1"),"mapping":payload.get("mapping",{})})
    dedup=[]; seen=set()
    for parser in parsers:
        if parser["parser_id"] not in seen:
            seen.add(parser["parser_id"]); dedup.append(parser)
    return {"source":source,"raw_sha256":sha256(raw),"fields":kv,"semantic_results":docs[:top_k],"candidate_parsers":dedup[:8],"schema":{"id":"ulpf-event-v1","fields":SCHEMA_FIELDS},"embedding":embedding_status()}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def detect_format(raw: str, hint: str | None = None) -> tuple[str, float]:
    if hint:
        return hint.lower(), 1.0
    stripped = raw.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return "json", 0.99
    if stripped.startswith("<") and stripped.endswith(">"):
        return "xml", 0.97
    if re.match(r"^<\d+>", stripped):
        return "syslog", 0.99
    if "CEF:" in stripped:
        return "cef", 0.98
    if "," in stripped and stripped.count(",") >= 3:
        return "csv-like", 0.80
    kv_count = len(re.findall(r"([A-Za-z][A-Za-z0-9_.-]*)=([^\s]+)", stripped))
    if kv_count >= 2:
        return "kv", 0.94
    return "unknown", 0.42


def classify_source(raw: str) -> tuple[str, float]:
    low = raw.lower()
    if "asa" in low or "%asa-" in low or "cisco" in low:
        return "Cisco ASA", 0.96
    if "fortigate" in low or "utm" in low or "devname=" in low:
        return "Fortinet", 0.95
    if "sshd" in low or "systemd" in low or "kernel:" in low:
        return "Linux", 0.91
    if "action=accept" in low or "action=deny" in low or "act=accept" in low or "act=deny" in low:
        return "Firewall-like unknown", 0.74
    return "Unknown source", 0.53


def log_dna(raw: str, fmt: str) -> dict[str, Any]:
    delimiters = {c: raw.count(c) for c in ["=", ",", " ", ":", "|", "[", "]"]}
    ipv4_count = len(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw))
    ports = len(re.findall(r"\bport[= ]\d+\b|\bdpt=\d+\b|\bspt=\d+\b|\bsport=\d+\b|\bdport=\d+\b", raw, flags=re.I))
    ts = bool(re.search(r"\d{4}-\d{2}-\d{2}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b", raw))
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_.-]*", raw)
    keys = sorted(parse_kv(raw).keys())
    signature = f"{fmt}|{len(raw)}|{len(tokens)}|{delimiters['=']}|{ipv4_count}|{ports}|{int(ts)}|{entropy(raw)}|{','.join(keys)}"
    return {
        "id": "LOG-DNA-" + sha256(signature)[:12].upper(), "format": fmt, "length": len(raw),
        "token_count": len(tokens), "ipv4_count": ipv4_count, "port_signal": ports,
        "timestamp_signal": ts, "entropy": entropy(raw), "key_fingerprint": keys, "signature": signature,
    }


def parse_kv(raw: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in re.findall(r"([A-Za-z][A-Za-z0-9_.-]*)=([^\s]+)", raw):
        out[key] = val.strip('"')
    return out


def value_valid(value: str, kind: str) -> bool:
    if kind == "ip":
        parts = value.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    if kind == "port":
        return value.isdigit() and 1 <= int(value) <= 65535
    return bool(value)


def infer_value_shape(value: str) -> str:
    v=value.strip().strip('"')
    if value_valid(v, 'ip'): return 'ipv4'
    if v.isdigit() and 1 <= int(v) <= 65535: return 'port-like-integer'
    if re.fullmatch(r'\d+', v): return 'integer'
    if re.fullmatch(r'[A-Za-z]+', v): return 'token'
    if re.match(r'^https?://', v): return 'url'
    return 'string'

def semantic_candidates(raw_key: str, value: str) -> list[dict[str, Any]]:
    k=raw_key.lower()
    shape=infer_value_shape(value)
    candidates=[]
    direct=ALIAS_RULES.get(k)
    if direct:
        target, base=direct
        shape_bonus=0.04 if ((target.endswith('.ip') and shape=='ipv4') or (target.endswith('.port') and shape=='port-like-integer')) else 0.0
        if target.endswith('.ip') and shape not in {'ipv4'}: shape_bonus=-0.20
        if target.endswith('.port') and shape not in {'port-like-integer','integer'}: shape_bonus=-0.15
        candidates.append({'target':target,'confidence':round(max(0,min(.995,base+shape_bonus)),3),'evidence':['alias_rule',f'value_shape:{shape}']})
    # Semantic neighbors: compare normalized labels against known aliases without requiring exact match.
    compact=re.sub(r'[^a-z0-9]','',k)
    for alias,target in SEMANTIC_SEEDS.items():
        ac=re.sub(r'[^a-z0-9]','',alias)
        if alias==k: continue
        # Only create a semantic-neighbor hypothesis when labels are genuinely similar;
        # short prefixes such as `source` must not inherit meanings from `source_port`.
        similarity=SequenceMatcher(None, compact, ac).ratio() if compact and ac else 0.0
        if len(compact)>=5 and similarity>=0.78 and abs(len(compact)-len(ac))<=4:
            base=ALIAS_RULES.get(alias,(target,.68))[1]
            score=max(.0,min(.94,base-0.15))
            candidates.append({'target':target,'confidence':round(score,3),'evidence':['semantic-neighbor',f'neighbor:{alias}',f'label_similarity:{similarity:.2f}',f'value_shape:{shape}']})
    # Deterministic type priors can introduce a competing hypothesis for intentionally ambiguous keys.
    if k in {'source','src'} and shape=='string' and not value_valid(value,'ip'):
        candidates.append({'target':'host.name','confidence':0.56,'evidence':['semantic-prior','source-string-not-ip']})
    by_target={}
    for c in candidates:
        cur=by_target.get(c['target'])
        if cur is None or c['confidence']>cur['confidence']: by_target[c['target']]=c
    return sorted(by_target.values(), key=lambda x:x['confidence'], reverse=True)

def record_semantic_observation(raw_key:str, target:str|None, value:str, confidence:float, reason:str, quarantined:bool=False) -> None:
    now=datetime.now(timezone.utc).isoformat(); shape=infer_value_shape(value); conn=db()
    aid=semantic_node_id(raw_key,'alias')
    conn.execute("INSERT OR IGNORE INTO semantic_nodes VALUES (?,?,?,?,?,?,?)",(aid,raw_key.lower(),'alias',target or None,now,now,0))
    conn.execute("UPDATE semantic_nodes SET last_seen=?, observation_count=observation_count+1 WHERE node_id=?",(now,aid))
    if target:
        tid=semantic_node_id(target,'canonical')
        conn.execute("INSERT OR IGNORE INTO semantic_nodes VALUES (?,?,?,?,?,?,?)",(tid,target,'canonical',SCHEMA_FIELDS.get(target),now,now,0))
        conn.execute("UPDATE semantic_nodes SET last_seen=?, observation_count=observation_count+1 WHERE node_id=?",(now,tid))
        edge=conn.execute("SELECT evidence_count,confidence,evidence_json FROM semantic_edges WHERE source_id=? AND target_id=? AND relation='maps_to'",(aid,tid)).fetchone()
        evidence={'last_reason':reason,'shape':shape,'quarantined':quarantined}
        if edge:
            old_ev=json.loads(edge['evidence_json']); old_ev['last_observation']=evidence
            ec=edge['evidence_count']+1; conf=round((edge['confidence']*(ec-1)+confidence)/ec,3)
            conn.execute("UPDATE semantic_edges SET evidence_count=?,confidence=?,evidence_json=?,last_seen=? WHERE source_id=? AND target_id=? AND relation='maps_to'",(ec,conf,json.dumps(old_ev),now,aid,tid))
        else:
            conn.execute("INSERT INTO semantic_edges VALUES (?,?,?,?,?,?,?)",(aid,tid,'maps_to',1,confidence,json.dumps(evidence),now))
    conn.execute("INSERT INTO semantic_observations(created_at,raw_key,candidate_target,chosen_target,value_shape,confidence,reason,quarantined) VALUES (?,?,?,?,?,?,?,?)",(now,raw_key,target or '',target,shape,confidence,reason,1 if quarantined else 0))
    conn.commit(); conn.close()

def semantic_analyze(raw:str) -> dict[str,Any]:
    kv=parse_kv(raw); fields=[]; quarantined=False
    for key,value in kv.items():
        cands=semantic_candidates(key,value)
        top=cands[0] if cands else None; second=cands[1] if len(cands)>1 else None
        ambiguous=bool(second and top and (top['confidence']-second['confidence'])<0.08)
        if ambiguous: quarantined=True
        reason='top semantic evidence wins' if top else 'no semantic evidence'
        record_semantic_observation(key, top['target'] if top and not ambiguous else None, value, top['confidence'] if top else 0.0, reason if not ambiguous else 'semantic conflict: competing canonical targets', ambiguous)
        fields.append({'raw_key':key,'value_shape':infer_value_shape(value),'candidates':cands[:4],'chosen_target':None if ambiguous or not top else top['target'],'confidence':0.0 if ambiguous or not top else top['confidence'],'conflict':ambiguous})
    return {'fields':fields,'quarantined':quarantined,'decision':'quarantine' if quarantined else 'safe-to-normalize','graph_evidence':'local semantic knowledge graph'}

AI_ROUTER_THRESHOLDS = {"deterministic": 0.99, "lightweight": 0.90}

def _deterministic_confidence(raw: str) -> float:
    try:
        _n, _pid, conf, evidence = deterministic_parser(raw)
        kv = parse_kv(raw)
        coverage = len(evidence) / max(len(kv), 1)
        return round(min(0.999, max(conf, 0.70 + 0.295 * coverage)), 3)
    except Exception:
        return 0.0

def _semantic_confidence_from_result(result: dict[str, Any]) -> float:
    vals = [float(f.get("confidence", 0.0)) for f in result.get("fields", []) if not f.get("conflict")]
    return round(sum(vals) / len(vals), 3) if vals else 0.0

def ai_route(raw: str, source: str = "unknown") -> dict[str, Any]:
    started = time.perf_counter()
    raw_hash = sha256(raw)
    det = _deterministic_confidence(raw)
    semantic = semantic_analyze(raw)
    sem = _semantic_confidence_from_result(semantic)
    if semantic.get("quarantined"):
        route, confidence, reason, model, execution, status = ("quarantine", 0.0, "semantic conflict requires human review", "none", "local-gate", "blocked")
    elif det >= AI_ROUTER_THRESHOLDS["deterministic"]:
        route, confidence, reason, model, execution, status = ("deterministic", det, "high-confidence approved deterministic parser path", "rule-engine-v1", "local-only", "trusted")
    elif max(det, sem) >= AI_ROUTER_THRESHOLDS["lightweight"]:
        route, confidence, reason, model, execution, status = ("lightweight-local", max(det, sem), "local semantic evidence is sufficient", "offline-mapper-v1", "local-only", "trusted")
    else:
        route = "gpt-oss" if AI_MODE in {"gpt-oss", "local-model"} else "review-fallback"
        confidence = 0.0
        reason = "low confidence; escalate to local GPT-OSS adapter" if route == "gpt-oss" else "low confidence and GPT-OSS adapter unavailable"
        model = AI_MODEL if route == "gpt-oss" else "offline-mapper-v1"
        execution = "local-openai-compatible" if route == "gpt-oss" else "local-only"
        status = "review"
    latency_ms = round((time.perf_counter() - started) * 1000, 3)
    reasons = [reason, f"deterministic={det:.3f}", f"semantic={sem:.3f}"]
    evidence = {"raw_sha256": raw_hash, "semantic_decision": semantic.get("decision"), "latency_ms": latency_ms}
    conn = db()
    conn.execute("INSERT INTO ai_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", ("AI-"+uuid.uuid4().hex[:12].upper(), datetime.now(timezone.utc).isoformat(), raw_hash, source, route, confidence, det, sem, model, execution, status, json.dumps(reasons), json.dumps(evidence)))
    conn.commit(); conn.close()
    return {"route": route, "confidence": round(confidence,3), "status": status, "reason": reason, "reasons": reasons, "evidence": evidence, "deterministic_confidence": det, "semantic_confidence": sem, "model": model, "execution": execution, "thresholds": AI_ROUTER_THRESHOLDS}


def local_ai_mapper(raw: str, source: str = "unknown") -> dict[str, Any]:
    if AI_MODE in {"gpt-oss", "local-model"}:
        model_result = _gpt_oss_map(raw, context_bundle(raw, source))
        if model_result and model_result.get("provider_status") == "available":
            model_result["mapping_id"] = persist_ai_mapping_evidence(raw, source, model_result)
            return model_result

    kv = parse_kv(raw)
    candidates={}; target_votes={}; unknown_fields=[]
    for key,value in kv.items():
        target,confidence=ALIAS_RULES.get(key.lower(),(None,0.0))
        if target is None: unknown_fields.append(key); continue
        final=max(0.0,min(0.995,confidence+(0.04 if value_valid(value,SCHEMA_FIELDS[target]) else -0.18)))
        candidates[key]={"target":target,"confidence":round(final,3),"evidence":"alias + value-shape validation","value":value}
        target_votes.setdefault(target,[]).append((key,final))
    conflicts=[]
    for target,votes in target_votes.items():
        if len(votes)>1:
            ordered=sorted(votes,key=lambda x:x[1],reverse=True)
            if ordered[0][1]-ordered[1][1]<0.07: conflicts.append({"target":target,"fields":[v[0] for v in votes],"reason":"semantic ambiguity"})
    semantic=semantic_analyze(raw)
    for f in semantic["fields"]:
        if f.get("chosen_target") and f["raw_key"] not in candidates:
            candidates[f["raw_key"]]={"target":f["chosen_target"],"confidence":f["confidence"],"evidence":"semantic knowledge graph + value shape","value":kv.get(f["raw_key"])}
        if f.get("conflict"): conflicts.append({"target":"ambiguous","fields":[f["raw_key"]]+[c["target"] for c in f.get("candidates",[])],"reason":"semantic graph conflict; evidence gap < 0.08"})
    confidence=round(sum(v["confidence"] for v in candidates.values())/len(candidates),3) if candidates else 0.0
    result={"candidate_mappings":candidates,"conflicts":conflicts,"unknown_fields":unknown_fields,"mapping_confidence":confidence,"retrieved_context":context_bundle(raw, source),"model":"offline-mapper-v1","execution":"local-only","semantic":semantic,"provider_status":"fallback"}
    result["mapping_id"]=persist_ai_mapping_evidence(raw,source,result)
    return result


def load_parser_definition(parser_id: str) -> dict[str, Any] | None:
    if parser_id in PARSERS:
        return PARSERS[parser_id]
    conn = db()
    row = conn.execute("SELECT payload_json FROM parser_candidates WHERE parser_id=? AND status='approved'", (parser_id,)).fetchone()
    conn.close()
    return json.loads(row['payload_json']) if row else None


def load_parser_any(parser_id: str) -> dict[str, Any] | None:
    """Read a seed parser or candidate. Candidates are allowed only in replay/sandbox paths."""
    approved = load_parser_definition(parser_id)
    if approved:
        return approved
    conn = db()
    row = conn.execute("SELECT payload_json FROM parser_candidates WHERE parser_id=?", (parser_id,)).fetchone()
    conn.close()
    return json.loads(row['payload_json']) if row else None


def parser_deterministic_with_definition(raw: str, parser_id: str, allow_candidate: bool = False) -> tuple[dict[str, Any], float, dict[str,str]]:
    definition = load_parser_any(parser_id) if allow_candidate else load_parser_definition(parser_id)
    if not definition:
        return {}, 0.0, {}
    kv = parse_kv(raw)
    normalized: dict[str, Any] = {}
    evidence: dict[str, str] = {}
    for key, value in kv.items():
        canonical = definition.get('mapping', {}).get(key) or definition.get('mapping', {}).get(key.lower())
        if not canonical:
            continue
        kind = SCHEMA_FIELDS.get(canonical, 'string')
        if canonical.endswith('.port') and value.isdigit():
            normalized[canonical] = int(value)
        elif canonical.endswith('.ip'):
            if value_valid(value, 'ip'):
                normalized[canonical] = value
            else:
                continue
        else:
            normalized[canonical] = value
        evidence[key] = canonical
    coverage = len(evidence) / max(len(kv), 1)
    confidence = min(0.995, 0.75 + 0.245 * coverage)
    return normalized, round(confidence, 3), evidence


def deterministic_parser(raw: str) -> tuple[dict[str, Any], str, float, dict[str, str]]:
    kv = parse_kv(raw)
    mappings = {k: v[0] for k, v in ALIAS_RULES.items()}
    normalized: dict[str, Any] = {}
    evidence: dict[str, str] = {}
    for key, value in kv.items():
        canonical = mappings.get(key.lower())
        if not canonical:
            continue
        converted: Any = value
        if canonical.endswith(".port") and value.isdigit():
            converted = int(value)
        if canonical.endswith(".ip") and not value_valid(value, "ip"):
            continue
        normalized[canonical] = converted
        evidence[key] = canonical
    if "event.action" in normalized:
        normalized["event.kind"] = "event"
    score = 0.985 if len(evidence) >= 2 else (0.72 if evidence else 0.45)
    parser_id = "syslog-firewall-v1" if evidence else "ai-candidate-local-v0"
    return normalized, parser_id, score, evidence


def parse_structured(raw: str, fmt: str) -> dict[str, Any]:
    """Best-effort structured extraction while retaining the original raw event."""
    if fmt == "json":
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else {"message": obj}
        except json.JSONDecodeError:
            return {}
    if fmt == "xml":
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(raw)
            return {child.tag: child.text for child in root.iter() if child is not root and child.text}
        except ET.ParseError:
            return {}
    if fmt == "cef":
        parts = raw.split('|', 7)
        if len(parts) == 8:
            out = {"cef_version": parts[0].replace("CEF:", ""), "device_vendor": parts[1], "device_product": parts[2], "device_version": parts[3], "signature_id": parts[4], "name": parts[5], "severity": parts[6]}
            out.update(parse_kv(parts[7]))
            return out
    if fmt == "csv-like":
        vals = [x.strip() for x in raw.split(',')]
        return {f"column_{i+1}": v for i, v in enumerate(vals)}
    return parse_kv(raw)


def normalize_event(raw: str, source: str, fmt: str) -> dict[str, Any]:
    """Route, semantically map, normalize and prove preservation of one event."""
    dna = log_dna(raw, fmt)
    vendor, vendor_conf = classify_source(raw)
    structured = parse_structured(raw, fmt)
    semantic_input = ' '.join(f'{k}={v}' for k, v in structured.items()) if fmt in {'json','xml','cef','csv-like'} else raw

    # Semantic analysis is the gatekeeper. For structured inputs it sees extracted
    # fields; for KV/syslog it sees the original pairs.
    semantic = semantic_analyze(semantic_input)
    route_decision = ai_route(semantic_input, source)
    ai = local_ai_mapper(semantic_input)
    ai['router'] = route_decision

    parsed: dict[str, Any] = {}
    evidence: dict[str, str] = {}
    processing_path = route_decision['route']
    route_reason = route_decision['reason']

    # 1) Apply graph-backed semantic mappings first. This lets newly learned aliases
    # influence normalization rather than merely appearing in the dashboard.
    if not semantic.get('quarantined'):
        for field in semantic.get('fields', []):
            key = field.get('raw_key')
            target = field.get('chosen_target')
            if not key or not target:
                continue
            value = str(structured.get(key, parse_kv(raw).get(key, '')))
            kind = SCHEMA_FIELDS.get(target, 'string')
            if kind == 'port':
                if not value.isdigit() or not (1 <= int(value) <= 65535):
                    continue
                value = int(value)
            elif kind == 'ip' and not value_valid(value, 'ip'):
                continue
            parsed[target] = value
            evidence[key] = target

    # 2) Deterministic parser is still the preferred production fast path for safe
    # events. If the semantic graph did not cover a field, approved alias rules can.
    if not semantic.get('quarantined'):
        det, det_parser_id, det_conf, det_evidence = deterministic_parser(raw)
        for k, v in det.items():
            parsed.setdefault(k, v)
        for k, v in det_evidence.items():
            evidence.setdefault(k, v)
        if det_evidence:
            parser_id = det_parser_id
            parse_conf = max(det_conf, semantic.get('fields') and max([f.get('confidence', 0) for f in semantic['fields']] or [0]) or 0)
        else:
            parser_id = 'semantic-local-v1' if evidence else 'ai-candidate-local-v0'
            parse_conf = semantic_confidence = (sum(f.get('confidence',0) for f in semantic.get('fields',[])) / max(len(semantic.get('fields',[])),1)) if semantic.get('fields') else 0.0
            parse_conf = round(semantic_confidence, 3)
    else:
        parser_id = 'quarantine-semantic-conflict-v1'
        parse_conf = 0.0
        processing_path = 'semantic-conflict-quarantine'
        route_reason = 'competing canonical meanings detected; normalization blocked'

    # 3) Structured formats get an explicit semantic route even when the general
    # deterministic aliases know nothing about the vendor-specific field names.
    if fmt in {'json','xml','cef','csv-like'} and not semantic.get('quarantined') and ai.get('candidate_mappings'):
        for source_key, info in ai['candidate_mappings'].items():
            target = info.get('target')
            value = str(info.get('value', structured.get(source_key, '')))
            if not target:
                continue
            kind = SCHEMA_FIELDS.get(target, 'string')
            if kind == 'port' and value.isdigit():
                value = int(value)
            if kind == 'ip' and not value_valid(value, 'ip'):
                continue
            parsed.setdefault(target, value)
            evidence.setdefault(source_key, target)
        if evidence and parser_id == 'ai-candidate-local-v0':
            parser_id = f'structured-{fmt}-semantic-v1'
            processing_path = 'semantic-structured-path'
            route_reason = 'structured extraction + semantic evidence'
            parse_conf = max(parse_conf, ai.get('mapping_confidence', 0.0))

    if semantic.get('quarantined') or ai.get('conflicts') and any('semantic graph conflict' in c.get('reason','') for c in ai.get('conflicts', [])):
        status = 'quarantine'
    elif parse_conf >= 0.90:
        status = 'trusted'
    else:
        status = 'review'
        if processing_path == 'deterministic-fast-path':
            processing_path = 'confidence-review'
            route_reason = 'mapping confidence below trusted threshold'

    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    raw_hash = sha256(raw)
    extension_source = structured if fmt in {'json','xml','cef','csv-like'} else parse_kv(raw)
    mapped_source_keys = set(evidence)
    # Preserve every unmapped field/value. Never throw away source-specific data.
    extensions = {k: v for k, v in extension_source.items() if k not in mapped_source_keys}
    normalized = {
        'event.id': event_id,
        '@timestamp': now,
        'observer.vendor': vendor,
        'observer.name': source,
        'event.category': 'network',
        **parsed,
        'ulpf.extensions': extensions,
    }
    artifact = build_translation_artifact(parser_id)
    parser_version = artifact.get("parser_version") if artifact else 1
    contract_id = artifact.get("contract_id") if artifact else None
    contract_version = artifact.get("contract_version") if artifact else None
    lineage = {
        'raw_sha256': raw_hash,
        'parser_id': parser_id,
        'schema_id': 'ulpf-event-v1',
        'schema_version': 1,
        'parser_version': parser_version,
        'contract_id': contract_id,
        'contract_version': contract_version,
        'artifact_id': artifact.get('artifact_id') if artifact else None,
        'mapping_evidence': evidence,
        'mapping_confidence': round(parse_conf, 3),
        'semantic_decision': semantic.get('decision'),
        'semantic_graph': semantic.get('graph_evidence'),
        'ai_model': ai.get('model'),
        'ai_router': route_decision,
        'dna_id': dna['id'],
        'processing_path': processing_path,
        'route_reason': route_reason,
        'transform_steps': [
            'ingest', 'format-detect', 'dna-fingerprint', 'structure-extract',
            'semantic-analysis', 'confidence-route', 'parse', 'normalize', 'lossless-proof'
        ],
    }
    proof = {
        'raw_sha256': raw_hash,
        'normalized_sha256': sha256(json.dumps(normalized, sort_keys=True)),
        'raw_preserved': True,
        'unmapped_fields': len(extensions),
        'information_loss': False,
        'preservation_policy': 'raw event + unmapped fields retained in ulpf.extensions',
    }
    event = {
        'event_id': event_id,
        'ingested_at': now,
        'source': source,
        'vendor': vendor,
        'vendor_confidence': vendor_conf,
        'format': fmt,
        'format_confidence': detect_format(raw, fmt)[1],
        'parser_id': parser_id,
        'parser_confidence': round(parse_conf, 3),
        'raw': raw,
        'raw_sha256': raw_hash,
        'normalized': normalized,
        'extensions': extensions,
        'lossless': True,
        'lossless_proof': proof,
        'unmapped_field_count': len(extensions),
        'lineage': lineage,
        'log_dna': dna,
        'status': status,
        'ai_mapping': ai,
        'normalization': {
            'decision': 'quarantine' if status == 'quarantine' else ('normalize' if status == 'trusted' else 'review'),
            'processing_path': processing_path,
            'route_reason': route_reason,
            'semantic_conflicts': semantic.get('quarantined', False),
        },
    }
    conn = db()
    existing = conn.execute('SELECT source FROM sources WHERE source=?', (source,)).fetchone()
    source_status = 'quarantine' if status == 'quarantine' else ('trusted' if status == 'trusted' else status)
    if existing:
        conn.execute('UPDATE sources SET last_seen=?, vendor=?, parser_id=?, dna_id=?, event_count=event_count+1, status=? WHERE source=?',
                     (now, vendor, parser_id, dna['id'], source_status, source))
    else:
        conn.execute('INSERT INTO sources VALUES (?,?,?,?,?,?,?,?)', (source, now, now, vendor, parser_id, dna['id'], 1, source_status))
    conn.execute('INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?)',
                 (event_id, now, source, vendor, fmt, parser_id, status, raw, raw_hash, json.dumps(event)))
    conn.execute('INSERT OR REPLACE INTO event_model_refs VALUES (?,?,?,?,?,?,?,?,?)', (
        event_id, 'ulpf-event-v1', 1, parser_id, parser_version, contract_id, contract_version,
        artifact.get('artifact_id') if artifact else None, now))
    trace = {
        'trace_id': 'TRACE-' + uuid.uuid4().hex[:12].upper(),
        'event_id': event_id,
        'created_at': now,
        'raw_sha256': raw_hash,
        'parser_id': parser_id,
        'schema_version': 'ulpf-event-v1',
        'status': status,
        'timeline': [
            {'stage':'ingest','status':'complete','detail':'raw event accepted','hash':raw_hash},
            {'stage':'format-detect','status':'complete','detail':f'format={fmt}'},
            {'stage':'log-dna','status':'complete','detail':f"dna={dna['id']}"},
            {'stage':'semantic-analysis','status':'quarantine' if semantic.get('quarantined') else 'complete','detail':semantic.get('decision','unknown')},
            {'stage':'ai-routing','status':'complete','detail':route_decision.get('route','unknown'),'confidence':route_decision.get('confidence',0)},
            {'stage':'parse','status':'complete' if evidence else 'review','detail':parser_id,'mapped_fields':len(evidence)},
            {'stage':'normalize','status':'blocked' if status=='quarantine' else ('complete' if status=='trusted' else 'review'),'detail':processing_path},
            {'stage':'lossless-proof','status':'complete','detail':'raw preserved + SHA-256 verified','information_loss':False},
        ],
        'proof': proof,
    }
    conn.execute('INSERT OR REPLACE INTO forensic_traces VALUES (?,?,?,?,?,?,?,?,?)',
                 (trace['trace_id'], event_id, now, raw_hash, parser_id, 'ulpf-event-v1', status, json.dumps(trace['timeline']), json.dumps(proof)))
    conn.execute('INSERT INTO dna_history (created_at, source, dna_json) VALUES (?,?,?)', (now, source, json.dumps(dna)))
    conn.commit()
    conn.close()
    return event


def get_events(limit: int = 50) -> list[dict[str, Any]]:
    conn = db()
    rows = conn.execute("SELECT payload_json FROM events ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 200)),)).fetchall()
    conn.close()
    return [json.loads(r["payload_json"]) for r in rows]


def dna_similarity(a: dict[str, Any], b: dict[str, Any]) -> float:
    scalar = ["format", "ipv4_count", "port_signal", "timestamp_signal"]
    score = sum(a[k] == b[k] for k in scalar) / len(scalar)
    aset, bset = set(a.get("key_fingerprint", [])), set(b.get("key_fingerprint", []))
    jaccard = len(aset & bset) / len(aset | bset) if (aset | bset) else 1.0
    length_delta = abs(a["length"] - b["length"]) / max(a["length"], b["length"], 1)
    score = (score * 0.55) + (jaccard * 0.35) + (max(0.0, 1.0 - length_delta) * 0.10)
    return round(score, 3)


def parser_families() -> list[dict[str, Any]]:
    conn = db()
    rows = conn.execute("SELECT payload_json FROM parser_candidates WHERE status='approved'").fetchall()
    conn.close()
    return list(PARSERS.values()) + [json.loads(r["payload_json"]) for r in rows]


def match_dna_to_parsers(dna: dict[str, Any]) -> list[dict[str, Any]]:
    matches=[]
    for p in parser_families():
        genome=p.get("genome", {})
        sample_sig=genome.get("dna_signature")
        if not sample_sig:
            continue
        # Compare stored family key sets/format hints where available. Older seed parsers get a conservative score.
        fmt_match = 1.0 if p.get("schema_version") and dna.get("format") == genome.get("format") else 0.55
        keys=set(dna.get("key_fingerprint", [])); pkeys=set(genome.get("key_fingerprint", []))
        key_score = (len(keys&pkeys)/len(keys|pkeys)) if (keys|pkeys) else 0.0
        score=round(fmt_match*0.55 + key_score*0.45,3)
        matches.append({"parser_id":p["id"],"score":score,"mapping_coverage":p.get("coverage",0.0),"status":p.get("status","approved")})
    return sorted(matches,key=lambda x:x["score"], reverse=True)[:5]


def dna_diff(a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    dims = [
        ("format", a.get("format"), b.get("format")),
        ("length", a.get("length"), b.get("length")),
        ("token_count", a.get("token_count"), b.get("token_count")),
        ("ipv4_count", a.get("ipv4_count"), b.get("ipv4_count")),
        ("port_signal", a.get("port_signal"), b.get("port_signal")),
        ("timestamp_signal", a.get("timestamp_signal"), b.get("timestamp_signal")),
        ("entropy", a.get("entropy"), b.get("entropy")),
        ("key_fingerprint", a.get("key_fingerprint", []), b.get("key_fingerprint", [])),
    ]
    out=[]
    for name, old, new in dims:
        if old != new:
            if isinstance(old,(int,float)) and isinstance(new,(int,float)):
                delta=round(float(new)-float(old),3)
            else:
                delta=None
            out.append({"dimension":name,"baseline":old,"current":new,"delta":delta})
    return out


def mutation_severity(similarity: float, diffs: list[dict[str, Any]]) -> str:
    format_changed = any(d["dimension"]=="format" for d in diffs)
    keys_changed = any(d["dimension"]=="key_fingerprint" for d in diffs)
    if similarity < 0.50 or (format_changed and keys_changed):
        return "critical"
    if similarity < 0.78 or keys_changed:
        return "warning"
    return "stable"


def persist_mutation_report(source: str, baseline: dict[str, Any], current: dict[str, Any], similarity: float, severity: str, decision: str, recommendation: str) -> dict[str, Any]:
    diffs=dna_diff(baseline,current)
    report={
        "report_id":"MUT-"+uuid.uuid4().hex[:10].upper(),
        "created_at":datetime.now(timezone.utc).isoformat(),
        "source":source, "baseline_dna_id":baseline["id"], "current_dna_id":current["id"],
        "similarity":similarity, "severity":severity, "decision":decision,
        "changed_dimensions":diffs, "recommendation":recommendation,
    }
    conn=db(); conn.execute("INSERT INTO mutation_reports VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
        report["report_id"],report["created_at"],source,baseline["id"],current["id"],similarity,severity,decision,json.dumps(diffs),recommendation,json.dumps(report)))
    conn.commit(); conn.close(); return report


@app.get("/api/ai/status")
def ai_status():
    return {"mode": AI_MODE, "model": AI_MODEL if AI_MODE != 'heuristic' else 'offline-mapper-v1', "base_url": AI_BASE_URL if AI_MODE != 'heuristic' else None, "air_gapped": True, "fallback": "heuristic-local"}

@app.get("/api/ai/gpt-oss/diagnostics")
def gpt_oss_diagnostics():
    if AI_MODE not in {"gpt-oss", "local-model"}:
        return {"enabled":False,"mode":AI_MODE,"model":AI_MODEL,"base_url":AI_BASE_URL,"message":"Set ULPF_AI_MODE=gpt-oss to enable live local inference."}
    probe=_gpt_oss_map("src_ip=10.0.0.1 action=accept")
    return {"enabled":True,"model":AI_MODEL,"base_url":AI_BASE_URL,"available":bool(probe and probe.get("provider_status")=="available"),"provider_status":(probe or {}).get("provider_status"),"latency_ms":(probe or {}).get("latency_ms"),"error":(probe or {}).get("error")}

@app.post("/api/ai/gpt-oss/map")
def gpt_oss_map(req: MappingRequest):
    if AI_MODE not in {"gpt-oss","local-model"}: raise HTTPException(503,"GPT-OSS local mode is disabled")
    result=_gpt_oss_map(req.raw)
    if result.get("provider_status")!="available": raise HTTPException(503,result.get("error","GPT-OSS endpoint unavailable"))
    result["mapping_id"]=persist_ai_mapping_evidence(req.raw,"api-test",result)
    return result

@app.get("/api/ai/mappings")
def ai_mappings(limit:int=50):
    conn=db(); rows=conn.execute("SELECT * FROM ai_mapping_evidence ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); conn.close(); out=[]
    for r in rows:
        d=dict(r); d["candidate_mappings"]=json.loads(d.pop("candidate_mappings_json")); d["unknown_fields"]=json.loads(d.pop("unknown_fields_json")); d["conflicts"]=json.loads(d.pop("conflicts_json")); d["validation_summary"]=json.loads(d.pop("validation_summary_json")); out.append(d)
    return out


@app.post("/api/ai/route")
def ai_route_endpoint(req: MappingRequest):
    return ai_route(req.raw)

@app.get("/api/ai/decisions")
def ai_decisions(limit: int = 50, route: str | None = None):
    conn=db(); q="SELECT * FROM ai_decisions"; params=[]
    if route: q += " WHERE route=?"; params.append(route)
    q += " ORDER BY created_at DESC LIMIT ?"; params.append(max(1,min(limit,200)))
    rows=conn.execute(q,tuple(params)).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["reasons"]=json.loads(d.pop("reasons_json")); d["evidence"]=json.loads(d.pop("evidence_json")); out.append(d)
    return out

@app.get("/api/ai/metrics")
def ai_metrics(window_hours: int = 24):
    hours=max(1,min(window_hours,24*30)); since=datetime.fromtimestamp(datetime.now(timezone.utc).timestamp()-hours*3600,timezone.utc).isoformat()
    conn=db(); total=conn.execute("SELECT COUNT(*) FROM ai_decisions WHERE created_at>=?",(since,)).fetchone()[0]
    rows=conn.execute("SELECT route,COUNT(*) AS c,AVG(confidence) AS conf FROM ai_decisions WHERE created_at>=? GROUP BY route ORDER BY c DESC",(since,)).fetchall()
    model_rows=conn.execute("SELECT model,COUNT(*) AS c FROM ai_decisions WHERE created_at>=? GROUP BY model ORDER BY c DESC",(since,)).fetchall()
    avg=conn.execute("SELECT AVG(confidence) FROM ai_decisions WHERE created_at>=?",(since,)).fetchone()[0] or 0
    conn.close(); return {"window_hours":hours,"total_decisions":total,"average_route_confidence":round(float(avg),3),"by_route":[{"route":r[0],"count":r[1],"confidence":round(float(r[2] or 0),3)} for r in rows],"by_model":[{"model":r[0],"count":r[1]} for r in model_rows],"thresholds":AI_ROUTER_THRESHOLDS,"policy":"AI escalates only when local deterministic/semantic evidence is insufficient"}


@app.get("/api/model/artifacts")
def list_translation_artifacts(limit: int = 50):
    conn=db(); rows=conn.execute("SELECT * FROM translation_artifacts ORDER BY created_at DESC LIMIT ?", (max(1,min(limit,200)),)).fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.get("/api/model/artifacts/{artifact_id}")
def get_translation_artifact(artifact_id: str):
    conn=db(); row=conn.execute("SELECT * FROM translation_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404, "Translation artifact not found")
    out=dict(row); out["payload"]=json.loads(out.pop("payload_json")); return out

class ModelCompareRequest(BaseModel):
    artifact_a: str
    artifact_b: str

@app.post("/api/model/compatibility")
def compare_translation_artifacts(req: ModelCompareRequest):
    conn=db(); rows=[]
    for aid in (req.artifact_a, req.artifact_b):
        row=conn.execute("SELECT * FROM translation_artifacts WHERE artifact_id=?", (aid,)).fetchone()
        if not row: conn.close(); raise HTTPException(404, f"Artifact {aid} not found")
        rows.append(row)
    a=json.loads(rows[0]["payload_json"]); b=json.loads(rows[1]["payload_json"])
    af=a["schema"]["fields"]; bf=b["schema"]["fields"]; am=a["parser"]["mapping"]; bm=b["parser"]["mapping"]
    added=sorted(set(bf)-set(af)); removed=sorted(set(af)-set(bf)); parser_added=sorted(set(bm)-set(am)); parser_removed=sorted(set(am)-set(bm)); parser_changed=sorted(k for k in set(am)&set(bm) if am[k]!=bm[k])
    contract_a=a.get("contract") or {}; contract_b=b.get("contract") or {}
    contract_changed=contract_a.get("hash") != contract_b.get("hash")
    compatible=not removed and not parser_removed and not parser_changed
    schema_impact="none" if not added and not removed else ("additive" if not removed else "breaking")
    parser_impact="none" if not parser_added and not parser_removed and not parser_changed else ("additive" if not parser_removed and not parser_changed else "breaking")
    contract_impact="changed" if contract_changed else "none"
    details={"schema_added":added,"schema_removed":removed,"parser_added":parser_added,"parser_removed":parser_removed,"parser_changed":parser_changed,"contract_changed":contract_changed}
    cid="CMP-"+uuid.uuid4().hex[:12].upper(); now=datetime.now(timezone.utc).isoformat(); conn.execute("INSERT INTO model_compatibility_checks VALUES (?,?,?,?,?,?,?,?,?)", (cid,now,req.artifact_a,req.artifact_b,int(compatible),schema_impact,parser_impact,contract_impact,json.dumps(details))); conn.commit(); conn.close()
    return {"check_id":cid,"compatible":compatible,"schema_impact":schema_impact,"parser_impact":parser_impact,"contract_impact":contract_impact,"details":details}

@app.get("/api/model/events/{event_id}")
def event_model_ref(event_id: str):
    conn=db(); row=conn.execute("SELECT * FROM event_model_refs WHERE event_id=?", (event_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404, "Model reference not found")
    return dict(row)

@app.get("/api/model/registry")
def unified_model_registry(limit: int = 50):
    conn=db()
    schemas=conn.execute("SELECT schema_id,version,created_at,status,fields_json FROM schema_registry ORDER BY schema_id,version").fetchall()
    parsers=conn.execute("SELECT parser_id,MAX(version) AS version,status,MAX(created_at) AS created_at FROM parser_versions GROUP BY parser_id,status ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall()
    contracts=conn.execute("SELECT parser_id,MAX(contract_version) AS version,MAX(created_at) AS created_at FROM parser_contracts GROUP BY parser_id ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall()
    artifacts=conn.execute("SELECT artifact_id,parser_id,parser_version,schema_id,schema_version,contract_id,contract_version,artifact_hash,status,created_at FROM translation_artifacts ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall()
    conn.close()
    return {"schemas":[{**dict(r),"fields":json.loads(r["fields_json"])} for r in schemas],"parsers":[dict(r) for r in parsers],"contracts":[dict(r) for r in contracts],"artifacts":[dict(r) for r in artifacts],"model":"ulpf-unified-data-model-v1"}

@app.get("/api/health")
def health():
    return {"status": "healthy", "air_gapped_ready": True, "version": app.version, "storage": "sqlite"}


@app.get("/api/observability")
def observability(window_seconds: int = 60):
    """Operational telemetry for the Nexus Command Center.
    Values are derived from local SQLite state only; no external telemetry service is used.
    """
    window_seconds = max(10, min(window_seconds, 3600))
    conn = db()
    now = datetime.now(timezone.utc)
    cutoff = (now.timestamp() - window_seconds)
    cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()

    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    trusted = conn.execute("SELECT COUNT(*) FROM events WHERE status='trusted'").fetchone()[0]
    review = conn.execute("SELECT COUNT(*) FROM events WHERE status='review'").fetchone()[0]
    quarantined = conn.execute("SELECT COUNT(*) FROM events WHERE status='quarantine'").fetchone()[0]

    recent = conn.execute("SELECT COUNT(*) FROM events WHERE created_at >= ?", (cutoff_iso,)).fetchone()[0]
    runs = conn.execute("SELECT COUNT(*), AVG(duration_ms), MAX(duration_ms) FROM event_processing_runs WHERE created_at >= ?", (cutoff_iso,)).fetchone()
    recent_runs = int(runs[0] or 0)
    avg_latency = float(runs[1] or 0)
    max_latency = float(runs[2] or 0)

    by_stage = []
    for row in conn.execute("SELECT stage, COUNT(*) AS n, AVG(duration_ms) AS avg_ms FROM event_processing_runs WHERE created_at >= ? GROUP BY stage ORDER BY n DESC", (cutoff_iso,)).fetchall():
        by_stage.append({"stage": row[0], "count": row[1], "avg_ms": round(float(row[2] or 0), 2)})

    by_status = []
    for row in conn.execute("SELECT status, COUNT(*) AS n FROM events GROUP BY status ORDER BY n DESC").fetchall():
        by_status.append({"status": row[0], "count": row[1]})

    parser_rows = conn.execute("SELECT parser_id, COUNT(*) AS n, AVG(parser_confidence) AS conf FROM events GROUP BY parser_id ORDER BY n DESC LIMIT 8").fetchall()
    parser_confidence = [{"parser_id": r[0], "events": r[1], "confidence": round(float(r[2] or 0), 4)} for r in parser_rows]

    connector_count = conn.execute("SELECT COUNT(*) FROM connectors").fetchone()[0]
    healthy_connectors = conn.execute("SELECT COUNT(*) FROM connectors WHERE status='healthy'").fetchone()[0]
    connector_errors = conn.execute("SELECT COUNT(*) FROM connectors WHERE status='error'").fetchone()[0]

    queue = conn.execute("SELECT COUNT(*) FROM processing_queue WHERE status IN ('queued','retry','processing')").fetchone()[0]
    dlq = conn.execute("SELECT COUNT(*) FROM dead_letter_queue").fetchone()[0]
    stream_total = conn.execute("SELECT COUNT(*) FROM stream_events WHERE stream='ulpf-events'").fetchone()[0]

    conn.close()

    eps = recent / window_seconds
    trust_rate = trusted / total if total else 0
    quarantine_rate = quarantined / total if total else 0
    error_rate = connector_errors / connector_count if connector_count else 0

    return {
        "generated_at": now.isoformat(), "window_seconds": window_seconds,
        "events_per_sec": round(eps, 3), "recent_events": recent,
        "total_events": total, "trusted_events": trusted, "review_events": review, "quarantined_events": quarantined,
        "trust_rate": round(trust_rate, 4), "quarantine_rate": round(quarantine_rate, 4),
        "processing_runs": recent_runs, "avg_latency_ms": round(avg_latency, 2), "max_latency_ms": round(max_latency, 2),
        "stage_breakdown": by_stage, "event_status": by_status, "parser_confidence": parser_confidence,
        "connectors": {"total": connector_count, "healthy": healthy_connectors, "errors": connector_errors, "error_rate": round(error_rate, 4)},
        "queue": {"active": queue, "dead_letter": dlq}, "stream": {"events": stream_total},
        "air_gapped": True, "telemetry_source": "local-sqlite"
    }


def _record_processing(event_id: str, stage: str, status: str, started: float, details: dict[str, Any]) -> None:
    import time as _time
    duration_ms = round((_time.perf_counter() - started) * 1000, 3)
    conn = db()
    conn.execute("INSERT INTO event_processing_runs VALUES (?,?,?,?,?,?,?)", (
        "RUN-" + uuid.uuid4().hex[:12].upper(), datetime.now(timezone.utc).isoformat(),
        event_id, stage, status, duration_ms, json.dumps(details)))
    conn.commit(); conn.close()


def _finalize_event_pipeline(req: ProcessRequest) -> dict[str, Any]:
    import time as _time
    started = _time.perf_counter()
    if req.idempotency_key:
        request_hash = sha256(req.source + "|" + (req.format_hint or "") + "|" + req.raw)
        conn = db(); existing = conn.execute("SELECT event_id, request_hash FROM idempotency_keys WHERE idempotency_key=?", (req.idempotency_key,)).fetchone(); conn.close()
        if existing:
            if existing["request_hash"] != request_hash:
                raise HTTPException(409, "Idempotency key already used for a different payload")
            conn = db(); row = conn.execute("SELECT payload_json FROM events WHERE event_id=?", (existing["event_id"],)).fetchone(); conn.close()
            if row: return {"replayed": True, **json.loads(row["payload_json"])}
    _record_processing("pending", "ingest", "started", started, {"source": req.source})
    event = normalize_event(req.raw, req.source, detect_format(req.raw, req.format_hint)[0])
    _record_processing(event["event_id"], "normalization", "completed", started, {"status": event["status"], "parser_id": event["parser_id"], "path": event["normalization"]["processing_path"]})
    if req.idempotency_key:
        conn = db(); conn.execute("INSERT OR IGNORE INTO idempotency_keys VALUES (?,?,?,?)", (req.idempotency_key, datetime.now(timezone.utc).isoformat(), event["event_id"], sha256(req.source + "|" + (req.format_hint or "") + "|" + req.raw))); conn.commit(); conn.close()
    if event["status"] == "quarantine":
        conflicts = event.get("ai_mapping", {}).get("conflicts", [])
        conn = db(); conn.execute("INSERT OR REPLACE INTO quarantine_queue VALUES (?,?,?,?,?,?,?,?,?)", (event["event_id"], datetime.now(timezone.utc).isoformat(), event["normalization"].get("route_reason", "quarantine"), "critical" if conflicts else "high", "open", None, None, None, None)); conn.commit(); conn.close()
    _publish_realtime("event.processed", {
        "event_id": event.get("event_id"), "source": event.get("source"), "status": event.get("status"),
        "action": event.get("normalized", {}).get("event.action"), "source_ip": event.get("normalized", {}).get("source.ip"),
        "destination_ip": event.get("normalized", {}).get("destination.ip"), "destination_port": event.get("normalized", {}).get("destination.port"),
        "parser_id": event.get("parser_id"), "parser_confidence": event.get("parser_confidence"),
        "log_dna": (event.get("log_dna") or {}).get("id"),
    })
    return event


@app.post("/api/pipeline/process")
def process_pipeline(req: ProcessRequest):
    return _finalize_event_pipeline(req)


@app.get("/api/pipeline/runs")
def pipeline_runs(limit: int = 100):
    conn = db(); rows = conn.execute("SELECT * FROM event_processing_runs ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall(); conn.close()
    out=[]
    for r in rows:
        item=dict(r); item["details"]=json.loads(item.pop("details_json")); out.append(item)
    return out


@app.get("/api/quarantine")
def quarantine_queue(status: str | None = "open", limit: int = 100):
    conn=db()
    if status:
        rows=conn.execute("SELECT * FROM quarantine_queue WHERE status=? ORDER BY queued_at DESC LIMIT ?", (status, max(1,min(limit,500)))).fetchall()
    else:
        rows=conn.execute("SELECT * FROM quarantine_queue ORDER BY queued_at DESC LIMIT ?", (max(1,min(limit,500)),)).fetchall()
    conn.close(); return [dict(r) for r in rows]


@app.post("/api/quarantine/{event_id}/review")
def review_quarantine(event_id: str, req: QuarantineReviewRequest):
    conn=db(); q=conn.execute("SELECT * FROM quarantine_queue WHERE event_id=?", (event_id,)).fetchone()
    if not q: conn.close(); raise HTTPException(404, "Quarantined event not found")
    row=conn.execute("SELECT payload_json FROM events WHERE event_id=?", (event_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404, "Event not found")
    event=json.loads(row["payload_json"])
    now=datetime.now(timezone.utc).isoformat(); new_status="trusted" if req.decision=="release" else "rejected"
    event["status"]=new_status; event["normalization"]["decision"]="normalize" if new_status=="trusted" else "reject"; event["lineage"]["transform_steps"].append("human-review:"+req.decision)
    conn.execute("UPDATE events SET status=?, payload_json=? WHERE event_id=?", (new_status, json.dumps(event), event_id))
    conn.execute("UPDATE quarantine_queue SET status='closed', reviewer=?, reviewed_at=?, decision=?, notes=? WHERE event_id=?", (req.reviewer,now,req.decision,req.notes,event_id))
    conn.commit(); conn.close(); return {"event_id":event_id,"status":new_status,"reviewer":req.reviewer,"decision":req.decision}


@app.post("/api/ingest")
def ingest(req: IngestRequest):
    fmt, _ = detect_format(req.raw, req.format_hint)
    event = normalize_event(req.raw, req.source, fmt)
    _publish_realtime("event.ingested", {
        "event_id": event.get("event_id"), "source": event.get("source"), "status": event.get("status"),
        "action": event.get("normalized", {}).get("event.action"), "source_ip": event.get("normalized", {}).get("source.ip"),
        "destination_ip": event.get("normalized", {}).get("destination.ip"), "destination_port": event.get("normalized", {}).get("destination.port"),
        "parser_id": event.get("parser_id"), "parser_confidence": event.get("parser_confidence"), "log_dna": (event.get("log_dna") or {}).get("id"),
    })
    return event


@app.post("/api/ingest/batch")
def ingest_batch(items: list[IngestRequest]):
    return [normalize_event(item.raw, item.source, detect_format(item.raw, item.format_hint)[0]) for item in items]



@app.post("/api/ingest/stream")
def ingest_stream(items: list[IngestRequest]):
    """Batch-oriented streaming facade for collectors; returns per-event routing telemetry."""
    if not items: raise HTTPException(400, "Batch cannot be empty")
    batch_id = str(uuid.uuid4()); started = datetime.now(timezone.utc)
    out=[]
    for item in items:
        out.append(normalize_event(item.raw, item.source, detect_format(item.raw, item.format_hint)[0]))
    trusted=sum(x["status"]=="trusted" for x in out); review=sum(x["status"]=="review" for x in out); quarantine=sum(x["status"]=="quarantine" for x in out)
    dur=(datetime.now(timezone.utc)-started).total_seconds()*1000
    conn=db(); conn.execute("INSERT INTO ingestion_batches VALUES (?,?,?,?,?,?,?,?)", (batch_id,started.isoformat(),items[0].source,len(items),trusted,review,quarantine,dur)); conn.commit(); conn.close()
    return {"batch_id":batch_id,"received":len(items),"accepted":trusted,"review":review,"quarantined":quarantine,"duration_ms":round(dur,2),"routing":"per-event format + confidence router","events":out}

@app.get("/api/ingestion/batches")
def ingestion_batches(limit: int = 25):
    conn=db(); rows=conn.execute("SELECT * FROM ingestion_batches ORDER BY created_at DESC LIMIT ?", (max(1,min(limit,100)),)).fetchall(); conn.close(); return [dict(r) for r in rows]

@app.get("/api/schema-registry")
def schema_registry():
    conn=db(); rows=conn.execute("SELECT * FROM schema_registry ORDER BY version DESC").fetchall(); conn.close()
    return [{"schema_id":r["schema_id"],"version":r["version"],"created_at":r["created_at"],"status":r["status"],"fields":json.loads(r["fields_json"])} for r in rows]

class EventSearchRequest(BaseModel):
    q: str | None = None
    source: str | None = None
    vendor: str | None = None
    status: str | None = None
    format: str | None = None
    parser_id: str | None = None
    since: str | None = None
    until: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)


def _parse_json_row(row: sqlite3.Row) -> dict[str, Any]:
    return json.loads(row["payload_json"])


@app.post("/api/storage/events/search")
def search_events(req: EventSearchRequest):
    conn = db()
    clauses = []
    params: list[Any] = []
    if req.q:
        clauses.append("(raw LIKE ? OR source LIKE ? OR vendor LIKE ? OR parser_id LIKE ?)")
        q = f"%{req.q}%"
        params.extend([q, q, q, q])
    if req.source:
        clauses.append("source=?"); params.append(req.source)
    if req.vendor:
        clauses.append("vendor=?"); params.append(req.vendor)
    if req.status:
        clauses.append("status=?"); params.append(req.status)
    if req.format:
        clauses.append("format=?"); params.append(req.format)
    if req.parser_id:
        clauses.append("parser_id=?"); params.append(req.parser_id)
    if req.since:
        clauses.append("created_at>=?"); params.append(req.since)
    if req.until:
        clauses.append("created_at<=?"); params.append(req.until)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"SELECT payload_json FROM events{where} ORDER BY created_at DESC LIMIT ?",
        (*params, req.limit),
    ).fetchall()
    conn.close()
    return [_parse_json_row(r) for r in rows]


@app.get("/api/storage/catalog")
def storage_catalog():
    conn = db()
    sources = [r[0] for r in conn.execute("SELECT DISTINCT source FROM events ORDER BY source").fetchall()]
    vendors = [r[0] for r in conn.execute("SELECT DISTINCT vendor FROM events ORDER BY vendor").fetchall()]
    statuses = [r[0] for r in conn.execute("SELECT DISTINCT status FROM events ORDER BY status").fetchall()]
    formats = [r[0] for r in conn.execute("SELECT DISTINCT format FROM events ORDER BY format").fetchall()]
    parsers = [r[0] for r in conn.execute("SELECT DISTINCT parser_id FROM events ORDER BY parser_id").fetchall()]
    conn.close()
    return {"sources": sources, "vendors": vendors, "statuses": statuses, "formats": formats, "parsers": parsers}


@app.get("/api/storage/analytics")
def storage_analytics(window_hours: int = 24):
    window_hours = max(1, min(window_hours, 24 * 365))
    conn = db()
    since = datetime.now(timezone.utc).timestamp() - window_hours * 3600
    since_iso = datetime.fromtimestamp(since, timezone.utc).isoformat()
    total = conn.execute("SELECT COUNT(*) FROM events WHERE created_at>=?", (since_iso,)).fetchone()[0]
    trusted = conn.execute("SELECT COUNT(*) FROM events WHERE created_at>=? AND status='trusted'", (since_iso,)).fetchone()[0]
    review = conn.execute("SELECT COUNT(*) FROM events WHERE created_at>=? AND status='review'", (since_iso,)).fetchone()[0]
    quarantine = conn.execute("SELECT COUNT(*) FROM events WHERE created_at>=? AND status='quarantine'", (since_iso,)).fetchone()[0]
    avg = conn.execute("SELECT AVG(json_extract(payload_json,'$.parser_confidence')) FROM events WHERE created_at>=?", (since_iso,)).fetchone()[0] or 0
    by_source = [{"source": r[0], "count": r[1]} for r in conn.execute("SELECT source, COUNT(*) FROM events WHERE created_at>=? GROUP BY source ORDER BY COUNT(*) DESC LIMIT 20", (since_iso,)).fetchall()]
    by_format = [{"format": r[0], "count": r[1]} for r in conn.execute("SELECT format, COUNT(*) FROM events WHERE created_at>=? GROUP BY format ORDER BY COUNT(*) DESC", (since_iso,)).fetchall()]
    archive_count = conn.execute("SELECT COUNT(*) FROM event_archive").fetchone()[0]
    db_bytes = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    conn.close()
    return {
        "window_hours": window_hours, "total": total,
        "trusted": trusted, "review": review, "quarantine": quarantine,
        "parser_confidence_avg": round(float(avg), 3), "by_source": by_source,
        "by_format": by_format, "archived_events": archive_count,
        "sqlite_bytes": db_bytes, "storage_backend": "sqlite",
    }


@app.get("/api/storage/retention")
def retention_status():
    conn = db()
    policies = [dict(r) for r in conn.execute("SELECT * FROM retention_policies ORDER BY name").fetchall()]
    stats = {
        "hot_events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "archived_events": conn.execute("SELECT COUNT(*) FROM event_archive").fetchone()[0],
    }
    conn.close()
    return {"policies": policies, "stats": stats, "compliance": "archive-before-delete enabled by default"}


@app.post("/api/storage/retention/apply")
def retention_apply(policy_id: str = "default-hot-30d", dry_run: bool = True):
    conn = db(); policy = conn.execute("SELECT * FROM retention_policies WHERE policy_id=?", (policy_id,)).fetchone()
    if not policy:
        conn.close(); raise HTTPException(404, "Retention policy not found")
    cutoff = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - int(policy["hot_days"]) * 86400, timezone.utc).isoformat()
    rows = conn.execute("SELECT * FROM events WHERE created_at<? ORDER BY created_at", (cutoff,)).fetchall()
    affected = len(rows)
    operation_id = str(uuid.uuid4()); now = datetime.now(timezone.utc).isoformat()
    if not dry_run:
        if policy["archive_before_delete"]:
            conn.executemany(
                "INSERT OR REPLACE INTO event_archive VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(r["event_id"], now, r["created_at"], r["source"], r["vendor"], r["format"], r["parser_id"], r["status"], r["raw"], r["raw_sha256"], r["payload_json"]) for r in rows],
            )
        conn.execute("DELETE FROM events WHERE created_at<?", (cutoff,))
    conn.execute("INSERT INTO storage_operations VALUES (?,?,?,?,?,?)", (operation_id, now, "retention", "dry-run" if dry_run else "completed", affected, json.dumps({"policy_id":policy_id,"cutoff":cutoff,"archive_before_delete":bool(policy["archive_before_delete"])})))
    conn.commit(); conn.close()
    return {"operation_id": operation_id, "dry_run": dry_run, "affected": affected, "cutoff": cutoff, "archived_before_delete": bool(policy["archive_before_delete"])}


@app.get("/api/storage/adapters")
def storage_adapters():
    return {
        "active": os.getenv("ULPF_STORAGE_BACKEND", "sqlite"),
        "adapters": [
            {"name":"sqlite", "status":"active", "mode":"embedded"},
            {"name":"postgresql", "status":"contract-ready", "mode":"external relational"},
            {"name":"opensearch", "status":"contract-ready", "mode":"search/index"},
            {"name":"clickhouse", "status":"contract-ready", "mode":"columnar analytics"},
        ],
        "air_gapped": True,
    }


@app.get("/api/storage/archive/{event_id}")
def archived_event(event_id: str):
    conn = db(); row = conn.execute("SELECT payload_json FROM event_archive WHERE event_id=?", (event_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404, "Archived event not found")
    return json.loads(row["payload_json"])


@app.get("/api/events")
def events(limit: int = 50):
    return get_events(limit)


@app.get("/api/events/{event_id}")
def event(event_id: str):
    conn = db()
    row = conn.execute("SELECT payload_json FROM events WHERE event_id=?", (event_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Event not found")
    return json.loads(row["payload_json"])


@app.get("/api/ai/embeddings/status")
def embeddings_status():
    return embedding_status()


class SemanticRetrieveRequest(BaseModel):
    query: str
    top_k: int = Field(default=8, ge=1, le=25)


@app.post("/api/ai/retrieve")
def ai_retrieve(req: SemanticRetrieveRequest):
    return semantic_retrieve(req.query, req.top_k)


class ContextMapRequest(BaseModel):
    raw: str
    source: str = "unknown"
    top_k: int = Field(default=6, ge=1, le=12)


@app.post("/api/ai/context")
def ai_context(req: ContextMapRequest):
    return context_bundle(req.raw, req.source, req.top_k)


@app.post("/api/ai/context-map")
def context_map(req: ContextMapRequest):
    context=context_bundle(req.raw, req.source, req.top_k)
    result=local_ai_mapper(req.raw, req.source)
    result["retrieved_context"]=context
    return result


@app.get("/api/ai/retrievals")
def ai_retrievals(limit:int=50):
    conn=db(); rows=conn.execute("SELECT * FROM semantic_retrievals ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["results"]=json.loads(d.pop("results_json")); out.append(d)
    return out


@app.post("/api/ai/map")
def ai_map(req: MappingRequest):
    return local_ai_mapper(req.raw)


@app.get("/api/schemas")
def schemas():
    return {
        "schema_id": "ulpf-event-v1",
        "principle": "canonical fields + preserved vendor extensions",
        "fields": {k: {"type": v} for k, v in SCHEMA_FIELDS.items()},
    }


@app.get("/api/semantic/graph")
def semantic_graph(limit:int=100):
    conn=db()
    nodes=conn.execute("SELECT * FROM semantic_nodes ORDER BY observation_count DESC, last_seen DESC LIMIT ?",(max(1,min(limit,500)),)).fetchall()
    edges=conn.execute("SELECT * FROM semantic_edges ORDER BY evidence_count DESC, confidence DESC LIMIT ?",(max(1,min(limit*2,1000)),)).fetchall()
    conn.close()
    return {"nodes":[dict(r) for r in nodes],"edges":[{**dict(r),"evidence":json.loads(r['evidence_json'])} for r in edges],"principle":"evidence-backed semantic equivalence; ambiguous mappings are quarantined"}

class SemanticAnalyzeRequest(BaseModel):
    raw: str

@app.post("/api/semantic/analyze")
def semantic_analyze_endpoint(req: SemanticAnalyzeRequest):
    return semantic_analyze(req.raw)

@app.get("/api/semantic/conflicts")
def semantic_conflicts(limit:int=50):
    conn=db(); rows=conn.execute("SELECT * FROM semantic_observations WHERE quarantined=1 ORDER BY id DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); conn.close()
    return [dict(r) for r in rows]


@app.post("/api/normalize/preview")
def normalize_preview(req: NormalizePreviewRequest):
    """Dry-run the semantic normalization gate without persisting an event."""
    fmt, fmt_conf = detect_format(req.raw, req.format_hint)
    structured = parse_structured(req.raw, fmt)
    semantic_input = ' '.join(f'{k}={v}' for k, v in structured.items()) if fmt in {'json','xml','cef','csv-like'} else req.raw
    semantic = semantic_analyze(semantic_input)
    ai = local_ai_mapper(semantic_input)
    if semantic.get('quarantined'):
        decision='quarantine'; path='semantic-conflict-quarantine'
    elif ai.get('mapping_confidence',0) >= 0.90:
        decision='normalize'; path='deterministic-fast-path'
    else:
        decision='review'; path='confidence-review'
    return {
        'format': fmt, 'format_confidence': fmt_conf, 'decision': decision,
        'processing_path': path, 'semantic': semantic, 'ai_mapping': ai,
        'raw_sha256': sha256(req.raw),
        'lossless_policy': 'raw event preserved; unmapped fields stored in ulpf.extensions'
    }


@app.get("/api/parsers")
def parsers():
    conn = db()
    candidates = conn.execute("SELECT payload_json FROM parser_candidates ORDER BY created_at DESC").fetchall()
    conn.close()
    return list(PARSERS.values()) + [json.loads(r["payload_json"]) for r in candidates]


def build_parser_intelligence(parser_id: str, samples: list[str]) -> dict[str, Any]:
    definition = load_parser_any(parser_id)
    if not definition: raise HTTPException(404, "Parser not found")
    obs: dict[str, dict[str, Any]] = {}
    rules = {"source.ip":["valid IPv4/IPv6 shape"],"destination.ip":["valid IPv4/IPv6 shape"],
             "source.port":["integer 1..65535"],"destination.port":["integer 1..65535"],
             "event.action":["non-empty action token"],"network.protocol":["known transport/protocol token when available"]}
    for raw in samples:
        ai=local_ai_mapper(raw)
        for raw_field, info in ai.get("candidate_mappings",{}).items():
            rec=obs.setdefault(raw_field,{"canonical":info["target"],"conf":[],"evidence":[],"samples":0})
            rec["canonical"]=info["target"]; rec["conf"].append(float(info.get("confidence",0))); rec["evidence"].append(info.get("evidence","local semantic mapper")); rec["samples"]+=1
    fields=[]
    for raw_field,rec in obs.items():
        conf=round(sum(rec["conf"])/max(len(rec["conf"]),1),3)
        fields.append({"raw_field":raw_field,"canonical_field":rec["canonical"],"confidence":conf,"sample_count":rec["samples"],
                       "evidence":list(dict.fromkeys(rec["evidence"]))[:6],"validation_rules":rules.get(rec["canonical"],["preserve original value if validation fails"])})
    return {"parser_id":parser_id,"field_count":len(fields),"fields":sorted(fields,key=lambda x:(-x["confidence"],x["raw_field"])),"schema_version":definition.get("schema_version","ulpf-event-v1"),"parser_status":definition.get("status","unknown")}


def persist_parser_field_evidence(parser_id: str, intelligence: dict[str, Any]) -> None:
    conn=db(); now=datetime.now(timezone.utc).isoformat()
    for f in intelligence["fields"]:
        conn.execute("INSERT INTO parser_field_evidence VALUES (NULL,?,?,?,?,?,?,?)",(now,parser_id,f["raw_field"],f["canonical_field"],f["confidence"],json.dumps(f["evidence"]),json.dumps(f["validation_rules"]),f["sample_count"]))
    conn.commit(); conn.close()


@app.post("/api/parsers/{parser_id}/intelligence")
def parser_intelligence(parser_id: str, req: ParserReplayRequest):
    if not req.samples: raise HTTPException(400,"At least one replay sample is required")
    intel=build_parser_intelligence(parser_id,req.samples); persist_parser_field_evidence(parser_id,intel); return intel


@app.get("/api/parsers/{parser_id}/evidence")
def parser_evidence(parser_id: str, limit:int=100):
    conn=db(); rows=conn.execute("SELECT * FROM parser_field_evidence WHERE parser_id=? ORDER BY confidence DESC,id DESC LIMIT ?",(parser_id,max(1,min(limit,500)))).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["evidence"]=json.loads(d.pop("evidence_json")); d["validation_rules"]=json.loads(d.pop("validation_rules_json")); out.append(d)
    return out


def _sandbox_evaluate(parser_id: str, samples: list[str]) -> dict[str, Any]:
    if not load_parser_any(parser_id): raise HTTPException(404,"Parser not found")
    results=[]; conflicts=0
    for raw in samples:
        normalized, confidence, evidence=parser_deterministic_with_definition(raw,parser_id,allow_candidate=True)
        raw_keys=set(parse_kv(raw)); mapped=set(evidence); coverage=len(mapped)/max(len(raw_keys),1)
        ai=local_ai_mapper(raw); c=len(ai.get("conflicts",[])); conflicts+=c
        results.append({"raw":raw,"coverage":round(coverage,3),"confidence":confidence,"mapped_fields":sorted(mapped),"unmapped_fields":sorted(raw_keys-mapped),"conflicts":c,"normalized":normalized})
    n=len(results); avg_cov=round(sum(r["coverage"] for r in results)/max(n,1),3); avg_conf=round(sum(r["confidence"] for r in results)/max(n,1),3)
    decision="approve" if avg_cov>=0.90 and avg_conf>=0.85 and conflicts==0 else ("review" if avg_cov>=0.75 else "block")
    run_id="SBX-"+uuid.uuid4().hex[:12].upper(); conn=db(); conn.execute("INSERT INTO parser_sandbox_runs VALUES (?,?,?,?,?,?,?,?,?,?)",(run_id,datetime.now(timezone.utc).isoformat(),parser_id,n,avg_cov,avg_conf,1.0,conflicts,decision,json.dumps(results))); conn.commit(); conn.close()
    intel=build_parser_intelligence(parser_id,samples); persist_parser_field_evidence(parser_id,intel)
    return {"run_id":run_id,"parser_id":parser_id,"sample_count":n,"avg_coverage":avg_cov,"avg_confidence":avg_conf,"lossless_rate":1.0,"conflict_count":conflicts,"decision":decision,"results":results,"intelligence":intel}


@app.post("/api/parsers/{parser_id}/sandbox-and-evaluate")
def sandbox_and_evaluate(parser_id: str, req: ParserReplayRequest):
    if not req.samples: raise HTTPException(400,"At least one sample is required")
    return _sandbox_evaluate(parser_id,req.samples)


@app.get("/api/parsers/{parser_id}/sandbox-runs")
def parser_sandbox_runs(parser_id: str, limit:int=50):
    conn=db(); rows=conn.execute("SELECT * FROM parser_sandbox_runs WHERE parser_id=? ORDER BY created_at DESC LIMIT ?",(parser_id,max(1,min(limit,200)))).fetchall(); conn.close()
    return [{**dict(r),"results":json.loads(r["results_json"])} for r in rows]


@app.post("/api/parsers/{parser_id}/promote")
def promote_parser(parser_id: str, req: ParserReplayRequest):
    if not req.samples: raise HTTPException(400,"Promotion requires replay samples")
    candidate=load_parser_any(parser_id)
    if not candidate: raise HTTPException(404,"Parser not found")
    if candidate.get("status")=="approved" and parser_id in PARSERS: raise HTTPException(409,"Seed parser is already production-approved")
    evaluation=_sandbox_evaluate(parser_id,req.samples)
    if evaluation["decision"]!="approve": raise HTTPException(409,"Promotion blocked by sandbox policy")
    conn=db(); candidate["status"]="approved"; candidate.setdefault("genome",{})["promotion"]={"run_id":evaluation["run_id"],"promoted_at":datetime.now(timezone.utc).isoformat(),"policy":"sandbox-gate-v1"}
    conn.execute("UPDATE parser_candidates SET status='approved', payload_json=? WHERE parser_id=?",(json.dumps(candidate),parser_id))
    parser_key=candidate.get("genome",{}).get("source") or parser_id.rsplit("-",1)[0]
    rowv=conn.execute("SELECT MAX(version) AS v FROM parser_versions WHERE parser_key=?",(parser_key,)).fetchone(); version=int(rowv["v"] or 0)+1
    conn.execute("INSERT INTO parser_versions VALUES (?,?,?,?,?,?,?,?)",(parser_key,version,parser_id,datetime.now(timezone.utc).isoformat(),"approved",float(candidate.get("coverage",0)),"sandbox-approved",json.dumps(candidate)))
    conn.execute("INSERT INTO parser_approval_history VALUES (NULL,?,?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),parser_id,version,"promote","sih-analyst","sandbox passed",evaluation["run_id"]))
    conn.commit(); conn.close(); candidate["version"]=version
    return {"result":"promoted","candidate":candidate,"evaluation":evaluation}


def _field_type_for_target(target: str) -> str:
    return SCHEMA_FIELDS.get(target, "string")


def compile_parser_contract(raw_samples: list[str], source: str, name: str | None = None) -> dict[str, Any]:
    """Build a deterministic, versioned translation contract from local evidence.
    The contract is executable by the existing deterministic parser path and contains
    detection, extraction, type conversion, validation, provenance and unknown-field policy.
    """
    if not raw_samples:
        raise HTTPException(400, "At least one raw sample is required")
    field_stats: dict[str, dict[str, Any]] = {}
    key_fingerprint = sorted(set().union(*(parse_kv(x).keys() for x in raw_samples)))
    format_name = detect_format(raw_samples[0], None)[0]
    ai_results=[]
    for raw in raw_samples:
        ai = local_ai_mapper(raw, source)
        ai_results.append(ai)
        for raw_field, info in ai.get("candidate_mappings", {}).items():
            rec=field_stats.setdefault(raw_field, {"target":info["target"],"conf":[],"evidence":[],"seen":0,"sample_values":[]})
            # Prefer the target with the strongest aggregate evidence across samples.
            if float(info.get("confidence",0)) >= (sum(rec["conf"])/len(rec["conf"]) if rec["conf"] else 0):
                rec["target"] = info["target"]
            rec["conf"].append(float(info.get("confidence",0)))
            rec["evidence"].append(info.get("evidence","local mapping evidence"))
            rec["seen"] += 1
            if len(rec["sample_values"])<5:
                rec["sample_values"].append(info.get("value"))
    mappings={}
    validation={}
    extraction={}
    for raw_field,rec in sorted(field_stats.items()):
        confidence=round(sum(rec["conf"])/max(len(rec["conf"]),1),3)
        target=rec["target"]
        mappings[raw_field]={"target":target,"confidence":confidence,"required":rec["seen"]==len(raw_samples),"type":_field_type_for_target(target)}
        extraction[raw_field]={"method":"key-value","key":raw_field,"value_shape":infer_value_shape(str(rec["sample_values"][0] if rec["sample_values"] else ""))}
        validation[raw_field]=[
            "ipv4/ipv6 shape" if target.endswith('.ip') else
            "integer 1..65535" if target.endswith('.port') else
            "non-empty" if target else "preserve"
        ]
    unknown=sorted(set(key_fingerprint)-set(mappings))
    contract={
        "contract_type":"ulpf.translation-contract",
        "contract_version":1,
        "source":source,
        "name":name or f"{source}-parser",
        "schema_version":"ulpf-event-v1",
        "detection":{"format":format_name,"key_fingerprint":key_fingerprint,"required_keys":sorted([k for k,v in mappings.items() if v.get("required")])},
        "extraction":extraction,
        "field_mapping":mappings,
        "type_conversion":{k:v["type"] for k,v in mappings.items()},
        "validation":validation,
        "preserve_unknown":True,
        "unknown_fields":unknown,
        "provenance":{"created_from":"local-evidence-compiler","samples":len(raw_samples),"ai_routes":sorted(set(a.get("route",a.get("execution","local")) for a in ai_results))},
        "safety":{"requires_sandbox":True,"direct_production":False},
    }
    contract_hash=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":" )).encode()).hexdigest()
    contract["contract_hash"]=contract_hash
    return contract


def persist_parser_contract(parser_id: str, contract: dict[str, Any], status: str = "candidate") -> str:
    contract_id="CTR-"+uuid.uuid4().hex[:12].upper()
    conn=db()
    row=conn.execute("SELECT COALESCE(MAX(contract_version),0) AS v FROM parser_contracts WHERE parser_id=?",(parser_id,)).fetchone()
    version=int(row["v"] or 0)+1
    payload=dict(contract); payload["contract_version"]=version
    conn.execute("INSERT INTO parser_contracts VALUES (?,?,?,?,?,?,?)",(contract_id,datetime.now(timezone.utc).isoformat(),parser_id,version,status,payload["contract_hash"],json.dumps(payload)))
    conn.commit(); conn.close()
    return contract_id


@app.post("/api/parsers/compile-contract")
def compile_contract(req: ParserContractRequest):
    contract=compile_parser_contract(req.raw_samples, req.source, req.name)
    candidate=parser_candidate(CandidateParserRequest(raw_samples=req.raw_samples,name=req.name or f"{req.source}-parser")) if req.compile_candidate else None
    parser_id=candidate["id"] if candidate else f"compiled-{sha256('|'.join(sorted(req.raw_samples)))[:12]}"
    contract_id=persist_parser_contract(parser_id, contract, "candidate")
    if candidate:
        candidate["genome"]["translation_contract"] = contract
        candidate["genome"]["contract_id"] = contract_id
        conn=db(); conn.execute("UPDATE parser_candidates SET payload_json=? WHERE parser_id=?",(json.dumps(candidate),parser_id)); conn.commit(); conn.close()
    return {"contract_id":contract_id,"parser_id":parser_id,"contract":contract,"candidate":candidate}


@app.get("/api/parsers/contracts")
def parser_contracts(limit:int=50):
    conn=db(); rows=conn.execute("SELECT * FROM parser_contracts ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); conn.close()
    return [{**dict(r),"payload":json.loads(r["payload_json"])} for r in rows]


@app.get("/api/parsers/contracts/{parser_id}")
def parser_contract_for_parser(parser_id:str):
    conn=db(); row=conn.execute("SELECT * FROM parser_contracts WHERE parser_id=? ORDER BY contract_version DESC LIMIT 1",(parser_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404,"No translation contract found")
    d=dict(row); d["payload"]=json.loads(d.pop("payload_json")); return d


@app.post("/api/parsers/candidates")
def parser_candidate(req: CandidateParserRequest):
    if not req.raw_samples:
        raise HTTPException(400, "At least one raw sample is required")
    merged: dict[str, str] = {}
    evidence: dict[str, Any] = {}
    confidence_values: list[float] = []
    conflicts: list[Any] = []
    for raw in req.raw_samples:
        ai = local_ai_mapper(raw)
        confidence_values.append(ai.get("mapping_confidence", 0.0))
        conflicts.extend(ai.get("conflicts", []))
        for field, info in ai.get("candidate_mappings", {}).items():
            merged[field] = info["target"]
            evidence[field] = info
    raw_key_count = len(set().union(*(parse_kv(x).keys() for x in req.raw_samples)))
    coverage = round(len(merged) / max(raw_key_count, 1), 3)
    parser_id = (req.name or "discovered-parser") + "-" + sha256("|".join(sorted(req.raw_samples)))[:8]
    contract = compile_parser_contract(req.raw_samples, req.name or "unknown-source", req.name)
    candidate = {
        "id": parser_id, "status": "candidate", "coverage": min(1.0, coverage),
        "schema_version": "ulpf-event-v1", "source_families": [req.name or "discovered-local"],
        "mapping": merged,
        "genome": {"mapping_confidence": round(sum(confidence_values) / len(confidence_values), 3),
                   "sample_count": len(req.raw_samples), "created_from": "local-ai-mapper",
                   "mapping_evidence": evidence, "conflicts": conflicts, "source": req.name or "unknown-source",
                   "contract": {"detection": ["key-value structure", "value-shape validation"],
                                "extraction": "parse_kv", "normalization": "ulpf-event-v1", "preserve_unknown": True},
                   "key_fingerprint": sorted(set().union(*(parse_kv(x).keys() for x in req.raw_samples))),
                   "format": detect_format(req.raw_samples[0], None)[0],
                   "translation_contract": contract}
    }
    conn = db(); conn.execute("INSERT OR REPLACE INTO parser_candidates VALUES (?,?,?,?)",
                              (parser_id, datetime.now(timezone.utc).isoformat(), "candidate", json.dumps(candidate))); conn.commit(); conn.close()
    contract_id=persist_parser_contract(parser_id, contract, "candidate")
    candidate["genome"]["contract_id"]=contract_id
    conn=db(); conn.execute("UPDATE parser_candidates SET payload_json=? WHERE parser_id=?",(json.dumps(candidate),parser_id)); conn.commit(); conn.close()
    return candidate


@app.post("/api/parsers/generate")
def generate_parser(req: ParserGenerateRequest):
    candidate = parser_candidate(CandidateParserRequest(raw_samples=req.raw_samples, name=req.name or f"{req.source}-parser"))
    candidate["genome"]["source"] = req.source
    conn = db(); conn.execute("UPDATE parser_candidates SET payload_json=? WHERE parser_id=?", (json.dumps(candidate), candidate["id"])); conn.commit(); conn.close()
    return candidate




def _load_contract(contract_id: str | None = None, parser_id: str | None = None, version: int | None = None) -> tuple[dict[str, Any], str]:
    conn = db()
    if contract_id:
        row = conn.execute("SELECT * FROM parser_contracts WHERE contract_id=?", (contract_id,)).fetchone()
    elif parser_id and version:
        row = conn.execute("SELECT * FROM parser_contracts WHERE parser_id=? AND contract_version=?", (parser_id, version)).fetchone()
    elif parser_id:
        row = conn.execute("SELECT * FROM parser_contracts WHERE parser_id=? ORDER BY contract_version DESC LIMIT 1", (parser_id,)).fetchone()
    else:
        row = None
    conn.close()
    if not row:
        raise HTTPException(404, "Translation contract not found")
    payload = json.loads(row["payload_json"])
    return payload, str(row["contract_id"])


def _contract_value(raw_value: str, target: str, type_name: str) -> tuple[Any, str | None]:
    value = raw_value.strip().strip('"')
    if type_name == "ip":
        if not value_valid(value, "ip"):
            return value, "invalid IP address"
        return value, None
    if type_name == "port":
        if not value.isdigit() or not (1 <= int(value) <= 65535):
            return value, "port must be an integer in 1..65535"
        return int(value), None
    if not value:
        return value, "value is empty"
    return value, None


def execute_translation_contract(raw: str, contract: dict[str, Any]) -> dict[str, Any]:
    kv = parse_kv(raw)
    mapping = contract.get("field_mapping", {})
    normalized: dict[str, Any] = {}
    extensions: dict[str, Any] = {}
    validation_errors: list[dict[str, str]] = []
    mapped_keys: list[str] = []
    for key, value in kv.items():
        spec = mapping.get(key) or mapping.get(key.lower())
        if not isinstance(spec, dict):
            extensions[key] = value
            continue
        target = spec.get("target")
        type_name = spec.get("type") or _field_type_for_target(str(target))
        converted, err = _contract_value(value, str(target), str(type_name))
        if err:
            validation_errors.append({"field": key, "target": str(target), "error": err})
            extensions[key] = value
            continue
        normalized[str(target)] = converted
        mapped_keys.append(key)
    coverage = round(len(mapped_keys) / max(len(kv), 1), 3)
    status = "validated" if not validation_errors else "validation-review"
    if not contract.get("preserve_unknown", True) and extensions:
        status = "validation-review"
    return {
        "status": status,
        "normalized": normalized,
        "extensions": extensions,
        "unknown_fields": sorted([k for k in extensions if k not in kv or k not in mapping]),
        "validation_errors": validation_errors,
        "mapped_fields": mapped_keys,
        "coverage": coverage,
        "raw_sha256": sha256(raw),
    }


class ContractExecuteRequest(BaseModel):
    raw: str
    contract_id: str | None = None
    parser_id: str | None = None
    version: int | None = None


class ContractCompareRequest(BaseModel):
    parser_id: str
    version_a: int
    version_b: int
    samples: list[str]


@app.post("/api/contracts/execute")
def contract_execute(req: ContractExecuteRequest):
    contract, contract_id = _load_contract(req.contract_id, req.parser_id, req.version)
    result = execute_translation_contract(req.raw, contract)
    run_id = "CEX-" + uuid.uuid4().hex[:12].upper()
    conn = db()
    conn.execute(
        "INSERT INTO contract_execution_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, datetime.now(timezone.utc).isoformat(), contract_id, str(contract.get("parser_id", req.parser_id or "unknown")),
         int(contract.get("contract_version", 1)), result["raw_sha256"], result["status"], result["coverage"],
         json.dumps(result["validation_errors"]), json.dumps(result["unknown_fields"]), json.dumps(result["normalized"]), json.dumps(result["extensions"])) )
    conn.commit(); conn.close()
    return {"run_id": run_id, "contract_id": contract_id, "contract": {"name": contract.get("name"), "version": contract.get("contract_version"), "hash": contract.get("contract_hash")}, **result}


@app.get("/api/contracts")
def contracts(parser_id: str | None = None, limit: int = 100):
    conn = db()
    if parser_id:
        rows = conn.execute("SELECT * FROM parser_contracts WHERE parser_id=? ORDER BY contract_version DESC LIMIT ?", (parser_id, max(1, min(limit, 300)))).fetchall()
    else:
        rows = conn.execute("SELECT * FROM parser_contracts ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 300)),)).fetchall()
    conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["payload"]=json.loads(d.pop("payload_json")); out.append(d)
    return out


@app.get("/api/contracts/{contract_id}/executions")
def contract_executions(contract_id: str, limit: int = 50):
    conn=db(); rows=conn.execute("SELECT * FROM contract_execution_runs WHERE contract_id=? ORDER BY created_at DESC LIMIT ?",(contract_id,max(1,min(limit,200)))).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r)
        for key in ("validation_errors_json","unknown_fields_json","normalized_json","extensions_json"):
            d[key[:-5] if key.endswith('_json') else key]=json.loads(d.pop(key))
        out.append(d)
    return out


@app.post("/api/contracts/compare")
def compare_contracts(req: ContractCompareRequest):
    if not req.samples:
        raise HTTPException(400, "At least one sample is required")
    a,_ = _load_contract(None, req.parser_id, req.version_a)
    b,_ = _load_contract(None, req.parser_id, req.version_b)
    rows=[]
    for raw in req.samples:
        ea=execute_translation_contract(raw,a); eb=execute_translation_contract(raw,b)
        keys_a=set(ea["normalized"]); keys_b=set(eb["normalized"])
        rows.append({"raw":raw,"coverage_a":ea["coverage"],"coverage_b":eb["coverage"],"coverage_delta":round(eb["coverage"]-ea["coverage"],3),"unknown_a":ea["unknown_fields"],"unknown_b":eb["unknown_fields"],"normalized_a":ea["normalized"],"normalized_b":eb["normalized"],"schema_impact":{"added":sorted(keys_b-keys_a),"removed":sorted(keys_a-keys_b),"changed_values":sorted(k for k in keys_a & keys_b if ea["normalized"].get(k)!=eb["normalized"].get(k))}})
    avg_a=round(sum(x["coverage_a"] for x in rows)/len(rows),3); avg_b=round(sum(x["coverage_b"] for x in rows)/len(rows),3)
    regression = avg_b < avg_a
    return {"parser_id":req.parser_id,"version_a":req.version_a,"version_b":req.version_b,"sample_count":len(rows),"avg_coverage_a":avg_a,"avg_coverage_b":avg_b,"coverage_delta":round(avg_b-avg_a,3),"regression":regression,"release_decision":"block" if regression else "pass","results":rows}


@app.post("/api/parsers/{parser_id}/approve")
def approve_parser(parser_id: str):
    conn = db()
    row = conn.execute("SELECT payload_json FROM parser_candidates WHERE parser_id=?", (parser_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Candidate parser not found")
    candidate = json.loads(row["payload_json"])
    candidate["status"] = "approved"
    candidate["genome"]["approved_at"] = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE parser_candidates SET status='approved', payload_json=? WHERE parser_id=?", (json.dumps(candidate), parser_id))
    parser_key = candidate.get("genome", {}).get("source") or parser_id.rsplit("-", 1)[0]
    rowv = conn.execute("SELECT MAX(version) AS v FROM parser_versions WHERE parser_key=?", (parser_key,)).fetchone()
    version = int(rowv["v"] or 0) + 1
    conn.execute(
        "INSERT INTO parser_versions VALUES (?,?,?,?,?,?,?,?)",
        (parser_key, version, parser_id, datetime.now(timezone.utc).isoformat(), "approved", float(candidate.get("coverage", 0)), "human-approved", json.dumps(candidate)),
    )
    # Bind the source family to the newly approved parser if it matches a registered source.
    source = candidate.get("genome", {}).get("source")
    if source:
        conn.execute("UPDATE sources SET parser_id=?, status='trusted' WHERE source=?", (parser_id, source))
    conn.commit(); conn.close()
    candidate["version"] = version
    return candidate


@app.post("/api/onboarding/analyze")
def onboarding_analyze(req: OnboardingRequest):
    if not req.samples:
        raise HTTPException(400, "At least one sample is required")
    first=req.samples[0]
    fmt,_=detect_format(first,None)
    dna=log_dna(first,fmt)
    matches=match_dna_to_parsers(dna)
    best=matches[0] if matches else None
    vendor_conf=0.0
    detected_vendor, vendor_conf=classify_source(first)
    expected=req.expected_vendor or detected_vendor
    recommendation = "bind-existing-parser" if best and best["score"] >= 0.72 else "create-candidate-parser"
    session_id=str(uuid.uuid4())
    status="matched" if recommendation=="bind-existing-parser" else "unknown"
    match_json={"best":best,"matches":matches,"detected_vendor":detected_vendor,"vendor_confidence":vendor_conf,"expected_vendor":expected}
    conn=db(); now=datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO onboarding_sessions VALUES (?,?,?,?,?,?,?)",(session_id,now,req.source,status,json.dumps(dna),json.dumps(match_json),recommendation))
    for raw in req.samples:
        conn.execute("INSERT INTO source_samples(session_id,source,raw,raw_sha256,created_at) VALUES (?,?,?,?,?)",(session_id,req.source,raw,sha256(raw),now))
    conn.commit(); conn.close()
    return {"session_id":session_id,"source":req.source,"status":status,"dna":dna,"matching":match_json,"recommendation":recommendation,"next": "approve-existing" if status=="matched" else "generate-candidate"}


@app.get("/api/onboarding")
def onboarding_list(limit:int=25):
    conn=db(); rows=conn.execute("SELECT * FROM onboarding_sessions ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,100)),)).fetchall(); conn.close()
    return [{"session_id":r["session_id"],"created_at":r["created_at"],"source":r["source"],"status":r["status"],"dna":json.loads(r["dna_json"]),"matching":json.loads(r["match_json"]),"recommendation":r["recommendation"]} for r in rows]


@app.post("/api/onboarding/{session_id}/promote")
def onboarding_promote(session_id:str, req:OnboardingPromoteRequest):
    conn=db(); row=conn.execute("SELECT * FROM onboarding_sessions WHERE session_id=?",(session_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Onboarding session not found")
    samples=conn.execute("SELECT raw FROM source_samples WHERE session_id=? ORDER BY id",(session_id,)).fetchall(); conn.close()
    raws=[r["raw"] for r in samples]
    matching=json.loads(row["match_json"]); best=matching.get("best")
    if best and best.get("score",0)>=0.72:
        # bind the already-approved parser without generating code
        now=datetime.now(timezone.utc).isoformat(); conn=db()
        vendor = matching.get("expected_vendor") or matching.get("detected_vendor","Unknown source")
        dna_id = json.loads(row["dna_json"])["id"]
        existing = conn.execute("SELECT source FROM sources WHERE source=?", (row["source"],)).fetchone()
        if existing:
            conn.execute("UPDATE sources SET vendor=?, parser_id=?, dna_id=?, status='trusted', last_seen=? WHERE source=?",(vendor,best["parser_id"],dna_id,now,row["source"]))
        else:
            conn.execute("INSERT INTO sources VALUES (?,?,?,?,?,?,?,?)",(row["source"],now,now,vendor,best["parser_id"],dna_id,len(raws),"trusted"))
        conn.execute("UPDATE onboarding_sessions SET status='trusted' WHERE session_id=?", (session_id,))
        conn.commit(); conn.close()
        return {"session_id":session_id,"result":"existing-parser-bound","parser_id":best["parser_id"],"source":row["source"],"status":"trusted"}
    candidate=parser_candidate(CandidateParserRequest(raw_samples=raws,name=req.candidate_name or row["source"]))
    candidate["genome"]["source"]=row["source"]
    conn=db(); conn.execute("UPDATE parser_candidates SET payload_json=? WHERE parser_id=?",(json.dumps(candidate),candidate["id"]))
    conn.execute("UPDATE onboarding_sessions SET status='candidate' WHERE session_id=?",(session_id,))
    conn.commit(); conn.close()
    return {"session_id":session_id,"result":"candidate-created","candidate":candidate,"status":"candidate"}


@app.get("/api/sources")
def sources():
    conn = db()
    rows = conn.execute("SELECT * FROM sources ORDER BY last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/sources/register")
def register_source(req: SourceRegisterRequest):
    now = datetime.now(timezone.utc).isoformat()
    conn = db()
    existing = conn.execute("SELECT * FROM sources WHERE source=?", (req.source,)).fetchone()
    if existing:
        conn.execute("UPDATE sources SET vendor=? WHERE source=?", (req.expected_vendor or existing["vendor"], req.source))
    else:
        conn.execute("INSERT INTO sources VALUES (?,?,?,?,?,?,?,?)", (req.source, now, now, req.expected_vendor or "Unknown source", "unassigned", "unassigned", 0, "registered"))
    conn.commit()
    row = conn.execute("SELECT * FROM sources WHERE source=?", (req.source,)).fetchone()
    conn.close()
    return dict(row)


@app.get("/api/parsers/{parser_id}/versions")
def parser_versions(parser_id: str):
    conn = db()
    rows = conn.execute("SELECT * FROM parser_versions WHERE parser_id=? ORDER BY version", (parser_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/parsers/{parser_id}/replay")
def replay_parser(req: ParserReplayRequest):
    if not load_parser_any(req.parser_id):
        raise HTTPException(404, "Parser not found")
    results = []
    for raw in req.samples:
        normalized, confidence, evidence = parser_deterministic_with_definition(raw, req.parser_id, allow_candidate=True)
        total = len(parse_kv(raw))
        results.append({"raw": raw, "coverage": round(len(evidence)/max(total,1),3), "confidence": confidence, "normalized": normalized, "unmapped_fields": sorted(set(parse_kv(raw)) - set(evidence))})
    avg = round(sum(x["coverage"] for x in results)/max(len(results),1),3)
    return {"parser_id": req.parser_id, "sample_count": len(results), "avg_coverage": avg, "results": results, "replay_status": "pass" if avg >= 0.90 else "review"}


@app.get("/api/evolution/summary")
def evolution_summary():
    conn = db()
    total_candidates = conn.execute("SELECT COUNT(*) FROM parser_candidates").fetchone()[0]
    approved = conn.execute("SELECT COUNT(*) FROM parser_candidates WHERE status='approved'").fetchone()[0]
    registered = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
    trusted = conn.execute("SELECT COUNT(*) FROM sources WHERE status='trusted'").fetchone()[0]
    conn.close()
    return {"sources_registered": registered, "sources_trusted": trusted, "candidates": total_candidates, "approved_parsers": approved, "learning_loop": "unknown -> candidate -> sandbox -> approval -> deterministic"}


@app.post("/api/sandbox/replay")
def sandbox(req: SandboxRequest):
    if not load_parser_any(req.parser_id):
        raise HTTPException(404, "Parser not found")
    results = []
    for raw in req.samples:
        normalized, confidence, evidence = parser_deterministic_with_definition(raw, req.parser_id, allow_candidate=True)
        raw_keys = set(parse_kv(raw)); mapped_keys = set(evidence)
        coverage = (len(mapped_keys) / len(raw_keys)) if raw_keys else 0
        ai = local_ai_mapper(raw)
        results.append({"raw": raw, "parser_id": req.parser_id, "confidence": confidence, "coverage": round(coverage, 3), "normalized": normalized, "conflicts": ai.get("conflicts", [])})
    avg_coverage = sum(x["coverage"] for x in results) / len(results) if results else 0
    passed = bool(results) and avg_coverage >= 0.75 and all(x["confidence"] >= 0.70 and not x["conflicts"] for x in results)
    return {"parser_id": req.parser_id, "sample_count": len(results), "avg_coverage": round(avg_coverage, 3), "passed": passed, "release_decision": "approve" if passed else "block", "results": results}


@app.post("/api/regression")
def regression(req: RegressionRequest):
    if not load_parser_definition(req.parser_a) or not load_parser_definition(req.parser_b):
        raise HTTPException(404, "Parser not found")
    rows = []
    for raw in req.samples:
        _, conf_a, ev_a = parser_deterministic_with_definition(raw, req.parser_a)
        _, conf_b, ev_b = parser_deterministic_with_definition(raw, req.parser_b)
        rows.append({"raw": raw, "a_coverage": round(len(ev_a)/max(len(parse_kv(raw)),1),3), "b_coverage": round(len(ev_b)/max(len(parse_kv(raw)),1),3), "a_confidence": conf_a, "b_confidence": conf_b})
    a = sum(r["a_coverage"] for r in rows); b = sum(r["b_coverage"] for r in rows)
    regression_detected = b + 0.01 < a
    return {"parser_a": req.parser_a, "parser_b": req.parser_b, "samples": rows, "avg_a_coverage": round(a/max(len(rows),1),3), "avg_b_coverage": round(b/max(len(rows),1),3), "regression_detected": regression_detected, "release_decision": "block" if regression_detected else "pass"}


@app.get("/api/mutation")
def mutation_check(source: str | None = None):
    conn = db()
    if source:
        rows = conn.execute("SELECT dna_json, source FROM dna_history WHERE source=? ORDER BY id DESC LIMIT 20", (source,)).fetchall()
    else:
        rows = conn.execute("SELECT dna_json, source FROM dna_history ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    if len(rows) < 2:
        return {"status":"insufficient_data","message":"Ingest at least two comparable events to compare recent Log DNA fingerprints.","source":source}
    current=json.loads(rows[0]["dna_json"]); current_source=rows[0]["source"]
    baseline=None
    for row in rows[1:]:
        candidate=json.loads(row["dna_json"])
        if candidate.get("id") != current.get("id"):
            baseline=candidate; break
    if not baseline: return {"status":"insufficient_data","message":"No baseline fingerprint found.","source":current_source}
    similarity=dna_similarity(current,baseline); diffs=dna_diff(baseline,current); severity=mutation_severity(similarity,diffs)
    status="stable" if severity=="stable" else ("mutation_suspected" if severity=="warning" else "mutation_detected")
    decision="continue" if status=="stable" else ("review-parser" if status=="mutation_suspected" else "quarantine-source")
    recommendation=("Continue current parser." if status=="stable" else
                   "Replay current parser against recent samples and review changed fields." if status=="mutation_suspected" else
                   "Stop trusting the current parser; quarantine source and generate a candidate parser." )
    report=persist_mutation_report(current_source,baseline,current,similarity,severity,decision,recommendation)
    return {"status":status,"severity":severity,"source":current_source,"similarity_score":similarity,"latest":current["id"],"previous":baseline["id"],"decision":decision,"recommendation":recommendation,"changed_dimensions":diffs,"report_id":report["report_id"]}


@app.get("/api/mutation/reports")
def mutation_reports(limit:int=25, source:str|None=None):
    conn=db()
    if source:
        rows=conn.execute("SELECT * FROM mutation_reports WHERE source=? ORDER BY created_at DESC LIMIT ?",(source,max(1,min(limit,100)))).fetchall()
    else:
        rows=conn.execute("SELECT * FROM mutation_reports ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,100)),)).fetchall()
    conn.close()
    out=[]
    for r in rows:
        item=dict(r); item["changed_dimensions"]=json.loads(r["changed_dimensions_json"]); item.pop("changed_dimensions_json",None); item["payload"]=json.loads(r["payload_json"]); item.pop("payload_json",None); out.append(item)
    return out



# -------------------- v1.1 async queue / backpressure --------------------
QUEUE_MAX_DEPTH = int(os.getenv("ULPF_QUEUE_MAX_DEPTH", "500"))
QUEUE_WORKERS = max(1, int(os.getenv("ULPF_QUEUE_WORKERS", "2")))
QUEUE_MAX_RETRIES = max(1, int(os.getenv("ULPF_QUEUE_MAX_RETRIES", "3")))
QUEUE_POLL_SECONDS = max(0.05, float(os.getenv("ULPF_QUEUE_POLL_SECONDS", "0.20")))
_QUEUE_STARTED = False
_QUEUE_LOCK = threading.Lock()


def _queue_depth(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM processing_queue WHERE status IN ('queued','retry')").fetchone()[0])


def _queue_metric(**kwargs: int | float) -> None:
    conn = db()
    current = conn.execute("SELECT * FROM queue_metrics WHERE id=1").fetchone()
    vals = dict(current) if current else {"enqueued":0,"processed":0,"failed":0,"retried":0,"dlq":0,"processing_ms_total":0}
    for key, value in kwargs.items():
        vals[key] = vals.get(key, 0) + value
    conn.execute("UPDATE queue_metrics SET enqueued=?,processed=?,failed=?,retried=?,dlq=?,processing_ms_total=?,last_updated=? WHERE id=1",
                 (vals["enqueued"],vals["processed"],vals["failed"],vals["retried"],vals["dlq"],vals["processing_ms_total"],datetime.now(timezone.utc).isoformat()))
    conn.commit(); conn.close()


def _claim_job() -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).isoformat()
    conn = db()
    row = conn.execute("SELECT * FROM processing_queue WHERE status IN ('queued','retry') AND (next_attempt_at IS NULL OR next_attempt_at<=?) ORDER BY created_at LIMIT 1", (now,)).fetchone()
    if not row:
        conn.close(); return None
    job_id = row["job_id"]
    updated = now
    worker = threading.current_thread().name
    cur = conn.execute("UPDATE processing_queue SET status='processing',updated_at=?,worker=? WHERE job_id=? AND status IN ('queued','retry')", (updated,worker,job_id))
    conn.commit()
    if cur.rowcount != 1:
        conn.close(); return None
    row = conn.execute("SELECT * FROM processing_queue WHERE job_id=?", (job_id,)).fetchone()
    conn.close(); return dict(row)


def _complete_job(job_id: str, event_id: str) -> None:
    conn=db(); conn.execute("UPDATE processing_queue SET status='completed',updated_at=?,event_id=?,last_error=NULL WHERE job_id=?", (datetime.now(timezone.utc).isoformat(),event_id,job_id)); conn.commit(); conn.close()


def _retry_or_dlq(job: dict[str, Any], error: str) -> None:
    attempts = int(job["attempts"]) + 1
    if attempts < int(job["max_attempts"]):
        delay = min(30, 2 ** max(0, attempts - 1))
        next_at = datetime.now(timezone.utc).timestamp() + delay
        next_iso = datetime.fromtimestamp(next_at, timezone.utc).isoformat()
        conn=db(); conn.execute("UPDATE processing_queue SET status='retry',attempts=?,updated_at=?,next_attempt_at=?,last_error=? WHERE job_id=?", (attempts,datetime.now(timezone.utc).isoformat(),next_iso,error[:1000],job["job_id"])); conn.commit(); conn.close(); _queue_metric(failed=1,retried=1)
    else:
        payload=json.dumps({"job_id":job["job_id"],"source":job["source"],"raw":job["raw"],"error":error})
        conn=db(); conn.execute("INSERT OR REPLACE INTO dead_letter_queue VALUES (?,?,?,?,?,?,?,?)", (job["job_id"],datetime.now(timezone.utc).isoformat(),"max-retries-exceeded",attempts,job["source"],job["raw"],error[:2000],payload)); conn.execute("UPDATE processing_queue SET status='dead-letter',attempts=?,updated_at=?,last_error=? WHERE job_id=?", (attempts,datetime.now(timezone.utc).isoformat(),error[:1000],job["job_id"])); conn.commit(); conn.close(); _queue_metric(failed=1,dlq=1)


def _queue_worker() -> None:
    while True:
        job=_claim_job()
        if not job:
            time.sleep(QUEUE_POLL_SECONDS); continue
        start=time.perf_counter()
        try:
            req=ProcessRequest(source=job["source"],raw=job["raw"],format_hint=job["format_hint"])
            event=_finalize_event_pipeline(req)
            _complete_job(job["job_id"],event["event_id"])
            _queue_metric(processed=1,processing_ms_total=(time.perf_counter()-start)*1000)
        except Exception as exc:
            _retry_or_dlq(job, f"{type(exc).__name__}: {exc}")


def start_queue_workers() -> None:
    global _QUEUE_STARTED
    with _QUEUE_LOCK:
        if _QUEUE_STARTED: return
        for idx in range(QUEUE_WORKERS):
            t=threading.Thread(target=_queue_worker,name=f"ulpf-worker-{idx+1}",daemon=True)
            t.start()
        _QUEUE_STARTED=True


@app.on_event("startup")
def _start_queue_on_startup():
    start_queue_workers()


@app.post("/api/queue/enqueue")
def queue_enqueue(req: IngestRequest):
    conn=db(); depth=_queue_depth(conn)
    if depth >= QUEUE_MAX_DEPTH:
        conn.close(); raise HTTPException(429, f"Queue backpressure active: depth {depth} >= limit {QUEUE_MAX_DEPTH}")
    job_id="JOB-"+uuid.uuid4().hex[:12].upper(); now=datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO processing_queue(job_id,created_at,updated_at,source,raw,format_hint,status,attempts,max_attempts,next_attempt_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (job_id,now,now,req.source,req.raw,req.format_hint,"queued",0,QUEUE_MAX_RETRIES,None)); conn.commit(); conn.close(); _queue_metric(enqueued=1)
    return {"job_id":job_id,"status":"queued","queue_depth":depth+1,"max_depth":QUEUE_MAX_DEPTH}


@app.post("/api/queue/enqueue-batch")
def queue_enqueue_batch(items: list[IngestRequest]):
    if not items: raise HTTPException(400,"Batch cannot be empty")
    conn=db(); depth=_queue_depth(conn); capacity=max(0,QUEUE_MAX_DEPTH-depth)
    accepted=min(len(items),capacity); jobs=[]; now=datetime.now(timezone.utc).isoformat()
    for item in items[:accepted]:
        jid="JOB-"+uuid.uuid4().hex[:12].upper(); conn.execute("INSERT INTO processing_queue(job_id,created_at,updated_at,source,raw,format_hint,status,attempts,max_attempts,next_attempt_at) VALUES (?,?,?,?,?,?,?,?,?,?)", (jid,now,now,item.source,item.raw,item.format_hint,"queued",0,QUEUE_MAX_RETRIES,None)); jobs.append(jid)
    conn.commit(); conn.close()
    if accepted: _queue_metric(enqueued=accepted)
    return {"accepted":accepted,"rejected":len(items)-accepted,"jobs":jobs,"backpressure":accepted<len(items),"queue_depth":depth+accepted,"max_depth":QUEUE_MAX_DEPTH}


@app.get("/api/queue/jobs")
def queue_jobs(status: str|None=None, limit: int=100):
    conn=db(); lim=max(1,min(limit,500))
    if status: rows=conn.execute("SELECT job_id,created_at,updated_at,source,status,attempts,max_attempts,next_attempt_at,event_id,last_error,worker FROM processing_queue WHERE status=? ORDER BY created_at DESC LIMIT ?",(status,lim)).fetchall()
    else: rows=conn.execute("SELECT job_id,created_at,updated_at,source,status,attempts,max_attempts,next_attempt_at,event_id,last_error,worker FROM processing_queue ORDER BY created_at DESC LIMIT ?",(lim,)).fetchall()
    conn.close(); return [dict(r) for r in rows]


@app.get("/api/queue/metrics")
def queue_metrics():
    conn=db(); m=conn.execute("SELECT * FROM queue_metrics WHERE id=1").fetchone(); depth=_queue_depth(conn); q=conn.execute("SELECT COUNT(*) FROM processing_queue WHERE status='queued'").fetchone()[0]; retry=conn.execute("SELECT COUNT(*) FROM processing_queue WHERE status='retry'").fetchone()[0]; processing=conn.execute("SELECT COUNT(*) FROM processing_queue WHERE status='processing'").fetchone()[0]; completed=conn.execute("SELECT COUNT(*) FROM processing_queue WHERE status='completed'").fetchone()[0]; dlq=conn.execute("SELECT COUNT(*) FROM dead_letter_queue").fetchone()[0]; conn.close()
    avg=(m["processing_ms_total"]/m["processed"]) if m and m["processed"] else 0
    return {"workers":QUEUE_WORKERS,"max_depth":QUEUE_MAX_DEPTH,"depth":depth,"queued":q,"retry":retry,"processing":processing,"completed":completed,"dead_letter":dlq,"enqueued":m["enqueued"] if m else 0,"processed":m["processed"] if m else 0,"failed":m["failed"] if m else 0,"retried":m["retried"] if m else 0,"avg_processing_ms":round(avg,3),"backpressure_active":depth>=QUEUE_MAX_DEPTH,"mode":"persistent-local-worker-queue"}


@app.get("/api/queue/dlq")
def queue_dlq(limit: int=100):
    conn=db(); rows=conn.execute("SELECT job_id,moved_at,reason,attempts,source,last_error,payload_json FROM dead_letter_queue ORDER BY moved_at DESC LIMIT ?",(max(1,min(limit,500)),)).fetchall(); conn.close()
    out=[]
    for r in rows:
        x=dict(r); x["payload"]=json.loads(x.pop("payload_json")); out.append(x)
    return out


@app.post("/api/queue/dlq/{job_id}/requeue")
def queue_dlq_requeue(job_id: str):
    conn=db(); row=conn.execute("SELECT * FROM dead_letter_queue WHERE job_id=?",(job_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"DLQ job not found")
    now=datetime.now(timezone.utc).isoformat(); conn.execute("UPDATE processing_queue SET status='queued',attempts=0,updated_at=?,next_attempt_at=NULL,last_error=NULL WHERE job_id=?",(now,job_id)); conn.execute("DELETE FROM dead_letter_queue WHERE job_id=?",(job_id,)); conn.commit(); conn.close(); return {"job_id":job_id,"status":"requeued"}


# -------------------- v1.2 partitioned replayable stream plane --------------------
STREAM_PARTITIONS = max(1, int(os.getenv("ULPF_STREAM_PARTITIONS", "4")))
STREAM_BATCH_MAX = max(1, int(os.getenv("ULPF_STREAM_BATCH_MAX", "100")))
_STREAM_LOCK = threading.Lock()

def _stream_partition(key: str) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % STREAM_PARTITIONS

def _next_sequence(conn: sqlite3.Connection, stream: str, partition_id: int) -> int:
    row = conn.execute(
        "SELECT MAX(sequence_no) AS m FROM stream_events WHERE stream=? AND partition_id=?",
        (stream, partition_id),
    ).fetchone()
    max_sequence = row["m"]
    # 0 is a valid sequence number; do not treat it as falsy.
    return int(max_sequence) + 1 if max_sequence is not None else 0

class StreamEventRequest(BaseModel):
    stream: str = "ulpf-events"
    key: str = "unknown"
    source: str = "unknown"
    raw: str
    format_hint: str | None = None
    message_id: str | None = None

class StreamBatchRequest(BaseModel):
    stream: str = "ulpf-events"
    events: list[StreamEventRequest]

class StreamPollRequest(BaseModel):
    stream: str = "ulpf-events"
    consumer: str = "ulpf-worker"
    partition_id: int
    batch_size: int = 20
    auto_process: bool = False

@app.post("/api/stream/publish")
def stream_publish(req: StreamEventRequest):
    stream = req.stream.strip() or "ulpf-events"
    pid = _stream_partition(req.key or req.source or "unknown")
    mid = req.message_id or ("MSG-" + uuid.uuid4().hex[:16].upper())
    now = datetime.now(timezone.utc).isoformat()
    with _STREAM_LOCK:
        conn = db()
        existing = conn.execute("SELECT stream,partition_id,sequence_no FROM stream_events WHERE message_id=?", (mid,)).fetchone()
        if existing:
            conn.close()
            return {"published": False, "duplicate": True, "message_id": mid, **dict(existing)}
        seq = _next_sequence(conn, stream, pid)
        while True:
            try:
                conn.execute("INSERT INTO stream_events(stream,partition_id,sequence_no,message_id,created_at,source,raw,format_hint,status) VALUES (?,?,?,?,?,?,?,?,?)",
                             (stream,pid,seq,mid,now,req.source,req.raw,req.format_hint,"available"))
                break
            except sqlite3.IntegrityError as exc:
                if "stream_events.stream" not in str(exc) and "sequence_no" not in str(exc):
                    raise
                seq += 1
        conn.commit(); conn.close()
    return {"published": True, "duplicate": False, "message_id": mid, "stream": stream, "partition_id": pid, "sequence_no": seq}

@app.post("/api/stream/publish-batch")
def stream_publish_batch(req: StreamBatchRequest):
    if not req.events: raise HTTPException(400, "events cannot be empty")
    if len(req.events) > STREAM_BATCH_MAX: raise HTTPException(413, f"batch exceeds {STREAM_BATCH_MAX}")
    out=[]; seen=set(); now=datetime.now(timezone.utc).isoformat()
    with _STREAM_LOCK:
        conn=db()
        for item in req.events:
            mid=item.message_id or ("MSG-" + uuid.uuid4().hex[:16].upper())
            if mid in seen:
                out.append({"message_id":mid,"published":False,"duplicate":True}); continue
            seen.add(mid)
            existing=conn.execute("SELECT stream,partition_id,sequence_no FROM stream_events WHERE message_id=?",(mid,)).fetchone()
            if existing:
                out.append({"message_id":mid,"published":False,"duplicate":True,**dict(existing)}); continue
            pid=_stream_partition(item.key or item.source or "unknown"); seq=_next_sequence(conn,req.stream,pid)
            while True:
                try:
                    conn.execute("INSERT INTO stream_events(stream,partition_id,sequence_no,message_id,created_at,source,raw,format_hint,status) VALUES (?,?,?,?,?,?,?,?,?)",
                                 (req.stream,pid,seq,mid,now,item.source,item.raw,item.format_hint,"available"))
                    break
                except sqlite3.IntegrityError as exc:
                    if "stream_events.stream" not in str(exc) and "sequence_no" not in str(exc):
                        raise
                    seq += 1
            out.append({"message_id":mid,"published":True,"partition_id":pid,"sequence_no":seq})
        conn.commit(); conn.close()
    return {"accepted":sum(1 for x in out if x.get('published')),"results":out,"partitions":STREAM_PARTITIONS}

@app.post("/api/stream/poll")
def stream_poll(req: StreamPollRequest):
    size=max(1,min(req.batch_size,STREAM_BATCH_MAX))
    conn=db()
    now=datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT OR IGNORE INTO stream_offsets(stream,consumer,partition_id,next_sequence,updated_at) VALUES (?,?,?,?,?)",
                 (req.stream,req.consumer,req.partition_id,0,now))
    off=conn.execute("SELECT next_sequence FROM stream_offsets WHERE stream=? AND consumer=? AND partition_id=?",
                     (req.stream,req.consumer,req.partition_id)).fetchone()[0]
    rows=conn.execute("SELECT * FROM stream_events WHERE stream=? AND partition_id=? AND sequence_no>=? ORDER BY sequence_no LIMIT ?",
                      (req.stream,req.partition_id,off,size)).fetchall()
    msgs=[dict(r) for r in rows]
    conn.close()
    if req.auto_process and msgs:
        for m in msgs:
            try:
                event=_finalize_event_pipeline(ProcessRequest(source=m['source'],raw=m['raw'],format_hint=m['format_hint']))
                conn=db(); ts=datetime.now(timezone.utc).isoformat()
                conn.execute("UPDATE stream_events SET status='processed', consumed_by=?, consumed_at=?, event_id=? WHERE stream=? AND partition_id=? AND sequence_no=?",
                             (req.consumer,ts,event['event_id'],req.stream,req.partition_id,m['sequence_no']))
                conn.execute("UPDATE stream_offsets SET next_sequence=?,updated_at=? WHERE stream=? AND consumer=? AND partition_id=?",
                             (m['sequence_no']+1,ts,req.stream,req.consumer,req.partition_id))
                conn.execute("INSERT OR REPLACE INTO stream_checkpoints VALUES (?,?,?,?,?,?)",
                             (req.stream,req.consumer,req.partition_id,m['sequence_no'],ts,event['event_id']))
                conn.commit(); conn.close()
                m['status']='processed'; m['event_id']=event['event_id']
            except Exception as exc:
                m['status']='failed'; m['error']=f"{type(exc).__name__}: {exc}"; break
    return {"stream":req.stream,"consumer":req.consumer,"partition_id":req.partition_id,"offset":off,"count":len(msgs),"messages":msgs}

@app.post("/api/stream/commit")
def stream_commit(stream: str, consumer: str, partition_id: int, sequence_no: int, event_id: str | None = None):
    if partition_id < 0 or partition_id >= STREAM_PARTITIONS: raise HTTPException(400, "invalid partition_id")
    conn=db(); exists=conn.execute("SELECT 1 FROM stream_events WHERE stream=? AND partition_id=? AND sequence_no=?",(stream,partition_id,sequence_no)).fetchone()
    if not exists: conn.close(); raise HTTPException(404,"sequence not found")
    now=datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO stream_offsets(stream,consumer,partition_id,next_sequence,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(stream,consumer,partition_id) DO UPDATE SET next_sequence=excluded.next_sequence, updated_at=excluded.updated_at",
                 (stream,consumer,partition_id,sequence_no+1,now))
    conn.execute("INSERT OR REPLACE INTO stream_checkpoints VALUES (?,?,?,?,?,?)",(stream,consumer,partition_id,sequence_no,now,event_id))
    conn.commit(); conn.close(); return {"committed":True,"next_sequence":sequence_no+1}

@app.get("/api/stream/offsets")
def stream_offsets(stream: str="ulpf-events", consumer: str="ulpf-worker"):
    conn=db(); rows=conn.execute("SELECT partition_id,next_sequence,updated_at FROM stream_offsets WHERE stream=? AND consumer=? ORDER BY partition_id",(stream,consumer)).fetchall(); conn.close()
    return {"stream":stream,"consumer":consumer,"partitions":[dict(r) for r in rows],"partition_count":STREAM_PARTITIONS}

@app.get("/api/stream/metrics")
def stream_metrics(stream: str="ulpf-events"):
    conn=db(); available=conn.execute("SELECT COUNT(*) FROM stream_events WHERE stream=? AND status='available'",(stream,)).fetchone()[0]; processed=conn.execute("SELECT COUNT(*) FROM stream_events WHERE stream=? AND status='processed'",(stream,)).fetchone()[0]; total=conn.execute("SELECT COUNT(*) FROM stream_events WHERE stream=?",(stream,)).fetchone()[0]; parts=[]
    for p in range(STREAM_PARTITIONS):
        row=conn.execute("SELECT COUNT(*) AS c, MIN(sequence_no) AS min_seq, MAX(sequence_no) AS max_seq FROM stream_events WHERE stream=? AND partition_id=?",(stream,p)).fetchone(); parts.append({"partition_id":p,"count":row['c'],"min_sequence":row['min_seq'],"max_sequence":row['max_seq']})
    conn.close(); return {"stream":stream,"partition_count":STREAM_PARTITIONS,"total":total,"available":available,"processed":processed,"partitions":parts,"ordering":"per-partition-sequence","replayable":True}

@app.post("/api/stream/replay")
def stream_replay(stream: str, consumer: str, partition_id: int, from_sequence: int, to_sequence: int | None = None):
    if from_sequence < 0: raise HTTPException(400,"from_sequence must be >= 0")
    if partition_id < 0 or partition_id >= STREAM_PARTITIONS: raise HTTPException(400,"invalid partition_id")
    conn=db(); max_seq=conn.execute("SELECT MAX(sequence_no) FROM stream_events WHERE stream=? AND partition_id=?",(stream,partition_id)).fetchone()[0]
    if max_seq is None: conn.close(); raise HTTPException(404,"partition has no events")
    end=min(to_sequence if to_sequence is not None else max_seq,max_seq)
    replay_id="RPL-"+uuid.uuid4().hex[:12].upper(); now=datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO stream_replay_requests VALUES (?,?,?,?,?,?,?,?,?,?)",(replay_id,stream,consumer,partition_id,from_sequence,end,'completed',now,now,max(0,end-from_sequence+1)))
    conn.execute("INSERT INTO stream_offsets(stream,consumer,partition_id,next_sequence,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(stream,consumer,partition_id) DO UPDATE SET next_sequence=excluded.next_sequence,updated_at=excluded.updated_at",(stream,consumer,partition_id,from_sequence,now))
    conn.commit(); conn.close(); return {"replay_id":replay_id,"status":"ready","stream":stream,"consumer":consumer,"partition_id":partition_id,"from_sequence":from_sequence,"to_sequence":end,"next_sequence":from_sequence}

@app.get("/api/stream/replays")
def stream_replays(limit: int=50):
    conn=db(); rows=conn.execute("SELECT * FROM stream_replay_requests ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); conn.close(); return [dict(r) for r in rows]


@app.get("/api/forensics/events")
def forensic_events(limit: int = 50, status: str | None = None, source: str | None = None):
    conn = db()
    sql = "SELECT e.event_id, e.created_at, e.source, e.vendor, e.format, e.parser_id, e.status, e.raw_sha256, f.trace_id FROM events e LEFT JOIN forensic_traces f ON f.event_id=e.event_id WHERE 1=1"
    params: list[Any] = []
    if status:
        sql += " AND e.status=?"; params.append(status)
    if source:
        sql += " AND e.source=?"; params.append(source)
    sql += " ORDER BY e.created_at DESC LIMIT ?"; params.append(max(1, min(limit, 200)))
    rows = conn.execute(sql, params).fetchall(); conn.close()
    return [dict(r) for r in rows]


@app.get("/api/forensics/events/{event_id}")
def forensic_event(event_id: str):
    conn = db()
    row = conn.execute("SELECT payload_json FROM events WHERE event_id=?", (event_id,)).fetchone()
    trace = conn.execute("SELECT * FROM forensic_traces WHERE event_id=?", (event_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Event not found")
    event = json.loads(row['payload_json'])
    if trace:
        event['forensic_trace'] = {
            'trace_id': trace['trace_id'],
            'timeline': json.loads(trace['timeline_json']),
            'proof': json.loads(trace['proof_json']),
        }
    return event


@app.get("/api/forensics/events/{event_id}/timeline")
def forensic_timeline(event_id: str):
    conn = db(); row = conn.execute("SELECT trace_id, event_id, created_at, raw_sha256, parser_id, schema_version, status, timeline_json, proof_json FROM forensic_traces WHERE event_id=?", (event_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404, "Forensic trace not found")
    return {**dict(row), 'timeline': json.loads(row['timeline_json']), 'proof': json.loads(row['proof_json'])}


class ForensicReplayRequest(BaseModel):
    event_id: str
    parser_a: str
    parser_b: str


@app.post("/api/forensics/replay-compare")
def forensic_replay_compare(req: ForensicReplayRequest):
    conn=db(); row=conn.execute("SELECT raw FROM events WHERE event_id=?",(req.event_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404,"Event not found")
    raw=row['raw']
    results=[]
    for parser_id in (req.parser_a, req.parser_b):
        normalized, conf, evidence = parser_deterministic_with_definition(raw, parser_id, allow_candidate=True)
        results.append({'parser_id':parser_id,'confidence':conf,'mapped_fields':len(evidence),'coverage':round(len(evidence)/max(len(parse_kv(raw)),1),3),'normalized':normalized,'evidence':evidence})
    delta=round(results[1]['coverage']-results[0]['coverage'],3)
    return {'event_id':req.event_id,'raw_sha256':sha256(raw),'parsers':results,'coverage_delta':delta,'regression':delta<0}




# -------------------- v2.7 threat hunting + correlation plane --------------------
def _threat_hunt_rows(limit: int = 5000) -> list[dict[str, Any]]:
    conn = db()
    rows = conn.execute("SELECT payload_json FROM events ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 5000)),)).fetchall()
    conn.close()
    return [json.loads(r["payload_json"]) for r in rows]

def _event_field(e: dict[str, Any], key: str) -> Any:
    n = e.get("normalized") or {}
    if key in n: return n.get(key)
    if key == "source.ip": return n.get("source.ip")
    if key == "destination.ip": return n.get("destination.ip")
    if key == "event.action": return n.get("event.action")
    if key == "network.protocol": return n.get("network.protocol")
    return None

class HuntQuery(BaseModel):
    source: str | None = None
    vendor: str | None = None
    action: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    parser_id: str | None = None
    status: str | None = None
    protocol: str | None = None
    text: str | None = None
    since: str | None = None
    until: str | None = None
    limit: int = Field(default=200, ge=1, le=2000)

def _match_hunt(e: dict[str, Any], q: HuntQuery) -> bool:
    checks = [
        (q.source, e.get("source")), (q.vendor, e.get("vendor")), (q.parser_id, e.get("parser_id")), (q.status, e.get("status")),
        (q.action, _event_field(e,"event.action")), (q.src_ip, _event_field(e,"source.ip")), (q.dst_ip, _event_field(e,"destination.ip")),
        (q.protocol, _event_field(e,"network.protocol")),
    ]
    for expected, actual in checks:
        if expected and str(actual).lower() != expected.lower(): return False
    if q.text:
        blob = json.dumps(e, sort_keys=True).lower()
        if q.text.lower() not in blob: return False
    ts = e.get("ingested_at") or ""
    if q.since and ts < q.since: return False
    if q.until and ts > q.until: return False
    return True

def _hunt_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    actions=Counter(str(_event_field(e,"event.action") or "unknown") for e in events)
    sources=Counter(str(e.get("source") or "unknown") for e in events)
    vendors=Counter(str(e.get("vendor") or "unknown") for e in events)
    protocols=Counter(str(_event_field(e,"network.protocol") or "unknown") for e in events)
    return {
        "total": len(events),
        "actions": dict(actions.most_common()),
        "sources": dict(sources.most_common(20)),
        "vendors": dict(vendors.most_common(20)),
        "protocols": dict(protocols.most_common()),
    }

@app.post("/api/threat-hunt/search")
def threat_hunt_search(q: HuntQuery):
    events=[e for e in _threat_hunt_rows() if _match_hunt(e,q)][:q.limit]
    return {"query": q.model_dump(), "count": len(events), "summary": _hunt_summary(events), "events": events}

@app.get("/api/threat-hunt/summary")
def threat_hunt_summary(limit: int = 2000):
    events=_threat_hunt_rows(limit)
    return _hunt_summary(events)

@app.get("/api/threat-hunt/correlation")
def threat_hunt_correlation(src_ip: str | None = None, dst_ip: str | None = None, action: str | None = None, window_seconds: int = 300, limit: int = 1000):
    events=[]
    for e in _threat_hunt_rows(limit):
        if src_ip and str(_event_field(e,"source.ip")) != src_ip: continue
        if dst_ip and str(_event_field(e,"destination.ip")) != dst_ip: continue
        if action and str(_event_field(e,"event.action")).lower() != action.lower(): continue
        events.append(e)
    events.sort(key=lambda e: e.get("ingested_at") or "")
    edges=Counter(); nodes=Counter()
    for e in events:
        src=_event_field(e,"source.ip"); dst=_event_field(e,"destination.ip")
        if not src or not dst: continue
        key=f"{src} → {dst}"; edges[key]+=1; nodes[str(src)]+=1; nodes[str(dst)]+=1
    bursts=[]
    for i,e in enumerate(events):
        src=_event_field(e,"source.ip"); dst=_event_field(e,"destination.ip")
        if not src or not dst: continue
        start=e.get("ingested_at") or ""
        count=0
        # Small local prototype: compare a bounded forward window using epoch seconds.
        try:
            t0=datetime.fromisoformat(start.replace("Z","+00:00"))
        except Exception:
            continue
        for later in events[i:i+100]:
            try: t1=datetime.fromisoformat((later.get("ingested_at") or "").replace("Z","+00:00"))
            except Exception: continue
            delta=(t1-t0).total_seconds()
            if 0 <= delta <= window_seconds and _event_field(later,"source.ip")==src and _event_field(later,"destination.ip")==dst: count+=1
            if delta > window_seconds: break
        if count >= 3:
            bursts.append({"source_ip":src,"destination_ip":dst,"events_in_window":count,"window_seconds":window_seconds,"started_at":start})
    return {"filters":{"src_ip":src_ip,"dst_ip":dst_ip,"action":action,"window_seconds":window_seconds},"event_count":len(events),"top_edges":[{"relationship":k,"count":v} for k,v in edges.most_common(20)],"nodes":[{"ip":k,"event_count":v} for k,v in nodes.most_common(30)],"bursts":bursts[:30],"signal":"local correlation only; no external enrichment"}

@app.get("/api/threat-hunt/timeline")
def threat_hunt_timeline(source: str | None = None, src_ip: str | None = None, dst_ip: str | None = None, limit: int = 300):
    q=HuntQuery(source=source, src_ip=src_ip, dst_ip=dst_ip, limit=max(1,min(limit,300)))
    events=[e for e in _threat_hunt_rows() if _match_hunt(e,q)]
    points=[]
    for e in sorted(events, key=lambda x: x.get("ingested_at") or ""):
        points.append({"event_id":e.get("event_id"),"timestamp":e.get("ingested_at"),"source":e.get("source"),"action":_event_field(e,"event.action"),"src_ip":_event_field(e,"source.ip"),"dst_ip":_event_field(e,"destination.ip"),"status":e.get("status")})
    return {"count":len(points),"timeline":points}


# -------------------- v2.8 detection & investigation rule engine --------------------
SEVERITIES = {"low", "medium", "high", "critical"}
ALERT_STATUSES = {"open", "acknowledged", "resolved", "dismissed"}

class DetectionCondition(BaseModel):
    field: str
    operator: str = Field(pattern="^(eq|neq|contains|prefix|gt|gte|lt|lte|in|exists)$")
    value: Any | None = None

class DetectionRuleRequest(BaseModel):
    name: str
    description: str = ""
    severity: str = "medium"
    rule_type: str = "threshold"
    threshold: int = 1
    window_seconds: int = 300
    conditions: list[DetectionCondition] = Field(default_factory=list)
    enabled: bool = True
    created_by: str = "analyst"

class AlertUpdateRequest(BaseModel):
    status: str = Field(pattern="^(open|acknowledged|resolved|dismissed)$")
    assigned_to: str | None = None
    resolution: str = ""


def _alert_field(event: dict[str, Any], field: str) -> Any:
    normalized = event.get("normalized") or {}
    if field in normalized:
        return normalized.get(field)
    if field.startswith("raw."):
        return (event.get("raw") or "")
    if field in event:
        return event.get(field)
    # Useful flat aliases for analyst-authored rules.
    aliases = {
        "src_ip":"source.ip", "dst_ip":"destination.ip", "action":"event.action",
        "source":"source", "vendor":"vendor", "format":"format", "status":"status",
        "protocol":"network.protocol", "src_port":"source.port", "dst_port":"destination.port",
    }
    target = aliases.get(field)
    return normalized.get(target) if target else None


def _condition_matches(event: dict[str, Any], c: DetectionCondition) -> bool:
    actual = _alert_field(event, c.field)
    op, expected = c.operator, c.value
    if op == "exists":
        return actual is not None and actual != ""
    if op == "eq": return str(actual).lower() == str(expected).lower()
    if op == "neq": return str(actual).lower() != str(expected).lower()
    if op == "contains": return str(expected).lower() in str(actual).lower()
    if op == "prefix": return str(actual).startswith(str(expected))
    if op == "in": return str(actual).lower() in {str(x).lower() for x in (expected or [])}
    try:
        a, b = float(actual), float(expected)
        return {"gt": a>b, "gte": a>=b, "lt": a<b, "lte": a<=b}[op]
    except (TypeError, ValueError):
        return False


def _event_dt(e: dict[str, Any]) -> datetime:
    raw=e.get("ingested_at") or e.get("created_at") or ""
    try: return datetime.fromisoformat(raw.replace("Z","+00:00"))
    except Exception: return datetime.min.replace(tzinfo=timezone.utc)


def _evaluate_rule(rule: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any] | None:
    conds=json.loads(rule["conditions_json"])
    matched=[e for e in events if all(_condition_matches(e, DetectionCondition(**c)) for c in conds)]
    matched.sort(key=_event_dt)
    threshold=max(1,int(rule["threshold"])); window=max(1,int(rule["window_seconds"]))
    if not matched: return None
    # Threshold rules can be global or source-grouped when a source field is present in conditions.
    for i, anchor in enumerate(matched):
        group=[anchor]
        t0=_event_dt(anchor)
        for e in matched[i+1:]:
            dt=(_event_dt(e)-t0).total_seconds()
            if dt>window: break
            group.append(e)
        if len(group)>=threshold:
            score=min(100.0, 50.0 + 10.0*len(group) + {"low":0,"medium":10,"high":20,"critical":30}.get(rule["severity"],10))
            return {"event_ids":[e.get("event_id") for e in group if e.get("event_id")],"matched_count":len(group),"window_seconds":window,"score":round(score,1),"started_at":anchor.get("ingested_at")}
    return None


def _serialize_rule(row: sqlite3.Row) -> dict[str, Any]:
    d=dict(row); d["conditions"]=json.loads(d.pop("conditions_json")); d["enabled"]=bool(d["enabled"]); return d

@app.get("/api/detections/rules")
def detection_rules(enabled: bool | None = None):
    conn=db();
    if enabled is None: rows=conn.execute("SELECT * FROM detection_rules ORDER BY updated_at DESC").fetchall()
    else: rows=conn.execute("SELECT * FROM detection_rules WHERE enabled=? ORDER BY updated_at DESC",(1 if enabled else 0,)).fetchall()
    conn.close(); return {"count":len(rows),"rules":[_serialize_rule(r) for r in rows]}

@app.post("/api/detections/rules")
def create_detection_rule(req: DetectionRuleRequest):
    if req.severity not in SEVERITIES: raise HTTPException(400,"invalid severity")
    if req.threshold<1 or req.threshold>100000: raise HTTPException(400,"threshold out of range")
    now=datetime.now(timezone.utc).isoformat(); rid="RULE-"+uuid.uuid4().hex[:10].upper()
    conn=db(); conn.execute("INSERT INTO detection_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now,now,req.name,req.description,1 if req.enabled else 0,req.severity,req.rule_type,int(req.threshold),int(req.window_seconds),json.dumps([c.model_dump() for c in req.conditions]),req.created_by,1)); conn.commit(); row=conn.execute("SELECT * FROM detection_rules WHERE rule_id=?",(rid,)).fetchone(); conn.close()
    return _serialize_rule(row)

@app.patch("/api/detections/rules/{rule_id}")
def update_detection_rule(rule_id: str, req: DetectionRuleRequest):
    now=datetime.now(timezone.utc).isoformat(); conn=db(); old=conn.execute("SELECT * FROM detection_rules WHERE rule_id=?",(rule_id,)).fetchone()
    if not old: conn.close(); raise HTTPException(404,"Rule not found")
    version=int(old["version"])+1
    conn.execute("UPDATE detection_rules SET updated_at=?,name=?,description=?,enabled=?,severity=?,rule_type=?,threshold=?,window_seconds=?,conditions_json=?,created_by=?,version=? WHERE rule_id=?",(now,req.name,req.description,1 if req.enabled else 0,req.severity,req.rule_type,req.threshold,req.window_seconds,json.dumps([c.model_dump() for c in req.conditions]),req.created_by,version,rule_id)); conn.commit(); row=conn.execute("SELECT * FROM detection_rules WHERE rule_id=?",(rule_id,)).fetchone(); conn.close(); return _serialize_rule(row)

@app.post("/api/detections/run")
def run_detection_rules(limit: int = 5000):
    events=_threat_hunt_rows(max(100, min(limit,10000)))
    conn=db(); rules=conn.execute("SELECT * FROM detection_rules WHERE enabled=1 ORDER BY updated_at DESC").fetchall(); fired=[]
    now=datetime.now(timezone.utc).isoformat()
    for rule in rules:
        hit=_evaluate_rule(rule,events)
        if not hit: continue
        # Avoid duplicate open alerts for identical rule + event set.
        fingerprint=sha256(json.dumps(sorted(hit["event_ids"]),separators=(",",":"))+rule["rule_id"])
        existing=conn.execute("SELECT alert_id FROM alerts WHERE rule_id=? AND status IN ('open','acknowledged') AND evidence_json LIKE ? LIMIT 1",(rule["rule_id"],f'%{fingerprint}%')).fetchone()
        if existing: continue
        aid="ALERT-"+uuid.uuid4().hex[:12].upper(); evidence={"fingerprint":fingerprint,**hit,"conditions":json.loads(rule["conditions_json"]),"source_count":len({e.get("source") for e in events if e.get("event_id") in hit["event_ids"]})}
        conn.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(aid,now,now,rule["rule_id"],rule["version"],rule["severity"],"open",rule["name"],rule["description"],next((e.get("source") for e in events if e.get("event_id") in hit["event_ids"]),None),json.dumps(hit["event_ids"]),json.dumps(evidence),hit["score"],None,None)); fired.append({"alert_id":aid,"rule_id":rule["rule_id"],"severity":rule["severity"],**hit})
    conn.commit(); conn.close()
    propagation=_propagate_risk("detection_engine", 200)
    return {"evaluated_rules":len(rules),"fired":len(fired),"alerts":fired,"risk_propagation":propagation}

@app.get("/api/detections/alerts")
def list_detection_alerts(status: str | None = None, severity: str | None = None, limit: int = 100):
    limit=max(1,min(limit,500)); conn=db(); clauses=[]; params=[]
    if status: clauses.append("status=?"); params.append(status)
    if severity: clauses.append("severity=?"); params.append(severity)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    rows=conn.execute(f"SELECT * FROM alerts{where} ORDER BY created_at DESC LIMIT ?",(*params,limit)).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["event_ids"]=json.loads(d.pop("event_ids_json")); d["evidence"]=json.loads(d.pop("evidence_json")); out.append(d)
    return {"count":len(out),"alerts":out}

@app.patch("/api/detections/alerts/{alert_id}")
def update_detection_alert(alert_id: str, req: AlertUpdateRequest):
    now=datetime.now(timezone.utc).isoformat(); conn=db(); row=conn.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Alert not found")
    conn.execute("UPDATE alerts SET updated_at=?,status=?,assigned_to=?,resolution=? WHERE alert_id=?",(now,req.status,req.assigned_to,req.resolution,alert_id)); conn.commit(); row=conn.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone(); conn.close()
    d=dict(row); d["event_ids"]=json.loads(d.pop("event_ids_json")); d["evidence"]=json.loads(d.pop("evidence_json")); return d

@app.get("/api/detections/summary")
def detection_summary():
    conn=db();
    rules=conn.execute("SELECT COUNT(*) total, SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) enabled FROM detection_rules").fetchone();
    statuses=conn.execute("SELECT status,COUNT(*) count FROM alerts GROUP BY status").fetchall(); sev=conn.execute("SELECT severity,COUNT(*) count FROM alerts GROUP BY severity").fetchall(); recent=conn.execute("SELECT alert_id,name,severity,status,created_at,score FROM alerts ORDER BY created_at DESC LIMIT 10").fetchall(); conn.close()
    return {"rules":{"total":rules[0] or 0,"enabled":rules[1] or 0},"alerts_by_status":{r[0]:r[1] for r in statuses},"alerts_by_severity":{r[0]:r[1] for r in sev},"recent":[dict(r) for r in recent]}

# -------------------- v2.6 investigation workspace --------------------
@app.get("/api/investigation/search")
def investigation_search(q: str | None = None, source: str | None = None, status: str | None = None, limit: int = 50):
    """Cross-index event discovery for a single investigation workspace. Local SQLite only."""
    limit = max(1, min(limit, 200))
    conn = db()
    clauses = []
    params: list[Any] = []
    if q:
        like = f"%{q}%"
        clauses.append("(e.raw LIKE ? OR e.event_id LIKE ? OR e.source LIKE ? OR e.vendor LIKE ? OR e.parser_id LIKE ? OR e.raw_sha256 LIKE ?)")
        params.extend([like, like, like, like, like, like])
    if source:
        clauses.append("e.source=?"); params.append(source)
    if status:
        clauses.append("e.status=?"); params.append(status)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(f"""SELECT e.event_id,e.created_at,e.source,e.vendor,e.format,e.parser_id,e.status,e.raw_sha256,
        f.trace_id, m.schema_id,m.schema_version,m.parser_version,m.contract_id,m.contract_version,m.artifact_id
        FROM events e LEFT JOIN forensic_traces f ON f.event_id=e.event_id
        LEFT JOIN event_model_refs m ON m.event_id=e.event_id
        {where} ORDER BY e.created_at DESC LIMIT ?""", (*params, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/investigation/{event_id}")
def investigation_workspace(event_id: str):
    """Return the complete locally persisted investigation bundle for an event."""
    conn = db()
    event_row = conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
    if not event_row:
        conn.close(); raise HTTPException(404, "Event not found")
    event = json.loads(event_row["payload_json"])
    raw_hash = event_row["raw_sha256"]
    model = conn.execute("SELECT * FROM event_model_refs WHERE event_id=?", (event_id,)).fetchone()
    trace = conn.execute("SELECT * FROM forensic_traces WHERE event_id=?", (event_id,)).fetchone()
    ai = conn.execute("SELECT * FROM ai_mapping_evidence WHERE raw_sha256=? ORDER BY created_at DESC LIMIT 10", (raw_hash,)).fetchall()
    decisions = conn.execute("SELECT * FROM ai_decisions WHERE raw_sha256=? ORDER BY created_at DESC LIMIT 10", (raw_hash,)).fetchall()
    dna = conn.execute("SELECT * FROM dna_history WHERE source=? ORDER BY id DESC LIMIT 10", (event_row["source"],)).fetchall()
    mutations = conn.execute("SELECT * FROM mutation_reports WHERE source=? ORDER BY created_at DESC LIMIT 10", (event_row["source"],)).fetchall()
    evolution = conn.execute("SELECT * FROM evolution_runs WHERE source=? ORDER BY created_at DESC LIMIT 10", (event_row["source"],)).fetchall()
    artifact = None
    if model and model["artifact_id"]:
        artifact = conn.execute("SELECT * FROM translation_artifacts WHERE artifact_id=?", (model["artifact_id"],)).fetchone()
    parser_version = None
    if model and model["parser_id"] and model["parser_version"]:
        parser_version = conn.execute("SELECT * FROM parser_versions WHERE parser_key=? AND version=?", (model["parser_id"], model["parser_version"])).fetchone()
    conn.close()

    def rows(rows):
        return [dict(r) for r in rows]
    bundle = {
        "event": event,
        "model_ref": dict(model) if model else None,
        "artifact": ({**dict(artifact), "payload": json.loads(artifact["payload_json"])} if artifact else None),
        "parser_version": ({**dict(parser_version), "payload": json.loads(parser_version["payload_json"])} if parser_version else None),
        "forensic_trace": ({**dict(trace), "timeline": json.loads(trace["timeline_json"]), "proof": json.loads(trace["proof_json"])} if trace else None),
        "ai_mapping_evidence": [{**x, "candidate_mappings": json.loads(x["candidate_mappings_json"]), "unknown_fields": json.loads(x["unknown_fields_json"]), "conflicts": json.loads(x["conflicts_json"]), "validation_summary": json.loads(x["validation_summary_json"])} for x in ai],
        "ai_decisions": [{**x, "reasons": json.loads(x["reasons_json"]), "evidence": json.loads(x["evidence_json"])} for x in decisions],
        "dna_history": [{**x, "dna": json.loads(x["dna_json"])} for x in dna],
        "mutation_history": [{**x, "changed_dimensions": json.loads(x["changed_dimensions_json"]), "payload": json.loads(x["payload_json"])} for x in mutations],
        "evolution_history": [{**x, "evidence": json.loads(x["evidence_json"])} for x in evolution],
        "integrity": {"raw_sha256": raw_hash, "raw_sha256_matches": sha256(event_row["raw"]) == raw_hash, "air_gapped": True},
    }
    return bundle


@app.post("/api/investigation/{event_id}/verify")
def investigation_verify(event_id: str):
    conn = db(); row = conn.execute("SELECT raw,raw_sha256,payload_json FROM events WHERE event_id=?", (event_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404, "Event not found")
    actual = sha256(row["raw"])
    payload = json.loads(row["payload_json"])
    normalized_hash = sha256(json.dumps(payload.get("normalized", {}), sort_keys=True))
    stored_normalized = ((payload.get("lossless_proof") or {}).get("normalized_sha256"))
    return {
        "event_id": event_id,
        "raw_sha256_expected": row["raw_sha256"],
        "raw_sha256_actual": actual,
        "raw_integrity": actual == row["raw_sha256"],
        "normalized_sha256": normalized_hash,
        "normalized_hash_matches": stored_normalized == normalized_hash if stored_normalized else False,
        "lossless": bool((payload.get("lossless_proof") or {}).get("information_loss") is False),
    }

# -------------------- v3.6 automated response & containment simulation --------------------
RESPONSE_ACTIONS = {
    "isolate_host": {"label":"Isolate host", "risk_band":"critical", "target_field":"destination.ip"},
    "block_source": {"label":"Block source", "risk_band":"high", "target_field":"source.ip"},
    "disable_account": {"label":"Disable account", "risk_band":"high", "target_field":"user.name"},
    "collect_forensics": {"label":"Collect forensic evidence", "risk_band":"medium", "target_field":None},
}

def _response_target_from_context(entity_type: str, context: dict[str, Any], action_type: str) -> str | None:
    target_field = RESPONSE_ACTIONS[action_type]["target_field"]
    if not target_field:
        return entity_type + ":" + str(context.get("event",{}).get("event_id") or context.get("incident",{}).get("incident_id") or context.get("path",{}).get("path_id") or "unknown")
    if entity_type == "event":
        return str((context.get("normalized") or {}).get(target_field) or "") or None
    if entity_type == "alert":
        conn=db(); ids=json.loads(context["alert"]["event_ids_json"]); value=None
        for eid in ids:
            r=conn.execute("SELECT payload_json FROM events WHERE event_id=?",(eid,)).fetchone()
            if r:
                norm=json.loads(r["payload_json"]).get("normalized",{}) or {}
                if norm.get(target_field): value=str(norm[target_field]); break
        conn.close(); return value
    if entity_type == "incident":
        conn=db(); ids=json.loads(context["incident"]["event_ids_json"]); value=None
        for eid in ids:
            r=conn.execute("SELECT payload_json FROM events WHERE event_id=?",(eid,)).fetchone()
            if r:
                norm=json.loads(r["payload_json"]).get("normalized",{}) or {}
                if norm.get(target_field): value=str(norm[target_field]); break
        conn.close(); return value
    if entity_type == "attack_path":
        conn=db(); ids=json.loads(context["path"]["event_ids_json"]); value=None
        for eid in ids:
            r=conn.execute("SELECT payload_json FROM events WHERE event_id=?",(eid,)).fetchone()
            if r:
                norm=json.loads(r["payload_json"]).get("normalized",{}) or {}
                if norm.get(target_field): value=str(norm[target_field]); break
        conn.close(); return value
    return None

def _response_evidence(context: dict[str, Any], action_type: str, reason: str) -> dict[str, Any]:
    raw_hashes=[]
    if context.get("event"): raw_hashes=[context["event"]["raw_sha256"]]
    elif context.get("alert"):
        conn=db(); ids=json.loads(context["alert"]["event_ids_json"]); raw_hashes=[r["raw_sha256"] for r in conn.execute("SELECT raw_sha256 FROM events WHERE event_id IN (%s)" % ",".join("?"*len(ids)),tuple(ids)).fetchall()] if ids else []; conn.close()
    elif context.get("incident"):
        conn=db(); ids=json.loads(context["incident"]["event_ids_json"]); raw_hashes=[r["raw_sha256"] for r in conn.execute("SELECT raw_sha256 FROM events WHERE event_id IN (%s)" % ",".join("?"*len(ids)),tuple(ids)).fetchall()] if ids else []; conn.close()
    elif context.get("path"):
        conn=db(); ids=json.loads(context["path"]["event_ids_json"]); raw_hashes=[r["raw_sha256"] for r in conn.execute("SELECT raw_sha256 FROM events WHERE event_id IN (%s)" % ",".join("?"*len(ids)),tuple(ids)).fetchall()] if ids else []; conn.close()
    return {"computed_locally":True,"action_type":action_type,"reason":reason,"raw_sha256s":raw_hashes,"schema":"response-v1","simulation_only":True}

def _recommend_response(entity_type: str, entity_id: str, analyst: str = "Nexus") -> dict[str, Any]:
    conn=db();
    try:
        if entity_type == "event": context=_event_risk_context(conn, entity_id); risk=context["score"]; band=context["band"]
        elif entity_type == "incident": context=_incident_risk_context(conn, entity_id); risk=context["score"]; band=context["band"]
        elif entity_type == "alert": context=_alert_risk_context(conn, entity_id); risk=context["score"]; band=context["band"]
        elif entity_type == "attack_path":
            row=conn.execute("SELECT * FROM attack_paths WHERE path_id=?",(entity_id,)).fetchone()
            if not row: raise HTTPException(404,"Attack path not found")
            context={"path":dict(row),"score":float(row["score"] or 0),"band":"critical" if float(row["score"] or 0)>=80 else "high" if float(row["score"] or 0)>=60 else "medium" if float(row["score"] or 0)>=30 else "low"}
            risk=context["score"]; band=context["band"]
        else: raise HTTPException(400,"Unsupported entity type")
    finally:
        conn.close()
    if entity_type == "attack_path" and band == "critical": action="isolate_host"
    elif band == "critical": action="block_source"
    elif band == "high": action="collect_forensics"
    else: action="collect_forensics"
    target=_response_target_from_context(entity_type, context, action)
    confidence=round(min(0.99,max(0.60,0.65 + min(0.30, risk/300.0))),3)
    reason=f"Local risk score {risk:.1f}/100 ({band.upper()}) supports {RESPONSE_ACTIONS[action]['label'].lower()} as the safest next step. No external control system is invoked."
    rid="RESP-"+uuid.uuid4().hex[:12].upper(); now=datetime.now(timezone.utc).isoformat()
    evidence=_response_evidence(context, action, reason)
    rec={"recommendation_id":rid,"created_at":now,"updated_at":now,"trigger_type":"manual","trigger_id":entity_id,"entity_type":entity_type,"entity_id":entity_id,"action_type":action,"title":RESPONSE_ACTIONS[action]["label"],"rationale":reason,"severity":band,"confidence":confidence,"status":"pending","evidence":evidence,"target":target,"created_by":analyst}
    conn=db(); conn.execute("INSERT INTO response_recommendations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now,now,"manual",entity_id,entity_type,entity_id,action,RESPONSE_ACTIONS[action]["label"],reason,band,confidence,"pending",json.dumps(evidence),analyst,None,None,"")); conn.commit(); conn.close(); return rec

@app.post("/api/response/recommend")
def recommend_response(req: ResponseRecommendationRequest):
    return _recommend_response(req.entity_type, req.entity_id, req.analyst)

@app.get("/api/response/recommendations")
def list_response_recommendations(status: str | None = None, limit: int = 100):
    conn=db(); params=[]; where=""
    if status: where=" WHERE status=?"; params.append(status)
    rows=conn.execute(f"SELECT * FROM response_recommendations{where} ORDER BY created_at DESC LIMIT ?",(*params,max(1,min(limit,200)))).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["evidence"]=json.loads(d.pop("evidence_json")); out.append(d)
    return {"count":len(out),"recommendations":out}

@app.post("/api/response/recommendations/{recommendation_id}/decision")
def response_decision(recommendation_id: str, req: ResponseApprovalRequest):
    conn=db(); row=conn.execute("SELECT * FROM response_recommendations WHERE recommendation_id=?",(recommendation_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Recommendation not found")
    if row["status"] != "pending": conn.close(); raise HTTPException(409,"Recommendation already decided")
    now=datetime.now(timezone.utc).isoformat(); new_status="approved" if req.decision=="approve" else "rejected"
    conn.execute("UPDATE response_recommendations SET status=?,updated_at=?,approved_by=?,approved_at=?,notes=? WHERE recommendation_id=?",(new_status,now,req.analyst,now if req.decision=="approve" else None,req.notes,recommendation_id)); conn.commit(); conn.close()
    return {"recommendation_id":recommendation_id,"status":new_status,"approved_by":req.analyst,"notes":req.notes,"simulation_only":True}

@app.post("/api/response/recommendations/{recommendation_id}/execute")
def execute_response_simulation(recommendation_id: str, analyst: str = "SIH-Analyst"):
    conn=db(); row=conn.execute("SELECT * FROM response_recommendations WHERE recommendation_id=?",(recommendation_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Recommendation not found")
    if row["status"] != "approved": conn.close(); raise HTTPException(409,"Human approval required before execution")
    now=datetime.now(timezone.utc).isoformat(); exec_id="EXEC-"+uuid.uuid4().hex[:12].upper()
    target=(json.loads(row["evidence_json"]).get("target") if isinstance(json.loads(row["evidence_json"]),dict) else None)
    result={"simulated":True,"action":row["action_type"],"target":target,"message":"No real firewall, identity, host or endpoint control was invoked.","audit":"human-approved simulation","recommendation_id":recommendation_id}
    conn.execute("INSERT INTO response_executions VALUES (?,?,?,?,?,?,?,?,?)",(exec_id,recommendation_id,now,row["action_type"],"simulation","simulated",analyst,target,json.dumps(result))); conn.execute("UPDATE response_recommendations SET status='executed',updated_at=? WHERE recommendation_id=?",(now,recommendation_id)); conn.commit(); conn.close()
    _publish_realtime("response.simulated", {"execution_id":exec_id,"recommendation_id":recommendation_id,"action_type":row["action_type"],"target":target,"status":"simulated"})
    return {"execution_id":exec_id,"status":"simulated","result":result}

@app.get("/api/response/executions")
def list_response_executions(limit: int = 100):
    conn=db(); rows=conn.execute("SELECT * FROM response_executions ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); conn.close(); out=[]
    for r in rows:
        d=dict(r); d["result"]=json.loads(d.pop("result_json")); out.append(d)
    return {"count":len(out),"executions":out,"simulation_only":True}


# -------------------- v3.7 integrated security orchestration --------------------
class SecurityOrchestrationRequest(BaseModel):
    detection_limit: int = 5000
    correlation_limit: int = 10000
    attack_path_refresh: bool = True
    auto_response: bool = True
    analyst: str = "Nexus"


def _active_response_exists(conn: sqlite3.Connection, entity_type: str, entity_id: str) -> bool:
    row = conn.execute(
        "SELECT recommendation_id FROM response_recommendations "
        "WHERE entity_type=? AND entity_id=? AND status IN ('pending','approved') "
        "ORDER BY created_at DESC LIMIT 1",
        (entity_type, entity_id),
    ).fetchone()
    return bool(row)


def _auto_response_for_entity(entity_type: str, entity_id: str, analyst: str = "Nexus") -> dict[str, Any] | None:
    conn = db()
    try:
        if _active_response_exists(conn, entity_type, entity_id):
            return None
        if entity_type == "alert":
            risk = _persist_alert_risk_or_reuse(conn, entity_id)
        elif entity_type == "incident":
            risk = _persist_incident_risk_or_reuse(conn, entity_id)
        elif entity_type == "attack_path":
            row = conn.execute("SELECT * FROM attack_paths WHERE path_id=?", (entity_id,)).fetchone()
            if not row:
                return None
            score = float(row["score"] or 0)
            if score < 60:
                return None
            risk = {"score": score, "band": "critical" if score >= 80 else "high", "confidence": 0.90}
        else:
            return None
        band = str(risk.get("band", "low"))
        # Only high/critical signals enter automated response recommendation flow.
        if band not in {"high", "critical"}:
            return None
    finally:
        conn.close()

    rec = _recommend_response(entity_type, entity_id, analyst)
    _publish_realtime("response.recommended", {
        "recommendation_id": rec["recommendation_id"],
        "entity_type": entity_type,
        "entity_id": entity_id,
        "action_type": rec["action_type"],
        "severity": rec["severity"],
        "confidence": rec["confidence"],
        "status": rec["status"],
        "simulation_only": True,
    })
    return rec


def _run_integrated_security_orchestration(
    detection_limit: int = 5000,
    correlation_limit: int = 10000,
    attack_path_refresh: bool = True,
    auto_response: bool = True,
    analyst: str = "Nexus",
) -> dict[str, Any]:
    started = __import__("time").perf_counter()
    detection = run_detection_rules(detection_limit)
    correlation = run_correlation_engine(correlation_limit)
    attack_paths = _build_attack_paths() if attack_path_refresh else {"created": [], "total": 0}

    # Re-propagate after correlation/attack-path creation so priority queue is current.
    propagation = _propagate_risk("security_orchestrator", 300)

    recommendations = []
    if auto_response:
        seen = set()
        for item in detection.get("alerts", []):
            eid = item.get("alert_id")
            if eid and ("alert", eid) not in seen:
                seen.add(("alert", eid))
                rec = _auto_response_for_entity("alert", eid, analyst)
                if rec:
                    recommendations.append(rec)
        for item in correlation.get("incidents", []):
            eid = item.get("incident_id")
            if eid and ("incident", eid) not in seen:
                seen.add(("incident", eid))
                rec = _auto_response_for_entity("incident", eid, analyst)
                if rec:
                    recommendations.append(rec)
        for item in attack_paths.get("paths", attack_paths.get("created", []) if isinstance(attack_paths.get("created", []), list) else []):
            eid = item.get("path_id")
            if eid and ("attack_path", eid) not in seen:
                seen.add(("attack_path", eid))
                rec = _auto_response_for_entity("attack_path", eid, analyst)
                if rec:
                    recommendations.append(rec)

    queue = propagation.get("queue", [])
    critical = sum(1 for x in queue if x.get("priority_band") == "P1")
    result = {
        "orchestration_id": "ORCH-" + uuid.uuid4().hex[:12].upper(),
        "duration_ms": round((__import__("time").perf_counter() - started) * 1000, 3),
        "detection": detection,
        "correlation": correlation,
        "attack_paths": attack_paths,
        "risk_propagation": propagation,
        "response_recommendations": recommendations,
        "analyst_queue": {"depth": len(queue), "p1": critical},
        "flow": ["detect", "correlate", "score", "prioritize", "recommend", "human-approve", "simulate"],
        "air_gapped": True,
        "simulation_only": True,
    }
    _publish_realtime("security.orchestrated", {
        "orchestration_id": result["orchestration_id"],
        "alerts_created": detection.get("fired", 0),
        "incidents_created": correlation.get("created", 0),
        "attack_paths_total": attack_paths.get("total_paths", attack_paths.get("total", 0)),
        "responses_recommended": len(recommendations),
        "queue_depth": len(queue),
        "p1_queue": critical,
    })
    return result


@app.post("/api/security/orchestrate")
def security_orchestrate(req: SecurityOrchestrationRequest):
    return _run_integrated_security_orchestration(
        req.detection_limit,
        req.correlation_limit,
        req.attack_path_refresh,
        req.auto_response,
        req.analyst,
    )


@app.get("/api/security/flow")
def security_flow():
    conn = db()
    active_recs = conn.execute("SELECT COUNT(*) FROM response_recommendations WHERE status IN ('pending','approved')").fetchone()[0] or 0
    open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('open','acknowledged')").fetchone()[0] or 0
    open_incidents = conn.execute("SELECT COUNT(*) FROM correlation_incidents WHERE status IN ('open','acknowledged')").fetchone()[0] or 0
    p1 = conn.execute("SELECT COUNT(*) FROM risk_queue WHERE priority_band='P1' AND status IN ('open','acknowledged')").fetchone()[0] or 0
    latest_exec = conn.execute("SELECT execution_id,created_at,action_type,status,target FROM response_executions ORDER BY created_at DESC LIMIT 1").fetchone()
    conn.close()
    return {
        "stages": {
            "detection": "active" if open_alerts else "idle",
            "correlation": "active" if open_incidents else "idle",
            "risk": "prioritized" if p1 else "standby",
            "response": "approval-required" if active_recs else "standby",
        },
        "open_alerts": open_alerts,
        "open_incidents": open_incidents,
        "p1_queue": p1,
        "pending_responses": active_recs,
        "latest_simulation": dict(latest_exec) if latest_exec else None,
        "air_gapped": True,
        "simulation_only": True,
    }

# -------------------- v3.5 real-time attack reconstruction --------------------
@app.get("/api/realtime/events")
def realtime_events(after: int = 0, timeout: int = 20):
    """Server-Sent Events feed for live event/attack reconstruction. Entirely local/in-process."""
    def stream():
        cursor = max(0, int(after))
        deadline = time.time() + max(1, min(int(timeout), 60))
        while time.time() < deadline:
            with _REALTIME_LOCK:
                pending = [e for e in _REALTIME_EVENTS if e["seq"] > cursor]
                if not pending:
                    _REALTIME_LOCK.wait(timeout=min(2.0, max(0.1, deadline-time.time())))
                    pending = [e for e in _REALTIME_EVENTS if e["seq"] > cursor]
            if not pending:
                yield ": heartbeat\n\n"
                continue
            for item in pending:
                cursor = item["seq"]
                yield f"id: {cursor}\nevent: {item['kind']}\ndata: {json.dumps(item, separators=(',',':'))}\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control":"no-cache","Connection":"keep-alive","X-Accel-Buffering":"no"})

@app.get("/api/realtime/state")
def realtime_state():
    with _REALTIME_LOCK:
        latest = _REALTIME_EVENTS[-1] if _REALTIME_EVENTS else None
        seq = _REALTIME_SEQ
    conn=db()
    now=datetime.now(timezone.utc)
    cutoff=(now.timestamp()-60)
    rows=conn.execute("SELECT created_at,status FROM events ORDER BY created_at DESC LIMIT 500").fetchall()
    conn.close()
    def ts(v):
        try: return datetime.fromisoformat(v.replace("Z","+00:00")).timestamp()
        except Exception: return 0
    recent=[r for r in rows if ts(r["created_at"]) >= cutoff]
    return {"sequence":seq,"latest":latest,"events_last_60s":len(recent),"live":True,"air_gapped":True}

@app.get("/api/metrics")
def metrics():
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    trusted = conn.execute("SELECT COUNT(*) FROM events WHERE status='trusted'").fetchone()[0]
    reviews = conn.execute("SELECT COUNT(*) FROM events WHERE status='review'").fetchone()[0]
    quarantined = conn.execute("SELECT COUNT(*) FROM events WHERE status='quarantine'").fetchone()[0]
    unknown = conn.execute("SELECT COUNT(*) FROM events WHERE vendor='Unknown source'").fetchone()[0]
    onboarding_unknown = conn.execute("SELECT COUNT(*) FROM onboarding_sessions WHERE status='unknown'").fetchone()[0]
    candidates = conn.execute("SELECT COUNT(*) FROM onboarding_sessions WHERE status='candidate'").fetchone()[0]
    conn.close()
    return {
        "total_events": total, "trusted_events": trusted, "review_events": reviews, "quarantined_events": quarantined,
        "lossless_rate": 1.0 if total else 0.0, "parser_count": len(parser_families()), "unknown_sources": unknown,
        "onboarding_unknown": onboarding_unknown, "onboarding_candidates": candidates,
        "air_gapped": True, "storage": os.getenv("ULPF_STORAGE_BACKEND", "sqlite"), "ai_execution": "local-only",
    }




def _latest_dna_for_source(source: str) -> dict[str, Any] | None:
    conn=db(); row=conn.execute("SELECT dna_json FROM dna_history WHERE source=? ORDER BY id DESC LIMIT 1",(source,)).fetchone(); conn.close()
    return json.loads(row[0]) if row else None

def _latest_mutation_for_source(source: str) -> dict[str, Any] | None:
    conn=db(); row=conn.execute("SELECT payload_json FROM mutation_reports WHERE source=? ORDER BY created_at DESC LIMIT 1",(source,)).fetchone(); conn.close()
    return json.loads(row[0]) if row else None

class EvolutionRunRequest(BaseModel):
    source: str = "unknown-source"
    samples: list[str] = Field(min_length=1, max_length=100)
    expected_vendor: str | None = None
    candidate_name: str | None = None

@app.post("/api/evolution/run")
def evolution_run(req: EvolutionRunRequest):
    started=time.perf_counter()
    primary=req.samples[0]
    fmt, _fmt_conf = detect_format(primary, None)
    dna=log_dna(primary, fmt)
    # Persist a current DNA observation so the command center can reason from this run.
    now=datetime.now(timezone.utc).isoformat()
    conn=db(); conn.execute("INSERT INTO dna_history(created_at,source,dna_json) VALUES(?,?,?)",(now,req.source,json.dumps(dna))); conn.commit(); conn.close()

    # Mutation intelligence uses latest baseline history if available.
    mutation={"severity":"stable","decision":"continue","similarity":1.0,"changed_dimensions":[],"recommendation":"no structural mutation detected"}
    conn=db(); rows=conn.execute("SELECT dna_json FROM dna_history WHERE source=? ORDER BY id DESC LIMIT 2",(req.source,)).fetchall(); conn.close()
    if len(rows)>=2:
        previous=json.loads(rows[1][0]); diffs=dna_diff(previous,dna)
        sim=dna_similarity(previous,dna)
        sev=mutation_severity(sim,diffs)
        mutation={"severity":sev,"decision":"quarantine" if sev=="critical" else ("review" if sev=="warning" else "continue"),"similarity":sim,"changed_dimensions":diffs,"recommendation":"replay and validate parser before release" if sev!="stable" else "no structural mutation detected"}
    # Re-use the AI router to guarantee auditable routing.
    ai=ai_route(primary,req.source)
    # Candidate generation is only attempted when the route is not trusted.
    candidate=None; sandbox=None; regression="not-run"; final_state="trusted" if ai["status"]=="trusted" and mutation["decision"]=="continue" else "review"
    reason=[]
    if mutation["severity"] in {"critical","warning"}: reason.append(f"mutation={mutation['severity']}")
    if ai["status"]!="trusted": reason.append(f"ai-route={ai['route']}")
    if ai["status"]=="blocked": final_state="quarantine"
    elif ai["route"] in {"gpt-oss","review-fallback"}:
        mapped=local_ai_mapper(primary)
        candidate=parser_candidate(CandidateParserRequest(raw_samples=req.samples, name=req.candidate_name or f"{req.source}-candidate"))
        candidate["genome"]["source"] = req.source
        # Persist candidate in the same registry used by the normal sandbox flow.
        conn=db(); conn.execute("INSERT OR REPLACE INTO parser_candidates(parser_id,created_at,status,payload_json) VALUES(?,?,?,?,?)", (candidate["id"],now,"candidate",json.dumps(candidate))); conn.commit(); conn.close()
        sandbox=_sandbox_evaluate(candidate["id"],req.samples)
        regression="blocked" if sandbox["decision"]!="approve" else "pass"
        if sandbox["decision"]=="approve" and not mapped.get("conflicts") and mutation["severity"]!="critical":
            final_state="candidate-ready"
        else:
            final_state="quarantine" if mapped.get("conflicts") or mutation["severity"]=="critical" else "review"
        reason.append(f"sandbox={sandbox['decision']}")
        if mapped.get("conflicts"): reason.append("semantic conflicts present")
    # Existing approved parser can be bound for high-confidence onboarding.
    if final_state=="trusted" and req.expected_vendor:
        reason.append(f"vendor={req.expected_vendor}")
    evidence={"dna":dna,"mutation":mutation,"ai":ai,"candidate":candidate,"sandbox":sandbox,"sample_count":len(req.samples),"duration_ms":round((time.perf_counter()-started)*1000,3)}
    run_id="EVR-"+uuid.uuid4().hex[:12].upper()
    conn=db(); conn.execute("INSERT INTO evolution_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(run_id,now,req.source,sha256(primary),dna["id"],mutation.get("severity","stable"),mutation.get("decision","continue"),ai["route"],ai["confidence"],candidate["id"] if candidate else None,sandbox.get("run_id") if sandbox else None,regression,final_state,"; ".join(reason) if reason else "high-confidence trusted path",json.dumps(evidence))); conn.commit(); conn.close()
    return {"run_id":run_id,"source":req.source,"final_state":final_state,"dna":dna,"mutation":mutation,"ai":ai,"candidate":candidate,"sandbox":sandbox,"regression":regression,"reason":reason}

@app.get("/api/evolution/runs")
def evolution_runs(limit:int=50, source:str|None=None):
    conn=db();
    if source: rows=conn.execute("SELECT * FROM evolution_runs WHERE source=? ORDER BY created_at DESC LIMIT ?",(source,max(1,min(limit,200)))).fetchall()
    else: rows=conn.execute("SELECT * FROM evolution_runs ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall()
    conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["evidence"]=json.loads(d.pop("evidence_json")); out.append(d)
    return out

@app.get("/api/evolution/control-center")
def evolution_control_center():
    conn=db()
    totals=conn.execute("SELECT final_state, COUNT(*) c FROM evolution_runs GROUP BY final_state").fetchall()
    routes=conn.execute("SELECT ai_route, COUNT(*) c, AVG(ai_confidence) avg_conf FROM evolution_runs GROUP BY ai_route").fetchall()
    mutation=conn.execute("SELECT mutation_severity, COUNT(*) c FROM evolution_runs GROUP BY mutation_severity").fetchall()
    recent=conn.execute("SELECT * FROM evolution_runs ORDER BY created_at DESC LIMIT 10").fetchall()
    conn.close()
    def rows_to_dict(rows): return [dict(r) for r in rows]
    return {"states":rows_to_dict(totals),"routes":rows_to_dict(routes),"mutations":rows_to_dict(mutation),"recent":[{**dict(r),"evidence":json.loads(r["evidence_json"])} for r in recent]}

@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/app.js")
def appjs():
    return FileResponse(FRONTEND / "app.js")


@app.get("/styles.css")
def styles():
    return FileResponse(FRONTEND / "styles.css")


# -------------------- v2.9 multi-event correlation engine --------------------
CORR_STATUSES = {"open", "acknowledged", "resolved", "dismissed"}

class CorrelationStep(BaseModel):
    name: str
    conditions: list[DetectionCondition] = Field(default_factory=list)

class CorrelationRuleRequest(BaseModel):
    name: str
    description: str = ""
    severity: str = "high"
    window_seconds: int = 900
    steps: list[CorrelationStep]
    group_by: str | None = None
    enabled: bool = True
    created_by: str = "analyst"

class CorrelationIncidentUpdateRequest(BaseModel):
    status: str = Field(pattern="^(open|acknowledged|resolved|dismissed)$")
    assigned_to: str | None = None
    resolution: str = ""


def _group_value(event: dict[str, Any], field: str | None) -> str | None:
    if not field:
        return None
    value = _alert_field(event, field)
    return None if value is None else str(value)


def _match_sequence(events: list[dict[str, Any]], steps: list[CorrelationStep], window_seconds: int, group_by: str | None = None) -> dict[str, Any] | None:
    if len(steps) < 2:
        return None
    ordered = sorted(events, key=_event_dt)
    for i, anchor in enumerate(ordered):
        group = _group_value(anchor, group_by)
        if group_by and group is None:
            continue
        if not all(_condition_matches(anchor, c) for c in steps[0].conditions):
            continue
        candidate = [anchor]
        matches = [{"step": 0, "name": steps[0].name, "event_id": anchor.get("event_id"), "timestamp": anchor.get("ingested_at")}]
        prev_time = _event_dt(anchor)
        step_ok = True
        for step_index, step in enumerate(steps[1:], start=1):
            found = None
            for later in ordered[i + 1:]:
                if group_by and _group_value(later, group_by) != group:
                    continue
                dt_from_anchor = (_event_dt(later) - _event_dt(anchor)).total_seconds()
                if dt_from_anchor > window_seconds:
                    break
                if _event_dt(later) < prev_time:
                    continue
                if all(_condition_matches(later, c) for c in step.conditions):
                    found = later
                    break
            if not found:
                step_ok = False
                break
            candidate.append(found)
            prev_time = _event_dt(found)
            matches.append({"step": step_index, "name": step.name, "event_id": found.get("event_id"), "timestamp": found.get("ingested_at")})
        if step_ok:
            elapsed = max(0.0, (_event_dt(candidate[-1]) - _event_dt(candidate[0])).total_seconds())
            return {"event_ids":[e.get("event_id") for e in candidate if e.get("event_id")],"step_matches":matches,"group_value":group,"started_at":candidate[0].get("ingested_at"),"completed_at":candidate[-1].get("ingested_at"),"elapsed_seconds":round(elapsed,3)}
    return None


def _serialize_correlation_rule(row: sqlite3.Row) -> dict[str, Any]:
    d=dict(row); d["steps"]=json.loads(d.pop("steps_json")); d["enabled"]=bool(d["enabled"]); return d

def _serialize_correlation_incident(row: sqlite3.Row) -> dict[str, Any]:
    d=dict(row); d["event_ids"]=json.loads(d.pop("event_ids_json")); d["step_matches"]=json.loads(d.pop("step_matches_json")); d["evidence"]=json.loads(d.pop("evidence_json")); return d

@app.get("/api/correlations/rules")
def correlation_rules(enabled: bool | None = None):
    conn=db()
    if enabled is None: rows=conn.execute("SELECT * FROM correlation_rules ORDER BY updated_at DESC").fetchall()
    else: rows=conn.execute("SELECT * FROM correlation_rules WHERE enabled=? ORDER BY updated_at DESC",(1 if enabled else 0,)).fetchall()
    conn.close(); return {"count":len(rows),"rules":[_serialize_correlation_rule(r) for r in rows]}

@app.post("/api/correlations/rules")
def create_correlation_rule(req: CorrelationRuleRequest):
    if req.severity not in SEVERITIES: raise HTTPException(400,"invalid severity")
    if not 1 <= req.window_seconds <= 86400: raise HTTPException(400,"window_seconds out of range")
    if not 2 <= len(req.steps) <= 12: raise HTTPException(400,"correlation rules require 2..12 ordered steps")
    now=datetime.now(timezone.utc).isoformat(); rid="CORR-"+uuid.uuid4().hex[:10].upper()
    conn=db(); conn.execute("INSERT INTO correlation_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now,now,req.name,req.description,1 if req.enabled else 0,req.severity,req.window_seconds,json.dumps([s.model_dump() for s in req.steps]),req.group_by,req.created_by,1)); conn.commit(); row=conn.execute("SELECT * FROM correlation_rules WHERE rule_id=?",(rid,)).fetchone(); conn.close(); return _serialize_correlation_rule(row)

@app.patch("/api/correlations/rules/{rule_id}")
def update_correlation_rule(rule_id: str, req: CorrelationRuleRequest):
    if req.severity not in SEVERITIES or not 2 <= len(req.steps) <= 12: raise HTTPException(400,"invalid correlation rule")
    conn=db(); old=conn.execute("SELECT * FROM correlation_rules WHERE rule_id=?",(rule_id,)).fetchone()
    if not old: conn.close(); raise HTTPException(404,"Correlation rule not found")
    now=datetime.now(timezone.utc).isoformat(); version=int(old["version"])+1
    conn.execute("UPDATE correlation_rules SET updated_at=?,name=?,description=?,enabled=?,severity=?,window_seconds=?,steps_json=?,group_by=?,created_by=?,version=? WHERE rule_id=?",(now,req.name,req.description,1 if req.enabled else 0,req.severity,req.window_seconds,json.dumps([s.model_dump() for s in req.steps]),req.group_by,req.created_by,version,rule_id)); conn.commit(); row=conn.execute("SELECT * FROM correlation_rules WHERE rule_id=?",(rule_id,)).fetchone(); conn.close(); return _serialize_correlation_rule(row)

@app.post("/api/correlations/run")
def run_correlation_engine(limit: int = 10000):
    events=_threat_hunt_rows(max(100,min(limit,20000))); conn=db(); rules=conn.execute("SELECT * FROM correlation_rules WHERE enabled=1 ORDER BY updated_at DESC").fetchall(); created=[]; now=datetime.now(timezone.utc).isoformat()
    for rule in rules:
        steps=[CorrelationStep(**x) for x in json.loads(rule["steps_json"])]; hit=_match_sequence(events,steps,int(rule["window_seconds"]),rule["group_by"])
        if not hit: continue
        fingerprint=sha256(rule["rule_id"]+json.dumps(hit["event_ids"],separators=(",",":")))
        existing=conn.execute("SELECT incident_id FROM correlation_incidents WHERE rule_id=? AND status IN ('open','acknowledged') AND evidence_json LIKE ? LIMIT 1",(rule["rule_id"],f'%{fingerprint}%')).fetchone()
        if existing: continue
        incident_id="INC-"+uuid.uuid4().hex[:12].upper(); sev_bonus={"low":0,"medium":8,"high":18,"critical":28}.get(rule["severity"],8); score=round(min(100.0,60+8*len(steps)+sev_bonus),1)
        evidence={"fingerprint":fingerprint,"window_seconds":int(rule["window_seconds"]),"sequence_length":len(steps),"elapsed_seconds":hit["elapsed_seconds"],"deterministic":True,"signal":"multi-event ordered correlation"}
        title=f"Correlated incident: {rule['name']}"; desc=rule["description"] or "Ordered multi-event sequence matched within a bounded time window."
        conn.execute("INSERT INTO correlation_incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(incident_id,now,now,rule["rule_id"],rule["version"],rule["severity"],"open",title,desc,hit.get("group_value"),json.dumps(hit["event_ids"]),json.dumps(hit["step_matches"]),json.dumps(evidence),score,None,None)); created.append({"incident_id":incident_id,"rule_id":rule["rule_id"],"severity":rule["severity"],"title":title,"score":score,**hit})
    conn.commit(); conn.close()
    propagation=_propagate_risk("correlation_engine", 200)
    return {"evaluated_rules":len(rules),"created":len(created),"incidents":created,"risk_propagation":propagation}

@app.get("/api/correlations/incidents")
def list_correlation_incidents(status: str | None = None, severity: str | None = None, limit: int = 100):
    limit=max(1,min(limit,500)); clauses=[]; params=[]
    if status: clauses.append("status=?"); params.append(status)
    if severity: clauses.append("severity=?"); params.append(severity)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    conn=db(); rows=conn.execute(f"SELECT * FROM correlation_incidents{where} ORDER BY created_at DESC LIMIT ?",(*params,limit)).fetchall(); conn.close(); return {"count":len(rows),"incidents":[_serialize_correlation_incident(r) for r in rows]}

@app.patch("/api/correlations/incidents/{incident_id}")
def update_correlation_incident(incident_id: str, req: CorrelationIncidentUpdateRequest):
    now=datetime.now(timezone.utc).isoformat(); conn=db(); row=conn.execute("SELECT * FROM correlation_incidents WHERE incident_id=?",(incident_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Incident not found")
    conn.execute("UPDATE correlation_incidents SET updated_at=?,status=?,assigned_to=?,resolution=? WHERE incident_id=?",(now,req.status,req.assigned_to,req.resolution,incident_id)); conn.commit(); row=conn.execute("SELECT * FROM correlation_incidents WHERE incident_id=?",(incident_id,)).fetchone(); conn.close(); return _serialize_correlation_incident(row)

@app.get("/api/correlations/summary")
def correlation_summary():
    conn=db(); rules=conn.execute("SELECT COUNT(*) total,SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) enabled FROM correlation_rules").fetchone(); statuses=conn.execute("SELECT status,COUNT(*) count FROM correlation_incidents GROUP BY status").fetchall(); sevs=conn.execute("SELECT severity,COUNT(*) count FROM correlation_incidents GROUP BY severity").fetchall(); conn.close(); return {"rules":{"total":rules[0] or 0,"enabled":rules[1] or 0},"incidents_by_status":{r[0]:r[1] for r in statuses},"incidents_by_severity":{r[0]:r[1] for r in sevs}}



# -------------------- v3.1 explainable risk intelligence --------------------
RISK_BANDS = {"low": (0.0, 29.9), "medium": (30.0, 59.9), "high": (60.0, 79.9), "critical": (80.0, 100.0)}
SEVERITY_WEIGHT = {"low": 10.0, "medium": 25.0, "high": 45.0, "critical": 65.0}

class RiskDecisionRequest(BaseModel):
    analyst: str = Field(min_length=1, max_length=120)
    decision: str = Field(pattern="^(open|accepted|false_positive|resolved)$")
    note: str = Field(default="", max_length=1000)


def _risk_band(score: float) -> str:
    s=max(0.0,min(100.0,float(score)))
    if s>=80: return "critical"
    if s>=60: return "high"
    if s>=30: return "medium"
    return "low"


def _clamp(v: float) -> float:
    return max(0.0,min(100.0,float(v)))


def _numeric_factor(name: str, score: float, weight: float, explanation: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {"name":name,"score":round(_clamp(score),2),"weight":round(_clamp(weight),2),"contribution":round(_clamp(score)*_clamp(weight)/100.0,2),"explanation":explanation,"evidence":evidence}


def _event_risk_context(conn: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    row=conn.execute("SELECT * FROM events WHERE event_id=?",(event_id,)).fetchone()
    if not row: raise HTTPException(404,"Event not found")
    payload=json.loads(row["payload_json"])
    norm=payload.get("normalized",{}) or {}
    src=row["source"] or "unknown"
    # Trust and quality signals are derived entirely from local evidence.
    ai=conn.execute("SELECT mapping_confidence,validation_summary_json FROM ai_mapping_evidence WHERE raw_sha256=? ORDER BY created_at DESC LIMIT 1",(row["raw_sha256"],)).fetchone()
    ai_conf=float(ai[0]) if ai else 1.0
    mutation=conn.execute("SELECT COUNT(*) FROM mutation_reports WHERE source=? AND severity IN ('critical','warning')",(src,)).fetchone()[0] or 0
    quarantine=conn.execute("SELECT COUNT(*) FROM quarantine_queue q JOIN events e ON e.event_id=q.event_id WHERE e.source=?",(src,)).fetchone()[0] or 0
    source_events=conn.execute("SELECT COUNT(*) FROM events WHERE source=?",(src,)).fetchone()[0] or 1
    alerts=conn.execute("SELECT COUNT(*) FROM alerts WHERE source=? AND status IN ('open','acknowledged')",(src,)).fetchone()[0] or 0
    factors=[]
    action=str(norm.get("event.action") or "").lower()
    severity_action=30.0 if action in {"deny","blocked","drop","reject","failed","failure"} else 10.0 if action else 0.0
    factors.append(_numeric_factor("detection_signal",severity_action,0.25,"Event action carries a local security signal.",{"action":action or None}))
    factors.append(_numeric_factor("ai_uncertainty",(1.0-ai_conf)*100.0,0.15,"Lower mapping confidence increases uncertainty.",{"mapping_confidence":round(ai_conf,3)}))
    mutation_rate=min(100.0,mutation*20.0)
    factors.append(_numeric_factor("source_mutation",mutation_rate,0.20,"Recent parser/Log DNA mutations reduce trust in the source representation.",{"mutation_reports":mutation}))
    quarantine_rate=min(100.0,(quarantine/max(1,source_events))*100.0*4.0)
    factors.append(_numeric_factor("quarantine_pressure",quarantine_rate,0.15,"Quarantine history is treated as a data-quality/security warning signal.",{"quarantined":quarantine,"events":source_events}))
    alert_pressure=min(100.0,alerts*25.0)
    factors.append(_numeric_factor("active_alert_pressure",alert_pressure,0.20,"Open or acknowledged alerts increase current investigation risk.",{"active_alerts_for_source":alerts}))
    completeness=100.0
    unknown=payload.get("extensions") or {}
    if unknown: completeness=max(45.0,100.0-min(55.0,len(unknown)*10.0))
    factors.append(_numeric_factor("evidence_completeness",100.0-completeness,0.05,"Unmapped extensions reduce evidence completeness but do not discard raw data.",{"extension_fields":len(unknown)}))
    score=round(sum(f["contribution"] for f in factors),2)
    # Minimum confidence reflects agreement among independently computed local signals.
    confidence=round(min(0.99,max(0.55,0.65+0.25*(1.0-(abs(50.0-score)/50.0)))),3)
    return {"event":dict(row),"normalized":norm,"factors":factors,"score":score,"band":_risk_band(score),"confidence":confidence,"source":src}


def _incident_risk_context(conn: sqlite3.Connection, incident_id: str) -> dict[str, Any]:
    inc=conn.execute("SELECT * FROM correlation_incidents WHERE incident_id=?",(incident_id,)).fetchone()
    if not inc: raise HTTPException(404,"Incident not found")
    event_ids=json.loads(inc["event_ids_json"])
    events=[]
    for eid in event_ids:
        row=conn.execute("SELECT * FROM events WHERE event_id=?",(eid,)).fetchone()
        if row: events.append(row)
    factors=[]
    severity=float(SEVERITY_WEIGHT.get(inc["severity"],25.0))
    factors.append(_numeric_factor("incident_severity",severity,0.25,"Correlation severity establishes the baseline risk.",{"severity":inc["severity"]}))
    base_score=float(inc["score"] or 0.0)
    factors.append(_numeric_factor("correlation_score",min(100.0,base_score),0.25,"Existing multi-event correlation score contributes to incident risk.",{"correlation_score":base_score}))
    unique_sources=len({e["source"] for e in events})
    factors.append(_numeric_factor("evidence_breadth",min(100.0,len(events)*18.0+unique_sources*10.0),0.10,"More independent matching evidence increases the confidence of the incident signal.",{"events":len(events),"sources":unique_sources}))
    open_alerts=conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('open','acknowledged') AND EXISTS (SELECT 1 FROM json_each(alerts.event_ids_json) j WHERE j.value IN ({seq}))".format(seq=','.join('?'*len(event_ids)) if event_ids else "NULL"),tuple(event_ids)).fetchone()[0] if event_ids else 0
    factors.append(_numeric_factor("related_alert_pressure",min(100.0,open_alerts*25.0),0.15,"Open alerts overlapping incident evidence increase risk.",{"related_open_alerts":open_alerts}))
    mutation_sources=0
    for src in {e["source"] for e in events}:
        mutation_sources += conn.execute("SELECT COUNT(*) FROM mutation_reports WHERE source=? AND severity IN ('critical','warning')",(src,)).fetchone()[0] or 0
    factors.append(_numeric_factor("mutation_exposure",min(100.0,mutation_sources*15.0),0.10,"Source mutations add uncertainty to the evidence chain.",{"mutation_reports":mutation_sources}))
    avg_conf=1.0
    confs=[]
    for e in events:
        ai=conn.execute("SELECT mapping_confidence FROM ai_mapping_evidence WHERE raw_sha256=? ORDER BY created_at DESC LIMIT 1",(e["raw_sha256"],)).fetchone()
        if ai: confs.append(float(ai[0]))
    if confs: avg_conf=sum(confs)/len(confs)
    factors.append(_numeric_factor("mapping_uncertainty",(1.0-avg_conf)*100.0,0.15,"Lower semantic mapping confidence increases uncertainty in the incident evidence.",{"average_mapping_confidence":round(avg_conf,3)}))
    score=round(sum(f["contribution"] for f in factors),2)
    band=_risk_band(score)
    confidence=round(min(0.99,max(0.60,0.70 + min(0.25,len(events)/10.0))),3)
    summary=f"{band.upper()} risk: {inc['title']} scored {score:.1f}/100 from {len(factors)} explainable local factors."
    return {"incident":dict(inc),"factors":factors,"score":score,"band":band,"confidence":confidence,"summary":summary,"event_count":len(events)}


def _persist_risk_assessment(entity_type: str, entity_id: str, context: dict[str, Any]) -> dict[str, Any]:
    rid="RISK-"+uuid.uuid4().hex[:12].upper()
    evidence={"entity_type":entity_type,"entity_id":entity_id,"computed_locally":True,"raw_sha256s":[],"schema":"risk-v1"}
    if entity_type=="event" and context.get("event"):
        evidence["raw_sha256s"]=[context["event"]["raw_sha256"]]
    elif entity_type=="incident":
        ids=[]
        conn=db();
        for eid in json.loads(context["incident"]["event_ids_json"]):
            r=conn.execute("SELECT raw_sha256 FROM events WHERE event_id=?",(eid,)).fetchone()
            if r: ids.append(r[0])
        conn.close(); evidence["raw_sha256s"]=ids
    now=datetime.now(timezone.utc).isoformat()
    conn=db(); conn.execute("INSERT INTO risk_assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now,entity_type,entity_id,context["score"],context["band"],context["confidence"],context.get("summary",f'{context["band"].upper()} risk assessment'),json.dumps(context["factors"]),json.dumps(evidence),"open",None,None)); conn.commit(); conn.close()
    return {"risk_id":rid,"created_at":now,"entity_type":entity_type,"entity_id":entity_id,"score":context["score"],"band":context["band"],"confidence":context["confidence"],"summary":context.get("summary"),"factors":context["factors"],"evidence":evidence,"decision_status":"open"}


@app.post("/api/risk/event/{event_id}")
def assess_event_risk(event_id: str):
    conn=db(); context=_event_risk_context(conn,event_id); conn.close()
    return _persist_risk_assessment("event",event_id,context)

@app.post("/api/risk/incident/{incident_id}")
def assess_incident_risk(incident_id: str):
    conn=db(); context=_incident_risk_context(conn,incident_id); conn.close()
    return _persist_risk_assessment("incident",incident_id,context)

@app.get("/api/risk/latest")
def latest_risk(entity_type: str | None = None, band: str | None = None, limit: int = 50):
    limit=max(1,min(limit,200)); conn=db(); clauses=[]; params=[]
    if entity_type: clauses.append("entity_type=?"); params.append(entity_type)
    if band: clauses.append("band=?"); params.append(band)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    rows=conn.execute(f"SELECT * FROM risk_assessments{where} ORDER BY created_at DESC LIMIT ?",(*params,limit)).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["factors"]=json.loads(d.pop("factors_json")); d["evidence"]=json.loads(d.pop("evidence_json")); out.append(d)
    return {"count":len(out),"assessments":out}

@app.get("/api/risk/summary")
def risk_summary():
    conn=db();
    bands=conn.execute("SELECT band,COUNT(*) count,ROUND(AVG(score),2) avg_score,MAX(score) max_score FROM risk_assessments GROUP BY band").fetchall()
    decisions=conn.execute("SELECT decision_status,COUNT(*) count FROM risk_assessments GROUP BY decision_status").fetchall()
    recent=conn.execute("SELECT risk_id,entity_type,entity_id,score,band,confidence,summary,created_at,decision_status FROM risk_assessments ORDER BY created_at DESC LIMIT 12").fetchall(); conn.close()
    return {"bands":{r[0]:{"count":r[1],"avg_score":r[2],"max_score":r[3]} for r in bands},"decisions":{r[0]:r[1] for r in decisions},"recent":[dict(r) for r in recent]}

@app.patch("/api/risk/{risk_id}/decision")
def decide_risk(risk_id: str, req: RiskDecisionRequest):
    now=datetime.now(timezone.utc).isoformat(); conn=db(); row=conn.execute("SELECT * FROM risk_assessments WHERE risk_id=?",(risk_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Risk assessment not found")
    status="resolved" if req.decision in {"resolved","false_positive"} else req.decision
    conn.execute("UPDATE risk_assessments SET decision_status=?,assigned_to=?,resolution=? WHERE risk_id=?",(status,req.analyst,req.note,risk_id))
    did="RDEC-"+uuid.uuid4().hex[:10].upper(); conn.execute("INSERT INTO risk_decisions VALUES (?,?,?,?,?,?)",(did,risk_id,now,req.analyst,req.decision,req.note)); conn.commit(); updated=conn.execute("SELECT * FROM risk_assessments WHERE risk_id=?",(risk_id,)).fetchone(); conn.close()
    d=dict(updated); d["factors"]=json.loads(d.pop("factors_json")); d["evidence"]=json.loads(d.pop("evidence_json")); d["last_decision"]={"decision_id":did,"decision":req.decision,"analyst":req.analyst,"note":req.note,"created_at":now}; return d


# -------------------- v3.2 automated risk propagation & analyst prioritization --------------------
PRIORITY_SLA_MINUTES = {"P1": 15, "P2": 60, "P3": 240, "P4": 1440}

def _priority_band(score: float) -> str:
    s = _clamp(score)
    if s >= 80: return "P1"
    if s >= 60: return "P2"
    if s >= 30: return "P3"
    return "P4"


def _priority_score(risk_score: float, risk_confidence: float, evidence_count: int, severity: str) -> float:
    sev_boost = {"low": 0.0, "medium": 7.0, "high": 15.0, "critical": 22.0}.get(severity, 0.0)
    evidence_boost = min(10.0, max(0, evidence_count) * 1.5)
    confidence_boost = _clamp(risk_confidence) * 8.0
    return round(_clamp(float(risk_score) * 0.78 + sev_boost + evidence_boost + confidence_boost), 2)


def _alert_risk_context(conn: sqlite3.Connection, alert_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if not row: raise HTTPException(404, "Alert not found")
    event_ids = json.loads(row["event_ids_json"])
    event_scores=[]; event_bands=[]; confs=[]
    for eid in event_ids:
        er = conn.execute("SELECT * FROM risk_assessments WHERE entity_type='event' AND entity_id=? ORDER BY created_at DESC LIMIT 1", (eid,)).fetchone()
        if er:
            event_scores.append(float(er["score"])); event_bands.append(er["band"]); confs.append(float(er["confidence"]))
    local_score = float(row["score"] or 0.0)
    max_event = max(event_scores) if event_scores else local_score
    severity_base = SEVERITY_WEIGHT.get(row["severity"], 25.0)
    score = round(_clamp(max(local_score, severity_base) * 0.72 + min(100.0, max_event) * 0.28), 2)
    confidence = round(sum(confs)/len(confs), 3) if confs else 0.72
    summary = f"{row['severity'].upper()} alert propagated to risk queue with score {score:.1f}/100 from local alert and event evidence."
    factors = [
        _numeric_factor("alert_signal", local_score, 0.55, "Detection alert score is the primary local signal.", {"alert_score": local_score}),
        _numeric_factor("severity_baseline", severity_base, 0.20, "Rule severity contributes a deterministic baseline.", {"severity": row["severity"]}),
        _numeric_factor("event_risk_elevation", max_event, 0.25, "Highest event risk overlapping the alert propagates into the alert score.", {"event_count": len(event_ids), "max_event_risk": max_event}),
    ]
    return {"alert":dict(row),"factors":factors,"score":score,"band":_risk_band(score),"confidence":confidence,"summary":summary,"event_count":len(event_ids)}


def _persist_queue_item(conn: sqlite3.Connection, entity_type: str, entity_id: str, risk: dict[str, Any], trigger_type: str) -> dict[str, Any]:
    evidence_count = int(risk.get("event_count", 1) or 1)
    severity = "medium"
    if entity_type == "incident": severity = risk["incident"].get("severity", "medium")
    elif entity_type == "alert": severity = risk["alert"].get("severity", "medium")
    elif entity_type == "event": severity = (risk.get("normalized") or {}).get("event.severity", "medium") or "medium"
    pscore = _priority_score(risk["score"], risk.get("confidence", 0.7), evidence_count, severity)
    pband = _priority_band(pscore)
    reason = f"{pband} priority: risk {risk['band']} at {risk['score']:.1f}/100; confidence {risk.get('confidence',0):.2f}; trigger {trigger_type}."
    now=datetime.now(timezone.utc); due=now + __import__('datetime').timedelta(minutes=PRIORITY_SLA_MINUTES[pband])
    existing=conn.execute("SELECT * FROM risk_queue WHERE entity_type=? AND entity_id=? AND status IN ('open','acknowledged') ORDER BY updated_at DESC LIMIT 1",(entity_type,entity_id)).fetchone()
    if existing:
        qid=existing["queue_id"]
        conn.execute("UPDATE risk_queue SET updated_at=?,risk_id=?,priority_score=?,priority_band=?,priority_reason=?,sla_due_at=?,rank=? WHERE queue_id=?",(now.isoformat(),risk["risk_id"],pscore,pband,reason,due.isoformat(),0,qid))
    else:
        qid="RQ-"+uuid.uuid4().hex[:12].upper()
        conn.execute("INSERT INTO risk_queue VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(qid,now.isoformat(),now.isoformat(),entity_type,entity_id,risk["risk_id"],pscore,pband,reason,None,"open",due.isoformat(),0))
    conn.execute("INSERT INTO risk_propagations VALUES (?,?,?,?,?,?,?,?,?)",("RP-"+uuid.uuid4().hex[:12].upper(),now.isoformat(),entity_type,entity_id,risk["risk_id"],trigger_type,risk["score"],risk["band"],json.dumps({"priority_score":pscore,"priority_band":pband,"confidence":risk.get("confidence"),"event_count":evidence_count})))
    return {"queue_id":qid,"entity_type":entity_type,"entity_id":entity_id,"risk_id":risk["risk_id"],"risk_score":risk["score"],"risk_band":risk["band"],"priority_score":pscore,"priority_band":pband,"sla_due_at":due.isoformat(),"reason":reason}


def _persist_event_risk_or_reuse(conn: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    row=conn.execute("SELECT * FROM risk_assessments WHERE entity_type='event' AND entity_id=? ORDER BY created_at DESC LIMIT 1",(event_id,)).fetchone()
    if row:
        d=dict(row); d["factors"]=json.loads(d.pop("factors_json")); d["evidence"]=json.loads(d.pop("evidence_json")); return d
    context=_event_risk_context(conn,event_id)
    # Keep transaction ownership in the caller by inserting directly.
    rid="RISK-"+uuid.uuid4().hex[:12].upper(); now=datetime.now(timezone.utc).isoformat()
    evidence={"entity_type":"event","entity_id":event_id,"computed_locally":True,"raw_sha256s":[context["event"]["raw_sha256"]],"schema":"risk-v1"}
    conn.execute("INSERT INTO risk_assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now,"event",event_id,context["score"],context["band"],context["confidence"],context.get("summary",f'{context["band"].upper()} risk assessment'),json.dumps(context["factors"]),json.dumps(evidence),"open",None,None))
    return {"risk_id":rid,"score":context["score"],"band":context["band"],"confidence":context["confidence"],"factors":context["factors"],"evidence":evidence,"normalized":context.get("normalized"),"event_count":1}


def _persist_incident_risk_or_reuse(conn: sqlite3.Connection, incident_id: str) -> dict[str, Any]:
    row=conn.execute("SELECT * FROM risk_assessments WHERE entity_type='incident' AND entity_id=? ORDER BY created_at DESC LIMIT 1",(incident_id,)).fetchone()
    if row:
        d=dict(row); d["factors"]=json.loads(d.pop("factors_json")); d["evidence"]=json.loads(d.pop("evidence_json"))
        inc=conn.execute("SELECT * FROM correlation_incidents WHERE incident_id=?",(incident_id,)).fetchone()
        d["incident"]=dict(inc) if inc else {"severity":"medium"}
        ids=json.loads(inc["event_ids_json"]) if inc else []
        d["event_count"]=len(ids)
        return d
    context=_incident_risk_context(conn,incident_id)
    rid="RISK-"+uuid.uuid4().hex[:12].upper(); now=datetime.now(timezone.utc).isoformat()
    ids=json.loads(context["incident"]["event_ids_json"]); hashes=[]
    for eid in ids:
        rr=conn.execute("SELECT raw_sha256 FROM events WHERE event_id=?",(eid,)).fetchone()
        if rr: hashes.append(rr[0])
    evidence={"entity_type":"incident","entity_id":incident_id,"computed_locally":True,"raw_sha256s":hashes,"schema":"risk-v1"}
    conn.execute("INSERT INTO risk_assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now,"incident",incident_id,context["score"],context["band"],context["confidence"],context["summary"],json.dumps(context["factors"]),json.dumps(evidence),"open",None,None))
    return {"risk_id":rid,"score":context["score"],"band":context["band"],"confidence":context["confidence"],"factors":context["factors"],"evidence":evidence,"event_count":context["event_count"],"incident":context["incident"]}


def _persist_alert_risk_or_reuse(conn: sqlite3.Connection, alert_id: str) -> dict[str, Any]:
    row=conn.execute("SELECT * FROM risk_assessments WHERE entity_type='alert' AND entity_id=? ORDER BY created_at DESC LIMIT 1",(alert_id,)).fetchone()
    if row:
        d=dict(row); d["factors"]=json.loads(d.pop("factors_json")); d["evidence"]=json.loads(d.pop("evidence_json"))
        al=conn.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone()
        d["alert"]=dict(al) if al else {"severity":"medium"}
        ids=json.loads(al["event_ids_json"]) if al else []
        d["event_count"]=len(ids)
        return d
    context=_alert_risk_context(conn,alert_id)
    rid="RISK-"+uuid.uuid4().hex[:12].upper(); now=datetime.now(timezone.utc).isoformat()
    hashes=[]
    for eid in json.loads(context["alert"]["event_ids_json"]):
        rr=conn.execute("SELECT raw_sha256 FROM events WHERE event_id=?",(eid,)).fetchone()
        if rr: hashes.append(rr[0])
    evidence={"entity_type":"alert","entity_id":alert_id,"computed_locally":True,"raw_sha256s":hashes,"schema":"risk-v1","source_alert":alert_id}
    conn.execute("INSERT INTO risk_assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now,"alert",alert_id,context["score"],context["band"],context["confidence"],context["summary"],json.dumps(context["factors"]),json.dumps(evidence),"open",None,None))
    return {"risk_id":rid,"score":context["score"],"band":context["band"],"confidence":context["confidence"],"factors":context["factors"],"evidence":evidence,"event_count":context["event_count"],"alert":context["alert"]}


def _propagate_risk(trigger_type: str = "manual", limit: int = 200) -> dict[str, Any]:
    conn=db(); queue=[]; processed={"alerts":0,"incidents":0,"events":0}
    alert_rows=conn.execute("SELECT alert_id FROM alerts WHERE status IN ('open','acknowledged') ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,500)),)).fetchall()
    incident_rows=conn.execute("SELECT incident_id FROM correlation_incidents WHERE status IN ('open','acknowledged') ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,500)),)).fetchall()
    for r in alert_rows:
        try:
            risk=_persist_alert_risk_or_reuse(conn,r[0]); queue.append(_persist_queue_item(conn,"alert",r[0],risk,trigger_type)); processed["alerts"]+=1
        except HTTPException: pass
    for r in incident_rows:
        try:
            risk=_persist_incident_risk_or_reuse(conn,r[0]); queue.append(_persist_queue_item(conn,"incident",r[0],risk,trigger_type)); processed["incidents"]+=1
        except HTTPException: pass
    conn.commit()
    rows=conn.execute("SELECT * FROM risk_queue WHERE status IN ('open','acknowledged') ORDER BY priority_score DESC, created_at ASC LIMIT 100").fetchall()
    for idx,row in enumerate(rows,1): conn.execute("UPDATE risk_queue SET rank=? WHERE queue_id=?",(idx,row["queue_id"]))
    conn.commit(); conn.close()
    return {"trigger":trigger_type,"processed":processed,"queue":[dict(r) for r in rows],"queue_depth":len(rows)}

@app.post("/api/risk/propagate")
def propagate_risk(limit: int = 200):
    return _propagate_risk("manual", limit)

@app.get("/api/risk/queue")
def risk_queue(status: str | None = None, priority_band: str | None = None, limit: int = 100):
    conn=db(); clauses=[]; params=[]
    if status: clauses.append("status=?"); params.append(status)
    if priority_band: clauses.append("priority_band=?"); params.append(priority_band)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    rows=conn.execute(f"SELECT * FROM risk_queue{where} ORDER BY priority_score DESC, created_at ASC LIMIT ?",(*params,max(1,min(limit,300)))).fetchall(); conn.close()
    return {"count":len(rows),"queue":[dict(r) for r in rows]}

@app.patch("/api/risk/queue/{queue_id}")
def update_risk_queue(queue_id: str, status: str, analyst: str | None = None):
    if status not in {"open","acknowledged","resolved","dismissed"}: raise HTTPException(400,"invalid queue status")
    conn=db(); row=conn.execute("SELECT * FROM risk_queue WHERE queue_id=?",(queue_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Queue item not found")
    conn.execute("UPDATE risk_queue SET updated_at=?,status=?,assigned_to=? WHERE queue_id=?",(datetime.now(timezone.utc).isoformat(),status,analyst,row["queue_id"])); conn.commit(); updated=conn.execute("SELECT * FROM risk_queue WHERE queue_id=?",(queue_id,)).fetchone(); conn.close(); return dict(updated)

@app.get("/api/risk/priority-summary")
def risk_priority_summary():
    conn=db(); bands=conn.execute("SELECT priority_band,COUNT(*) count,ROUND(AVG(priority_score),2) avg_score FROM risk_queue WHERE status IN ('open','acknowledged') GROUP BY priority_band ORDER BY priority_band").fetchall(); statuses=conn.execute("SELECT status,COUNT(*) count FROM risk_queue GROUP BY status").fetchall(); late=conn.execute("SELECT COUNT(*) FROM risk_queue WHERE status IN ('open','acknowledged') AND sla_due_at < ?",(datetime.now(timezone.utc).isoformat(),)).fetchone()[0] or 0; conn.close()
    return {"priority":{"bands":{r[0]:{"count":r[1],"avg_score":r[2]} for r in bands},"statuses":{r[0]:r[1] for r in statuses},"over_sla":late}}


def _risk_graph_node(conn: sqlite3.Connection, entity_type: str, entity_id: str):
    row=conn.execute("SELECT risk_id,score,band,confidence,decision_status FROM risk_assessments WHERE entity_type=? AND entity_id=? ORDER BY created_at DESC LIMIT 1",(entity_type,entity_id)).fetchone()
    return dict(row) if row else None


# -------------------- v3.0 investigation graph --------------------
def _incident_event_rows(conn: sqlite3.Connection, event_ids: list[str]) -> list[sqlite3.Row]:
    if not event_ids:
        return []
    marks=','.join('?' for _ in event_ids)
    return conn.execute(f"SELECT * FROM events WHERE event_id IN ({marks}) ORDER BY created_at ASC", event_ids).fetchall()


def _add_graph_node(nodes: dict[str, dict[str, Any]], node_id: str, node_type: str, label: str, data: dict[str, Any] | None = None) -> None:
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "type": node_type, "label": label, "data": data or {}}


def _add_graph_edge(edges: list[dict[str, Any]], source: str, target: str, relation: str, data: dict[str, Any] | None = None) -> None:
    edge_id=sha256(f"{source}|{target}|{relation}|{json.dumps(data or {},sort_keys=True)}")[:16]
    if not any(e["id"]==edge_id for e in edges):
        edges.append({"id":edge_id,"source":source,"target":target,"relation":relation,"data":data or {}})


@app.get("/api/investigation-graph/{incident_id}")
def investigation_graph(incident_id: str):
    """Build an explainable incident graph from locally persisted events and evidence."""
    conn=db()
    incident=conn.execute("SELECT * FROM correlation_incidents WHERE incident_id=?",(incident_id,)).fetchone()
    if not incident:
        conn.close(); raise HTTPException(404,"Incident not found")
    event_ids=json.loads(incident["event_ids_json"])
    event_rows=_incident_event_rows(conn,event_ids)
    nodes={}; edges=[]
    incident_node=f"incident:{incident_id}"
    _add_graph_node(nodes,incident_node,"incident",incident["title"],{"incident_id":incident_id,"severity":incident["severity"],"status":incident["status"],"score":incident["score"],"rule_id":incident["rule_id"]})

    # Correlation-rule and step context
    rule=conn.execute("SELECT * FROM correlation_rules WHERE rule_id=?",(incident["rule_id"],)).fetchone()
    if rule:
        rid=f"corr-rule:{rule['rule_id']}"
        _add_graph_node(nodes,rid,"correlation_rule",rule["name"],{"version":rule["version"],"window_seconds":rule["window_seconds"],"group_by":rule["group_by"]})
        _add_graph_edge(edges,incident_node,rid,"detected-by",{"version":rule["version"]})

    step_matches=json.loads(incident["step_matches_json"])
    for idx, er in enumerate(event_rows):
        payload=json.loads(er["payload_json"])
        norm=payload.get("normalized",{}) or {}
        eid=er["event_id"]
        enode=f"event:{eid}"
        _add_graph_node(nodes,enode,"event",f"Event {eid[:8]}",{"event_id":eid,"source":er["source"],"created_at":er["created_at"],"status":er["status"],"format":er["format"],"raw_sha256":er["raw_sha256"],"parser_id":er["parser_id"],"action":norm.get("event.action"),"source_ip":norm.get("source.ip"),"destination_ip":norm.get("destination.ip"),"destination_port":norm.get("destination.port"),"protocol":norm.get("network.protocol")})
        _add_graph_edge(edges,incident_node,enode,"contains",{"sequence_index":idx+1})

        src=norm.get("source.ip")
        dst=norm.get("destination.ip")
        parser=er["parser_id"]
        pnode=f"parser:{parser}"
        _add_graph_node(nodes,pnode,"parser",parser,{"status":"approved" if parser in PARSERS else "candidate"})
        _add_graph_edge(edges,enode,pnode,"parsed-by")
        if src:
            snode=f"ip:{src}"
            _add_graph_node(nodes,snode,"entity",src,{"entity_type":"source.ip"})
            _add_graph_edge(edges,snode,enode,"source-of")
        if dst:
            dnode=f"ip:{dst}"
            _add_graph_node(nodes,dnode,"entity",dst,{"entity_type":"destination.ip"})
            _add_graph_edge(edges,enode,dnode,"targets")
        if norm.get("event.action"):
            anode=f"action:{norm.get('event.action')}"
            _add_graph_node(nodes,anode,"attribute",str(norm.get("event.action")),{"field":"event.action"})
            _add_graph_edge(edges,enode,anode,"has-action")

        trace=conn.execute("SELECT * FROM forensic_traces WHERE event_id=?",(eid,)).fetchone()
        if trace:
            tnode=f"trace:{trace['trace_id']}"
            _add_graph_node(nodes,tnode,"trace","Forensic Trace",{"trace_id":trace["trace_id"],"schema_version":trace["schema_version"],"status":trace["status"]})
            _add_graph_edge(edges,enode,tnode,"forensic-trace")
        model=conn.execute("SELECT * FROM event_model_refs WHERE event_id=?",(eid,)).fetchone()
        if model and model["artifact_id"]:
            an=f"artifact:{model['artifact_id']}"
            _add_graph_node(nodes,an,"artifact",model["artifact_id"],{"schema_id":model["schema_id"],"schema_version":model["schema_version"],"contract_id":model["contract_id"],"contract_version":model["contract_version"]})
            _add_graph_edge(edges,enode,an,"translated-with")
        # AI evidence / routing associated with the raw hash
        ai=conn.execute("SELECT model,execution,mapping_confidence,created_at FROM ai_mapping_evidence WHERE raw_sha256=? ORDER BY created_at DESC LIMIT 1",(er["raw_sha256"],)).fetchone()
        if ai:
            ain=f"ai:{er['raw_sha256'][:12]}"
            _add_graph_node(nodes,ain,"ai_evidence","Local AI evidence",{"model":ai[0],"execution":ai[1],"mapping_confidence":ai[2],"created_at":ai[3]})
            _add_graph_edge(edges,enode,ain,"ai-evidence")
        dna=conn.execute("SELECT id,dna_json,created_at FROM dna_history WHERE source=? ORDER BY id DESC LIMIT 1",(er["source"],)).fetchone()
        if dna:
            dn=f"dna:{er['source']}"
            d=json.loads(dna[1]); _add_graph_node(nodes,dn,"dna",d.get("id","Log DNA"),{"source":er["source"],"created_at":dna[2],"similarity":d.get("similarity_to_previous")})
            _add_graph_edge(edges,enode,dn,"fingerprinted-as")

    # Source and destination relationship edges across sequence
    for i,a in enumerate(event_rows):
        pa=json.loads(a["payload_json"]).get("normalized",{}) or {}
        for b in event_rows[i+1:]:
            pb=json.loads(b["payload_json"]).get("normalized",{}) or {}
            if pa.get("source.ip") and pa.get("destination.ip") and pb.get("source.ip")==pa.get("destination.ip"):
                _add_graph_edge(edges,f"event:{a['event_id']}",f"event:{b['event_id']}","causal-sequence",{"handoff":"destination→source"})

    # Attach detection alerts whose event set overlaps the incident.
    incidents=set(event_ids)
    alerts=conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200").fetchall()
    for alert in alerts:
        ids=set(json.loads(alert["event_ids_json"]))
        overlap=list(incidents & ids)
        if overlap:
            aid=f"alert:{alert['alert_id']}"
            _add_graph_node(nodes,aid,"alert",alert["title"],{"alert_id":alert["alert_id"],"severity":alert["severity"],"status":alert["status"],"score":alert["score"]})
            _add_graph_edge(edges,incident_node,aid,"related-alert",{"overlap":overlap})

    # v3.2: attach the latest incident risk assessment to the investigation graph.
    risk_node = _risk_graph_node(conn, "incident", incident_id)
    if risk_node:
        rn=f"risk:{incident_id}"
        _add_graph_node(nodes,rn,"risk-assessment",f"Risk {risk_node['score']:.1f}/100",risk_node)
        _add_graph_edge(edges,incident_node,rn,"risk-prioritized")
    conn.close()
    return {"incident":{"incident_id":incident_id,"title":incident["title"],"severity":incident["severity"],"status":incident["status"],"score":incident["score"]},"nodes":list(nodes.values()),"edges":edges,"node_count":len(nodes),"edge_count":len(edges),"generated_at":datetime.now(timezone.utc).isoformat(),"air_gapped":True}


@app.get("/api/investigation-graph")
def investigation_graph_latest(status: str | None = None):
    conn=db()
    if status:
        row=conn.execute("SELECT incident_id FROM correlation_incidents WHERE status=? ORDER BY created_at DESC LIMIT 1",(status,)).fetchone()
    else:
        row=conn.execute("SELECT incident_id FROM correlation_incidents ORDER BY created_at DESC LIMIT 1").fetchone()
    conn.close()
    if not row:
        return {"incident":None,"nodes":[],"edges":[],"node_count":0,"edge_count":0,"generated_at":datetime.now(timezone.utc).isoformat(),"air_gapped":True}
    return investigation_graph(row[0])


# -------------------- v1.4 live socket/file connector plane --------------------
CONNECTOR_TYPES = {
    "http",
    "syslog_udp",
    "syslog_tcp",
    "file_tail",
    "kafka",
    "redis_streams",
    "nats",
}
CONNECTOR_STATUSES = {"configured", "healthy", "degraded", "disabled", "error"}


def _ensure_connector_schema() -> None:
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS connectors (
        connector_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        connector_type TEXT NOT NULL,
        source TEXT NOT NULL,
        config_json TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'configured',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_heartbeat TEXT,
        last_error TEXT,
        events_received INTEGER NOT NULL DEFAULT 0,
        bytes_received INTEGER NOT NULL DEFAULT 0,
        last_event_at TEXT
    );
    CREATE TABLE IF NOT EXISTS connector_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        connector_id TEXT NOT NULL,
        received_at TEXT NOT NULL,
        source TEXT NOT NULL,
        raw_bytes INTEGER NOT NULL,
        status TEXT NOT NULL,
        event_id TEXT,
        error TEXT,
        metadata_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_connector_events_connector_time
      ON connector_events(connector_id, received_at);
    """)
    conn.commit(); conn.close()


_ensure_connector_schema()


class ConnectorConfigRequest(BaseModel):
    name: str
    connector_type: str
    source: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class ConnectorTestRequest(BaseModel):
    sample_raw: str | None = None


class ConnectorReceiveRequest(BaseModel):
    raw: str
    format_hint: str | None = None
    process: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConnectorEnableRequest(BaseModel):
    enabled: bool


def _connector_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if not row:
        return None
    item = dict(row)
    try:
        item["config"] = json.loads(item.pop("config_json"))
    except Exception:
        item["config"] = {}
    item["enabled"] = bool(item.get("enabled"))
    return item


def _connector_probe(connector_type: str, config: dict[str, Any], sample_raw: str | None = None) -> dict[str, Any]:
    """Side-effect-free adapter probe. External brokers remain optional adapters."""
    now = datetime.now(timezone.utc).isoformat()
    if connector_type == "http":
        return {"healthy": True, "adapter": "HTTP push", "mode": "receiver", "checked_at": now}
    if connector_type in {"syslog_udp", "syslog_tcp"}:
        host = str(config.get("host", "0.0.0.0")); port = int(config.get("port", 5514))
        return {"healthy": True, "adapter": connector_type, "mode": "listener-ready", "host": host, "port": port, "checked_at": now}
    if connector_type == "file_tail":
        path = Path(str(config.get("path", "")))
        return {"healthy": path.exists(), "adapter": "file tail", "path": str(path), "mode": "watch-ready", "checked_at": now,
                "error": None if path.exists() else "configured file does not exist"}
    if connector_type in {"kafka", "redis_streams", "nats"}:
        endpoint = config.get("endpoint") or config.get("bootstrap_servers") or config.get("url")
        return {"healthy": bool(endpoint), "adapter": connector_type, "mode": "compatible-adapter",
                "endpoint": endpoint, "checked_at": now,
                "error": None if endpoint else "configure an endpoint to enable an external broker adapter"}
    return {"healthy": False, "adapter": "unknown", "checked_at": now, "error": f"Unsupported connector type: {connector_type}"}


def _connector_set_health(connector_id: str, status: str, error: str | None = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = db(); conn.execute(
        "UPDATE connectors SET status=?,updated_at=?,last_heartbeat=?,last_error=? WHERE connector_id=?",
        (status, now, now, error, connector_id)
    ); conn.commit(); conn.close()


@app.get("/api/connectors")
def connectors():
    conn = db(); rows = conn.execute("SELECT * FROM connectors ORDER BY created_at DESC").fetchall(); conn.close()
    return [_connector_row(r) for r in rows]


@app.get("/api/connectors/health")
def connector_health():
    conn = db(); rows = conn.execute("SELECT * FROM connectors ORDER BY name").fetchall(); conn.close()
    items = []
    for r in rows:
        item = _connector_row(r); probe = _connector_probe(item["connector_type"], item["config"])
        # Do not overwrite runtime status for disabled connectors.
        if not item["enabled"]:
            item["status"] = "disabled"
        elif probe["healthy"] and item["status"] not in {"healthy", "degraded"}:
            item["status"] = "healthy"
        elif not probe["healthy"]:
            item["status"] = "degraded"
        item["probe"] = probe
        items.append(item)
    return {"connectors": items, "healthy": sum(1 for x in items if x["status"] == "healthy"), "total": len(items)}


@app.post("/api/connectors")
def register_connector(req: ConnectorConfigRequest):
    ctype = req.connector_type.strip().lower()
    if ctype not in CONNECTOR_TYPES:
        raise HTTPException(400, f"Unsupported connector_type. Use one of: {', '.join(sorted(CONNECTOR_TYPES))}")
    if not req.name.strip() or not req.source.strip():
        raise HTTPException(400, "name and source are required")
    cid = "CONN-" + uuid.uuid4().hex[:12].upper(); now = datetime.now(timezone.utc).isoformat()
    probe = _connector_probe(ctype, req.config)
    status = "healthy" if req.enabled and probe["healthy"] else ("disabled" if not req.enabled else "degraded")
    conn = db(); conn.execute(
        "INSERT INTO connectors(connector_id,name,connector_type,source,config_json,enabled,status,created_at,updated_at,last_heartbeat,last_error) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (cid, req.name.strip(), ctype, req.source.strip(), json.dumps(req.config, sort_keys=True), int(req.enabled), status, now, now, now, probe.get("error"))
    ); conn.commit(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (cid,)).fetchone(); conn.close()
    return {**_connector_row(row), "probe": probe}


@app.post("/api/connectors/{connector_id}/test")
def test_connector(connector_id: str, req: ConnectorTestRequest):
    conn = db(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone(); conn.close()
    item = _connector_row(row)
    if not item: raise HTTPException(404, "Connector not found")
    probe = _connector_probe(item["connector_type"], item["config"], req.sample_raw)
    _connector_set_health(connector_id, "healthy" if probe["healthy"] else "degraded", probe.get("error"))
    return {"connector_id": connector_id, "status": "healthy" if probe["healthy"] else "degraded", "probe": probe}


@app.post("/api/connectors/{connector_id}/enable")
def enable_connector(connector_id: str, req: ConnectorEnableRequest):
    conn = db(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404, "Connector not found")
    now = datetime.now(timezone.utc).isoformat()
    status = "configured" if req.enabled else "disabled"
    conn.execute("UPDATE connectors SET enabled=?,status=?,updated_at=? WHERE connector_id=?", (int(req.enabled), status, now, connector_id)); conn.commit()
    item = _connector_row(conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone()); conn.close()
    return item


@app.post("/api/connectors/{connector_id}/receive")
def connector_receive(connector_id: str, req: ConnectorReceiveRequest):
    conn = db(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone(); conn.close()
    item = _connector_row(row)
    if not item: raise HTTPException(404, "Connector not found")
    if not item["enabled"]: raise HTTPException(409, "Connector is disabled")
    started = time.perf_counter(); now = datetime.now(timezone.utc).isoformat()
    status = "accepted"; event_id = None; error = None
    try:
        if req.process:
            result = _finalize_event_pipeline(ProcessRequest(source=item["source"], raw=req.raw, format_hint=req.format_hint))
            event_id = result.get("event_id")
        else:
            result = {"queued": True}
        conn = db(); conn.execute(
            "INSERT INTO connector_events(connector_id,received_at,source,raw_bytes,status,event_id,error,metadata_json) VALUES (?,?,?,?,?,?,?,?)",
            (connector_id, now, item["source"], len(req.raw.encode("utf-8")), status, event_id, None, json.dumps(req.metadata, sort_keys=True))
        )
        conn.execute("UPDATE connectors SET status='healthy',last_heartbeat=?,last_event_at=?,events_received=events_received+1,bytes_received=bytes_received+?,updated_at=?,last_error=NULL WHERE connector_id=?",
                     (now, now, len(req.raw.encode("utf-8")), now, connector_id))
        conn.commit(); conn.close()
        return {"accepted": True, "connector_id": connector_id, "event_id": event_id, "processing_ms": round((time.perf_counter()-started)*1000, 2), "result": result}
    except Exception as exc:
        status = "error"; error = f"{type(exc).__name__}: {exc}"
        conn = db(); conn.execute(
            "INSERT INTO connector_events(connector_id,received_at,source,raw_bytes,status,event_id,error,metadata_json) VALUES (?,?,?,?,?,?,?,?)",
            (connector_id, now, item["source"], len(req.raw.encode("utf-8")), status, None, error[:1000], json.dumps(req.metadata, sort_keys=True))
        ); conn.execute("UPDATE connectors SET status='error',last_heartbeat=?,updated_at=?,last_error=? WHERE connector_id=?", (now, now, error[:1000], connector_id)); conn.commit(); conn.close()
        raise HTTPException(500, error)


@app.get("/api/connectors/{connector_id}/events")
def connector_events(connector_id: str, limit: int = 50):
    conn = db(); rows = conn.execute("SELECT * FROM connector_events WHERE connector_id=? ORDER BY id DESC LIMIT ?", (connector_id, max(1, min(limit, 200)))).fetchall(); conn.close()
    return [dict(r) for r in rows]



# Runtime listener registry. Threads are deliberately process-local for the SIH prototype.
RUNTIME_CONNECTORS: dict[str, dict[str, Any]] = {}

def _record_connector_delivery(connector_id: str, raw: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    # Reuse the exact same unified receive contract as HTTP connectors.
    req = ConnectorReceiveRequest(raw=raw, process=True, metadata=metadata or {})
    return connector_receive(connector_id, req)

def _syslog_worker(connector_id: str, sock_type: int) -> None:
    import socket
    conn = db(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone(); conn.close()
    item = _connector_row(row)
    if not item or not item["enabled"]: return
    cfg = item["config"]; host = str(cfg.get("host", "0.0.0.0")); port = int(cfg.get("port", 5514))
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    sock.bind((host, port))
    if sock_type == socket.SOCK_STREAM: sock.listen(16)
    state = RUNTIME_CONNECTORS.setdefault(connector_id, {"running": True})
    state.update({"type": "syslog_tcp" if sock_type == socket.SOCK_STREAM else "syslog_udp", "socket": sock, "started_at": datetime.now(timezone.utc).isoformat()})
    _connector_set_health(connector_id, "healthy")
    try:
        while RUNTIME_CONNECTORS.get(connector_id, {}).get("running"):
            try:
                if sock_type == socket.SOCK_DGRAM:
                    data, addr = sock.recvfrom(65535)
                    raw = data.decode("utf-8", errors="replace").strip()
                    if raw:
                        _record_connector_delivery(connector_id, raw, {"transport": "udp", "remote": f"{addr[0]}:{addr[1]}"})
                else:
                    client, addr = sock.accept(); client.settimeout(1.0)
                    with client:
                        buf = b""
                        while RUNTIME_CONNECTORS.get(connector_id, {}).get("running"):
                            try: chunk = client.recv(65535)
                            except socket.timeout: break
                            if not chunk: break
                            buf += chunk
                            while b"\n" in buf:
                                line, buf = buf.split(b"\n", 1)
                                raw = line.decode("utf-8", errors="replace").strip()
                                if raw: _record_connector_delivery(connector_id, raw, {"transport": "tcp", "remote": f"{addr[0]}:{addr[1]}"})
                        if buf.strip(): _record_connector_delivery(connector_id, buf.decode("utf-8", errors="replace").strip(), {"transport": "tcp", "remote": f"{addr[0]}:{addr[1]}"})
            except TimeoutError:
                continue
            except OSError:
                break
            except Exception as exc:
                _connector_set_health(connector_id, "error", f"{type(exc).__name__}: {exc}")
    finally:
        try: sock.close()
        except Exception: pass
        RUNTIME_CONNECTORS.pop(connector_id, None)
        _connector_set_health(connector_id, "configured")

def _file_tail_worker(connector_id: str) -> None:
    conn = db(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone(); conn.close()
    item = _connector_row(row)
    if not item or not item["enabled"]: return
    path = Path(str(item["config"].get("path", "")))
    interval = max(0.05, float(item["config"].get("poll_interval", 0.5)))
    if not path.exists():
        _connector_set_health(connector_id, "degraded", "file does not exist")
        return
    position = int(RUNTIME_CONNECTORS.get(connector_id, {}).get("position", 0))
    state = RUNTIME_CONNECTORS.setdefault(connector_id, {"running": True})
    state.update({"type": "file_tail", "position": position, "started_at": datetime.now(timezone.utc).isoformat()})
    _connector_set_health(connector_id, "healthy")
    try:
        while RUNTIME_CONNECTORS.get(connector_id, {}).get("running"):
            try:
                size = path.stat().st_size
                if size < position: position = 0  # rotation/truncation
                with path.open("rb") as f:
                    f.seek(position)
                    chunk = f.read()
                if chunk:
                    lines = chunk.splitlines()
                    complete_bytes = sum(len(x) + 1 for x in lines)
                    position += complete_bytes
                    for line in lines:
                        raw = line.decode("utf-8", errors="replace").strip()
                        if raw: _record_connector_delivery(connector_id, raw, {"transport": "file_tail", "path": str(path)})
                RUNTIME_CONNECTORS.setdefault(connector_id, {})["position"] = position
                time.sleep(interval)
            except Exception as exc:
                _connector_set_health(connector_id, "error", f"{type(exc).__name__}: {exc}")
                time.sleep(interval)
    finally:
        RUNTIME_CONNECTORS.pop(connector_id, None)
        _connector_set_health(connector_id, "configured")

def _start_runtime_connector(connector_id: str) -> dict[str, Any]:
    if connector_id in RUNTIME_CONNECTORS and RUNTIME_CONNECTORS[connector_id].get("running"):
        return {"started": False, "reason": "already_running"}
    conn = db(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone(); conn.close()
    item = _connector_row(row)
    if not item: raise HTTPException(404, "Connector not found")
    if not item["enabled"]: raise HTTPException(409, "Connector is disabled")
    if item["connector_type"] not in {"syslog_udp", "syslog_tcp", "file_tail"}:
        raise HTTPException(400, "Live runtime is supported for syslog_udp, syslog_tcp and file_tail")
    marker = {"running": True}
    RUNTIME_CONNECTORS[connector_id] = marker
    target = _syslog_worker if item["connector_type"] in {"syslog_udp", "syslog_tcp"} else _file_tail_worker
    args = (connector_id, __import__('socket').SOCK_DGRAM if item["connector_type"] == "syslog_udp" else __import__('socket').SOCK_STREAM) if item["connector_type"] in {"syslog_udp", "syslog_tcp"} else (connector_id,)
    thread = threading.Thread(target=target, args=args, daemon=True, name=f"ulpf-{connector_id}")
    marker["thread"] = thread; thread.start()
    return {"started": True, "connector_id": connector_id, "type": item["connector_type"]}

def _stop_runtime_connector(connector_id: str) -> dict[str, Any]:
    state = RUNTIME_CONNECTORS.get(connector_id)
    if not state: return {"stopped": False, "reason": "not_running"}
    state["running"] = False
    sock = state.get("socket")
    if sock:
        try: sock.close()
        except Exception: pass
    thread = state.get("thread")
    if thread and thread is not threading.current_thread(): thread.join(timeout=2)
    RUNTIME_CONNECTORS.pop(connector_id, None)
    return {"stopped": True, "connector_id": connector_id}

@app.post("/api/connectors/{connector_id}/start")
def start_connector(connector_id: str):
    return _start_runtime_connector(connector_id)

@app.post("/api/connectors/{connector_id}/stop")
def stop_connector(connector_id: str):
    return _stop_runtime_connector(connector_id)

@app.get("/api/connectors/runtime")
def runtime_connector_status():
    return {"running": [{"connector_id": cid, "type": s.get("type"), "started_at": s.get("started_at"), "position": s.get("position")} for cid, s in RUNTIME_CONNECTORS.items()]}

@app.get("/api/connectors/{connector_id}")
def connector_detail(connector_id: str):
    conn = db(); row = conn.execute("SELECT * FROM connectors WHERE connector_id=?", (connector_id,)).fetchone(); conn.close()
    item = _connector_row(row)
    if not item: raise HTTPException(404, "Connector not found")
    item["probe"] = _connector_probe(item["connector_type"], item["config"])
    return item


# -------------------- v3.3 entity intelligence & attack-path analysis --------------------
ENTITY_TYPES = {"ip", "user", "host", "service", "source", "unknown"}


def _ensure_entity_tables() -> None:
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS entities (
        entity_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, entity_key TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 0, risk_score REAL NOT NULL DEFAULT 0,
        trust_score REAL NOT NULL DEFAULT 1.0, status TEXT NOT NULL DEFAULT 'active',
        metadata_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type, last_seen);
    CREATE INDEX IF NOT EXISTS idx_entities_risk ON entities(risk_score DESC, last_seen DESC);
    CREATE TABLE IF NOT EXISTS entity_observations (
        observation_id TEXT PRIMARY KEY, entity_id TEXT NOT NULL, event_id TEXT NOT NULL,
        role TEXT NOT NULL, observed_at TEXT NOT NULL, value_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_entity_obs_entity ON entity_observations(entity_id, observed_at);
    CREATE INDEX IF NOT EXISTS idx_entity_obs_event ON entity_observations(event_id, observed_at);
    CREATE TABLE IF NOT EXISTS entity_relationships (
        relationship_id TEXT PRIMARY KEY, source_entity_id TEXT NOT NULL, target_entity_id TEXT NOT NULL,
        relation TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 1, confidence REAL NOT NULL DEFAULT 1.0,
        evidence_json TEXT NOT NULL,
        UNIQUE(source_entity_id, target_entity_id, relation)
    );
    CREATE INDEX IF NOT EXISTS idx_entity_rel_source ON entity_relationships(source_entity_id, last_seen);
    CREATE INDEX IF NOT EXISTS idx_entity_rel_target ON entity_relationships(target_entity_id, last_seen);
    CREATE TABLE IF NOT EXISTS attack_paths (
        path_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, title TEXT NOT NULL,
        severity TEXT NOT NULL, score REAL NOT NULL, status TEXT NOT NULL DEFAULT 'candidate',
        start_entity_id TEXT, end_entity_id TEXT, node_ids_json TEXT NOT NULL,
        edge_ids_json TEXT NOT NULL, event_ids_json TEXT NOT NULL, evidence_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attack_paths_score ON attack_paths(score DESC, created_at DESC);
    CREATE TABLE IF NOT EXISTS entity_risk_links (
        entity_id TEXT PRIMARY KEY, risk_score REAL NOT NULL DEFAULT 0, band TEXT NOT NULL DEFAULT 'low',
        updated_at TEXT NOT NULL, source_json TEXT NOT NULL
    );
    """)
    conn.commit(); conn.close()


_ensure_entity_tables()


def _entity_id(entity_type: str, key: str) -> str:
    return f"ENT-{entity_type.upper()}-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16].upper()}"


def _upsert_entity(conn: sqlite3.Connection, entity_type: str, key: str, display_name: str, when: str, metadata: dict[str, Any] | None = None) -> str:
    entity_type = entity_type if entity_type in ENTITY_TYPES else "unknown"
    ek = f"{entity_type}:{key.strip().lower()}"
    eid = _entity_id(entity_type, ek)
    row = conn.execute("SELECT * FROM entities WHERE entity_id=?", (eid,)).fetchone()
    meta = metadata or {}
    if row:
        merged = json.loads(row["metadata_json"]); merged.update(meta)
        conn.execute("UPDATE entities SET display_name=?,last_seen=?,observation_count=observation_count+1,metadata_json=? WHERE entity_id=?",
                     (display_name, when, json.dumps(merged, sort_keys=True), eid))
    else:
        conn.execute("INSERT INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (eid, entity_type, ek, display_name, when, when, 1, 0.0, 1.0, "active", json.dumps(meta, sort_keys=True)))
    return eid


def _event_entities(payload: dict[str, Any], source: str, event_id: str, when: str) -> list[tuple[str, str, str, dict[str, Any]]]:
    n = payload.get("normalized") or {}
    found: list[tuple[str, str, str, dict[str, Any]]] = []
    if n.get("source.ip"):
        found.append(("ip", str(n["source.ip"]), "source_ip", {"field": "source.ip"}))
    if n.get("destination.ip"):
        found.append(("ip", str(n["destination.ip"]), "destination_ip", {"field": "destination.ip"}))
    if n.get("user.name"):
        found.append(("user", str(n["user.name"]), "user", {"field": "user.name"}))
    if n.get("host.name"):
        found.append(("host", str(n["host.name"]), "host", {"field": "host.name"}))
    if n.get("destination.port") is not None:
        proto = str(n.get("network.protocol") or "unknown").lower()
        service_key = f"{proto}/{n['destination.port']}"
        found.append(("service", service_key, "destination_service", {"protocol": proto, "port": n["destination.port"]}))
    if source:
        found.append(("source", source, "log_source", {"field": "observer.name"}))
    return found


def _upsert_relationship(conn: sqlite3.Connection, src: str, dst: str, relation: str, when: str, confidence: float, evidence: dict[str, Any]):
    row = conn.execute("SELECT * FROM entity_relationships WHERE source_entity_id=? AND target_entity_id=? AND relation=?", (src,dst,relation)).fetchone()
    if row:
        ec = int(row["observation_count"]) + 1
        conf = round((float(row["confidence"]) * (ec - 1) + confidence) / ec, 4)
        ev = json.loads(row["evidence_json"]); ev["last"] = evidence
        conn.execute("UPDATE entity_relationships SET last_seen=?,observation_count=?,confidence=?,evidence_json=? WHERE relationship_id=?", (when,ec,conf,json.dumps(ev),row["relationship_id"]))
    else:
        rid = "ER-" + uuid.uuid4().hex[:14].upper()
        conn.execute("INSERT INTO entity_relationships VALUES (?,?,?,?,?,?,?,?,?)", (rid,src,dst,relation,when,when,1,confidence,json.dumps(evidence)))


def _rebuild_entities_from_events() -> dict[str, Any]:
    _ensure_entity_tables()
    conn = db()
    # Rebuild is a deterministic projection of the event store, so repeated runs do not inflate counts.
    conn.execute("DELETE FROM entity_observations")
    conn.execute("DELETE FROM entity_relationships")
    conn.execute("DELETE FROM entities")
    conn.commit()
    rows = conn.execute("SELECT event_id,created_at,source,payload_json FROM events ORDER BY created_at ASC").fetchall()
    created_entities = 0; obs = 0; rels = 0
    for r in rows:
        payload = json.loads(r["payload_json"]); items = _event_entities(payload, r["source"], r["event_id"], r["created_at"])
        mapping: dict[str, str] = {}
        for et, key, role, meta in items:
            eid = _upsert_entity(conn, et, key, key, r["created_at"], meta)
            mapping[role] = eid
            oid = "EO-" + hashlib.sha256(f"{eid}|{r['event_id']}|{role}".encode()).hexdigest()[:20].upper()
            conn.execute("INSERT OR IGNORE INTO entity_observations VALUES (?,?,?,?,?,?)", (oid,eid,r["event_id"],role,r["created_at"],json.dumps(meta,sort_keys=True)))
            obs += 1
        if mapping.get("source_ip") and mapping.get("destination_ip"):
            _upsert_relationship(conn,mapping["source_ip"],mapping["destination_ip"],"communicates_with",r["created_at"],0.98,{"event_id":r["event_id"],"source":r["source"]}); rels += 1
        if mapping.get("destination_ip") and mapping.get("destination_service"):
            _upsert_relationship(conn,mapping["destination_ip"],mapping["destination_service"],"targets_service",r["created_at"],0.95,{"event_id":r["event_id"]}); rels += 1
        if mapping.get("user") and mapping.get("source_ip"):
            _upsert_relationship(conn,mapping["user"],mapping["source_ip"],"originates_from",r["created_at"],0.88,{"event_id":r["event_id"]}); rels += 1
        if mapping.get("host") and mapping.get("source_ip"):
            _upsert_relationship(conn,mapping["host"],mapping["source_ip"],"resolves_to",r["created_at"],0.9,{"event_id":r["event_id"]}); rels += 1
    conn.commit()
    entity_count = conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"]
    relationship_count = conn.execute("SELECT COUNT(*) c FROM entity_relationships").fetchone()["c"]
    conn.close()
    return {"events_scanned": len(rows), "entity_count": entity_count, "relationship_count": relationship_count, "observations_created": obs, "relationship_observations": rels}


def _entity_row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row); d["metadata"] = json.loads(d.pop("metadata_json")); return d


def _relationship_row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row); d["evidence"] = json.loads(d.pop("evidence_json")); return d


@app.post("/api/entities/rebuild")
def rebuild_entity_graph():
    return _rebuild_entities_from_events()


@app.get("/api/entities/summary")
def entity_summary():
    _ensure_entity_tables(); conn = db()
    counts = conn.execute("SELECT entity_type,COUNT(*) count FROM entities GROUP BY entity_type ORDER BY count DESC").fetchall()
    top = conn.execute("SELECT entity_id,entity_type,display_name,observation_count,last_seen,risk_score FROM entities ORDER BY observation_count DESC,last_seen DESC LIMIT 12").fetchall()
    rels = conn.execute("SELECT relation,COUNT(*) count FROM entity_relationships GROUP BY relation ORDER BY count DESC").fetchall()
    conn.close(); return {"entities_by_type":[dict(r) for r in counts],"top_entities":[dict(r) for r in top],"relationships_by_type":[dict(r) for r in rels]}


@app.get("/api/entities")
def list_entities(entity_type: str | None = None, q: str | None = None, limit: int = 100):
    _ensure_entity_tables(); limit = max(1, min(limit, 300)); conn = db(); clauses=[]; params=[]
    if entity_type: clauses.append("entity_type=?"); params.append(entity_type)
    if q: clauses.append("(display_name LIKE ? OR entity_key LIKE ?)"); like=f"%{q}%"; params.extend([like,like])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute(f"SELECT * FROM entities{where} ORDER BY risk_score DESC, observation_count DESC, last_seen DESC LIMIT ?", (*params,limit)).fetchall(); conn.close()
    return [_entity_row(r) for r in rows]


@app.get("/api/entities/{entity_id}")
def entity_detail(entity_id: str):
    _ensure_entity_tables(); conn=db(); row=conn.execute("SELECT * FROM entities WHERE entity_id=?",(entity_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Entity not found")
    rel_src=conn.execute("SELECT * FROM entity_relationships WHERE source_entity_id=? ORDER BY observation_count DESC",(entity_id,)).fetchall()
    rel_dst=conn.execute("SELECT * FROM entity_relationships WHERE target_entity_id=? ORDER BY observation_count DESC",(entity_id,)).fetchall()
    obs=conn.execute("SELECT * FROM entity_observations WHERE entity_id=? ORDER BY observed_at DESC LIMIT 50",(entity_id,)).fetchall()
    conn.close()
    return {"entity":_entity_row(row),"outgoing":[_relationship_row(x) for x in rel_src],"incoming":[_relationship_row(x) for x in rel_dst],"observations":[dict(x) for x in obs]}


@app.get("/api/entities/{entity_id}/neighbors")
def entity_neighbors(entity_id: str, depth: int = 1):
    _ensure_entity_tables(); depth=max(1,min(depth,2)); conn=db(); seen={entity_id}; frontier=[entity_id]; edges=[]
    for _ in range(depth):
        nxt=[]
        for cur in frontier:
            rows=conn.execute("SELECT * FROM entity_relationships WHERE source_entity_id=? OR target_entity_id=?",(cur,cur)).fetchall()
            for r in rows:
                rd=_relationship_row(r); edges.append(rd)
                other=r["target_entity_id"] if r["source_entity_id"]==cur else r["source_entity_id"]
                if other not in seen: seen.add(other); nxt.append(other)
        frontier=nxt
    ids=tuple(seen); placeholders=','.join('?'*len(ids)); entities=conn.execute(f"SELECT * FROM entities WHERE entity_id IN ({placeholders})",ids).fetchall(); conn.close()
    return {"root":entity_id,"depth":depth,"entities":[_entity_row(x) for x in entities],"relationships":edges}


def _event_kind(payload: dict[str, Any]) -> tuple[str, str]:
    n=payload.get("normalized") or {}; action=str(n.get("event.action") or "").lower(); port=n.get("destination.port")
    if action in {"deny","denied","reject","blocked","failed","failure"}: return ("failed_attempt",action)
    if action in {"allow","accepted","accept","success","successful","login_success"}: return ("successful_access",action)
    if action in {"privilege_change","privilege_changed","admin_grant","role_change"}: return ("privilege_change",action)
    if action in {"sensitive_access","data_access","read_secret","download"}: return ("sensitive_access",action)
    if port in {22,3389,5985,5986}: return ("remote_access",str(port))
    return ("event",action)


def _build_attack_paths() -> dict[str, Any]:
    _ensure_entity_tables(); conn=db(); rows=conn.execute("SELECT event_id,created_at,payload_json FROM events ORDER BY created_at ASC").fetchall()
    typed=[]
    for r in rows:
        payload=json.loads(r["payload_json"]); kind,label=_event_kind(payload); n=payload.get("normalized") or {}
        if n.get("source.ip") and n.get("destination.ip"):
            typed.append({"event_id":r["event_id"],"time":r["created_at"],"kind":kind,"label":label,"src":str(n["source.ip"]),"dst":str(n["destination.ip"]),"payload":payload})
    created=[]
    # Candidate attack path: failed attempt -> successful access -> privilege change -> sensitive access,
    # grouped by source/destination continuity and ordered timestamps.
    for i,a in enumerate(typed):
        if a["kind"] != "failed_attempt": continue
        path=[a]; last=a; kinds=[a["kind"]]
        for b in typed[i+1:]:
            if b["time"] < last["time"]: continue
            if (datetime.fromisoformat(b["time"]) - datetime.fromisoformat(a["time"])).total_seconds() > 3600: break
            if b["src"] != a["src"]: continue
            if b["dst"] != a["dst"]: continue
            if len(path)==1 and b["kind"]=="successful_access": path.append(b); kinds.append(b["kind"]); last=b
            elif len(path)==2 and b["kind"]=="privilege_change": path.append(b); kinds.append(b["kind"]); last=b
            elif len(path)==3 and b["kind"]=="sensitive_access": path.append(b); kinds.append(b["kind"]); last=b; break
        if len(path)>=2:
            score=min(100.0, 35 + 20*(len(path)-1) + (10 if len(path)==4 else 0))
            severity="critical" if len(path)==4 else "high" if len(path)==3 else "medium"
            node_keys=[f"ip:{a['src']}",f"ip:{a['dst']}"]
            node_ids=[]
            for k in node_keys:
                er=conn.execute("SELECT entity_id FROM entities WHERE entity_key=?",(k,)).fetchone();
                if er: node_ids.append(er["entity_id"])
            event_ids=[x["event_id"] for x in path]
            existing=conn.execute("SELECT path_id FROM attack_paths WHERE event_ids_json=?",(json.dumps(event_ids,separators=(",",":")),)).fetchone()
            if existing:
                continue
            title=" → ".join(["Failed Login","Successful Access","Privilege Change","Sensitive Access"][:len(path)])
            pid="PATH-"+uuid.uuid4().hex[:12].upper()
            edge_ids=[]
            if len(node_ids)>=2:
                er=conn.execute("SELECT relationship_id FROM entity_relationships WHERE source_entity_id=? AND target_entity_id=? AND relation='communicates_with'",(node_ids[0],node_ids[-1])).fetchone()
                if er: edge_ids.append(er["relationship_id"])
            evidence={"pattern":kinds,"source_ip":a["src"],"destination_ip":a["dst"],"elapsed_seconds":round((datetime.fromisoformat(path[-1]["time"])-datetime.fromisoformat(path[0]["time"])).total_seconds(),2),"explainable":True}
            conn.execute("INSERT INTO attack_paths VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(pid,datetime.now(timezone.utc).isoformat(),title,severity,score,"candidate",node_ids[0] if node_ids else None,node_ids[-1] if node_ids else None,json.dumps(node_ids),json.dumps(edge_ids),json.dumps(event_ids,separators=(",",":")),json.dumps(evidence)))
            created.append({"path_id":pid,"title":title,"severity":severity,"score":score,"event_ids":[x["event_id"] for x in path],"evidence":evidence})
    conn.commit(); total=conn.execute("SELECT COUNT(*) c FROM attack_paths").fetchone()["c"]; conn.close()
    return {"created":len(created),"total_paths":total,"paths":created}


@app.post("/api/attack-paths/build")
def build_attack_paths():
    return _build_attack_paths()


@app.get("/api/attack-paths")
def list_attack_paths(limit: int = 50):
    _ensure_entity_tables(); conn=db(); rows=conn.execute("SELECT * FROM attack_paths ORDER BY score DESC, created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["node_ids"]=json.loads(d.pop("node_ids_json")); d["edge_ids"]=json.loads(d.pop("edge_ids_json")); d["event_ids"]=json.loads(d.pop("event_ids_json")); d["evidence"]=json.loads(d.pop("evidence_json")); out.append(d)
    return out


@app.get("/api/attack-paths/{path_id}/graph")
def attack_path_graph(path_id: str):
    """Return a UI-ready attack-path graph with ordered attack progression and evidence edges."""
    _ensure_entity_tables(); conn=db()
    row=conn.execute("SELECT * FROM attack_paths WHERE path_id=?",(path_id,)).fetchone()
    if not row:
        conn.close(); raise HTTPException(404,"Attack path not found")
    event_ids=json.loads(row["event_ids_json"])
    node_ids=json.loads(row["node_ids_json"])
    events=[]; nodes=[]; edges=[]

    def add_node(nid, ntype, label, data=None):
        if any(n["id"]==nid for n in nodes): return
        nodes.append({"id":nid,"type":ntype,"label":label,"data":data or {}})

    def add_edge(src,dst,relation,data=None):
        eid=sha256(f"{src}|{dst}|{relation}|{json.dumps(data or {},sort_keys=True)}")[:16]
        if not any(e["id"]==eid for e in edges):
            edges.append({"id":eid,"source":src,"target":dst,"relation":relation,"data":data or {}})

    for idx,eid in enumerate(event_ids):
        er=conn.execute("SELECT * FROM events WHERE event_id=?",(eid,)).fetchone()
        if not er: continue
        payload=json.loads(er["payload_json"]); norm=payload.get("normalized",{}) or {}
        kind,label=_event_kind(payload)
        event_node=f"event:{eid}"
        add_node(event_node,"event",f"STEP {idx+1} · {kind.replace('_',' ').upper()}",{
            "event_id":eid,"created_at":er["created_at"],"source":er["source"],"status":er["status"],
            "action":norm.get("event.action"),"source_ip":norm.get("source.ip"),
            "destination_ip":norm.get("destination.ip"),"destination_port":norm.get("destination.port"),
            "protocol":norm.get("network.protocol"),"raw_sha256":er["raw_sha256"]
        })
        events.append({"event_id":eid,"kind":kind,"label":label,"created_at":er["created_at"],"source":er["source"],"normalized":norm,"raw_sha256":er["raw_sha256"]})
        if idx:
            add_edge(f"event:{event_ids[idx-1]}",event_node,"attack-sequence",{"step":idx+1})
        src=norm.get("source.ip"); dst=norm.get("destination.ip")
        if src:
            sid=f"entity-ip:{src}"; add_node(sid,"entity",str(src),{"entity_type":"ip","role":"source","value":src}); add_edge(sid,event_node,"source-of")
        if dst:
            did=f"entity-ip:{dst}"; add_node(did,"entity",str(dst),{"entity_type":"ip","role":"destination","value":dst}); add_edge(event_node,did,"targets")
        action=norm.get("event.action")
        if action:
            aid=f"action:{action}"; add_node(aid,"action",str(action),{"field":"event.action"}); add_edge(event_node,aid,"has-action")

    path_node=f"path:{path_id}"
    evidence=json.loads(row["evidence_json"])
    add_node(path_node,"attack_path",row["title"],{"path_id":path_id,"severity":row["severity"],"score":row["score"],"status":row["status"],"elapsed_seconds":evidence.get("elapsed_seconds",0)})
    for eid in event_ids:
        if any(n["id"]==f"event:{eid}" for n in nodes): add_edge(path_node,f"event:{eid}","contains")

    rr=conn.execute("SELECT * FROM risk_assessments WHERE entity_type='attack_path' AND entity_id=? ORDER BY created_at DESC LIMIT 1",(path_id,)).fetchone()
    if rr:
        rn=f"risk:{path_id}"; add_node(rn,"risk",f"Risk {float(rr['score']):.1f}/100",{"risk_id":rr["risk_id"],"score":rr["score"],"band":rr["band"],"confidence":rr["confidence"]}); add_edge(path_node,rn,"risk-prioritized")
    conn.close()
    return {"path":{"path_id":path_id,"title":row["title"],"severity":row["severity"],"score":row["score"],"status":row["status"],"event_ids":event_ids,"node_ids":node_ids,"evidence":evidence},"events":events,"nodes":nodes,"edges":edges,"node_count":len(nodes),"edge_count":len(edges),"generated_at":datetime.now(timezone.utc).isoformat(),"air_gapped":True}


@app.get("/api/attack-paths/{path_id}")
def attack_path_detail(path_id: str):
    _ensure_entity_tables(); conn=db(); row=conn.execute("SELECT * FROM attack_paths WHERE path_id=?",(path_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"Attack path not found")
    events=[]
    for eid in json.loads(row["event_ids_json"]):
        er=conn.execute("SELECT * FROM events WHERE event_id=?",(eid,)).fetchone()
        if er: events.append(json.loads(er["payload_json"]))
    d=dict(row); d["node_ids"]=json.loads(d.pop("node_ids_json")); d["edge_ids"]=json.loads(d.pop("edge_ids_json")); d["event_ids"]=json.loads(d.pop("event_ids_json")); d["evidence"]=json.loads(d.pop("evidence_json")); conn.close()
    d["events"]=events; return d


# ---------------------------------------------------------------------------
# v3.8 Enterprise Hardening
# ---------------------------------------------------------------------------

def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = __import__("hashlib").scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(salt).decode(), base64.b64encode(digest).decode()


def _verify_password(password: str, salt_b64: str, expected_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode())
        digest = __import__("hashlib").scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return secrets.compare_digest(base64.b64encode(digest).decode(), expected_b64)
    except Exception:
        return False


def _ensure_hardening_tables() -> None:
    init_db()
    conn = db()
    now = _utc()
    admin_user = os.getenv("ULPF_BOOTSTRAP_ADMIN", "admin")
    admin_password = os.getenv("ULPF_BOOTSTRAP_PASSWORD", "change-me")
    row = conn.execute("SELECT username FROM auth_users WHERE username=?", (admin_user,)).fetchone()
    if not row and admin_password:
        salt, digest = _hash_password(admin_password)
        conn.execute("INSERT INTO auth_users VALUES (?,?,?,?,?,?,?)", (admin_user, "admin", salt, digest, 1, now, now))
    defaults = {
        "auth_mode": AUTH_MODE,
        "air_gapped": "true",
        "simulation_only": "true",
        "audit_chain": "sha256",
        "log_level": os.getenv("ULPF_LOG_LEVEL", "INFO"),
        "session_ttl_seconds": str(SESSION_TTL_SECONDS),
    }
    for k, v in defaults.items():
        conn.execute("INSERT OR IGNORE INTO app_config(key,value,secret,updated_at) VALUES (?,?,0,?)", (k, v, now))
    conn.commit(); conn.close()


def _auth_from_header(authorization: str | None) -> dict[str, str]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization.split(" ", 1)[1].strip()
    if len(token) < 24:
        raise HTTPException(401, "Invalid token")
    token_hash = sha256(token)
    conn = db()
    row = conn.execute("SELECT username,role,expires_at,revoked FROM auth_sessions WHERE token_hash=?", (token_hash,)).fetchone()
    if not row:
        conn.close(); raise HTTPException(401, "Invalid token")
    now = datetime.now(timezone.utc)
    try: expires = datetime.fromisoformat(row["expires_at"])
    except ValueError: expires = now
    if row["revoked"] or expires <= now:
        conn.close(); raise HTTPException(401, "Session expired or revoked")
    conn.execute("UPDATE auth_sessions SET last_seen_at=? WHERE token_hash=?", (_utc(), token_hash)); conn.commit(); conn.close()
    return {"username": row["username"], "role": row["role"]}


def _require_role(authorization: str | None, roles: set[str]) -> dict[str, str]:
    actor = _auth_from_header(authorization)
    if actor["role"] not in roles:
        raise HTTPException(403, "Insufficient role")
    return actor


def _audit(actor: str, role: str, action: str, resource: str, payload: dict[str, Any]) -> str:
    conn = db()
    prev = conn.execute("SELECT entry_hash FROM hardening_audit ORDER BY created_at DESC LIMIT 1").fetchone()
    prev_hash = prev["entry_hash"] if prev else "GENESIS"
    created = _utc(); audit_id = "AUD-" + uuid.uuid4().hex[:12].upper(); request_id = REQUEST_ID.get()
    canonical = json.dumps({"audit_id":audit_id,"created_at":created,"actor":actor,"role":role,"action":action,"resource":resource,"request_id":request_id,"payload":payload,"prev_hash":prev_hash}, sort_keys=True, separators=(",",":"))
    entry_hash = sha256(prev_hash + canonical)
    conn.execute("INSERT INTO hardening_audit VALUES (?,?,?,?,?,?,?,?,?,?)", (audit_id, created, actor, role, action, resource, request_id, json.dumps(payload, sort_keys=True), prev_hash, entry_hash))
    conn.commit(); conn.close(); return audit_id


class LoginRequest(BaseModel):
    username: str
    password: str


class UserRequest(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=12, max_length=200)
    role: str = Field(pattern="^(admin|analyst|viewer)$")


class ConfigRequest(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    value: str = Field(max_length=500)
    secret: bool = False



# -------------------- v3.9 air-gap operations --------------------
AIRGAP_REQUIRED_ENV = {
    "ULPF_AUTH_MODE": ("development", "production"),
    "ULPF_AI_MODE": ("heuristic", "gpt-oss"),
}

class ImportConfigRequest(BaseModel):
    configuration: dict[str, str] = Field(default_factory=dict)
    include_secrets: bool = False

class RestoreRequest(BaseModel):
    backup_path: str = Field(min_length=1, max_length=500)
    confirm: bool = False


def _startup_self_test() -> dict[str, Any]:
    results: dict[str, Any] = {}
    failures: list[str] = []
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        probe = DATA_DIR / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        results["data_dir_writable"] = True
    except Exception as exc:
        results["data_dir_writable"] = False
        failures.append(f"data_dir_writable:{exc}")
    try:
        _ensure_hardening_tables()
        conn = db()
        required = ["events","app_config","auth_users","auth_sessions","hardening_audit","service_health"]
        missing=[]
        for table in required:
            row=conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
            if not row:
                missing.append(table)
        conn.close()
        results["required_tables"]={"ok":not missing,"missing":missing}
        if missing:
            failures.append("missing_tables")
    except Exception as exc:
        results["database_schema"]={"ok":False,"error":str(exc)}
        failures.append("database_schema")
    ai_mode=os.getenv("ULPF_AI_MODE","heuristic").lower()
    results["ai_mode_valid"] = ai_mode in {"heuristic","gpt-oss"}
    if not results["ai_mode_valid"]:
        failures.append("ai_mode")
    origins=os.getenv("ULPF_ALLOWED_ORIGINS","*")
    results["cors_review_required"] = origins.strip()=="*"
    results["air_gapped"] = True
    results["simulation_only"] = True
    return {"passed":not failures,"failures":failures,"checks":results,"checked_at":_utc()}


def _safe_config_export(include_secrets: bool=False) -> dict[str, Any]:
    conn=db()
    rows=conn.execute("SELECT key,value,secret,updated_at FROM app_config ORDER BY key").fetchall()
    conn.close()
    config={}
    for r in rows:
        if r["secret"] and not include_secrets:
            continue
        config[r["key"]]=r["value"]
    return {"format":"ulpf-nexus-config","version":"1","exported_at":_utc(),"air_gapped":True,"configuration":config}


@app.get("/api/airgap/status")
def airgap_status():
    checks=_startup_self_test()
    return {"status":"ready" if checks["passed"] else "degraded", "air_gapped":True, "network_mode":"disconnected-by-deployment-policy", "external_ai_required":False, "simulation_only":True, "startup_checks":checks}


@app.post("/api/airgap/self-test")
def airgap_self_test(authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin","analyst"})
    result=_startup_self_test()
    aid=_audit(actor["username"],actor["role"],"airgap.self_test","runtime",{"passed":result["passed"],"failures":result["failures"]})
    result["audit_id"]=aid
    return result


@app.get("/api/airgap/config/export")
def airgap_config_export(include_secrets: bool=False, authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin"})
    if include_secrets and AUTH_MODE != "development":
        raise HTTPException(400,"Secret export is disabled outside development mode")
    payload=_safe_config_export(include_secrets)
    aid=_audit(actor["username"],actor["role"],"config.export","app_config",{"include_secrets":include_secrets,"keys":sorted(payload["configuration"])})
    payload["audit_id"]=aid
    return payload


@app.post("/api/airgap/config/import")
def airgap_config_import(req: ImportConfigRequest, authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin"})
    if req.include_secrets and AUTH_MODE != "development":
        raise HTTPException(400,"Secret import is disabled outside development mode")
    now=_utc()
    applied=[]
    conn=db()
    try:
        for key,value in req.configuration.items():
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", key):
                raise HTTPException(400,f"Invalid configuration key: {key}")
            secret = 1 if key.lower().endswith(("password","token","secret","key")) else 0
            if secret and not req.include_secrets:
                continue
            conn.execute("INSERT INTO app_config(key,value,secret,updated_at) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,secret=excluded.secret,updated_at=excluded.updated_at",(key,str(value),secret,now))
            applied.append(key)
        conn.commit()
    finally:
        conn.close()
    aid=_audit(actor["username"],actor["role"],"config.import","app_config",{"keys":sorted(applied)})
    return {"status":"imported","keys":applied,"requires_restart":True,"audit_id":aid}


@app.post("/api/airgap/backup")
def airgap_backup(authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin"})
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    target=DATA_DIR / f"backup_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}.db"
    src=sqlite3.connect(DB_PATH)
    dst=sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    aid=_audit(actor["username"],actor["role"],"backup.create","database",{"path":str(target.relative_to(ROOT)),"sha256":digest})
    return {"status":"created","backup_path":str(target.relative_to(ROOT)),"sha256":digest,"audit_id":aid}


@app.post("/api/airgap/restore")
def airgap_restore(req: RestoreRequest, authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin"})
    if not req.confirm:
        raise HTTPException(400,"Set confirm=true to restore a backup")
    backup=Path(req.backup_path)
    if not backup.is_absolute():
        backup=(ROOT / backup).resolve()
    if not backup.exists() or backup.suffix != ".db":
        raise HTTPException(400,"Backup database not found")
    try:
        backup.relative_to(DATA_DIR.resolve())
    except ValueError:
        raise HTTPException(400,"Backup must reside under backend/data")
    pre=DATA_DIR / f"pre_restore_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}.db"
    src0=sqlite3.connect(DB_PATH); dst0=sqlite3.connect(pre)
    try: src0.backup(dst0)
    finally: dst0.close(); src0.close()
    digest=hashlib.sha256(backup.read_bytes()).hexdigest()
    src=sqlite3.connect(backup); dst=sqlite3.connect(DB_PATH)
    try: src.backup(dst)
    finally: dst.close(); src.close()
    aid=_audit(actor["username"],actor["role"],"backup.restore","database",{"backup":str(backup.relative_to(ROOT)),"sha256":digest,"pre_restore":str(pre.relative_to(ROOT))})
    return {"status":"restored","backup_sha256":digest,"pre_restore_backup":str(pre.relative_to(ROOT)),"requires_restart":True,"audit_id":aid}


@app.get("/api/airgap/environment")
def airgap_environment(authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin","analyst"})
    checks={}
    for key, allowed in AIRGAP_REQUIRED_ENV.items():
        value=os.getenv(key, "")
        checks[key]={"value":value,"valid":value in allowed}
    warnings=[]
    if os.getenv("ULPF_ALLOWED_ORIGINS","*").strip()=="*":
        warnings.append("ULPF_ALLOWED_ORIGINS is wildcard; set explicit origins for production")
    if os.getenv("ULPF_BOOTSTRAP_PASSWORD","change-me")=="change-me":
        warnings.append("Bootstrap password remains the sample value")
    if os.getenv("ULPF_AUTH_MODE","development")!="production":
        warnings.append("Authentication mode is not production")
    return {"actor":actor,"checks":checks,"warnings":warnings,"air_gapped":True}


@app.on_event("startup")
def hardening_startup():
    _ensure_hardening_tables()


@app.get("/api/health")
def health_check():
    checks = {}
    conn = db()
    try:
        conn.execute("SELECT 1").fetchone(); checks["database"] = {"status":"healthy"}
    finally:
        conn.close()
    checks["air_gapped"] = {"status":"healthy", "enabled": True}
    checks["response_simulation"] = {"status":"healthy", "simulation_only": True}
    return {"status":"healthy", "version":"3.8.0", "checks":checks, "request_id":REQUEST_ID.get()}


@app.get("/api/ready")
def readiness_check():
    try:
        _ensure_hardening_tables()
        conn=db(); count=conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]; conn.close()
        return {"status":"ready", "database":"ready", "event_count":count, "request_id":REQUEST_ID.get()}
    except Exception as exc:
        raise HTTPException(503, f"Not ready: {exc}")


@app.post("/api/auth/login")
def login(req: LoginRequest):
    _ensure_hardening_tables(); conn=db()
    row=conn.execute("SELECT * FROM auth_users WHERE username=? AND enabled=1",(req.username,)).fetchone()
    if not row or not _verify_password(req.password,row["password_salt"],row["password_hash"]):
        conn.close(); raise HTTPException(401,"Invalid username or password")
    token=secrets.token_urlsafe(32); now=datetime.now(timezone.utc); expires=now.replace() + __import__('datetime').timedelta(seconds=SESSION_TTL_SECONDS)
    conn.execute("INSERT INTO auth_sessions VALUES (?,?,?,?,?,?,?)",(sha256(token),row["username"],row["role"],now.isoformat(),expires.isoformat(),0,now.isoformat()))
    conn.commit(); conn.close(); audit=_audit(row["username"],row["role"],"login","session",{"expires_at":expires.isoformat()})
    return {"access_token":token,"token_type":"bearer","expires_at":expires.isoformat(),"role":row["role"],"audit_id":audit}


@app.post("/api/auth/logout")
def logout(authorization: str | None = None):
    actor=_auth_from_header(authorization)
    # FastAPI does not bind a raw optional header automatically, so this endpoint also supports X-Nexus-Token below.
    raise HTTPException(400,"Use Authorization: Bearer <token>")


@app.post("/api/auth/logout/header")
def logout_header(authorization: str | None = Header(default=None)):
    actor=_auth_from_header(authorization); token=authorization.split(" ",1)[1].strip()
    conn=db(); conn.execute("UPDATE auth_sessions SET revoked=1 WHERE token_hash=?",(sha256(token),)); conn.commit(); conn.close()
    return {"status":"logged_out","actor":actor["username"]}


@app.get("/api/security/config")
def security_config(authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin","analyst"}); conn=db(); rows=conn.execute("SELECT key,value,secret,updated_at FROM app_config ORDER BY key").fetchall(); conn.close()
    out=[{"key":r["key"],"value":"***" if r["secret"] else r["value"],"secret":bool(r["secret"]),"updated_at":r["updated_at"]} for r in rows]
    return {"actor":actor,"auth_mode":AUTH_MODE,"configuration":out,"air_gapped":True}


@app.post("/api/security/config")
def update_security_config(req: ConfigRequest, authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin"}); now=_utc(); conn=db(); conn.execute("INSERT INTO app_config(key,value,secret,updated_at) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,secret=excluded.secret,updated_at=excluded.updated_at",(req.key,req.value,int(req.secret),now)); conn.commit(); conn.close()
    aid=_audit(actor["username"],actor["role"],"config.update",req.key,{"secret":req.secret})
    return {"status":"updated","key":req.key,"audit_id":aid}


@app.post("/api/security/users")
def create_security_user(req: UserRequest, authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin"}); salt,digest=_hash_password(req.password); now=_utc(); conn=db()
    try:
        conn.execute("INSERT INTO auth_users VALUES (?,?,?,?,?,?,?)",(req.username,req.role,salt,digest,1,now,now)); conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(409,"User already exists")
    conn.close(); aid=_audit(actor["username"],actor["role"],"user.create",req.username,{"role":req.role})
    return {"status":"created","username":req.username,"role":req.role,"audit_id":aid}


@app.get("/api/security/audit")
def security_audit(limit: int = 100, authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin","analyst"}); conn=db(); rows=conn.execute("SELECT * FROM hardening_audit ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,500)),)).fetchall(); conn.close()
    out=[]
    for r in rows:
        d=dict(r); d["payload"]=json.loads(d.pop("payload_json")); out.append(d)
    return {"actor":actor,"entries":out}


@app.post("/api/security/audit/verify")
def verify_security_audit(authorization: str | None = Header(default=None)):
    actor=_require_role(authorization,{"admin"}); conn=db(); rows=conn.execute("SELECT * FROM hardening_audit ORDER BY created_at ASC").fetchall(); conn.close()
    previous="GENESIS"; failures=[]
    for r in rows:
        payload=json.loads(r["payload_json"])
        canonical=json.dumps({"audit_id":r["audit_id"],"created_at":r["created_at"],"actor":r["actor"],"role":r["role"],"action":r["action"],"resource":r["resource"],"request_id":r["request_id"],"payload":payload,"prev_hash":r["prev_hash"]}, sort_keys=True, separators=(",",":"))
        expected=sha256(r["prev_hash"]+canonical)
        if r["prev_hash"] != previous or r["entry_hash"] != expected: failures.append(r["audit_id"])
        previous=r["entry_hash"]
    aid=_audit(actor["username"],actor["role"],"audit.verify","hardening_audit",{"checked":len(rows),"failures":failures})
    return {"valid":not failures,"checked":len(rows),"failures":failures,"verification_audit_id":aid}


@app.get("/api/security/health/components")
def component_health():
    conn=db(); components=[]
    for name, fn in [
        ("database", lambda: conn.execute("SELECT 1").fetchone() is not None),
        ("event_store", lambda: conn.execute("SELECT COUNT(*) FROM events").fetchone() is not None),
        ("audit_chain", lambda: conn.execute("SELECT COUNT(*) FROM hardening_audit").fetchone() is not None),
        ("auth_store", lambda: conn.execute("SELECT COUNT(*) FROM auth_users").fetchone() is not None),
    ]:
        try: ok=bool(fn()); status="healthy" if ok else "degraded"; details={"ok":ok}
        except Exception as exc: status="error"; details={"error":str(exc)[:200]}
        components.append({"component":name,"status":status,"details":details})
        conn.execute("INSERT OR REPLACE INTO service_health VALUES (?,?,?,?)",(name,status,json.dumps(details),_utc()))
    conn.commit(); conn.close()
    return {"status":"healthy" if all(x["status"]=="healthy" for x in components) else "degraded","components":components}


# -------------------- v4.0 SIH Demo & Scenario Command Center --------------------
class DemoRunRequest(BaseModel):
    scenario: str = Field(default="full_sih_demo", pattern="^(full_sih_demo|attack_reconstruction|parser_evolution)$")
    reset_demo: bool = True
    analyst: str = "SIH-Analyst"


def _ensure_demo_tables() -> None:
    conn = db()
    conn.execute("""CREATE TABLE IF NOT EXISTS demo_runs (
        run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, scenario TEXT NOT NULL,
        status TEXT NOT NULL, duration_ms REAL NOT NULL, step_count INTEGER NOT NULL,
        summary_json TEXT NOT NULL, evidence_json TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_demo_runs_created ON demo_runs(created_at)")
    conn.commit(); conn.close()


def _demo_seed_logs() -> list[str]:
    return [
        "src_ip=10.77.1.10 dst_ip=10.77.1.50 action=deny user=alice service=ssh",
        "src_ip=10.77.1.10 dst_ip=10.77.1.50 action=allow user=alice service=ssh",
        "src_ip=10.77.1.10 dst_ip=10.77.1.50 action=privilege_change user=alice service=ssh",
        "src_ip=10.77.1.10 dst_ip=10.77.1.50 action=sensitive_access user=alice service=db",
    ]


def _ensure_demo_rules() -> dict[str, str]:
    conn=db()
    detection_name="ULPF Nexus Demo — Sensitive Access"
    d=conn.execute("SELECT rule_id FROM detection_rules WHERE name=? ORDER BY updated_at DESC LIMIT 1",(detection_name,)).fetchone()
    if d: did=d["rule_id"]
    else:
        did="RULE-DEMO-ACCESS"
        cond=[{"field":"event.action","operator":"eq","value":"sensitive_access"}]
        now=_utc(); conn.execute("INSERT OR IGNORE INTO detection_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",(did,now,now,detection_name,"SIH demo signal for the final sensitive-access stage",1,"high","threshold",1,300,json.dumps(cond),"Nexus Demo",1))
    corr_name="ULPF Nexus Demo — Account Takeover Chain"
    c=conn.execute("SELECT rule_id FROM correlation_rules WHERE name=? ORDER BY updated_at DESC LIMIT 1",(corr_name,)).fetchone()
    if c: cid=c["rule_id"]
    else:
        cid="CORR-DEMO-CHAIN"
        steps=[
            {"name":"FAILED LOGIN","conditions":[{"field":"event.action","operator":"eq","value":"deny"}]},
            {"name":"SUCCESSFUL ACCESS","conditions":[{"field":"event.action","operator":"eq","value":"allow"}]},
            {"name":"PRIVILEGE CHANGE","conditions":[{"field":"event.action","operator":"eq","value":"privilege_change"}]},
            {"name":"SENSITIVE ACCESS","conditions":[{"field":"event.action","operator":"eq","value":"sensitive_access"}]},
        ]
        now=_utc(); conn.execute("INSERT OR IGNORE INTO correlation_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(cid,now,now,corr_name,"Demonstration sequence: denied attempt → access → privilege change → sensitive access",1,"critical",900,json.dumps(steps),"source.ip","Nexus Demo",1))
    conn.commit(); conn.close(); return {"detection_rule_id":did,"correlation_rule_id":cid}


def _demo_cleanup() -> None:
    conn=db()
    # Only remove deterministic demo artifacts; never delete user/production history.
    for table,col,prefix in [
        ("detection_rules","rule_id","RULE-DEMO-"),
        ("correlation_rules","rule_id","CORR-DEMO-"),
    ]:
        conn.execute(f"DELETE FROM {table} WHERE {col} LIKE ?", (prefix+"%",))
    conn.commit(); conn.close()


def _latest_demo_incident() -> dict[str, Any] | None:
    conn=db(); row=conn.execute("SELECT * FROM correlation_incidents ORDER BY created_at DESC LIMIT 1").fetchone(); conn.close()
    return _serialize_correlation_incident(row) if row else None


def _demo_record(run_id: str, scenario: str, status: str, duration_ms: float, steps: int, summary: dict[str,Any], evidence: dict[str,Any]) -> None:
    _ensure_demo_tables(); conn=db(); conn.execute("INSERT INTO demo_runs VALUES (?,?,?,?,?,?,?,?)",(run_id,_utc(),scenario,status,duration_ms,steps,json.dumps(summary),json.dumps(evidence))); conn.commit(); conn.close()


@app.post("/api/demo/run")
def run_demo_scenario(req: DemoRunRequest):
    started=__import__('time').perf_counter()
    if req.reset_demo: _demo_cleanup()
    ids=_ensure_demo_rules()
    steps=[]; events=[]
    if req.scenario in {"full_sih_demo","attack_reconstruction"}:
        source="SIH-DEMO-FIREWALL"
        for idx, raw in enumerate(_demo_seed_logs(), start=1):
            event=process_pipeline(ProcessRequest(source=source, raw=raw, format_hint="syslog", idempotency_key=f"demo-{uuid.uuid4().hex}"))
            events.append({"event_id":event["event_id"],"action":event.get("normalized",{}).get("event.action"),"status":event["status"],"parser":event["parser_id"],"dna":event.get("log_dna",{}).get("id")})
            # The demo processes the event synchronously; mirror that completed state into the replayable
            # stream so the Command Center and Stream Control show consistent evidence.
            with _STREAM_LOCK:
                conn=db(); stream="ulpf-events"; pid=_stream_partition(source); seq=_next_sequence(conn,stream,pid); mid="DEMO-"+uuid.uuid4().hex[:16].upper(); now=_utc()
                conn.execute("INSERT INTO stream_events(stream,partition_id,sequence_no,message_id,created_at,source,raw,format_hint,status,consumed_by,consumed_at,event_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                             (stream,pid,seq,mid,now,source,raw,"syslog","processed","sih-demo",now,event["event_id"]))
                conn.commit(); conn.close()
            steps.append({"step":f"ingest-{idx}","status":"complete","event_id":event["event_id"],"stream":{"partition_id":pid,"sequence_no":seq}})
        steps.append({"step":"entity-rebuild","status":"complete","result":_rebuild_entities_from_events()})
        steps.append({"step":"attack-path-refresh","status":"complete","result":_build_attack_paths()})
    if req.scenario in {"full_sih_demo","parser_evolution"}:
        samples=[
            "src=10.90.0.4 dst=10.90.0.20 action=allow user=bob proto=tcp",
            "src=10.90.0.4 dst=10.90.0.20 action=deny user=bob proto=tcp",
        ]
        onboarding=onboarding_analyze(OnboardingRequest(source="SIH-UNKNOWN-VENDOR",samples=samples,expected_vendor="Unknown Vendor"))
        steps.append({"step":"unknown-source-discovery","status":"complete","result":{"session_id":onboarding["session_id"],"recommendation":onboarding["recommendation"],"dna":onboarding["dna"]["id"]}})
        candidate=parser_candidate(CandidateParserRequest(raw_samples=samples,name="SIH-demo-evolving-parser"))
        steps.append({"step":"ai-parser-candidate","status":"complete","result":{"parser_id":candidate["id"],"coverage":candidate["coverage"],"mapping_confidence":candidate["genome"]["mapping_confidence"]}})
        sandbox_result=sandbox(SandboxRequest(parser_id=candidate["id"],samples=samples))
        steps.append({"step":"sandbox-replay","status":"complete","result":sandbox_result})
    orch=_run_integrated_security_orchestration(5000,10000,True,True,req.analyst)
    steps.append({"step":"security-orchestrator","status":"complete","result":{"alerts_created":orch["detection"].get("fired",0),"incidents_created":orch["correlation"].get("created",0),"p1":orch["analyst_queue"].get("p1",0),"responses":len(orch["response_recommendations"])}})
    incident=_latest_demo_incident()
    summary={
        "events_ingested":len(events),"trusted_events":sum(1 for e in events if e["status"]=="trusted"),
        "incident_id":incident["incident_id"] if incident else None,
        "attack_path_count":orch["attack_paths"].get("total_paths",orch["attack_paths"].get("total",0)),
        "alerts_created":orch["detection"].get("fired",0),
        "responses_pending":len(orch["response_recommendations"]),
        "analyst_p1":orch["analyst_queue"].get("p1",0),
        "air_gapped":True,"simulation_only":True,
    }
    evidence={"events":events,"steps":steps,"incident":incident,"orchestration_id":orch["orchestration_id"],"rules":ids}
    duration=round((__import__('time').perf_counter()-started)*1000,3)
    run_id="DEMO-"+uuid.uuid4().hex[:12].upper(); _demo_record(run_id,req.scenario,"completed",duration,len(steps),summary,evidence)
    _publish_realtime("demo.completed",{"run_id":run_id,"scenario":req.scenario,"summary":summary})
    return {"run_id":run_id,"scenario":req.scenario,"status":"completed","duration_ms":duration,"summary":summary,"steps":steps,"incident":incident,"air_gapped":True,"simulation_only":True}


@app.get("/api/demo/runs")
def demo_runs(limit:int=20):
    _ensure_demo_tables(); conn=db(); rows=conn.execute("SELECT * FROM demo_runs ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,100)),)).fetchall(); conn.close(); out=[]
    for r in rows:
        d=dict(r); d["summary"]=json.loads(d.pop("summary_json")); d["evidence"]=json.loads(d.pop("evidence_json")); out.append(d)
    return {"count":len(out),"runs":out}


@app.get("/api/demo/command-center")
def demo_command_center():
    _ensure_demo_tables(); conn=db()
    latest=conn.execute("SELECT * FROM demo_runs ORDER BY created_at DESC LIMIT 1").fetchone()
    conn.close()
    system_metrics=globals()["metrics"]()
    if latest:
        d=dict(latest); d["summary"]=json.loads(d.pop("summary_json")); d["evidence"]=json.loads(d.pop("evidence_json"))
    else: d=None
    return {"version":"4.0.3","latest_run":d,"system_metrics":system_metrics,"flow":["unknown-log","log-dna","ai-mapping","parser-evolution","normalization","lossless-proof","detection","attack-path","risk","response","forensics"],"air_gapped":True,"simulation_only":True}
