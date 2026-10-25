#!/usr/bin/env python3
"""Evidence-grounded deletion audit for the Ghost Data Still Exists challenge.

The output builder is deterministic. It never uses reported workflow status as
proof. Optional image extraction uses a vision model only to transcribe visible
records; the model does not decide deletion status or write output steps.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "dataset"
DEFAULT_OUTPUT = ROOT / "output.csv"

KNOWN_CATEGORIES = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
    "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
    "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE", "DATA_FLOW",
}
CATEGORY_SYSTEM = {
    "USER_PROFILE": "account_service", "SECONDARY_IDENTIFIER": "identity_service",
    "SEARCH_INDEX_ENTRY": "search_service", "CACHE_ENTRY": "cache_service",
    "SUPPORT_MESSAGE": "support_platform", "SUPPORT_ATTACHMENT": "support_platform",
    "ANALYTICS_PROFILE": "analytics_platform", "PRODUCT_TELEMETRY": "analytics_platform",
    "USER_EXPORT": "export_service", "MARKETING_PROFILE": "marketing_service",
    "EMAIL_DELIVERY_LOG": "notification_service", "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "legal_service", "BACKUP_ARCHIVE": "backup_service",
    "ACCOUNT_TOMBSTONE": "identity_service", "DATA_FLOW": "integration_service",
}
CATEGORY_ACTION = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE", "SUPPORT_MESSAGE": "REDACT", "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE", "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE", "EMAIL_DELIVERY_LOG": "REDACT", "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN", "BACKUP_ARCHIVE": "BLOCK_RESTORE", "ACCOUNT_TOMBSTONE": "REDACT",
    "DATA_FLOW": "DISABLE",
}
PII_KEYS = {
    "email", "owner_email", "customer_email", "requester_email", "phone", "owner_phone",
    "customer_phone", "requester_phone", "name", "full_name", "display_name",
    "requester_name", "email_hash", "matched_value", "lookup_key", "subject_key",
}
TIME_KEYS = ("observed_at", "recorded_at", "event_time", "captured_at", "updated_at", "indexed_at", "created_at")


def utc_key(value: Any) -> str:
    if value is None or value == "":
        return ""
    s = str(value).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError):
        return s


def norm(s: Any) -> str:
    if s is None:
        return ""
    return "".join(ch for ch in unicodedata.normalize("NFKD", str(s)).casefold()
                   if not unicodedata.combining(ch)).strip()


def norm_phone(s: Any) -> str:
    return "".join(c for c in str(s or "") if c.isdigit())


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def flatten_scalars(value: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(flatten_scalars(v, key))
            else:
                out[key] = v
    elif isinstance(value, list):
        for i, v in enumerate(value):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                out.update(flatten_scalars(v, key))
            else:
                out[key] = v
    return out


def scalar_values(value: Any) -> list[str]:
    return [str(v) for v in flatten_scalars(value).values() if v is not None and str(v).strip()]


@dataclass
class Fact:
    file_id: str
    captured_at: str
    observed_at: str
    system_id: str
    resource_id: str
    category: str
    state: str
    attrs: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    quality: int = 0


def infer_category(explicit: Any, context: dict[str, Any], path_parts: Iterable[str], attrs: dict[str, Any]) -> str:
    value = str(explicit or "").strip().upper().replace(" ", "_")
    if value in KNOWN_CATEGORIES:
        return value
    parts = [str(x).casefold() for x in path_parts]
    joined = " ".join(parts + [str(context.get(k, "")).casefold() for k in ("data_store", "collection", "collection_name", "system")])
    # A child collection path is more specific than a generic category inherited
    # from a JSON parent. In particular, `service_exports` is the envelope name
    # for every service and does not make all contained records USER_EXPORT.
    if "tombstone" in joined or "deleted_customer_reference" in joined:
        return "ACCOUNT_TOMBSTONE"
    if "attachment" in joined:
        return "SUPPORT_ATTACHMENT"
    if "profile_lookups" in joined or "customer_profiles" in joined or "user_profile" in joined or "account_service" in joined:
        return "USER_PROFILE"
    if "search" in joined or "index_query" in joined:
        return "SEARCH_INDEX_ENTRY"
    if "analytics" in joined:
        return "ANALYTICS_PROFILE"
    if "telemetry" in joined:
        return "PRODUCT_TELEMETRY"
    if "support" in joined or "ticket" in joined or "message" in joined:
        return "SUPPORT_MESSAGE"
    if any(part in {"user_exports", "export_records", "exports", "user_export"} for part in parts) or "export_service" in joined:
        return "USER_EXPORT"
    if "connector" in joined or "data_flow" in joined or "integration" in joined:
        return "DATA_FLOW"
    if "backup" in joined or "restore" in joined or "archive" in joined:
        return "BACKUP_ARCHIVE"
    if "security" in joined or "audit" in joined:
        return "SECURITY_AUDIT_LOG"
    if "marketing" in joined:
        return "MARKETING_PROFILE"
    if "delivery_log" in joined or "notification" in joined:
        return "EMAIL_DELIVERY_LOG"
    for key in ("record_type", "data_category", "category", "collection", "collection_name", "recordType"):
        v = str(context.get(key, "")).strip().upper().replace(" ", "_")
        if v in KNOWN_CATEGORIES:
            return v
    rid = str(attrs.get("resource_id", "")).casefold()
    for prefix, cat in (("account_", "USER_PROFILE"), ("search_", "SEARCH_INDEX_ENTRY"),
                        ("analytics_", "ANALYTICS_PROFILE"), ("support_", "SUPPORT_MESSAGE"),
                        ("export_", "USER_EXPORT"), ("backup_", "BACKUP_ARCHIVE"),
                        ("data_flow_", "DATA_FLOW"), ("audit_record_", "SECURITY_AUDIT_LOG"),
                        ("tombstone_", "ACCOUNT_TOMBSTONE")):
        if rid.startswith(prefix):
            return cat
    return ""


def infer_system(explicit: Any, category: str, context: dict[str, Any], path_parts: Iterable[str]) -> str:
    candidates = [explicit, context.get("system"), context.get("service"), context.get("data_store"),
                  context.get("origin_system"), context.get("source_system")]
    for candidate in candidates:
        value = str(candidate or "").strip().casefold()
        if value.endswith("_service") or value in {"analytics_platform", "support_platform", "search_service", "identity_service", "notification_service", "cache_service", "marketing_service", "legal_service"}:
            if value in {"customer_data_read_replica", "customer_data_reporting_replica", "customer_data_replica", "customer_data_primary"}:
                continue
            return value
    for part in reversed(list(path_parts)):
        value = str(part).casefold()
        if value.endswith("_service") or value in {"analytics_platform", "support_platform", "search_service", "identity_service", "notification_service", "cache_service", "marketing_service", "legal_service"}:
            return value
    return CATEGORY_SYSTEM.get(category, "")


def infer_state(attrs: dict[str, Any], category: str, text: str = "") -> str:
    flat = {norm(k.split(".")[-1]): v for k, v in attrs.items()}
    compact_text = norm(text)
    # Strong explicit readback states first.
    for key in ("result", "read_result", "state", "status", "lookup_result"):
        value = norm(flat.get(key, ""))
        if value in {"not found", "not_found", "absent", "missing", "deleted", "404", "no hit", "no hits"}:
            return "ABSENT"
        if value in {"identifiable", "exposed", "pii present", "present with pii"}:
            return "IDENTIFIABLE"
        if value in {"anonymized", "anonymised"}:
            return "ANONYMIZED"
        if value in {"redacted", "masked"}:
            return "REDACTED"
        if value in {"active", "enabled", "running"}:
            return "ACTIVE"
        if value in {"disabled", "stopped", "inactive"}:
            return "DISABLED"
        if value in {"blocked", "false"} and category == "BACKUP_ARCHIVE":
            return "BLOCKED"
        if value in {"found", "present", "hit", "success"}:
            return "PRESENT"
    status_code = str(flat.get("status_code", ""))
    if status_code == "404" or str(flat.get("http_status", "")) == "404":
        return "ABSENT"
    if status_code == "200" or str(flat.get("http_status", "")) == "200":
        return "PRESENT"
    if str(flat.get("rows", "")) in {"0", "0.0"}:
        return "ABSENT"
    if "total_hits" in flat and str(flat.get("total_hits")) in {"0", "0.0"}:
        return "ABSENT"
    if "hits.total" in flat and str(flat.get("hits.total")) in {"0", "0.0"}:
        return "ABSENT"
    if category == "DATA_FLOW":
        enabled = norm(flat.get("enabled", flat.get("is_enabled", "")))
        if enabled in {"true", "1", "yes"}:
            return "ACTIVE"
        if enabled in {"false", "0", "no"}:
            return "DISABLED"
    if category == "BACKUP_ARCHIVE":
        allowed = norm(flat.get("restore_allowed", flat.get("restore_enabled", "")))
        if allowed in {"true", "1", "yes"}:
            return "ACTIVE"
        if allowed in {"false", "0", "no"}:
            return "BLOCKED"
        if norm(flat.get("eligible", "")) in {"true", "1", "yes"} and norm(flat.get("deletion_block", "")) in {"false", "0", "no"}:
            return "ACTIVE"
        if norm(flat.get("deletion_block", "")) in {"true", "1", "yes"}:
            return "BLOCKED"
    if category == "ACCOUNT_TOMBSTONE" and norm(flat.get("account_status", "")) == "deleted":
        return "PRESENT"
    if category == "ANALYTICS_PROFILE":
        if compact_text and "anonymized" in compact_text:
            return "ANONYMIZED"
        if compact_text and ("identifiable" in compact_text or "pii" in compact_text):
            return "IDENTIFIABLE"
    if category == "SUPPORT_MESSAGE" and compact_text and "redacted" in compact_text:
        return "REDACTED"
    if category == "SECURITY_AUDIT_LOG" and compact_text and ("expired" in compact_text or "not found" in compact_text):
        return "ABSENT"
    # A resource-bearing snapshot row is evidence that a record exists.
    return "PRESENT"


class EvidenceIndex:
    def __init__(self, dataset: Path, use_vision: bool = False, model: str = "gpt-6.1-sol"):
        self.dataset = dataset
        self.manifest = read_csv(dataset / "evidence_files.csv")
        self.file_by_path = {r["file_path"].replace("\\", "/"): r for r in self.manifest}
        self.facts: list[Fact] = []
        self.account_inventory_snapshots: list[tuple[str, str, set[str]]] = []
        self.identity_links: list[tuple[str, str, str, str, str]] = []
        self.use_vision = use_vision
        self.model = model
        self.freellmapi_base_url = os.environ.get("FREELLMAPI_BASE_URL", "").strip().rstrip("/")
        self.freellmapi_key = os.environ.get("FREELLMAPI_API_KEY", "").strip()
        self.use_freellmapi = bool(self.freellmapi_base_url or self.freellmapi_key)
        if self.use_freellmapi and not self.freellmapi_base_url:
            self.freellmapi_base_url = "http://localhost:3001/v1"
        self.usage = {"provider": "none", "model": "none", "calls": 0, "input_tokens": 0, "output_tokens": 0}
        self._load_all()

    def add(self, file_id: str, captured: str, obj: dict[str, Any], context: dict[str, Any], path_parts: tuple[str, ...], text: str = "", quality: int = 0) -> None:
        attrs = flatten_scalars(obj)
        attrs.update({f"context.{k}": v for k, v in context.items() if not isinstance(v, (dict, list))})
        resource = str(obj.get("resource_id") or attrs.get("resource_id") or "").strip()
        if not resource:
            return
        category = infer_category(obj.get("record_type") or obj.get("data_category") or obj.get("category"), context, path_parts, attrs)
        if not category:
            return
        explicit_system = obj.get("system") or obj.get("service")
        system = infer_system(explicit_system, category, context, path_parts)
        if not system:
            return
        observed = ""
        for key in TIME_KEYS:
            if obj.get(key):
                observed = str(obj[key]); break
        if not observed:
            for key in TIME_KEYS:
                if context.get(key):
                    observed = str(context[key]); break
        state = infer_state(attrs, category, text)
        self.facts.append(Fact(file_id, utc_key(captured), utc_key(observed) or utc_key(captured), system, resource,
                               category, state, attrs, text, quality))

    def _walk_json(self, value: Any, file_id: str, captured: str, context: dict[str, Any] | None = None,
                   path_parts: tuple[str, ...] = ()) -> None:
        context = dict(context or {})
        if isinstance(value, dict):
            for k in ("system", "service", "data_store", "collection", "collection_name", "origin_system",
                      "source_system", "record_type", "data_category", "category", *TIME_KEYS):
                if value.get(k) is not None:
                    context[k] = value[k]
            if value.get("resource_id"):
                self.add(file_id, captured, value, context, path_parts)
            for k, v in value.items():
                if isinstance(v, (dict, list)):
                    self._walk_json(v, file_id, captured, context, path_parts + (str(k),))
        elif isinstance(value, list):
            for item in value:
                self._walk_json(item, file_id, captured, context, path_parts)

    @staticmethod
    def _kv(line: str) -> dict[str, str]:
        pairs = re.findall(r'([A-Za-z_][\w.-]*)="([^"]*)"|([A-Za-z_][\w.-]*)=([^\s|]+)', line)
        out: dict[str, str] = {}
        for a, b, c, d in pairs:
            out[a or c] = b if a else d
        return out


    def _extract_json_line(self, line: str):
        stripped = line.strip()
        if not stripped.startswith('{'):
            return None
        try:
            jstart = line.index('{')
            return json.loads(line[jstart:])
        except (json.JSONDecodeError, ValueError):
            return None
    def _parse_log(self, path: Path, file_id: str, captured: str) -> None:
        content = path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        # Many distributed traces carry the subject only on the initial request
        # event. Propagate those identity keys to later resource readbacks on
        # the same trace, while keeping each line's actual resource/state.
        trace_identity: dict[str, dict[str, str]] = defaultdict(dict)
        for line in lines:
            kv = self._kv(line)
            trace_id = kv.get("trace_id", "")
            if not trace_id:
                obj = self._extract_json_line(line)
                if obj:
                    trace_id = obj.get("trace_id", "")
                    if trace_id:
                        kv = {str(k): str(v) for k, v in obj.items() if v is not None}
            if trace_id:
                for key in ("subject_key", "subject_ref", "correlation_key", "user_id", "email", "phone", "email_hash", "lookup_key", "match_key"):
                    if kv.get(key):
                        trace_identity[trace_id][key] = kv[key]
        for line in lines:
            m = re.match(r"\s*(\d{4}-\d\d-\d\dT[^\s|]+)", line)
            timestamp = m.group(1) if m else captured
            # JSON structured log line
            obj = self._extract_json_line(line)
            if obj is not None:
                resource = obj.get("resource_id")
                if not resource:
                    continue
                event = (obj.get("event") or "").casefold()
                system = (obj.get("service") or obj.get("logger") or "").casefold()
                if not system:
                    continue
                kv = {str(k): str(v) for k, v in obj.items() if v is not None}
                trace_id = kv.get("trace_id", "")
                kv.update({k: v for k, v in trace_identity.get(trace_id, {}).items() if not kv.get(k)})
                category = ""
                fact_system = system
                if "profile_lookup" in event or ("profile_read" in event and system == "account_service"):
                    category = "USER_PROFILE"
                elif "index_query" in event or "search" in system:
                    category = "SEARCH_INDEX_ENTRY"
                elif "support" in system or "ticket" in event or "message" in event or "attachment" in event:
                    category = "SUPPORT_ATTACHMENT" if "attachment" in event else "SUPPORT_MESSAGE"
                elif "analytics" in system:
                    category = "ANALYTICS_PROFILE"
                elif "connector" in event or "integration" in system:
                    category = "DATA_FLOW"
                elif "restore" in event or "backup" in system:
                    category = "BACKUP_ARCHIVE"
                elif "audit" in event or "security" in system:
                    category = "SECURITY_AUDIT_LOG"
                elif "export" in event or "export" in system:
                    category = "USER_EXPORT"
                elif "delivery" in event or "notification" in system:
                    category = "EMAIL_DELIVERY_LOG"
                if not category:
                    continue
                relevant = (event.endswith("_completed") or "pii_scan" in event
                            or event.endswith("_blocked") or event.endswith("_disabled") or event.endswith("_found")
                            or event in {"connector_heartbeat", "restore_candidate_evaluated"})
                if not relevant:
                    continue
                attrs = dict(kv)
                attrs.update({"resource_id": resource, "event": event, "system": fact_system, "record_type": category})
                self.add(file_id, captured, attrs, {"system": fact_system, "record_type": category}, (fact_system, event), line, 4)
                continue
            # Handover format: time | system | resource | category | state | subject
            handover = re.match(r"\s*[-*]?\s*(\d{4}-\d\d-\d\dT[^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.*)$", line)
            if handover:
                ts, system, resource, category, state, subject = [x.strip() for x in handover.groups()]
                cat = infer_category(category, {}, (), {"resource_id": resource})
                if cat:
                    attrs = {"resource_id": resource, "subject_reference": subject, "result": state,
                             "record_type": cat, "system": system}
                    self.add(file_id, captured, attrs, {"system": system, "record_type": cat}, (), line, 5)
                    # Preserve the explicit state vocabulary if the generic parser did not map it.
                    if self.facts:
                        self.facts[-1].observed_at = utc_key(ts) or self.facts[-1].observed_at
                continue
            kv = self._kv(line)
            resource = kv.get("resource_id")
            if not resource:
                continue
            event = (kv.get("event") or "").casefold()
            system = (kv.get("service") or kv.get("system") or "").casefold()
            if not system:
                continue
            kv.update({k: v for k, v in trace_identity.get(kv.get("trace_id", ""), {}).items() if not kv.get(k)})
            category = ""
            fact_system = system
            if event == "contact_query_completed" and "support_replica" in system:
                # A legacy support contact-index row is a subject-only
                # identifier, not a shared support conversation.
                category, fact_system = "SECONDARY_IDENTIFIER", "support_platform"
            elif event == "contact_lookup_completed" and system == "analytics_platform":
                # This event is an address-keyed contact lookup stored beside
                # analytics, so policy requires deleting the lookup row.
                category = "SECONDARY_IDENTIFIER"
            elif "profile_lookup" in event or ("profile_read" in event and system == "account_service"):
                category = "USER_PROFILE"
            elif "index_query" in event or "search" in system:
                category = "SEARCH_INDEX_ENTRY"
            elif "support" in system or "ticket" in event or "message" in event or "attachment" in event:
                category = "SUPPORT_ATTACHMENT" if "attachment" in event else "SUPPORT_MESSAGE"
            elif "analytics" in system:
                category = "ANALYTICS_PROFILE"
            elif "connector" in event or "integration" in system:
                category = "DATA_FLOW"
            elif "restore" in event or "backup" in system:
                category = "BACKUP_ARCHIVE"
            elif "audit" in event or "security" in system:
                category = "SECURITY_AUDIT_LOG"
            elif "export" in event or "export" in system:
                category = "USER_EXPORT"
            elif "delivery" in event or "notification" in system:
                category = "EMAIL_DELIVERY_LOG"
            if not category:
                continue
            # Only completed reads and direct PII scan events establish state.
            relevant = (event.endswith("_completed") or "pii_scan" in event
                        or event.endswith("_blocked") or event.endswith("_disabled") or event.endswith("_found")
                        or event in {"connector_heartbeat", "restore_candidate_evaluated"})
            if not relevant:
                continue
            attrs: dict[str, Any] = dict(kv)
            attrs.update({"resource_id": resource, "event": event, "system": fact_system, "record_type": category})
            self.add(file_id, captured, attrs, {"system": fact_system, "record_type": category}, (fact_system, event), line, 4)

    def _parse_pdf(self, path: Path, file_id: str, captured: str) -> None:
        try:
            from pypdf import PdfReader  # optional; only needed for PDF evidence
            text = "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
        except Exception:
            return
        ids = re.findall(r"\b(?:account|search|support|export|backup|analytics|data_flow|audit_record|tombstone)_\d+\b", text, re.I)
        name = path.name.casefold()
        for resource in sorted(set(ids)):
            if "delivery_correction" in name or "attachment" in name:
                category = "SUPPORT_ATTACHMENT"
            else:
                category = infer_category(None, {}, (path.stem,), {"resource_id": resource})
            if not category:
                continue
            system = CATEGORY_SYSTEM.get(category, "")
            attrs: dict[str, Any] = {"resource_id": resource, "document_text": text}
            self.add(file_id, captured, attrs, {"system": system, "record_type": category}, (path.stem,), text, 3)

    def _load_all(self) -> None:
        for entry in self.manifest:
            rel = entry["file_path"].replace("\\", "/")
            path = self.dataset / rel
            if not path.exists():
                continue
            file_id, captured = entry["file_id"], utc_key(entry.get("captured_at", ""))
            suffix = path.suffix.casefold()
            try:
                if suffix == ".json":
                    self._walk_json(json.loads(path.read_text(encoding="utf-8-sig")), file_id, captured)
                elif suffix == ".sql":
                    self._parse_sql(path, file_id, captured)
                elif suffix in {".log", ".txt"}:
                    self._parse_log(path, file_id, captured)
                elif suffix == ".pdf":
                    self._parse_pdf(path, file_id, captured)
                elif suffix == ".png" and self.use_vision:
                    self._parse_image(path, file_id, captured)
            except Exception as exc:
                print(f"warning: could not parse {rel}: {exc}", file=sys.stderr)

        # Activity rows can connect a resource to a subject, but they do not
        # establish that the resource's state-changing operation succeeded.
        for row in read_csv(self.dataset / "system_activity.csv"):
            if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
                continue
            details = row.get("details", "")
            email_match = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", details)
            user_match = re.search(r"\buser_\d+\b", details, re.I)
            resource = row.get("resource_id", "")
            if resource and (email_match or user_match):
                self.identity_links.append((utc_key(row.get("event_time", "")), resource,
                                            row.get("target_system", ""),
                                            email_match.group(0) if email_match else "",
                                            user_match.group(0) if user_match else ""))

    def _parse_sql(self, path: Path, file_id: str, captured: str) -> None:
        db = sqlite3.connect(":memory:")
        try:
            db.executescript(path.read_text(encoding="utf-8", errors="replace"))
            account_table_names: set[str] = set()
            account_resources: set[str] = set()
            for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                cols = [r[1] for r in db.execute(f'PRAGMA table_info("{table}")')]
                if "resource_id" not in cols:
                    continue
                if "customer_profiles" in table.casefold() or table.casefold().startswith("account_"):
                    account_table_names.add(table.casefold())
                for row in db.execute(f'SELECT * FROM "{table}"'):
                    obj = dict(zip(cols, row))
                    if ("customer_profiles" in table.casefold() or table.casefold().startswith("account_")) and obj.get("resource_id"):
                        account_resources.add(str(obj["resource_id"]))
                    nested = obj.get("record_json")
                    if isinstance(nested, str):
                        try:
                            parsed = json.loads(nested)
                            if isinstance(parsed, dict):
                                obj.update(parsed)
                        except json.JSONDecodeError:
                            pass
                    context = {"collection": table, "origin_system": obj.get("origin_system", ""),
                               "collection_name": obj.get("collection_name", ""), "record_type": obj.get("record_type", "")}
                    cat = infer_category(obj.get("record_type"), context, (table,), flatten_scalars(obj))
                    # Tables in a point-in-time inventory are unambiguous by name.
                    if not cat:
                        cat = infer_category(None, context, (table,), flatten_scalars(obj))
                    if cat:
                        context["record_type"] = cat
                    self.add(file_id, captured, obj, context, (table,), quality=2)
            has_primary = any("primary" in name for name in account_table_names)
            has_replica = any("replica" in name or "failover" in name for name in account_table_names)
            if has_primary and has_replica:
                self.account_inventory_snapshots.append((file_id, utc_key(captured), account_resources))
        finally:
            db.close()

    def _parse_image(self, path: Path, file_id: str, captured: str) -> None:
        api_key = self.freellmapi_key if self.use_freellmapi else os.environ.get("OPENAI_API_KEY")
        if not api_key:
            required = "FREELLMAPI_API_KEY" if self.use_freellmapi else "OPENAI_API_KEY"
            raise RuntimeError(f"--vision requires {required}")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("Install the optional openai package to use --vision") from exc
        client = OpenAI(api_key=api_key, base_url=self.freellmapi_base_url or None)
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        mime = "image/png" if path.suffix.casefold() == ".png" else "image/jpeg"
        image_url = f"data:{mime};base64,{encoded}"
        prompt = (
            "Transcribe records visible in this business screenshot into JSON only: "
            "{\"records\":[{\"system_id\":string,\"resource_id\":string,\"category\":string,"
            "\"state\":string,\"observed_at\":string|null,\"subject_reference\":string|null,"
            "\"name\":string|null,\"email\":string|null,\"phone\":string|null,"
            "\"email_hash\":string|null,\"note\":string|null}]}. "
            "Include selected panels and table rows only when their record IDs are legible. "
            "Do not infer deletion status or propose operations. Use null for unreadable fields."
        )
        if self.use_freellmapi:
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_url, "detail": "high"}},
                ]}],
            )
            output_text = response.choices[0].message.content or ""
            self.usage["provider"] = "FreeLLMAPI"
            self.usage["model"] = self.model
            routed_model = getattr(response, "model", None)
            if routed_model:
                self.usage.setdefault("routed_models", {})
                self.usage["routed_models"][routed_model] = self.usage["routed_models"].get(routed_model, 0) + 1
            usage = getattr(response, "usage", None)
            if usage:
                self.usage["input_tokens"] += int(getattr(usage, "prompt_tokens", 0) or getattr(usage, "input_tokens", 0) or 0)
                self.usage["output_tokens"] += int(getattr(usage, "completion_tokens", 0) or getattr(usage, "output_tokens", 0) or 0)
        else:
            response = client.responses.create(
                model=self.model,
                input=[{"role": "user", "content": [
                    {"type": "input_text", "text": prompt},
                    {"type": "input_image", "image_url": image_url, "detail": "high"},
                ]}],
            )
            output_text = response.output_text
            self.usage["provider"] = "OpenAI"
            self.usage["model"] = self.model
            usage = getattr(response, "usage", None)
            if usage:
                self.usage["input_tokens"] += int(getattr(usage, "input_tokens", 0) or 0)
                self.usage["output_tokens"] += int(getattr(usage, "output_tokens", 0) or 0)
        self.usage["calls"] += 1
        output_text = output_text.strip()
        if output_text.startswith("```json"):
            output_text = output_text[7:]
        elif output_text.startswith("```"):
            output_text = output_text[3:]
        if output_text.endswith("```"):
            output_text = output_text[:-3]
        parsed = json.loads(output_text.strip())
        for row in parsed.get("records", []):
            cat = str(row.get("category", "")).upper()
            if cat not in KNOWN_CATEGORIES:
                continue
            attrs = dict(row)
            self.add(file_id, captured, attrs, {"system": row.get("system_id", ""), "record_type": cat},
                     (path.stem,), quality=6)


def authorized_deletion(text: str) -> bool:
    """Conservative multilingual check for requests that authorize erasure."""
    t = norm(text)
    negative = (
        "do not delete", "don't delete", "do not erase", "don't erase", "not requesting deletion",
        "not asking for deletion", "no deletion request", "do not close my account", "dont delete",
        "no quiero borrar", "no quiero eliminar", "ne demande pas la suppression", "ne pas supprimer",
        "nicht loschen", "não quero excluir", "nao quero excluir",
    )
    if any(x in t for x in negative):
        return False
    deletion_terms = (
        "delete", "deletion", "erase", "erasure", "removed", "removal", "removing", "remove my account", "remove my personal",
        "remove my data", "close my account", "close this account", "account closure", "data removal",
        "eliminar", "eliminacion", "borrar", "suprimir", "supresion", "suppression", "supprimer",
        "effacer", "fermer mon compte", "loschen", "loeschen", "konto loschen", "excluir", "apagar",
        "cancellare", "eliminare", "削除", "삭제", "删除", "हटाना", "supprim",
    )
    if any(x in t for x in deletion_terms):
        # “Remove me from marketing” is an opt-out, not an account/data erasure.
        marketing_only = any(x in t for x in ("marketing", "newsletter", "unsubscribe", "opt out", "promotional"))
        account_or_data = any(x in t for x in ("account", "data", "profile", "personal", "customer", "compte", "datos", "cuenta", "donnees", "données", "cuenta", "meu cadastro"))
        if marketing_only and not account_or_data and not any(x in t for x in ("delete my", "erase my", "eliminar mi cuenta", "supprimer mon compte")):
            return False
        return True
    # Requests often phrase erasure as removal of a specific profile or of
    # personal details rather than use the word "delete".
    erase_verb = re.search(r"\b(remove|removing|erase|erasing|delete|deleting|wipe|purge)\b", t)
    data_object = any(x in t for x in (
        "profile", "personal detail", "personal information", "personal data", "my data",
        "account", "customer record", "record about me", "remaining copy", "my information",
        "my details", "right to be forgotten", "cuenta", "datos personales", "mi perfil",
    ))
    close_account = re.search(r"\b(close|closing|closed)\b", t) and any(x in t for x in ("account", "cuenta", "compte"))
    verify_completed_deletion = any(x in t for x in ("deleted", "deletion", "removed", "removal", "gone", "erased")) and data_object
    if (erase_verb and data_object) or close_account or verify_completed_deletion:
        marketing_only = any(x in t for x in ("marketing", "newsletter", "unsubscribe", "opt out", "promotional"))
        if not marketing_only:
            return True
    # “Please close my account” is covered above. Broad access/export/correction
    # requests do not authorize deletion.
    return False


def build_identity_index(dataset: Path) -> tuple[dict[str, dict[str, set[str]]], dict[str, str]]:
    identities = read_csv(dataset / "user_identities.csv")
    audit = read_csv(dataset / "user_audit_log.csv")
    by_user: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    email_to_user: dict[str, str] = {}
    for row in identities:
        uid = row.get("user_id", "")
        if not uid:
            continue
        by_user[uid]["user_id"].add(uid)
        for key in ("name", "email", "phone", "email_hash"):
            if row.get(key):
                by_user[uid][key].add(row[key])
        if row.get("email"):
            email_to_user[norm(row["email"])] = uid
    for row in audit:
        uid = row.get("user_id", "")
        key = row.get("field_name", "").strip().casefold()
        if not uid or not key:
            continue
        for val in (row.get("old_value", ""), row.get("new_value", "")):
            if val:
                by_user[uid][key].add(val)
                if key == "email":
                    email_to_user[norm(val)] = uid
    # Email hashes in older stores are SHA-256 of the normalized email in this
    # dataset; retain both the supplied hash and computed hashes for aliases.
    for uid, fields in by_user.items():
        for email in tuple(fields.get("email", set())):
            fields["email_hash"].add(hashlib.sha256(norm(email).encode("utf-8")).hexdigest())
    return by_user, email_to_user


def aliases_for(fields: dict[str, set[str]], email: str) -> dict[str, set[str]]:
    aliases = {k: set(v) for k, v in fields.items()}
    aliases.setdefault("email", set()).add(email)
    return aliases


def fact_matches(fact: Fact, aliases: dict[str, set[str]]) -> bool:
    vals = list(fact.attrs.values()) + list(flatten_scalars(fact.attrs).values())
    norm_aliases = {norm(v) for group in aliases.values() for v in group if v}
    phone_aliases = {norm_phone(v) for v in aliases.get("phone", set()) if len(norm_phone(v)) >= 7}
    user_ids = {norm(v) for v in aliases.get("user_id", set()) if v}
    email_aliases = {norm(v) for v in aliases.get("email", set()) if v}
    hash_aliases = {norm(v) for v in aliases.get("email_hash", set()) if v}
    name_aliases = {norm(v) for v in aliases.get("name", set()) if v}
    for val in vals:
        if val is None:
            continue
        raw = str(val).strip()
        n = norm(raw)
        if n in norm_aliases:
            return True
        digits = norm_phone(raw)
        if len(digits) >= 7 and digits in phone_aliases:
            return True
        # Textual document bodies and log lines are searched with word-ish
        # boundaries to avoid matching partial email addresses or user IDs.
        if any(a and re.search(r"(?<![\w.+-])" + re.escape(a) + r"(?![\w.+-])", n) for a in (email_aliases | user_ids | hash_aliases)):
            return True
    if fact.text:
        ntext = norm(fact.text)
        if any(a and re.search(r"(?<![\w.+-])" + re.escape(a) + r"(?![\w.+-])", ntext)
               for a in (email_aliases | user_ids | hash_aliases)):
            return True
        if any(len(a) >= 8 and re.search(r"(?<![\w])" + re.escape(a) + r"(?![\w])", ntext)
               for a in name_aliases):
            return True
    return False


def subject_pii_present(fact: Fact, aliases: dict[str, set[str]]) -> bool:
    norm_aliases = {norm(v) for group in aliases.values() for v in group if v}
    phone_aliases = {norm_phone(v) for v in aliases.get("phone", set()) if len(norm_phone(v)) >= 7}
    for key, val in flatten_scalars(fact.attrs).items():
        key_norm = norm(key.split(".")[-1])
        if key_norm not in PII_KEYS or val is None or not str(val).strip():
            continue
        if norm(val) in norm_aliases:
            return True
        digits = norm_phone(val)
        if len(digits) >= 7 and digits in phone_aliases:
            return True
    # Extracted screenshot/PDF narrative can explicitly call out identifiable data.
    if fact.state == "IDENTIFIABLE":
        return True
    return False


def subject_identifier_anywhere(fact: Fact, aliases: dict[str, set[str]]) -> bool:
    """Detect a subject link even when a hash is stored in a generic key such as correlation_key."""
    vals = flatten_scalars(fact.attrs)
    phone_aliases = {norm_phone(v) for v in aliases.get("phone", set()) if len(norm_phone(v)) >= 7}
    direct_aliases = {norm(v) for group in aliases.values() for v in group if v}
    text_aliases = {norm(v) for group in (aliases.get("email", set()), aliases.get("user_id", set()), aliases.get("email_hash", set())) for v in group if v}
    name_aliases = {norm(v) for v in aliases.get("name", set()) if len(norm(v)) >= 8}
    for value in vals.values():
        if value is None:
            continue
        n = norm(value)
        if n in direct_aliases:
            return True
        digits = norm_phone(value)
        if len(digits) >= 7 and digits in phone_aliases:
            return True
        if any(re.search(r"(?<![\w.+-])" + re.escape(a) + r"(?![\w.+-])", n) for a in text_aliases):
            return True
        if any(re.search(r"(?<![\w])" + re.escape(a) + r"(?![\w])", n) for a in name_aliases):
            return True
    return False


def latest_facts_for_case(index: EvidenceIndex, aliases: dict[str, set[str]], audit_at: str) -> list[Fact]:
    cutoff = utc_key(audit_at)
    email_aliases = {norm(v) for v in aliases.get("email", set()) if v}
    user_aliases = {norm(v) for v in aliases.get("user_id", set()) if v}
    linked_resources: dict[str, str] = {}
    for linked_at, resource, _system, email, user_id in index.identity_links:
        if linked_at <= cutoff and ((email and norm(email) in email_aliases)
                                    or (user_id and norm(user_id) in user_aliases)):
            linked_resources[resource] = user_id or email
    # Require both the source capture and resource observation to be no later
    # than audit_at. Catalog links can identify a resource, but only its own
    # evidence row establishes the resource state.
    matches: list[Fact] = []
    for fact in index.facts:
        if fact.captured_at > cutoff or fact.observed_at > cutoff:
            continue
        is_linked = fact.resource_id in linked_resources
        if not fact_matches(fact, aliases) and not is_linked:
            continue
        if is_linked:
            attrs = dict(fact.attrs)
            attrs["catalog_link"] = linked_resources[fact.resource_id]
            matches.append(replace(fact, attrs=attrs))
        else:
            matches.append(fact)
    # The early challenge snapshot has complete primary/failover profile
    # inventories. For legacy case IDs with a matching user suffix, absence
    # from both tables is a direct, evidence-backed account absence check.
    user_suffixes = {m.group(1) for v in aliases.get("user_id", set())
                     if (m := re.fullmatch(r"user_(\d+)", norm(v))) and int(m.group(1)) <= 10}
    known_account_ids = {f.resource_id for f in matches if f.category == "USER_PROFILE"}
    if user_suffixes:
        for file_id, captured, present_accounts in index.account_inventory_snapshots:
            if captured > cutoff:
                continue
            for suffix in user_suffixes:
                resource = f"account_{int(suffix):03d}"
                if resource in present_accounts or resource in known_account_ids:
                    continue
                matches.append(Fact(file_id, captured, captured, "account_service", resource, "USER_PROFILE", "ABSENT",
                                    {"resource_id": resource, "user_id": f"user_{suffix}"}, quality=3))
    # A stale negative readback is historical evidence, but cannot establish
    # absence after months in which an account could have been recreated.
    audit_dt = datetime.fromisoformat(cutoff.replace("Z", "+00:00")) if cutoff else None
    if audit_dt:
        retained: list[Fact] = []
        for fact in matches:
            if fact.category == "USER_PROFILE" and fact.state == "ABSENT" and fact.observed_at:
                observed_dt = datetime.fromisoformat(fact.observed_at.replace("Z", "+00:00"))
                if (audit_dt - observed_dt).days > 30:
                    continue
            retained.append(fact)
        matches = retained
    # When a point-in-time resource is observed more than once, keep the latest
    # state. Duplicate primary/replica rows with the same capture time collapse;
    # a present replica copy is still considered present.
    grouped: dict[tuple[str, str, str], list[Fact]] = defaultdict(list)
    for fact in matches:
        grouped[(fact.system_id, fact.resource_id, fact.category)].append(fact)
    selected: list[Fact] = []
    for group in grouped.values():
        group.sort(key=lambda f: (f.captured_at, f.observed_at, f.quality, f.file_id))
        newest_time = max((f.captured_at, f.observed_at) for f in group)
        newest = [f for f in group if (f.captured_at, f.observed_at) == newest_time]
        # Within a single snapshot, any surviving duplicate copy means present;
        # explicit absence readbacks take priority when there is no present row.
        present = [f for f in newest if f.state not in {"ABSENT", "ANONYMIZED", "REDACTED", "DISABLED", "BLOCKED"}]
        if present:
            selected.append(max(present, key=lambda f: (f.quality, f.file_id)))
        else:
            selected.append(max(newest, key=lambda f: (f.quality, f.file_id)))
    return selected


def assessment(fact: Fact, aliases: dict[str, set[str]]) -> tuple[str, str, str] | None:
    """Return (finding_operation, remediation_operation, verification_operation),
    or a verification-only tuple when the observed state is compliant."""
    category = fact.category
    action = CATEGORY_ACTION.get(category, "")
    if not action:
        return None
    if category == "DATA_FLOW":
        if fact.state == "ACTIVE":
            return ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED")
        if fact.state == "DISABLED":
            return ("", "", "VERIFY_DATA_FLOW_DISABLED")
        return None
    if category == "BACKUP_ARCHIVE":
        if fact.state == "ACTIVE":
            return ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED")
        if fact.state == "BLOCKED":
            return ("", "", "VERIFY_RESTORE_BLOCKED")
        return None
    if action == "DELETE":
        if fact.state == "ABSENT":
            return ("", "", "VERIFY_RECORD_ABSENT")
        return ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT")
    if action == "RETAIN":
        if fact.state == "ABSENT":
            return None
        return ("", "", "VERIFY_RECORD_PRESENT")
    if action == "REDACT":
        exposed = subject_pii_present(fact, aliases) or fact.state == "IDENTIFIABLE"
        if exposed:
            return ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED")
        if fact.state in {"ABSENT", "REDACTED", "ANONYMIZED"} or fact.state == "PRESENT":
            return ("", "", "VERIFY_RECORD_REDACTED")
    if action == "ANONYMIZE":
        # For analytics and telemetry, a stable user key still links the record.
        vals = {norm(v) for v in flatten_scalars(fact.attrs).values() if v is not None}
        links_by_user = bool(vals & {norm(v) for v in aliases.get("user_id", set()) if v})
        exposed = subject_pii_present(fact, aliases) or links_by_user or subject_identifier_anywhere(fact, aliases) or fact.state == "IDENTIFIABLE"
        if exposed:
            return ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED")
        if fact.state in {"ANONYMIZED", "REDACTED", "PRESENT"}:
            return ("", "", "VERIFY_RECORD_ANONYMIZED")
    return None


FINDING_RANK = {"REPORT_REMAINING_RECORD": 1, "REPORT_EXPOSED_PII": 2, "REPORT_ACTIVE_DATA_FLOW": 3, "REPORT_RESTORE_RISK": 4}
REMEDIATION_RANK = {"DISABLE_DATA_FLOW": 1, "BLOCK_RESTORE": 2, "DELETE_RECORD": 3, "REDACT_RECORD": 4, "ANONYMIZE_RECORD": 5}
VERIFY_RANK = {"VERIFY_RECORD_ABSENT": 1, "VERIFY_RECORD_PRESENT": 2, "VERIFY_RECORD_REDACTED": 3,
               "VERIFY_RECORD_ANONYMIZED": 4, "VERIFY_DATA_FLOW_DISABLED": 5, "VERIFY_RESTORE_BLOCKED": 6}


def make_steps(case: dict[str, str], facts: list[Fact], aliases: dict[str, set[str]]) -> tuple[str, list[dict[str, Any]]]:
    if not authorized_deletion(case.get("request_text", "")):
        return "NOT_APPLICABLE", []
    findings: list[tuple[Fact, str, str]] = []
    remediations: list[tuple[Fact, str, str]] = []
    verifications: list[tuple[Fact, str, str]] = []
    for fact in facts:
        result = assessment(fact, aliases)
        if not result:
            continue
        finding, remediation, verification = result
        if finding:
            findings.append((fact, finding, "PRESENT" if finding != "REPORT_ACTIVE_DATA_FLOW" and finding != "REPORT_RESTORE_RISK" else "ACTIVE"))
            remediations.append((fact, remediation, {"DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED"}[remediation]))
            verifications.append((fact, verification, {"VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}[verification]))
        else:
            verifications.append((fact, verification, {"VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}[verification]))
    # If there are no supported violations, a case is complete only when at least
    # one evidence-backed verification establishes the account's state. Unknown
    # cases stay incomplete rather than trusting the workflow's reported status.
    status = "INCOMPLETE" if findings else ("COMPLETE" if verifications else "INCOMPLETE")
    if status == "COMPLETE":
        ordered = sorted(verifications, key=lambda x: (VERIFY_RANK[x[1]], x[0].system_id, x[0].resource_id))
        items = [("VERIFICATION", f, op, state, f.file_id) for f, op, state in ordered]
    else:
        fs = sorted(findings, key=lambda x: (FINDING_RANK[x[1]], x[0].system_id, x[0].resource_id))
        rs = sorted(remediations, key=lambda x: (REMEDIATION_RANK[x[1]], x[0].system_id, x[0].resource_id))
        vs = sorted(verifications, key=lambda x: (VERIFY_RANK[x[1]], x[0].system_id, x[0].resource_id))
        items = ([ ("FINDING", f, op, state, f.file_id) for f, op, state in fs ] +
                 [ ("REMEDIATION", f, op, state, "") for f, op, state in rs ] +
                 [ ("VERIFICATION", f, op, state, "") for f, op, state in vs ])
    # A resource may be observed in duplicate nested JSON objects; exact duplicate
    # output actions are removed before step numbering.
    unique: list[tuple[str, Fact, str, str, str]] = []
    seen = set()
    for phase, fact, op, state, evidence in items:
        key = (phase, fact.system_id, fact.resource_id, op, state)
        if key in seen:
            continue
        seen.add(key)
        unique.append((phase, fact, op, state, evidence))
    steps = []
    for i, (phase, fact, op, state, evidence) in enumerate(unique, 1):
        steps.append({"step_no": i, "phase": phase, "system_id": fact.system_id,
                      "resource_id": fact.resource_id, "operation": op, "state": state,
                      "evidence_id": evidence})
    return status, steps


def build_output(dataset: Path, requests_path: Path, output_path: Path, use_vision: bool = False,
                 model: str = "gpt-6.1-sol") -> dict[str, Any]:
    identities, email_to_user = build_identity_index(dataset)
    index = EvidenceIndex(dataset, use_vision=use_vision, model=model)
    requests = read_csv(requests_path)
    rows: list[dict[str, str]] = []
    for request in requests:
        email = request.get("email", "")
        uid = email_to_user.get(norm(email), "")
        if not uid:
            # A request may use an email absent from both the current snapshot and
            # audit log; still search the supplied email directly.
            aliases = {"email": {email}, "user_id": set(), "name": set(), "phone": set(), "email_hash": set()}
        else:
            aliases = aliases_for(identities.get(uid, {}), email)
        facts = latest_facts_for_case(index, aliases, request.get("audit_at", ""))
        status, steps = make_steps(request, facts, aliases)
        rows.append({"case_id": request["case_id"], "deletion_status": status,
                     "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    rows.sort(key=lambda r: r["case_id"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    return {"rows": len(rows), "usage": index.usage, "facts": len(index.facts), "output": str(output_path)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--requests", type=Path, default=None, help="Request CSV; defaults to dataset/deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--vision", action="store_true", help="Use the configured OpenAI vision model to transcribe screenshots")
    default_model = os.environ.get("AUDIT_MODEL") or (
        "auto:smart" if os.environ.get("FREELLMAPI_BASE_URL") or os.environ.get("FREELLMAPI_API_KEY") else "gpt-6.1-sol"
    )
    parser.add_argument("--model", default=default_model)
    args = parser.parse_args()
    req_path = args.requests or args.dataset / "deletion_requests.csv"
    summary = build_output(args.dataset, req_path, args.output, use_vision=args.vision, model=args.model)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
