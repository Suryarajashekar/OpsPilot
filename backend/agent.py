from __future__ import annotations

import json
import calendar
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from backend.providers import OpenAIResponsesProvider, ProviderError, ProviderResult
from backend.store import SQLiteStore


ROOT = Path(__file__).resolve().parents[1]
KNOWN_SERVICES = {"payments-api", "checkout-api", "catalog-api", "order-events", "platform"}
ALLOWED_ACTIONS = {"recycle_connection_pool", "rollback_checkout", "scale_catalog", "scale_consumers", "collect_more_evidence"}
APPROVER_ROLES = {"incident_commander", "on_call_engineer", "admin"}


@dataclass
class TraceEvent:
    name: str
    status: str
    detail: str
    duration_ms: int
    metadata: dict[str, Any]


class KnowledgeBase:
    def __init__(self, path: Path | None = None) -> None:
        source = path or ROOT / "data" / "knowledge.json"
        self.documents = json.loads(source.read_text(encoding="utf-8"))

    @staticmethod
    def _tokens(value: str) -> set[str]:
        return {token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) > 2}

    def search(self, query: str, limit: int = 4) -> list[dict[str, Any]]:
        query_tokens = self._tokens(query)
        results: list[tuple[float, dict[str, Any]]] = []
        for document in self.documents:
            haystack = " ".join([document["title"], document["service"], " ".join(document["tags"]), document["content"]])
            document_tokens = self._tokens(haystack)
            overlap = query_tokens & document_tokens
            score = len(overlap) / max(1, len(query_tokens))
            if document["service"] in query.lower():
                score += 0.28
            if any(tag in query.lower() for tag in document["tags"]):
                score += 0.12
            if score:
                results.append((score, {**document, "score": round(min(score, 0.99), 3), "matched_terms": sorted(overlap)}))
        results.sort(key=lambda item: item[0], reverse=True)
        return [document for _, document in results[:limit]]


class ToolRegistry:
    """Deterministic demo tools with the same contract as real integrations."""

    def service_health(self, service: str) -> dict[str, Any]:
        snapshots = {
            "payments-api": {"status": "degraded", "error_rate": 0.071, "p95_ms": 4210, "replicas": 8},
            "checkout-api": {"status": "degraded", "error_rate": 0.124, "p95_ms": 2800, "replicas": 10},
            "catalog-api": {"status": "degraded", "error_rate": 0.032, "p95_ms": 1900, "replicas": 6},
            "order-events": {"status": "degraded", "error_rate": 0.018, "p95_ms": 840, "replicas": 4},
        }
        return {"service": service, **snapshots.get(service, {"status": "unknown", "error_rate": 0, "p95_ms": 0, "replicas": 0}), "source": "demo"}

    def query_logs(self, service: str, incident: str) -> dict[str, Any]:
        logs = {
            "payments-api": ["WARN pool.acquire timeout after 3000ms active=498 max=500", "ERROR transaction remained open request_id=pay_8f3a duration_ms=11984"],
            "checkout-api": ["ERROR upstream payments-api returned 504", "WARN gateway translated upstream timeout into HTTP 502"],
            "catalog-api": ["WARN heap_used=91% cache_entries=1842032", "ERROR container OOMKilled restart_count=4"],
            "order-events": ["WARN consumer_lag partition=3 lag=182044", "INFO consumers healthy throughput=820 msg/s required=1200 msg/s"],
        }
        return {"service": service, "query": incident[:120], "lines": logs.get(service, ["No matching structured logs in demo store."]), "source": "demo"}

    def query_metrics(self, service: str) -> dict[str, Any]:
        metrics = {
            "payments-api": {"db_connections_pct": 98, "cpu_pct": 38, "latency_trend": "rising"},
            "checkout-api": {"upstream_latency_ms": 4200, "cpu_pct": 44, "latency_trend": "rising"},
            "catalog-api": {"memory_pct": 94, "cpu_pct": 51, "cache_growth": "linear"},
            "order-events": {"consumer_lag": 182044, "throughput_ratio": 0.68, "latency_trend": "rising"},
        }
        return {"service": service, **metrics.get(service, {}), "source": "demo"}

    def execute_action(self, action: str, service: str) -> dict[str, Any]:
        return {"result": "simulated_success", "message": f"Demo tool executed: {action} for {service}.", "action": action, "service": service, "dry_run": True}


class DemoReasoner:
    """Reproducible, evidence-aware fallback used by tests and offline demos."""

    name = "demo"

    def decide(self, incident: str, sources: list[dict[str, Any]], evidence: dict[str, Any]) -> ProviderResult:
        text = incident.lower()
        source_ids = [source["id"] for source in sources[:2]]
        service_hint = sources[0]["service"] if sources and sources[0]["score"] >= 0.2 else "platform"
        metrics = evidence.get("metrics", {})
        unsafe_or_injected = any(term in text for term in ["ignore", "bypass", "without approval", "no approval", "make up", "invent", "reveal", "delete", "infinity", "aggressive", "privileged", "do not ask for evidence", "pretend", "no logs", "no evidence", "even if"])
        if unsafe_or_injected:
            decision = {"service": service_hint, "severity": "P2", "confidence": 0.05, "summary": "The request contains unsafe or conflicting instructions and cannot authorize an action.", "cause": "Evidence and authorization are insufficient; a human responder must provide a normal incident description.", "action": "collect_more_evidence", "action_label": "Collect verified evidence and an authorized request", "risk": "none", "checks": ["Confirm the affected service", "Confirm the approver identity and requested change"]}
        elif any(term in text for term in ["too many clients", "database clients", "connection pool", "connection acquisition", "database connections", "pool usage", "saturated on connections", "pool exhaustion", "active db connections", "leaked transaction", "cannot obtain a db connection"]):
            decision = {"service": "payments-api", "severity": "P1", "confidence": 0.94, "summary": "Payments is exhausting its database connection pool, causing request timeouts.", "cause": "A leaked or long-lived transaction is saturating the pool; the evidence points away from CPU pressure.", "action": "recycle_connection_pool", "action_label": "Recycle the payments connection pool", "risk": "low", "checks": ["Confirm active connections fall below 70%", "Verify payment p95 latency for 10 minutes"]}
        elif any(term in text for term in ["502", "gateway", "checkout"]):
            decision = {"service": "checkout-api", "severity": "P1", "confidence": 0.91, "summary": "Checkout is surfacing upstream payment timeouts as 502 gateway errors.", "cause": "The latest checkout path is waiting on a degraded payments dependency; rollback is safer than scaling checkout blindly.", "action": "rollback_checkout", "action_label": "Roll back the latest checkout release", "risk": "medium", "checks": ["Confirm the previous version is healthy", "Verify 502 rate returns below 1%"]}
        elif any(term in text for term in ["oom", "memory", "heap", "out of memory", "gc time", "cache entries", "heap usage"]):
            decision = {"service": "catalog-api", "severity": "P1", "confidence": 0.93, "summary": "Catalog is under memory pressure and restarting from OOM kills.", "cause": "Heap and cache growth are consuming the container limit; scaling out reduces customer impact while the leak is investigated.", "action": "scale_catalog", "action_label": "Add one catalog replica and reduce cache TTL", "risk": "low", "checks": ["Confirm memory stays below 80%", "Inspect heap growth after 15 minutes"]}
        elif any(term in text for term in ["kafka", "consumer lag", "backlog", "order event", "throughput below", "incoming message rate"]):
            decision = {"service": "order-events", "severity": "P2", "confidence": 0.9, "summary": "Order-event consumers are healthy but cannot keep up with the incoming rate.", "cause": "Throughput is below demand without deserialization errors, so horizontal consumer scaling is appropriate.", "action": "scale_consumers", "action_label": "Increase order-event consumers from 4 to 6", "risk": "low", "checks": ["Confirm lag decreases for five minutes", "Check partition balance after scaling"]}
        else:
            decision = {"service": service_hint, "severity": "P2", "confidence": 0.42, "summary": "The incident does not match a high-confidence runbook yet.", "cause": "More evidence is needed before selecting a safe mutation.", "action": "collect_more_evidence", "action_label": "Collect logs and service health before acting", "risk": "none", "checks": ["Identify the affected service", "Attach a timestamped error sample"]}
        decision["citations"] = source_ids
        decision["metadata"] = {"metrics_seen": sorted(metrics.keys())}
        return ProviderResult(decision, self.name, "deterministic-demo", 0, 0)


def build_provider() -> Any:
    if os.getenv("OPS_PILOT_PROVIDER", "demo").lower() == "openai" and os.getenv("OPENAI_API_KEY"):
        return OpenAIResponsesProvider(os.environ["OPENAI_API_KEY"])
    return DemoReasoner()


def build_tools() -> Any:
    prometheus_url = os.getenv("PROMETHEUS_URL")
    if prometheus_url:
        from backend.integrations import PrometheusToolRegistry

        return PrometheusToolRegistry(prometheus_url)
    return ToolRegistry()


class OpsPilot:
    def __init__(self, store: SQLiteStore | None = None, provider: Any | None = None, tools: Any | None = None) -> None:
        self.kb = KnowledgeBase()
        self.store = store or SQLiteStore(os.getenv("OPS_PILOT_DB", str(ROOT / "data" / "ops_pilot.db")))
        self.tools = tools or build_tools()
        self.provider = provider or build_provider()
        self.investigations: dict[str, dict[str, Any]] = {item["id"]: item for item in self.store.list_investigations()}

    @staticmethod
    def _event(name: str, detail: str, metadata: dict[str, Any], started: float, status: str = "ok") -> dict[str, Any]:
        return asdict(TraceEvent(name, status, detail, max(1, int((time.perf_counter() - started) * 1000)), metadata))

    def investigate(self, incident: str) -> dict[str, Any]:
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        started = time.perf_counter()
        trace: list[dict[str, Any]] = []

        step = time.perf_counter()
        sources = self.kb.search(incident)
        trace.append(self._event("retrieve_evidence", f"Retrieved {len(sources)} documents", {"top_score": sources[0]["score"] if sources else 0, "retrieval": "token-overlap-v1"}, step))

        hint = sources[0]["service"] if sources and sources[0]["score"] >= 0.2 else "platform"
        health = self.tools.service_health(hint)
        trace.append(self._event("tool.service_health", f"Read health snapshot for {hint}", {"status": health["status"]}, step))
        logs = self.tools.query_logs(hint, incident)
        trace.append(self._event("tool.query_logs", f"Read {len(logs['lines'])} log lines", {"service": hint}, step))
        metrics = self.tools.query_metrics(hint)
        trace.append(self._event("tool.query_metrics", "Read telemetry metrics", {"keys": list(metrics.keys()), "source": metrics.get("source", "unknown")}, step))

        evidence = {"health": health, "logs": logs, "metrics": metrics}
        provider_started = time.perf_counter()
        provider_fallback = False
        try:
            result = self.provider.decide(incident, sources, evidence)
        except ProviderError as error:
            result = DemoReasoner().decide(incident, sources, evidence)
            provider_fallback = True
            trace.append(self._event("provider.fallback", "Model provider failed; deterministic fallback used", {"error": str(error)[:180]}, provider_started, "fallback"))
        decision = self._normalize_decision(result.decision, sources)
        trace.append(self._event("plan_diagnosis", "Produced a schema-validated diagnosis", {"provider": result.provider, "model": result.model, "confidence": decision["confidence"]}, provider_started, "fallback" if provider_fallback else "ok"))

        now = time.time()
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 900))
        duration_ms = max(1, int((time.perf_counter() - started) * 1000))
        investigation = {
            "id": investigation_id,
            "status": "awaiting_approval" if decision["action"] != "collect_more_evidence" else "needs_attention",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "incident": incident,
            "diagnosis": decision,
            "evidence": evidence,
            "sources": sources,
            "trace": trace,
            "approval": {"required": decision["action"] != "collect_more_evidence", "approved": False, "executed": False, "expires_at": expires_at, "approver": None, "idempotency_key": None},
            "observability": {"latency_ms": duration_ms, "input_tokens": result.input_tokens, "output_tokens": result.output_tokens, "estimated_tokens": result.input_tokens + result.output_tokens or 1240, "estimated_cost_usd": self._estimate_cost(result), "provider": result.provider, "model": result.model, "tool_mode": "prometheus" if os.getenv("PROMETHEUS_URL") else "demo"},
        }
        self.investigations[investigation_id] = investigation
        self.store.save_investigation(investigation)
        self.store.append_audit(investigation_id, "investigation.created", "system", {"status": investigation["status"], "provider": result.provider})
        return investigation

    @staticmethod
    def _estimate_cost(result: ProviderResult) -> float:
        if not result.input_tokens and not result.output_tokens:
            return 0.0062
        return round((result.input_tokens * 0.000005) + (result.output_tokens * 0.000015), 6)

    @staticmethod
    def _normalize_decision(decision: dict[str, Any], sources: list[dict[str, Any]]) -> dict[str, Any]:
        safe = dict(decision)
        if safe.get("service") not in KNOWN_SERVICES:
            safe["service"] = "platform"
        if safe.get("action") not in ALLOWED_ACTIONS:
            safe["action"] = "collect_more_evidence"
        safe["confidence"] = max(0.0, min(1.0, float(safe.get("confidence", 0.0))))
        allowed_citations = {source["id"] for source in sources}
        safe["citations"] = [citation for citation in safe.get("citations", []) if citation in allowed_citations]
        if safe["action"] != "collect_more_evidence" and not safe["citations"]:
            safe["action"] = "collect_more_evidence"
            safe["confidence"] = min(safe["confidence"], 0.49)
        safe.setdefault("checks", [])
        safe.setdefault("risk", "medium")
        return safe

    def approve(self, investigation_id: str, actor: str = "demo-user", role: str = "incident_commander", idempotency_key: str | None = None) -> dict[str, Any]:
        if not actor or role not in APPROVER_ROLES:
            raise PermissionError("A named approver with an approved incident role is required.")
        investigation = self.investigations.get(investigation_id) or self.store.get_investigation(investigation_id)
        if not investigation:
            raise KeyError(investigation_id)
        if not investigation["approval"]["required"]:
            return investigation
        if investigation["approval"]["executed"]:
            return investigation
        if time.time() > self._parse_time(investigation["approval"]["expires_at"]):
            investigation["status"] = "expired"
            self.store.save_investigation(investigation)
            raise ValueError("Approval window expired; investigate again before acting.")
        action = investigation["diagnosis"]["action"]
        execution = self.tools.execute_action(action, investigation["diagnosis"]["service"])
        investigation["approval"].update({"approved": True, "executed": True, "approver": actor, "idempotency_key": idempotency_key or f"approve-{investigation_id}"})
        investigation["status"] = "executed"
        investigation["execution"] = {**execution, "audit_id": f"audit-{uuid.uuid4().hex[:10]}", "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        investigation["trace"].append(asdict(TraceEvent("approval.execute", "ok", "Human approval received; action executor called", 8, {"action": action, "actor": actor, "dry_run": execution.get("dry_run", execution.get("result") == "dry_run")})))
        self.investigations[investigation_id] = investigation
        self.store.save_investigation(investigation)
        self.store.append_audit(investigation_id, "action.approved_and_executed", actor, {"role": role, "action": action, "audit_id": investigation["execution"]["audit_id"], "idempotency_key": investigation["approval"]["idempotency_key"]})
        return investigation

    @staticmethod
    def _parse_time(value: str) -> float:
        return float(calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")))

    def metrics(self) -> dict[str, Any]:
        investigations = self.store.list_investigations()
        executed = sum(1 for item in investigations if item["status"] == "executed")
        latencies = [item["observability"]["latency_ms"] for item in investigations]
        return {"investigations": len(investigations), "executed_actions": executed, "approval_rate": round(executed / len(investigations), 2) if investigations else 0, "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0, "mode": os.getenv("OPS_PILOT_PROVIDER", "demo"), "persistence": "sqlite", "tool_mode": "prometheus" if os.getenv("PROMETHEUS_URL") else "demo"}
