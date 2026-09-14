from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class PrometheusToolRegistry:
    """Read-only Prometheus adapter; mutations stay dry-run and approval-gated."""

    def __init__(self, base_url: str, timeout: int = 5) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _query(self, promql: str) -> dict[str, Any]:
        url = f"{self.base_url}/api/v1/query?{urllib.parse.urlencode({'query': promql})}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as error:
            return {"status": "error", "error": str(error), "query": promql}
        return payload

    @staticmethod
    def _first_value(payload: dict[str, Any]) -> float | None:
        try:
            result = payload["data"]["result"]
            return float(result[0]["value"][1]) if result else None
        except (KeyError, IndexError, TypeError, ValueError):
            return None

    def service_health(self, service: str) -> dict[str, Any]:
        error_rate = self._first_value(self._query(f'sum(rate(http_requests_total{{service="{service}",status=~"5.."}}[5m]))'))
        latency = self._first_value(self._query(f'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{{service="{service}"}}[5m])) by (le))'))
        return {"service": service, "status": "degraded" if (error_rate or 0) > 0 else "healthy", "error_rate_per_second": error_rate, "p95_ms": round((latency or 0) * 1000, 1), "source": "prometheus"}

    def query_metrics(self, service: str) -> dict[str, Any]:
        return {"service": service, "source": "prometheus", "error_rate": self._first_value(self._query(f'sum(rate(http_requests_total{{service="{service}",status=~"5.."}}[5m]))')), "cpu_pct": self._first_value(self._query(f'avg(rate(process_cpu_seconds_total{{service="{service}"}}[5m])) * 100'))}

    def query_logs(self, service: str, incident: str) -> dict[str, Any]:
        return {"service": service, "query": incident[:120], "lines": ["Prometheus is metrics-only; connect Loki for log evidence."], "source": "prometheus"}

    def execute_action(self, action: str, service: str) -> dict[str, Any]:
        return {"result": "dry_run", "message": f"Prometheus mode is read-only; action {action} for {service} was not mutated.", "action": action, "service": service}
