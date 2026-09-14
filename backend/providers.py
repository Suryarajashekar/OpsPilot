from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol


DECISION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "service": {"type": "string"},
        "severity": {"type": "string", "enum": ["P1", "P2", "P3"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "summary": {"type": "string"},
        "cause": {"type": "string"},
        "action": {"type": "string"},
        "action_label": {"type": "string"},
        "risk": {"type": "string", "enum": ["none", "low", "medium", "high"]},
        "checks": {"type": "array", "items": {"type": "string"}},
        "citations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["service", "severity", "confidence", "summary", "cause", "action", "action_label", "risk", "checks", "citations"],
}


class ProviderError(RuntimeError):
    pass


@dataclass
class ProviderResult:
    decision: dict[str, Any]
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    fallback: bool = False


class DiagnosisProvider(Protocol):
    name: str

    def decide(self, incident: str, sources: list[dict[str, Any]], evidence: dict[str, Any]) -> ProviderResult:
        ...


class OpenAIResponsesProvider:
    """Minimal stdlib adapter for the Responses API.

    It uses structured JSON output and sends `store=false` by default. The
    project has no SDK dependency so the demo remains easy to run.
    """

    name = "openai-responses"

    def __init__(self, api_key: str, model: str | None = None, timeout: int = 30) -> None:
        self.api_key = api_key
        self.model = model or os.getenv("OPS_PILOT_MODEL", "gpt-5")
        self.timeout = timeout

    def decide(self, incident: str, sources: list[dict[str, Any]], evidence: dict[str, Any]) -> ProviderResult:
        context = {
            "incident": incident,
            "retrieved_sources": [{"id": item["id"], "title": item["title"], "service": item["service"], "content": item["content"]} for item in sources],
            "tool_evidence": evidence,
            "allowed_actions": ["recycle_connection_pool", "rollback_checkout", "scale_catalog", "scale_consumers", "collect_more_evidence"],
            "instructions": "Cite only retrieved source ids. If evidence is insufficient or conflicting, choose collect_more_evidence. Never invent a tool result.",
        }
        body = {
            "model": self.model,
            "store": False,
            "input": [
                {"role": "system", "content": [{"type": "input_text", "text": "You are a cautious production incident investigator. Return only the requested JSON object."}]},
                {"role": "user", "content": [{"type": "input_text", "text": json.dumps(context, separators=(",", ":"))}]},
            ],
            "text": {"format": {"type": "json_schema", "name": "incident_diagnosis", "strict": True, "schema": DECISION_SCHEMA}},
        }
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise ProviderError(f"OpenAI provider request failed: {error}") from error
        text = payload.get("output_text") or self._extract_output_text(payload)
        try:
            decision = json.loads(text)
        except (TypeError, json.JSONDecodeError) as error:
            raise ProviderError("OpenAI provider returned non-JSON diagnosis") from error
        usage = payload.get("usage") or {}
        return ProviderResult(decision, self.name, self.model, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0)))

    @staticmethod
    def _extract_output_text(payload: dict[str, Any]) -> str:
        chunks: list[str] = []
        for item in payload.get("output", []):
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"} and content.get("text"):
                    chunks.append(content["text"])
        return "".join(chunks)
