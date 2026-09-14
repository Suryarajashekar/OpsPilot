import json
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.agent import KnowledgeBase, OpsPilot
from backend.store import SQLiteStore
from backend.integrations import PrometheusToolRegistry
from scripts.run_evals import build_cases, run as run_evals


class OpsPilotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pilot = OpsPilot(store=SQLiteStore(":memory:"))

    def test_retrieval_finds_payment_runbook(self) -> None:
        results = KnowledgeBase().search("payments database connection pool too many clients")
        self.assertEqual(results[0]["service"], "payments-api")
        self.assertGreater(results[0]["score"], 0.2)

    def test_investigation_requires_approval(self) -> None:
        result = self.pilot.investigate("Payments are timing out because the database has too many clients")
        self.assertEqual(result["status"], "awaiting_approval")
        self.assertTrue(result["approval"]["required"])
        self.assertFalse(result["approval"]["executed"])
        self.assertEqual(result["diagnosis"]["action"], "recycle_connection_pool")
        self.assertTrue(result["diagnosis"]["citations"])
        self.assertGreaterEqual(len(result["sources"]), 1)
        self.assertGreaterEqual(len(result["trace"]), 5)

    def test_approval_executes_once(self) -> None:
        result = self.pilot.investigate("Catalog pods are being OOMKilled and memory is growing")
        executed = self.pilot.approve(result["id"], actor="alice", role="incident_commander", idempotency_key="demo-123")
        self.assertEqual(executed["status"], "executed")
        self.assertTrue(executed["execution"]["dry_run"])
        audit_id = executed["execution"]["audit_id"]
        again = self.pilot.approve(result["id"], actor="alice", role="incident_commander", idempotency_key="demo-123")
        self.assertEqual(again["execution"]["audit_id"], audit_id)
        self.assertEqual(len(self.pilot.store.audit_events(result["id"])), 2)

    def test_unknown_incident_abstains(self) -> None:
        result = self.pilot.investigate("The moonbase inventory dashboard is missing a color legend.")
        self.assertEqual(result["status"], "needs_attention")
        self.assertEqual(result["diagnosis"]["action"], "collect_more_evidence")
        with self.assertRaises(PermissionError):
            self.pilot.approve(result["id"], actor="guest", role="viewer")

    def test_evaluation_suite_covers_known_unknown_and_adversarial_inputs(self) -> None:
        cases = build_cases()
        self.assertEqual(len(cases), 60)
        report = run_evals()
        self.assertEqual(report["cases"], 60)
        self.assertGreaterEqual(report["service_accuracy"], 0.95)
        self.assertGreaterEqual(report["action_accuracy"], 0.95)
        self.assertEqual(report["abstention_accuracy"], 1.0)
        self.assertEqual(report["failures"], [])

    def test_prometheus_adapter_parses_real_api_shape(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps({"status": "success", "data": {"resultType": "vector", "result": [{"value": ["1710000000", "0.7"]}]}}).encode()

        registry = PrometheusToolRegistry("http://prometheus.test")
        with patch("backend.integrations.urllib.request.urlopen", return_value=FakeResponse()):
            health = registry.service_health("payments-api")
        self.assertEqual(health["source"], "prometheus")
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["error_rate_per_second"], 0.7)

    def test_eval_cases_are_satisfied(self) -> None:
        cases = json.loads((ROOT / "data" / "evals.json").read_text(encoding="utf-8"))
        passed = 0
        for case in cases:
            result = self.pilot.investigate(case["incident"])
            passed += int(result["diagnosis"]["service"] == case["expected_service"] and result["diagnosis"]["action"] == case["expected_action"])
        self.assertEqual(passed, len(cases))


if __name__ == "__main__":
    unittest.main()
