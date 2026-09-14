# OpsPilot

OpsPilot is a portfolio-ready AI incident-response agent. It turns an incident description into a grounded diagnosis, shows its evidence, proposes a reversible action, and pauses for human approval before executing anything risky.

The project demonstrates the engineering surface area hiring teams look for in production AI systems:

- evidence retrieval over runbooks and past incidents
- stateful agent workflow with explicit stages and trace events
- typed tools for service health, logs, and metrics, with a Prometheus adapter
- human-in-the-loop approval for mutations
- structured model output with an offline deterministic fallback
- SQLite persistence and hash-chained audit events
- 60-case evaluation suite with adversarial and abstention cases
- latency, token/cost, provider, and tool observability
- a small browser dashboard and a zero-dependency Python API

## Run it

Requirements: Python 3.10+.

```powershell
cd outputs/ops-pilot
python backend/server.py
```

Open <http://127.0.0.1:8080>.

Run the evaluation suite:

```powershell
python -m unittest discover -s tests -v
python scripts/run_evals.py --write-report
```

Run with Docker:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

## Demo flow

1. Select an example incident or type one yourself.
2. Click **Investigate**.
3. Inspect retrieved evidence, the trace, and the proposed action.
4. Click **Approve & execute**. The mutation is simulated and recorded in the audit trail.

The app defaults to a deterministic provider so that the demo is reproducible and the evals are meaningful. To enable structured model reasoning, set `OPS_PILOT_PROVIDER=openai` and `OPENAI_API_KEY`. If the provider fails, OpsPilot records a fallback trace and continues with the safe deterministic provider.

Set `PROMETHEUS_URL` to connect the read-only Prometheus adapter. Mutations remain dry-run by design; a real executor must be implemented behind the same interface and kept behind the approval policy.

## Safety and architecture

- `backend/providers.py` isolates structured model output from the workflow.
- `backend/integrations.py` provides a read-only Prometheus integration.
- `backend/store.py` persists investigations and chains audit-event hashes.
- POST endpoints optionally require `Authorization: Bearer ...`.
- Actions require a named approver role, expire after 15 minutes, and default to dry-run execution.
- `scripts/run_evals.py` generates 40 known, 10 unknown, and 10 adversarial cases.

## Portfolio talking points

- Why does every mutation require approval?
- How do you measure retrieval quality separately from answer quality?
- What happens when evidence conflicts or the agent is uncertain?
- How do you control cost and latency during an incident?
- Which actions are reversible, and how is the audit trail used?
- How does the system behave if the model provider is unavailable?
- What is the difference between demo telemetry and a real Prometheus signal?
