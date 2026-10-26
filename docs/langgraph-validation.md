# LangGraph implementation validation — 25 October 2026

## Automated checks

- Python: `python -m pytest tests -q --tb=short --basetemp=data/pytest-graph-release-01`
  — **61 passed** (12.81 seconds).
- UI: `node tests/test_investigation_ui.cjs` — passed. Checks graph counters,
  safe rendering of untrusted error text, legacy progress and excluded log status.
- Dashboard inline JavaScript parsed with Node; `git diff --check` passed.
- Local virtual environment: `pip check` — no broken requirements.

Tests use isolated SQLite databases and mock model responses. They cover local
tool scope, strict argument validation, auth successes/failures, Zeek historical
connections, unavailable/empty/truncated outcomes, evidence deduplication,
checkpoint resume, interrupted-model refusal, budgets, schema repair, invented
references, DoS impact conservatism, API pagination, legacy rollback and playbook
failure isolation. Runtime RAG does not create a missing knowledge database.

## Actual local Qwen3:8b checks

No synthetic event was posted to the production webhook or operational DB.

1. Native tool calling: Qwen3 returned `get_alert` with structured arguments.
2. Minimal JSON Schema: Qwen3 returned `{"verdict":"inconclusive"}`.
3. Full graph check with synthetic authentication failure and success records in
   an isolated DB: **completed in 54.8 seconds**, two model calls, two unique tool
   calls, two evidence records, verdict `inconclusive`, stop `round_budget`.
   Both findings referenced the correct generated evidence IDs. No repair needed.
   Limits for this check: one round, three total model calls including one
   possible repair, three tool calls, 300 seconds. Ollama context 4096, prediction
   limit 1024; Qwen3 used a mixture of CPU/GPU on this machine.

Problems found and addressed during live validation:

- Ollama 0.13.5 rejected the original schema grammar with “number of repetitions
  exceeds sane defaults”. Transport string-length constraints were removed;
  full Pydantic length validation remains enforced at the backend.
- A subsequent test exceeded its intentionally short 120-second budget at the
  conclusion step. The final report prompt was shortened. The bounded 300-second
  check above then completed in 54.8 seconds.

This is a compatibility/smoke check, not a detection benchmark. Timing depends
on model residency, hardware, evidence size and concurrent workload. The checked
report correctly retained uncertainty; model wording still needs analyst review.
No claim is made that all attack scenarios or all report conclusions are correct.

## Runtime rollout

The app image is rebuilt with pinned LangGraph dependencies. Rollout uses the
existing local Compose override and existing named runtime volume. Before
rollout the runtime contained 202 `events`, 67,669 `zeek_logs`, 16 `ai_jobs` and
67,833 `log_index` rows. Queue states: 12 completed and 4 failed. No queued job
was retroactively launched for validation.

Post-deployment checks succeeded:

- All four Compose services healthy. Application reports one live worker.
- `investigation_index_v1` committed. At the checked snapshot, `log_index` and
  `investigation_event_index` each contained **71,691** rows.
- Runtime had **229 events** and **71,506 Zeek logs** at the checked snapshot.
  Counts increased because the real forwarder continued delivery while building.
  Comparing every event/Zeek ID in the pre-migration backup against the deployed
  database found **zero missing IDs** in both tables.
- Backup: `/app/runtime/backups/pre-log-index-20261025T105709028207.sqlite3`
  inside the existing persistent runtime volume.
- Queue: 14 completed, 4 failed; existing failures were not automatically rerun.
- Local HTTP checks from inside the container: `/api/logs?limit=25` 28.9 ms,
  Zeek conn filter 29.4 ms, `/api/sources/status` 31.6 ms. These are single
  smoke measurements, not performance percentiles or browser end-to-end latency.
- Runtime RAG retrieved two playbook documents from existing local knowledge and
  cached embedding weights, no error (6.1 seconds including first load).
- The deployed Linux image also passed an isolated graph/checkpoint smoke check
  with mock model responses (two model reservations, two tools, `inconclusive`).
  `pip check` inside that image reported no broken requirements. Active workflow
  was confirmed as `langgraph`.
- Browser checked the new UI against the isolated local-model result: counters,
  verdict, evidence records and tool-history tab displayed correctly. The
  temporary validation server was stopped afterward. Screenshot retained locally
  under `data/langgraph-ui-validation.png` (ignored by Git).

New eligible alerts use LangGraph. Historical reports remain historical; the
rollout does not automatically regenerate them.

See [configuration and rollback](langgraph-investigation.md).
