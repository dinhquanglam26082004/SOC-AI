# Evidence-based investigation with LangGraph

## Scope

`AI_WORKFLOW=langgraph` is the default. Wazuh remains the detection engine and
assigns severity. Only records passing `is_security_alert()` can enter the AI
queue, including eligible Zeek detections delivered through Wazuh. Ordinary
Wazuh/Zeek logs are retained and searchable without launching the model.

The workflow uses one local Ollama model (Qwen3:8b). No endpoint shell, arbitrary
SQL, live process inspection, public threat-intelligence lookup or response
execution tool is provided. Recommendations require analyst review.

## Workflow

```text
security alert → scope/triage → investigate → local tools
                                  ↑             │
                                  └ review evidence ←┘
                                        ↓ when ready / budget reached
                              structured conclusion → safety verification → save report
```

The planner uses native Ollama `messages` and `tool_calls`. It is offered only
the deterministic alert-type tool set, and the same set is enforced at dispatch;
an unsupported model request is recorded as `tool_not_allowed`. Tool outputs and
log text are untrusted data. Final output uses an Ollama JSON Schema and Pydantic
validation. Unknown evidence references and guidance-only findings are rejected.
The transport schema omits string-length grammar constraints: Ollama 0.13.5
rejects large bounded repetitions when generating the grammar. The complete
Pydantic schema still validates all string lengths after generation; types,
required fields, enums and object structure remain in the transport schema.
One repair is allowed within the same model-call budget. Invalid or truncated
reports remain failures with diagnostics; no fabricated successful report replaces
them. A workflow that runs out of time before a conclusion can save a clearly
labelled `workflow_budget_stop` partial report with verdict `inconclusive`.

The verifier requires cited corroborating observations beyond the triggering
alert for a definitive verdict. Missing/error/truncated sources prevent a benign
verdict. A suspected DoS cannot become proven malicious DoS using these tools:
service impact and intent are not independently measured. Semantic truth cannot
be guaranteed by schema validation; analysts must inspect the linked evidence.
Confidence, when provided, is a model estimate, not calibrated probability.

### Version 2: hypotheses, review and analyst handoff

- Hypotheses have application-assigned `H-` IDs, `supporting`, `refuting`,
  `question` and status (`open`, `supported`, `refuted`, `inconclusive`). Unknown
  evidence IDs, guidance used to resolve an incident hypothesis, and the same
  evidence on both sides are rejected. Unmentioned existing hypotheses are
  retained rather than silently dropped.
- The planner can return a structured review decision with `need_more` and a
  concrete question. A code review gate runs before conclusion, can route back
  to the planner, and records its decision. Repeated questions and original
  round/model/tool/time limits bound the loop. Review is part of the planner's
  existing model calls, not a mandatory additional model call every round.
- Authentication tool results include exact retained-record aggregates per
  agent, exact username and source IP, independent of the displayed row limit.
  Outcome classification uses explicit rule groups, Windows event IDs and known
  SSH decoder messages; unknown/contradictory outcomes remain unknown. A strict
  earlier-failure/later-success flag does not assert compromise. Counts describe
  retained normalized records, not unique sessions or complete source coverage.
- Positive authorization is required for a benign conclusion. This installation
  has no trusted maintenance/authorization connector: successful authentication,
  a maintenance claim in a log, or no matching events cannot justify automatic
  benign. An analyst may record a separately verified benign assessment.
- Inconclusive, budget-limited, unresolved-hypothesis, incomplete-source and
  failed investigations are marked for analyst review. The Investigations page
  shows a paginated review queue, verification checklist and a review form.
  A review requires a decision, notes (20+ characters) and evidence IDs from the
  same investigation. It is recorded separately and does not rewrite the AI
  verdict, original report or source severity. The queue is cleared by explicit
  analyst review, not by merely opening the alert. New explicit retries of the
  same failed alert create a separate run according to existing retry rules.

The analyst interface follows the existing single-user, loopback deployment.
`actor=local-analyst` is an audit label, not an authenticated multi-user identity.
No response action is executed by review submission.

## Five local tools

| Tool | Reads | Boundary |
| --- | --- | --- |
| `get_alert` | Triggering alert | Exact alert ID |
| `search_auth_events` | Retained authentication success and failure records | Exact agent; incident time window |
| `search_related_alerts` | Retained security alerts | Same agent/window |
| `search_zeek_connections` | Historical Zeek `conn` observations | Same agent/window; not live sockets/process ownership |
| `search_runbook` | Existing local Chroma knowledge | Guidance only; never incident proof |

Search window is source event time ±15 minutes. The caller can narrow it but
cannot expand it or select another agent. Optional IP must match the original
alert's source/destination or agent address. Default 50, maximum 100 rows.
SQLite connections use `mode=ro`, `query_only` and a query progress deadline.
Runbook retrieval uses a bounded single-thread executor and timeout. A timed-out
retrieval can continue in that one thread; further retrieval reports busy instead
of creating more threads. Cached embedding weights are required at runtime;
`python -m rag.ingest` is the explicit setup/download step.

Tool outcomes distinguish `ok`, `empty`, `unavailable`, `error`, `truncated`.
Empty means no retained matches; it does not prove the source collected all
events, or that the host is safe. Authentication categorization uses rule groups,
decoder names and Windows event IDs. Unrecognized archive formats may require
additional normalization before the authentication tool can find them.

## Storage and restart

All three SQLite files live beside `RUNTIME_DB_PATH`, in the same persistent
directory/volume:

| File | Purpose |
| --- | --- |
| `soc_runtime.sqlite3` (or configured basename) | Existing logs, alerts, cases, AI jobs and new `investigation_event_index` metadata |
| `soc_investigations.sqlite3` | Investigation summaries/reports, evidence, tool/model audit, leases |
| `soc_checkpoints.sqlite3` | LangGraph checkpoints/pending writes; not an audit replacement |

Version 2 adds `authentication_facts` and the `authentication_facts_v1` migration
marker in the runtime DB. Existing data is backed up before the additive
migration. The audit DB adds `analyst_reviews` and an indexed pending-review
status, with its own pre-schema backup. No historical report is regenerated.

Open a database with DB Browser for SQLite. Audit tables are `investigations`,
`evidence`, `calls`, `leases`; JSON payload columns can be inspected/exported.
Original events remain in the main runtime DB. `event_time` and `collected_at`
are distinct. Evidence IDs are generated by application code, deduplicated by
source record and evidence type. Timeline entries use observed source timestamps.

The additive metadata migration backs up an existing runtime DB under
`backups/pre-log-index-*.sqlite3` before its first execution. Backfill and marker
are transactional and idempotent. Existing optimized log-query indexes are kept.
All stores/checkpoints use WAL and FULL synchronization. Back up live databases
with SQLite's backup API (or stop the app before copying DB + WAL files).

A recovered queued job resumes the same running investigation/thread ID and its
original time/call budgets. Completed tool/model calls replay saved results.
Interrupted read-only tool calls can repeat safely with deduplicated evidence;
an interrupted model call without a saved response fails explicitly to avoid
unaccounted regeneration. An explicit retry of a failed job creates a new
investigation, preserving prior audit. A saved completed report is reused if the
process died before committing the queue result. One app process/worker is
supported; do not run multiple app instances against the same databases.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `AI_WORKFLOW` | `langgraph` | `langgraph` or explicit `legacy`; no silent fallback |
| `AI_GRAPH_MAX_ROUNDS` | 3 | Maximum planning/tool rounds |
| `AI_GRAPH_MAX_MODEL_CALLS` | 4 | All planner, conclusion and repair calls |
| `AI_GRAPH_MAX_TOOL_CALLS` | 6 | Unique reserved tool calls, including initial alert read |
| `AI_GRAPH_TIMEOUT` | 900 | Total investigation wall-clock seconds, retained on restart |
| `AI_TOOL_TIMEOUT` | 15 | Per-tool seconds, capped by remaining investigation budget |
| `AI_GRAPH_CONTEXT_CHARS` | 9000 | Evidence context allowance; full evidence stays in audit |
| `AI_PLAYBOOK_ENABLED` | false | Optional separate legacy playbook step after durable report |

The planner reserves room for the conclusion and one repair. Therefore the
default four model calls often permit two planning rounds, rather than three.
The effective evidence context is also reduced according to the configured
Ollama context/prediction sizes and space needed by schemas/tool history. Whole
evidence summaries are omitted rather than cutting JSON in half. Omission is
reported as a coverage gap; the full records remain in the dossier. The character
estimate is conservative, not an exact tokenizer measurement.
`OLLAMA_TIMEOUT` also caps individual requests. Existing context/prediction/GPU
settings remain in effect. Concurrency is clamped to one for LangGraph.
Use `LANGGRAPH_STRICT_MSGPACK=true`, `LANGCHAIN_TRACING_V2=false`,
`LANGSMITH_TRACING=false`. Checkpoint serialization disables pickle and arbitrary
msgpack object revival. No remote tracing is configured.

Optional playbook work has its own existing model timeout; it is **outside** the
investigation budget and off by default. Its failure does not erase or fail the
saved investigation. Actions are recommendations only. The legacy workflow
remains available for controlled rollback.

## UI and API

Investigations shows the recorded stage, elapsed time, model/tool counters,
verdict, stop reason, hypotheses and unknowns. Evidence, tool history and model
call metadata load on selection in pages of 20, not on every timer tick.
The default **AI activity** tab appears above the report. It combines persisted
workflow steps and model/tool calls in chronological order. Expand an entry to
see a tool's documented purpose, query parameters, outcome, returned record
count, evidence IDs and duration. Model entries show which tools were requested.
While the selected investigation is running, the dossier refreshes every four
seconds. Open activity entries stay expanded during refresh. The purposes are
tool descriptions; they are not claimed to be the model's private reasoning.
Old investigations show only history that was actually recorded; missing stage
history is not reconstructed. An existing audit DB is backed up before adding
the `workflow_steps` table.
Models tab exposes call timing/state, while raw prompts/responses remain in the
local audit DB. Evidence and tool history may contain sensitive logs, as does
the existing local SOC UI. Keep the app's default loopback binding.

- `GET /api/alerts/{id}/investigation`: compact current run summary.
- `GET /api/investigations/{id}?section=activity|evidence|tools|models&limit=20&offset=0`:
  paginated dossier, maximum 100 rows.
- `/api/sources/status`: compact graph metadata only; no evidence history scan.
- `GET /api/investigations?limit=20&offset=0`: pending analyst reviews.
- `POST /api/investigations/{id}/review`: explicit analyst assessment; schema
  fields `decision`, `notes`, `evidence_ids`. Completed/failed runs only; rejects
  evidence outside the run. Historical reviews remain in `analyst_reviews`.
- Existing retry, claim, cooldown and finish semantics remain in place.

## Deploy and roll back

For a normal checkout using the standard bind-mounted data directory:

```powershell
docker compose --profile app build soc-ai-app
docker compose --profile app up -d --no-deps soc-ai-app
docker compose logs --tail 80 soc-ai-app
```

Use the **same Compose override files as the current installation**. This
workstation uses `-f docker-compose.yml -f data/local-runtime.compose.yml` to
retain the existing named runtime volume and GPU settings. Do not replace that
volume with a new empty `data/` database. No Manager/forwarder rebuild or Agent
re-enrollment is required for this workflow change.

Rollback: set `AI_WORKFLOW=legacy` in `.env` and recreate only `soc-ai-app` with
the same Compose files. This stops using the graph; additive tables/audit remain
available. It does not retroactively rerun completed alerts or erase audit.
Use a pre-migration backup only if database restoration is deliberately required,
with app and ingestion stopped. Do not run reset scripts to roll back.

## Validation

`tests/test_investigation_graph.py` uses synthetic events, temporary databases and
mock model responses only. Coverage includes scope/row limits, both auth outcomes,
unavailable/empty/truncated sources, guidance classification, call/time budgets,
schema repair/fabricated IDs, restart recovery, interrupted model refusal,
deduplication, API pagination and playbook failure isolation. Existing ingestion,
optimized log query and timeseries tests must pass as well.

Model quality and actual investigation latency are separate from mocked tests.
No synthetic alert is injected into production by this test suite.

Standalone UI rendering checks: `node tests/test_investigation_ui.cjs`.

See the [25 October validation record](langgraph-validation.md) for actual test,
local-model and rollout results.

For the version 2 evaluation suite and its limits, see
[high-priority improvements](investigation-priorities.md).
