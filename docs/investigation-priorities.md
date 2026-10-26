# Investigation priorities — 26 October 2026

## Implemented

1. **Structured hypotheses:** stable application-assigned `H-` IDs, supporting
   and refuting evidence IDs, unresolved question and status. A document cannot
   resolve an incident hypothesis; unknown/cross-run evidence and contradictory
   reference directions are rejected. Existing unresolved hypotheses are retained.
2. **Pre-conclusion review:** an explicit `review` graph node evaluates the
   planner's structured decision and may return to investigation. The planner
   performs model reassessment inside the existing call budget. The gate stops
   repeated questions or exhausted budgets; no extra mandatory model per round.
3. **Authentication facts:** deterministic classification and SQL aggregation
   by Agent, exact username and source IP, with ordered failure-before-success.
   Aggregate counts cover retained records independently of the row display cap.
   Unknown outcomes, same-time events, different users/IPs and omitted groups
   remain explicit. A sequence never establishes authorization or compromise.
4. **Positive benign basis:** this installation lacks a trusted maintenance or
   authorization connector, so the AI cannot automatically certify benign based
   on log text, successful login or absence of evidence. Code conservatively
   changes unsupported benign to inconclusive. Authentication-only observations
   also cannot establish successful compromise. `model_verdict` and
   `policy_adjustments` distinguish a model proposal from the verified result.
5. **Analyst handoff:** unresolved hypotheses, missing/failed sources, budget
   stops and investigation failures produce a pending review with reasons and a
   checklist. Investigations shows a paginated queue and explicit review form.
   Decision, notes and same-run evidence are stored in `analyst_reviews`; the
   original AI report and Wazuh severity remain unchanged. Old terminal runs
   without review metadata are flagged once, without rerunning the model or
   reconstructing missing history. The pending queue shows the latest run per alert.
6. **Separate quality evaluation:** eight synthetic cases, a contract mode with
   mocks, and explicit live mode for Qwen3. Quality output distinguishes completed
   model reports, failed validation, tool selection, denied invalid requests,
   inconclusive results and verdict agreement with each case's expected evidence.

Triage supplies recommended tools for the alert type: network/Zeek, file/malware,
or authentication. The model still chooses the calls; scope checks and the tool
allowlist apply to every request. This guidance does not guarantee correct reasoning.

## Storage, safety and compatibility

- Runtime: additive `authentication_facts`, indexed by existing event IDs;
  `authentication_facts_v1` marker and pre-migration SQLite backup. Existing log
  queries and metadata indexes remain in use.
- Audit: additive `analyst_reviews`, `audit_migrations`, indexed pending-review
  metadata and pre-schema backup. Checkpoints still live separately. Audit review
  migration is idempotent; old reports are not rewritten.
- The original model/tool/round/time/concurrency limits remain. Telemetry does
  not launch AI. Playbooks remain separate recommendations; no response adapter
  or endpoint execution tool is added.
- Analyst identity is `local-analyst` in this existing single-user loopback app.
  It is not a multi-user authentication system. Recording a review is a human UI
  action; the AI's tool allowlist contains no review-writing capability.
- Review submissions require 20+ characters of notes and one or more valid
  evidence IDs from that run. This records the analyst's verification, not an
  independent automated check of the assertion in the notes.
- `AI_WORKFLOW=legacy` remains the rollback switch. Additive tables need not be
  removed to roll back. Do not reset or replace the current runtime volume.

## Files

| File | Role |
| --- | --- |
| `agents/investigation_schema.py` | Hypothesis, report, review-decision and analyst-review contracts |
| `agents/investigation_policy.py` | Reference validation, conservative verdict policy, handoff reasons |
| `agents/investigation_graph.py` | Review node, bounded loop, hypothesis persistence, final policy |
| `common/auth_events.py` | Deterministic collected-record outcome classification |
| `common/investigation_index.py` | Authentication-facts migration/backfill and writes |
| `agents/investigation_tools.py` | Scoped username/source filtering and full-window aggregate |
| `agents/investigation_store.py` | Audit migration, pending-review queue and human assessments |
| `api/app.py` | Queue/review endpoints; compact operational alert payloads |
| `web/index.html` | Hypothesis cards, authentication table, review queue/form |
| `evaluation/investigation_cases.py` | Eight documented synthetic evaluation cases |
| `evaluation/run_investigation.py` | Isolated contract/live runner and results |
| `tests/test_investigation_priorities.py` | New behavior and policy regression coverage |

## Running the evaluation

Contract checks (these **do not measure model accuracy**):

```powershell
.venv\Scripts\python.exe -m evaluation.run_investigation --mode contract --output data/investigation-contract.json
```

Live model, with existing app/Ollama configuration, no service ports or webhook
delivery and all synthetic records confined to an automatically created temporary
database:

```powershell
docker compose --profile app run --rm --no-deps -T soc-ai-app python -m evaluation.run_investigation --mode live --output /app/data/investigation-live.json
```

Use the installation's existing Compose overrides where applicable. This
workstation adds `-f docker-compose.yml -f data/local-runtime.compose.yml`.
Each case has its own 240-second budget, one tool/planning round, three model
calls including one possible repair, and four tool calls. Output is written after
each case. `--case <case-name> [more-case-names ...]` selects a subset. Evaluation is sequential
to avoid competing local model calls. Run while the operational queue is idle.

Cases: failure followed by success, different users, different source IPs,
success before failure, missing auth evidence, an untrusted benign claim,
suspected DoS without service-impact evidence, and corroborated synthetic malware
signatures. They do not cover all attacks, real authorized maintenance, identity
resolution, all log formats or long-running investigations.

The live JSON contains the report and metrics. A report that failed schema or
evidence-reference validation is recorded as a failure, never silently converted
to a successful report. Raw-model verdict metrics are separate from final
policy-gated verdict metrics when available. The runner does not score semantic
truth of every sentence; findings still require review against the input cases.
Neither a small synthetic set nor confidence numbers establish production accuracy.

## Validation record

The initial live run completed 6/8 cases. Two reports failed evidence-ID validation
(`missing_auth_source`, `corroborated_malware`). Among completed cases, 6 matched
the expected final verdict and 5 selected the expected tool. No invalid tool
request was accepted and no false benign final result was recorded. These are
counts on the small supplied set, not an accuracy claim.

After repair instructions supplied exact valid evidence IDs, the second full run
completed 8/8 reports in 403.9 seconds. Seven final and seven raw-model verdicts
matched expectations, but only 4/8 cases selected the expected tool. There were
zero invalid tool requests and zero false benign final results. The synthetic
malware case remained inconclusive instead of the expected malicious assessment.

After adding alert-type tool guidance, a targeted rerun of the four affected cases
completed 4/4 in 161.66 seconds, all selecting the expected tool. Three verdicts
matched expectations; the synthetic malware case remained inconclusive. This is
a four-case rerun, not a fresh full-suite accuracy result. One generated explanation
also said no verification tools executed despite a recorded related-alert lookup;
sentence-level reasoning remains a known model limitation and needs analyst review.

Local result files (ignored by Git):

- Initial: `data/investigation-live-20261026.json`.
- Second full suite: `data/investigation-live-20261026-v2.json`.
- Targeted routing rerun: `data/investigation-live-20261026-routing.json`.

Automated checks: **82 Python tests passed** in 9.27 seconds; both Node UI render
checks passed. `git diff --check` found no whitespace errors. These checks cover
contracts and application behavior, not model accuracy.

Deployment used the existing Compose runtime-volume and GPU overrides. Migration
retained 297 events, 77,692 Zeek records and 77,930 indexed logs, and backfilled 25
authentication facts. Comparison with the pre-migration backup found zero missing
event or Zeek IDs. The backup is
`/app/runtime/backups/pre-log-index-20261026T160110404609.sqlite3`.
Four historical investigations appear in the analyst queue without rewriting their
AI reports. The review form was inspected without submitting an analyst decision.
The revised hypotheses/review workflow applies to new runs; historical conclusions
are not retrospectively corrected. The app was rebuilt and restarted with the
existing operational data retained.
Final `/health` returned `status: ok` with one live AI worker and no queued or
running jobs (18 completed, four historical failed jobs).
