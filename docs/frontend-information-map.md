# Frontend information ownership

Updated 26 October 2026. Implementation: `web/index.html`.

| Surface | Primary information | Links to detail |
| --- | --- | --- |
| Shared header | Current page, its purpose, backend availability, refresh | Navigation |
| Dashboard | Severity totals, grouped attention items, collection/queue health | Alerts, selected investigation |
| Alerts | Full detection list, severity, investigation status, concise alert summary | Source log, selected investigation |
| Logs | Collected events, structured source fields, original and JSON representations | Selected investigation for security alerts |
| Investigations | AI assessment, findings, hypotheses, analyst checklist and review | Source log, response proposal, report download |
| AI activity tab | One timeline of workflow steps, model decisions and tools | Expand a step for details |
| Evidence tab | Observations and retrieval guidance with their references | Expand a record for source fields |
| Knowledge Sources | Paginated indexed content, type filters, text search, chunk reader; collection/model status in a disclosure | Select a chunk to read its complete indexed text and metadata |
| Response | Collapsed action proposals per alert and recorded history | Selected investigation |

Removed duplicated sidebar counters/status, repeated body page headings, duplicate
refresh controls, full AI reports inside alert modals, AI state in raw log rows,
repeated log-summary subtitles, and separate timeline/tool/model tab copies.
Finished investigations use one compact status/timing/call-count line. Full reports
are downloadable JSON instead of another inline rendering. Unknowns and unresolved
questions are presented through the analyst checklist when a review is required;
the saved report retains the original information.

Dashboard grouping is presentation only: agent, rule, description and next action
must match. It groups only loaded attention items and links to the first matching
alert. Alerts retains individual records. Lists are not claimed to represent every
stored investigation or proposal: Response labels its scope as loaded alerts.

Knowledge browsing uses read-only `/api/knowledge/chunks` and
`/api/knowledge/chunk?id=...`. Content search matches exact case-sensitive text;
it does not invoke semantic search or an AI model. Results show indexed chunks,
not a count of original source files. Chroma initialization is shared and locked
across status, browsing and retrieval to prevent concurrent client initialization.
Knowledge availability uses `/api/system/status`; it is not a retrieval-quality
score or a claim that external threat-intelligence feeds are installed. Response
does not execute actions or provide an approval adapter. Historical report text
and persisted events are not rewritten by these presentation changes.

Deployment uses the workstation's existing Compose override and runtime volume.
Manual browser inspection covers navigation and displayed pages. No automated
tests were added or run for this presentation-only request.
