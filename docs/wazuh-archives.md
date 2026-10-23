# All Wazuh events in SOC-AI

## Scope

The Manager enables `global/logall_json=yes`. Wazuh writes received events,
including events that do not trigger a rule, to
`/var/ossec/logs/archives/archives.json`.
This includes only sources configured on agents or the Manager: it cannot read
files that the agent has not been configured to monitor.

Reference: [Wazuh event logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html).

## Delivery and display

The forwarder reads the read-only Manager logs volume at
`/manager-logs/archives/archives.json`. It also discovers retained daily
`ossec-archive-*.json` and `.json.gz` files every 30 seconds.
`WAZUH_ARCHIVES_ENABLED=true` enables this reader; alert-level and group
forwarding filters do not apply to the archive reader.

Each complete line and its byte checkpoint commit together in the delivery
spool SQLite database. Retries and restarts resume from this checkpoint.
The first line identifies a file across rotation and gzip compression.
Partial final lines wait for the writer. Malformed records or spool capacity
errors stop progress at that line and set the archive status to error.
Retain Manager archive files until the reader has caught up; deleted source
files cannot be recovered by the reader.

The authenticated `/wazuh` endpoint accepts archive envelopes. Records without
a matched rule receive a normalized level-0 placeholder while the original
JSON is preserved. They are telemetry and never trigger AI investigation.
Security rules retain the existing classification and investigation policy.
Events with the same Manager name and Wazuh event ID are deduplicated across
archives and the alert integration. An alert can upgrade an earlier telemetry
record. If the Manager supplies no ID, a deterministic evidence hash identifies
the archive event. Old records before the configured reset cutoff stay excluded.

Open **Logs**, select **Source: Wazuh**, **All categories**, and clear **Hide
telemetry**. New sessions and Clear filters now show all categories by default;
an existing URL containing `hideTelemetry=1` still preserves that filter.
Select a row for the original message, decoded fields, agent, and source JSON.
Zeek events carried by Wazuh remain under the Zeek source.

## Operations

Run from the project root:

```powershell
docker compose --profile app logs --tail 50 wazuh-forwarder
docker compose exec wazuh-manager tail -n 3 /var/ossec/logs/archives/archives.json
docker compose exec wazuh-forwarder cat /spool/status.json
```

The status includes `archives.state`, `archives.file`, `archives.offset`,
`archives.last_read_at`, and the process-local `archives.enqueued` count.
Queue pending/dead-letter/error metrics remain available alongside it.
The HTTP payload size limit and disk capacity still apply; oversized records
appear in dead letters rather than being silently acknowledged.

Changes to Manager logging require restarting the Manager. No Indexer or
Filebeat service is required for this SOC-AI ingestion path. Existing source
configuration, enrollment keys, AI models, and runtime databases are retained.
All-event archives consume more disk space than alert-only logging.
