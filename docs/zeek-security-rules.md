# Zeek detections evaluated by Wazuh Manager

## Pipeline

Zeek JSON files on the monitored victim → Wazuh Agent → Manager JSON decoder
and rules → integration / archives → SOC-AI Logs and Alerts.
Rule level is assigned by Wazuh, not by Zeek or the AI model.

The managed source is `docker/wazuh/zeek-notice-rules.xml`. The Manager startup
script installs it to `/var/ossec/etc/rules/soc-ai-zeek-notice.xml`.
Do not edit default Wazuh rules. IDs in this managed range must remain unique.

## Detection policy

| Rule | Evidence | Level | SOC classification |
| --- | --- | --- | --- |
| 100121 | Other Zeek JSON records | 3 | Telemetry |
| 100120 | Unclassified notice | 3 | Telemetry, available for review |
| 100122 | `Scan::Port_Scan` or `Scan::Address_Scan` | 8 | Alert / Medium |
| 100123 | `Intel::Notice` | 10 | Alert / High |
| 100124 | CaptureLoss / ChecksumOffloading notice | 3 | Sensor telemetry |
| 100130 | HTTP URI matching selected SQL-injection patterns | 8 | Suspected attempt / Medium |
| 100131 | HTTP traversal pattern targeting sensitive files | 8 | Suspected attempt / Medium |
| 100132 | HTTP command separator followed by selected shell/download commands | 8 | Suspected attempt / Medium |
| 100140 | TCP `S0` or `REJ` connection | 3 | Correlation evidence, Telemetry |
| 100141 | Frequency 12 / 60 seconds; same origin and destination, different destination ports, rule 100140 | 8 | Possible port scan / Medium |
| 100150 | DNS NXDOMAIN response | 3 | Correlation evidence, Telemetry |
| 100151 | Frequency 20 / 60 seconds; same origin, rule 100150 | 7 | DNS failure burst / Medium |
| 100152 | DNS label at least 32 octets, including Zeek `\xNN` representations, with domain exclusions | 5 | Candidate / telemetry |
| 100154 | Long label and TXT, NULL, CNAME or MX query type | 7 | Candidate alert; manual AI investigation |
| 100155 | Long label resembling base32 or hex | 7 | Candidate / telemetry |
| 100153 | 2 distinct long-label queries from same source in 120 seconds | 8 | Suspected DNS tunneling / Medium |
| 100156 | 5 distinct long-label TXT/NULL/CNAME/MX queries from same source in 120 seconds | 12 | Suspected DNS tunneling / High |
| 100157 | 2 distinct encoded-looking long-label queries from same source in 120 seconds | 8 | Suspected DNS tunneling / Medium |
| 100183 | A DNS query type NULL, PRIVATE or KEY | 4 | Individual observation / telemetry |
| 100181 | Frequency 5 / 60 seconds for the same agent, source, destination/port and rare query type, with a differing query; ignore for 200 seconds after firing | 7 | Unusual DNS activity / Medium |
| 100142 | Failed TCP flow burst to the same destination port | 8 | Suspected DoS / Medium |
| 100160 | Unclassified live DoS summary | 3 | Telemetry |
| 100161–100164 | Live TCP/HTTP/UDP-flow/ICMP-flow threshold summaries | 8 | Suspected DoS / Medium |

See [DoS detection](zeek-dos.md) for thresholds, live sensor installation,
evidence fields, and limitations. Packet flood coverage is incomplete; findings
must not be described as confirmed DoS or DDoS.

Rule 100152 counts each Zeek `\xNN` escape as one byte, not four display
characters. Escaped bytes or long labels alone do not prove a tunnel or intent;
the broader match may increase candidate and correlated alert volume.
DNS tunneling rules 100153, 100156, and 100157 do not set a Wazuh ignore interval.
Rule 100151 retains its 60-second interval. Correlation counters are scoped
to the collecting Wazuh agent and reset with the Manager/session. Sensor overlap
and duplicated input can affect thresholds. Tune for actual traffic before
using findings for response decisions. A DNS failure burst may be a configuration
problem; URI signatures describe attempts and do not prove successful exploitation.

## DNS tunneling limitations

Rules 100152–100157 are heuristics for long DNS names, not proof of DNS
tunneling, C2, exfiltration or service impact. Rule 100153 groups by origin and
agent, not by domain; long queries to unrelated domains can contribute. Short or
infrequent tunnel queries and encrypted DNS may be missed. The two-query threshold
is tuned for the lab and may produce false positives; raise it after measuring
normal traffic. Wazuh candidate rule 100152 has level 5 and can create Manager
alerts even though the SOC mapper classifies
its `zeek_telemetry` events as log-only; monitor event volume and tune in a lab.
The `.local` suffix is not excluded so that `tunnel.lab.local` remains observable.
Rule 100181 requires `qtype_name`, `query`, `id.orig_h`, `id.resp_h`, and
`id.resp_p` in collected Zeek JSON. Its counter is per agent, source, destination,
port, and query type, but **not** per domain. Wazuh's `different_field` is not a
distinct-name counter: repeated values can contribute, so do not describe the
result as five distinct queries. Events may be repeated observations and rare
DNS types alone do not prove tunneling. Rule 100183 is telemetry in SOC; Wazuh
itself may still write its level-4 match to `alerts.json`. Long-label matches can
take the 100152/100154/100155 branch and reach its correlation rules instead of
100181; 100181 therefore does not count every rare-type query. After rule 100181
fires, its `ignore=200` interval suppresses repeat matches for 200 seconds. Do
not assume this interval is isolated per source or agent; validate on the deployed
Wazuh version. Other rule IDs can still alert, and retained source logs are needed
to inspect activity during suppression. This 5/60 threshold may miss slow tunnels;
tune it after measuring ordinary traffic. SOC's active-investigation grouping can
also avoid a concurrent duplicate AI job without suppressing source alerts.
The excluded suffix list is a local policy, not proof the domains are benign; review
it for your environment. Rule 100157 covers 100155 because a more specific child
can prevent the 100152 correlation rule from matching in logtest.
Validate agent log collection and forwarding separately from rule matching.

On the Manager, `wazuh-logtest -l /opt/zeek/logs/current/dns.log` can evaluate
Zeek JSON examples. Use a single logtest session for frequency rules and include
`id.orig_h`, `query`, and distinct UIDs. Verify ordinary short names do not
trigger the long-name rule and repeated long names from different origins do not
accidentally satisfy a same-origin test. Logtest sessions are isolated tests;
they do not validate the live agent-to-SOC pipeline.

`zeek_detection` identifies security detections. SOC requires this group and
level ≥ 7, excludes operational sensor notices, and keeps all other Zeek events
as telemetry. Existing AI policy still decides which alerts are investigated.
Do not add the detection group to generic transport rules.

Alerts from Zeek appear alongside Wazuh endpoint alerts, retaining **Zeek · via
Wazuh**, Manager rule ID, source level, MITRE mapping where applicable, endpoints,
and source evidence. Event inspector links to the matching alert. Detection
metadata explicitly states that suspicious activity is not proof of compromise.
Historical events retain their original classification; this deployment does
not reprocess or rewrite previous investigations.

## Victim requirements

The Wazuh Agent must collect JSON files at `/opt/zeek/logs/current/`.
Manager rules do not start Zeek or configure capture interfaces remotely.
See [victim setup](ubuntu-victim-setup.md) for file collection configuration.
HTTP rules inspect visible URI fields; HTTPS encryption normally hides these
fields. These patterns are a baseline, not complete web-attack detection.

The connection and DNS rules work from the collected raw logs. To also emit
the supported Scan notices, load Zeek's `policy/misc/scan` in the victim's
`/opt/zeek/share/zeek/site/local.zeek`, then deploy with `zeekctl deploy`.
Intel notices additionally need a configured Zeek intelligence feed and the
Intel notice policy. An empty feed cannot detect malicious domains.

## Deployment

From the project root:

```powershell
docker compose --profile app up -d --build --force-recreate wazuh-manager wazuh-forwarder soc-ai-app
```

If using a local GPU/runtime override, include the same override used to start
the project, for example `-f docker-compose.yml -f data/local-runtime.compose.yml`.
Keep existing volumes, enrollment keys, and model files. Refresh the browser
with Ctrl+F5. A disconnected victim cannot produce new events.

References: [Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html),
[Wazuh logtest](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).
