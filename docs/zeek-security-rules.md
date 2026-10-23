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
| 100142 | Failed TCP flow burst to the same destination port | 8 | Suspected DoS / Medium |
| 100160 | Unclassified live DoS summary | 3 | Telemetry |
| 100161–100164 | Live TCP/HTTP/UDP-flow/ICMP-flow threshold summaries | 8 | Suspected DoS / Medium |

See [DoS detection](zeek-dos.md) for thresholds, live sensor installation,
evidence fields, and limitations. Packet flood coverage is incomplete; findings
must not be described as confirmed DoS or DDoS.

Correlation rules suppress repeated firing for 60 seconds. Counters are scoped
to the collecting Wazuh agent and reset with the Manager/session. Sensor overlap
and duplicated input can affect thresholds. Tune for actual traffic before
using findings for response decisions. A DNS failure burst may be a configuration
problem; URI signatures describe attempts and do not prove successful exploitation.

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
