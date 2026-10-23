# Suspected DoS detection

This policy flags traffic anomalies, not confirmed service outages. It is a
baseline requiring tuning against normal traffic. No automatic blocking is added.

## Manager-only fallback

Rule **100142** correlates unsuccessful TCP `S0`/`REJ` flow records (100140):
frequency 100 within 10 seconds, same origin, destination, and destination port.
The alert is level 8, Medium, with a 60-second ignore interval. This is separate
from the different-port scan rule 100141. It counts received log records, not
SYN packets; connection expiry and delivery backlog can delay or concentrate
records. It cannot confirm a SYN flood or detect all distributed attacks.

## Live Zeek aggregation

`scripts/zeek/soc-dos.zeek` observes `new_connection` and `http_request`, then
emits JSON `dos.log` summaries at the end of fixed 10-second network-time windows.
It aggregates all visible origins by destination IP, destination port, and metric.
It does not wait for the connection log to close and does not install an expensive
per-packet handler. New flow counts include both failed and successful attempts.

| Metric | Default observations / 10 seconds | Manager rule |
| --- | --- | --- |
| TCP new connections | 300 | 100161 |
| HTTP requests | 200 | 100162 |
| UDP new flows | 500 | 100163 |
| ICMP new flows | 300 | 100164 |

All these findings are Medium / Wazuh level 8. Rules use `zeek_detection` and
`zeek_dos` groups. Generic/unrecognized summaries remain telemetry (100160).
The backend requires a recognized producer and metric, a valid destination,
positive threshold/window, and observed count ≥ threshold. Invalid summaries
remain logs. Summary evidence displays the count, threshold, window, average
observations per second, source count, and unconfirmed availability impact.
The word "observations" means requests or new flows, never packet rate.

Source counting is capped at 64 per target bucket and explicitly flagged when
capped. Multiple observed sources do not prove DDoS; proxies, NAT, spoofing,
and legitimate clients affect interpretation. At most 20,000 target buckets
are tracked per window; omitted observations generate a Zeek Reporter warning.
Restrict `SOCDOS::protected_nets` and monitor sensor capacity/capture loss.

## Install on the victim

The policy is provided in this repository; it is **not remotely installed** by
building Docker. Copy it from Windows (replace VICTIM_IP):

```powershell
scp scripts/zeek/soc-dos.zeek victim@VICTIM_IP:/tmp/soc-dos.zeek
```

On the Ubuntu victim:

```bash
sudo install -m 644 /tmp/soc-dos.zeek /opt/zeek/share/zeek/site/soc-dos.zeek
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

Add exactly one line:

```zeek
@load ./soc-dos
```

Optional tuning in `local.zeek` after that load:

```zeek
# Example only: replace with the victim subnet and measured baseline.
redef SOCDOS::protected_nets = { 192.168.19.0/24 };
redef SOCDOS::window = 10sec;
redef SOCDOS::http_limit = 200;
redef SOCDOS::tcp_limit = 300;
```

Use a positive window no longer than 300 seconds and positive thresholds.
Then deploy the changed sensor configuration:

```bash
sudo /opt/zeek/bin/zeekctl deploy
```

In `/var/ossec/etc/ossec.conf` on the victim, collect `dos.log` once (skip the
explicit entry if an existing wildcard already covers it):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/dos.log</location>
</localfile>
```

Apply Agent configuration:

```bash
sudo systemctl restart wazuh-agent
```

The supplied Docker Manager rules and SOC backend must also be deployed.
Open **Alerts** or **Logs → Source: Zeek → Type: dos**. Summaries only appear
when thresholds are met; no traffic-generator command is needed for installation.

## Limits and deployment status

- Fixed windows can split a burst across boundaries; they are not sliding windows.
- Defaults are starting points, not measured production thresholds.
- UDP/ICMP packet floods within a single existing flow may be missed.
- HTTP payload inspection requires visible HTTP; encrypted HTTPS needs service
  access logs or authorized TLS visibility for request counting.
- TCP counts are new connections, not direct SYN counters. Add packet/flow
  telemetry from an appropriate sensor for packet-level detection.
- This initial policy targets a standalone Zeek sensor. Do not assume its local
  counters aggregate across Zeek cluster workers or independent sensors.
- Sensor packet loss, load balancers, and asymmetric capture affect evidence.
- Availability needs corroboration from service errors, latency, health and
  resource/network utilization before declaring a confirmed DoS.
- The implementation has not undergone the scenario verification suite, following
  the user's instruction not to run verification. Sensor activation on the victim
  is a separate installation step; Manager deployment alone does not enable it.

References: [Zeek HTTP events](https://docs.zeek.org/en/v6.1.1/scripts/base/bif/plugins/Zeek_HTTP.events.bif.zeek.html),
[Zeek connection events](https://docs.zeek.org/en/v6.0.9/scripts/base/bif/event.bif.zeek.html),
[Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).
