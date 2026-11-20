# DNS investigation tools

`summarize_dns_activity` in `agents/investigation_tools.py` aggregates retained Zeek DNS records for an agent, an exact domain and its subdomains in a half-open window. Records without query names cannot be attributed to a domain. Duplicate records may be included. Results describe retained records, not unique requests or complete capture. Up to five raw examples and an aggregate evidence record are saved.

`compare_dns_baseline` in `agents/investigation_tools.py` compares two equal-duration non-overlapping windows for the same agent and domain. Both windows must fall within the investigation scope. An empty baseline is not proof that baseline collection was functioning. Neither a long query nor a change from baseline proves tunneling or exfiltration.

`search_process_events` and `search_file_access` in `agents/investigation_tools.py` search retained Wazuh records carrying the `audit_command` and `audit_watch_read` rule groups respectively. They do not infer file reads from FIM. These groups depend on configured Linux auditd rules, Wazuh audit log collection and rule decoding. Empty results do not prove the source is configured or that activity did not occur. File path matching uses the exact decoded `data.audit.file.name`; directory watches and alternate decoded formats may not match. Retained records may not cover the complete audit stream.

`agents/investigation_tools.py` defines argument validation, dispatch, read-only scope and evidence records. New tools are offered to the model but their invocation is not guaranteed. The fixed investigation window and tool timeout still apply. If the scan exceeds the limit or times out, no partial total is presented as complete.
