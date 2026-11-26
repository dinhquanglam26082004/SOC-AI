"""Fixed SOC intake policy for explicitly selected Wazuh and Zeek sources."""

ZEEK_LOG_TYPES = frozenset({'dns', 'conn', 'http', 'ssh', 'ssl', 'notice', 'files', 'dhcp', 'weird'})
WAZUH_LOCATIONS = frozenset({'last -n 20', 'wazuh-agent', 'wazuh-monitord',
                             'wazuh-remoted', 'syscheck', 'rootcheck', '/var/log/dpkg.log', 'logcollector'})
WAZUH_LOG_TYPES = WAZUH_LOCATIONS | {'journald', 'netstat listening ports'}
AUTH_GROUPS = frozenset({'authentication_failed', 'authentication_success', 'invalid_login',
                         'authentication', 'pam', 'sshd', 'sudo', 'account_management',
                         'privilege_escalation'})
AUTH_PROGRAMS = frozenset({'sshd', 'ssh', 'sudo', 'su', 'login', 'useradd', 'usermod', 'gpasswd'})
EXCLUDED_GROUPS = frozenset({'stats', 'syscollector', 'sca'})
ROOTKIT_GROUPS = frozenset({'rootcheck', 'rootkit', 'kernel_monitoring', 'kernel_integrity',
                            'kernel_module_activity', 'endpoint_snapshot'})
ROOTKIT_RULES = frozenset({'521', '5132', '80700', '80705', '100200', '100201', '100205', '100206'})


def selected_source(raw):
    """Return whether an event belongs to the selected intake, not whether it is safe.

    Wazuh sometimes uses a Zeek filename as the *location* of its own rule 11
    statistics. The rule group is checked first so those are not Zeek events.
    """
    if not isinstance(raw, dict):
        return False
    rule = raw.get('rule') if isinstance(raw.get('rule'), dict) else {}
    groups = rule.get('groups') if isinstance(rule.get('groups'), list) else []
    groups = {g.lower() for g in groups if isinstance(g, str)}
    if groups & EXCLUDED_GROUPS:
        return False
    # Kernel/rootkit telemetry may arrive through journald or an audit location
    # that is not one of the ordinary Wazuh locations. Retain it at intake;
    # AI eligibility is decided later by mapper.is_security_alert/ai_eligible.
    data = raw.get('data') if isinstance(raw.get('data'), dict) else {}
    if (groups & ROOTKIT_GROUPS or str(rule.get('id', '')) in ROOTKIT_RULES
            or data.get('producer') == 'soc-ai-rootkit-snapshot-v1'):
        return True
    location = raw.get('location') if isinstance(raw.get('location'), str) else ''
    if '/zeek/logs/current/' in location:
        filename = location.rsplit('/', 1)[-1]
        return filename.endswith('.log') and filename[:-4] in ZEEK_LOG_TYPES
    if location == 'journald':
        predecoder = raw.get('predecoder') if isinstance(raw.get('predecoder'), dict) else {}
        program = str(predecoder.get('program_name') or '').lower().split('[', 1)[0]
        decoder = raw.get('decoder') if isinstance(raw.get('decoder'), dict) else {}
        decoder_name = str(decoder.get('name') or '').lower()
        return bool(groups & AUTH_GROUPS or program in AUTH_PROGRAMS or decoder_name in AUTH_PROGRAMS | {'pam'})
    if location == 'netstat listening ports':
        return str(rule.get('id', '')) == '533'
    if location in WAZUH_LOCATIONS:
        return True
    # Some Wazuh FIM alerts omit location but still carry the FIM object.
    return not location and isinstance(raw.get('syscheck'), dict) and 'syscheck' in groups
