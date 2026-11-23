import xml.etree.ElementTree as ET
from pathlib import Path

from wazuh_integration.mapper import ai_eligible, map_wazuh_alert


RULE_FILE = Path(__file__).resolve().parents[1] / 'docker' / 'wazuh' / 'soc-local-rules.xml'


def test_authentication_correlation_threshold_and_secondary_alert_priority():
    root = ET.fromstring('<rules>' + RULE_FILE.read_text(encoding='utf-8') + '</rules>')
    rules = {rule.get('id'): rule for rule in root.iter('rule')}

    correlation = rules['40111']
    assert correlation.get('overwrite') == 'yes'
    assert (correlation.get('level'), correlation.get('frequency'),
            correlation.get('timeframe')) == ('10', '9', '160')
    assert correlation.findtext('if_matched_group') == 'authentication_failed'
    assert correlation.find('same_source_ip') is not None
    assert correlation.findtext('description') == 'Multiple authentication failures.'
    assert 'authentication_failures' in correlation.findtext('group').split(',')

    summary = rules['2502']
    assert summary.get('level') == '5'
    assert summary.findtext('match') == 'more authentication failures;|REPEATED login failures'
    assert 'authentication_failed' in summary.findtext('group').split(',')

    assert '40112' not in rules


def test_linux_account_creation_and_sudo_group_rules():
    root = ET.fromstring('<rules>' + RULE_FILE.read_text(encoding='utf-8') + '</rules>')
    rules = {rule.get('id'): rule for rule in root.iter('rule')}

    account_created = rules['101200']
    assert account_created.get('level') == '5'
    assert account_created.findtext('if_group') == 'syslog'
    assert account_created.findtext('program_name') == '^useradd$'
    assert account_created.findtext('match') == 'new user: name='
    assert account_created.findtext('mitre/id') == 'T1136.001'
    created = map_wazuh_alert({
        'id': 'account-create-1', 'timestamp': '2026-11-23T08:00:00Z',
        'agent': {'id': '001', 'name': 'ubuntu-agent'}, 'manager': {'name': 'soc-manager'},
        'rule': {'id': '101200', 'level': 5, 'description': 'Linux account created',
                 'groups': ['syslog', 'linux', 'account_management']},
        'location': 'journald', 'full_log': 'useradd[123]: new user: name=soc-lab-user, UID=1002',
    })
    assert created['event_kind'] == 'alert'
    assert created['ai_allowed'] is True
    assert ai_eligible(created) is False

    for rule_id, program, message in (
        ('101201', '^usermod$', "to group 'sudo'"),
        ('101202', '^gpasswd$', 'to group sudo'),
    ):
        privileged_group = rules[rule_id]
        assert privileged_group.get('level') == '10'
        assert privileged_group.findtext('if_group') == 'syslog'
        assert privileged_group.findtext('program_name') == program
        assert privileged_group.findtext('match') == message
        assert privileged_group.findtext('mitre/id') == 'T1098'
        assert 'privilege_escalation' in privileged_group.findtext('group').split(',')
