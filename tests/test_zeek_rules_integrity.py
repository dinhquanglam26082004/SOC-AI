"""Checks for custom Wazuh rule references and DNS detection coverage."""

from pathlib import Path
import xml.etree.ElementTree as ET

from wazuh_integration.mapper import ai_eligible, map_wazuh_alert


RULE_FILE = Path(__file__).resolve().parents[1] / 'docker' / 'wazuh' / 'zeek-notice-rules.xml'


def test_custom_rule_references_resolve_and_ids_are_unique():
    root = ET.parse(RULE_FILE).getroot()
    rules = root.findall('rule')
    ids = [rule.get('id') for rule in rules]
    assert len(ids) == len(set(ids))
    for rule in rules:
        for tag in ('if_sid', 'if_matched_sid'):
            for node in rule.findall(tag):
                for reference in (node.text or '').split(','):
                    reference = reference.strip()
                    if reference.isdigit() and 100120 <= int(reference) <= 100199:
                        assert reference in ids, f"Rule {rule.get('id')} refers to missing rule {reference}"


def test_removed_lab_rules_do_not_remove_general_dns_detections():
    root = ET.parse(RULE_FILE).getroot()
    ids = {rule.get('id') for rule in root.findall('rule')}
    assert not {'100180', '100182'} & ids
    assert {'100150', '100151', '100152', '100153', '100154', '100155',
            '100156', '100157', '100181', '100183'} <= ids


def test_dns_tunneling_rules_do_not_suppress_repeat_alerts_for_five_minutes():
    root = ET.parse(RULE_FILE).getroot()
    for rule_id in ('100153', '100156', '100157'):
        rule = root.find(f"rule[@id='{rule_id}']")
        assert rule is not None and rule.get('ignore') is None
        assert rule.get('timeframe') == '120' and int(rule.get('frequency')) >= 2
    assert root.find("rule[@id='100151']").get('ignore') == '60'


def test_rare_dns_records_are_telemetry_until_correlated():
    root = ET.parse(RULE_FILE).getroot()
    base = root.find("rule[@id='100183']")
    alert = root.find("rule[@id='100181']")
    assert base is not None and alert is not None
    assert base.get('level') == '4'
    assert base.findtext('if_sid') == '100121'
    assert base.find("field[@name='qtype_name']").text == '^(NULL|PRIVATE|KEY)$'
    assert 'zeek_telemetry' in base.findtext('group').split(',')
    assert 'zeek_detection' not in base.findtext('group').split(',')
    assert (alert.get('level'), alert.get('frequency'), alert.get('timeframe')) == ('7', '3', '120')
    assert alert.findtext('if_matched_sid') == '100183'
    assert {field.text for field in alert.findall('same_field')} == {
        'id.orig_h', 'id.resp_h', 'id.resp_p', 'qtype_name'
    }
    assert alert.findtext('different_field') == 'query'
    assert 'zeek_detection' in alert.findtext('group').split(',')


def test_rare_dns_candidates_and_correlated_alert_reach_the_right_soc_views(monkeypatch):
    monkeypatch.setenv('WAZUH_AI_MIN_LEVEL', '7')
    root = ET.parse(RULE_FILE).getroot()
    for rule_id, expected_kind in [('100183', 'telemetry'), ('100181', 'alert')]:
        rule = root.find(f"rule[@id='{rule_id}']")
        event = {
            'id': 'test-' + rule_id, 'timestamp': '2026-11-18T11:00:00Z',
            'agent': {'id': '001', 'name': 'ubuntu-agent'},
            'manager': {'name': 'soc-manager'},
            'location': '/opt/zeek/logs/current/dns.log',
            'data': {'query': 'example.test', 'qtype_name': 'NULL',
                     'id.orig_h': '192.0.2.10', 'id.resp_h': '192.0.2.53', 'id.resp_p': 53},
            'rule': {'id': rule_id, 'level': int(rule.get('level')),
                     'description': rule.findtext('description'),
                     'groups': ['zeek', 'network'] + rule.findtext('group').strip(',').split(',')},
        }
        mapped = map_wazuh_alert(event)
        assert mapped['event_kind'] == expected_kind
        assert ai_eligible(mapped) is (expected_kind == 'alert')
