import xml.etree.ElementTree as ET
from pathlib import Path


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
