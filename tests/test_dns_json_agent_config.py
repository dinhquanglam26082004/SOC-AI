"""Validate narrow changes to the Wazuh Agent DNS reader."""

from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from scripts.configure_dns_json_agent import DNS_LOG, with_dns_json


SAMPLE = '''<!-- existing settings -->
<agent_config name="^ubuntu-agent$">
  <rootcheck><disabled>no</disabled></rootcheck>
  <localfile><log_format>syslog</log_format><location>/opt/zeek/logs/current/dns.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/opt/zeek/logs/current/conn.log</location></localfile>
</agent_config>
<agent_config name="another-agent">
  <localfile><log_format>syslog</log_format><location>/opt/zeek/logs/current/dns.log</location></localfile>
</agent_config>'''


def test_update_changes_only_the_selected_dns_reader_and_is_idempotent():
    updated = with_dns_json(SAMPLE)
    expected = SAMPLE.replace('<log_format>syslog</log_format><location>' + DNS_LOG,
                              '<log_format>json</log_format><location>' + DNS_LOG, 1)
    assert updated == expected
    assert with_dns_json(updated) == updated


def test_rejects_ambiguous_or_unexpected_configuration():
    duplicate_dns = SAMPLE.replace('</agent_config>',
        '<localfile><log_format>syslog</log_format><location>' + DNS_LOG + '</location></localfile></agent_config>', 1)
    with pytest.raises(ValueError, match='exactly one centralized'):
        with_dns_json(duplicate_dns)
    with pytest.raises(ValueError, match='Unexpected'):
        with_dns_json(SAMPLE.replace('<log_format>syslog</log_format>', '<log_format>audit</log_format>', 1))
    with pytest.raises(ValueError, match='exactly one ubuntu-agent'):
        with_dns_json(SAMPLE.replace('^ubuntu-agent$', 'other'))


@pytest.mark.parametrize('name', ['zeek-all-agent.conf', 'zeek-agent-localfile.xml'])
def test_repository_templates_collect_one_json_dns_reader(name):
    path = Path(__file__).resolve().parents[1] / 'docker' / 'wazuh' / name
    root = ET.fromstring('<shared>' + path.read_text(encoding='utf-8') + '</shared>')
    readers = [node for node in root.iter('localfile') if node.findtext('location') == DNS_LOG]
    assert len(readers) == 1
    assert readers[0].findtext('log_format') == 'json'
    assert readers[0].findtext('only-future-events') == 'yes'
