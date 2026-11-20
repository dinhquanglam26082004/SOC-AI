from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from wazuh_integration.collection_policy import selected_source


def raw(location, rule_id='1', groups=(), **extra):
    return {'id': '1.1', 'timestamp': '2026-11-17T00:00:00Z',
            'agent': {'id': '001', 'name': 'ubuntu-agent'}, 'manager': {'name': 'soc-manager'},
            'rule': {'id': rule_id, 'level': 7, 'description': 'test', 'groups': list(groups)},
            'location': location, **extra}


@pytest.mark.parametrize('name', ['dns', 'conn', 'http', 'ssh', 'ssl', 'notice', 'files', 'dhcp', 'weird'])
def test_allowed_zeek_types(name):
    assert selected_source(raw('/opt/zeek/logs/current/' + name + '.log'))


@pytest.mark.parametrize('name', ['stats', 'capture_loss', 'ntp', 'known_services', 'software', 'conn-summary.1'])
def test_disallowed_zeek_types(name):
    assert not selected_source(raw('/opt/zeek/logs/current/' + name + '.log'))


def test_stats_with_conn_location_are_not_zeek():
    assert not selected_source(raw('/opt/zeek/logs/current/conn.log', rule_id='11', groups=['stats']))


def test_journal_and_command_filtering():
    assert selected_source(raw('journald', predecoder={'program_name': 'sshd'}))
    assert selected_source(raw('journald', groups=['authentication_failed']))
    assert selected_source(raw('journald', decoder={'name': 'sudo'}))
    assert not selected_source(raw('journald', predecoder={'program_name': 'systemd'}))
    assert selected_source(raw('netstat listening ports', rule_id='533'))
    assert not selected_source(raw('netstat listening ports', rule_id='530'))
    for name in ('last -n 20', 'wazuh-agent', 'wazuh-monitord', 'wazuh-remoted',
                 'syscheck', 'rootcheck', '/var/log/dpkg.log', 'logcollector'):
        assert selected_source(raw(name))
    assert selected_source(raw('rootcheck', rule_id='521', groups=['ossec', 'rootcheck']))
    for name in ('syscollector', 'sca', 'df -P', '/var/log/unknown.log'):
        assert not selected_source(raw(name))


def test_ingest_discards_both_streams_without_falsely_claiming_a_write(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN', 'test-only-token')
    with TestClient(create_app(tmp_path / 'policy.db', workers=False)) as client:
        headers = {'X-Webhook-Token': 'test-only-token'}
        for archived in (False, True):
            event = raw('/opt/zeek/logs/current/stats.log')
            if archived:
                event['_soc_stream'] = 'archives'
            response = client.post('/wazuh', json=event, headers=headers)
            assert response.status_code == 202
            assert response.json()['filtered'] is True
            assert response.json()['durable'] is False
        keep = deepcopy(raw('journald', predecoder={'program_name': 'sshd'}))
        assert client.post('/wazuh', json=keep, headers=headers).json()['durable'] is True


def test_rootcheck_alert_and_archive_are_retained_and_visible(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN', 'test-only-token')
    with TestClient(create_app(tmp_path / 'rootcheck.db', workers=False)) as client:
        headers = {'X-Webhook-Token': 'test-only-token'}
        alert = raw('rootcheck', rule_id='521', groups=['ossec', 'rootcheck'])
        archive = raw('rootcheck', rule_id='0')
        archive.update(id='2.2', _soc_stream='archives')
        for event in (alert, archive):
            response = client.post('/wazuh', json=event, headers=headers)
            assert response.status_code == 202
            assert response.json()['durable'] is True
        page = client.get('/api/logs', params={'selected_only': 'true', 'source': 'wazuh', 'log_type': 'rootcheck'}).json()
        assert page['total'] == 2
        assert all(item['log_type'] == 'rootcheck' for item in page['logs'])
