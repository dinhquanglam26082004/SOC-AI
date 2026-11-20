import importlib.util
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient
from api.app import create_app

path = Path(__file__).resolve().parents[1] / 'docker' / 'wazuh' / 'healthcheck.py'
spec = importlib.util.spec_from_file_location('wazuh_healthcheck', path)
healthcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(healthcheck)


def test_agent_control_parser_excludes_manager_and_preserves_status():
    output = '''Wazuh agent_control. List of available agents:
   ID: 000, Name: soc-manager (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: ubuntu-agent, IP: any, Active
   ID: 002, Name: server-b, IP: any, Disconnected
List of agentless devices:
'''
    assert healthcheck.parse_agents(output) == [
        {'id': '001', 'name': 'ubuntu-agent', 'registered_ip': 'any', 'status': 'Active'},
        {'id': '002', 'name': 'server-b', 'registered_ip': 'any', 'status': 'Disconnected'},
    ]


def test_api_reports_stale_manager_and_agent_status(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_CHAT_ID', raising=False)
    monkeypatch.setenv('WAZUH_FORWARDER_STATUS_FILE', str(tmp_path / 'status.json'))
    (tmp_path / 'manager-status.json').write_text(json.dumps({'updated': time.time()-120,
        'manager': {'state': 'ready'}, 'agents': {'state': 'ok', 'items': [{'id':'001', 'name':'vm', 'status':'Active'}]}}))
    with TestClient(create_app(db_path=tmp_path / 'runtime.db', workers=False)) as client:
        payload = client.get('/api/sources/status').json()
        assert payload['manager_monitor']['stale'] is True
        assert payload['agent_monitor']['stale'] is True
        assert payload['agent_monitor']['items'][0]['id'] == '001'
