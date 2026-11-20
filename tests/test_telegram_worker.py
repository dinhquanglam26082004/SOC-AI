import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from api.app import ai_worker
from common.telegram_notifier import format_investigation_alert
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert


def test_worker_notifies_only_after_successful_result_commit(tmp_path):
    async def run():
        event = {
            "id": "test-alert-1",
            "timestamp": "2026-10-20T08:00:00+07:00",
            "agent": {"id": "007", "name": "test-agent", "ip": "192.0.2.7"},
            "manager": {"name": "soc-manager"},
            "rule": {"id": "550", "level": 8, "description": "File changed", "groups": ["syscheck"]},
            "syscheck": {"path": "C:\\SOC-Lab\\watched\\hello.txt", "event": "modified"},
        }
        store = EventStore(tmp_path / "worker-notify.db")
        record, _ = store.accept(map_wazuh_alert(event), True)
        app = SimpleNamespace(state=SimpleNamespace(store=store, ai_slots=asyncio.Semaphore(1)))
        report = {"verdict": "malicious"}
        proposal = {"status": "matched", "playbook_name": "Test response"}
        with patch("api.app.analyze", return_value=(report, proposal)), \
                patch("api.app.send_investigation_alert") as notify:
            task = asyncio.create_task(ai_worker(app))
            for _ in range(100):
                await asyncio.sleep(.01)
                if store.get(record["id"])["ai_status"] == "completed" and notify.called:
                    break
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        assert store.get(record["id"])["ai_status"] == "completed"
        notify.assert_called_once()
        assert notify.call_args.args[0]["playbook_proposal"] == proposal

    asyncio.run(run())


def test_worker_does_not_notify_failed_investigation(tmp_path):
    async def run():
        event = {
            "id": "test-alert-2",
            "timestamp": "2026-10-20T08:00:00+07:00",
            "agent": {"id": "007", "name": "test-agent", "ip": "192.0.2.7"},
            "manager": {"name": "soc-manager"},
            "rule": {"id": "550", "level": 8, "description": "File changed", "groups": ["syscheck"]},
            "syscheck": {"path": "C:\\SOC-Lab\\watched\\hello.txt", "event": "modified"},
        }
        store = EventStore(tmp_path / "worker-failure.db")
        record, _ = store.accept(map_wazuh_alert(event), True)
        app = SimpleNamespace(state=SimpleNamespace(store=store, ai_slots=asyncio.Semaphore(1)))
        with patch("api.app.analyze", side_effect=RuntimeError("analysis failed")), \
                patch("api.app.send_investigation_alert") as notify:
            task = asyncio.create_task(ai_worker(app))
            for _ in range(100):
                await asyncio.sleep(.01)
                if store.get(record["id"])["ai_status"] == "failed":
                    break
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        assert store.get(record["id"])["ai_status"] == "failed"
        notify.assert_not_called()

    asyncio.run(run())


@pytest.mark.parametrize('audit_state', ['matching', 'other_incident', 'unavailable'])
def test_notification_uses_matching_full_report_without_expanding_saved_alert(tmp_path, audit_state):
    async def run():
        event = {
            'id': 'test-alert-full-report', 'timestamp': '2026-10-20T08:00:00+07:00',
            'agent': {'id': '007', 'name': 'test-agent'},
            'manager': {'name': 'soc-manager'},
            'rule': {'id': '550', 'level': 8, 'description': 'File changed', 'groups': ['syscheck']},
            'syscheck': {'path': '/tmp/example', 'event': 'modified'},
        }
        store = EventStore(tmp_path / 'worker-full-report.db')
        record, _ = store.accept(map_wazuh_alert(event), True)
        compact = {'incident_id': 'INV-one', 'verdict': 'inconclusive', 'tool_outcomes': []}
        full = {**compact, 'tool_outcomes': [{'tool': 'search_auth_events',
                'authentication_summary': {'groups': [{'failure_count': 11}]}}]}
        def current(_):
            if audit_state == 'unavailable':
                raise RuntimeError('audit unavailable')
            return {'id': 'INV-one' if audit_state == 'matching' else 'INV-other', 'report': full}
        app = SimpleNamespace(state=SimpleNamespace(store=store, ai_slots=asyncio.Semaphore(1),
                                                     investigation_store=SimpleNamespace(current=current)))
        with patch('api.app.analyze', return_value=(compact, {})), \
                patch('api.app.send_investigation_alert') as notify:
            task = asyncio.create_task(ai_worker(app))
            for _ in range(100):
                await asyncio.sleep(.01)
                if notify.called:
                    break
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        notify.assert_called_once()
        assert store.get(record['id'])['investigation_report'] == compact
        assert notify.call_args.args[0]['investigation_report'] == (full if audit_state == 'matching' else compact)

    asyncio.run(run())


def test_worker_persists_and_notifies_only_source_backed_preview(tmp_path):
    async def run():
        event={'id':'preview-alert','timestamp':'2026-10-20T08:00:00+07:00',
               'agent':{'id':'007','name':'lab'},'manager':{'name':'soc-manager'},
               'rule':{'id':'550','level':8,'description':'File changed','groups':['syscheck']},
               'syscheck':{'path':'/tmp/example','event':'modified'}}
        store=EventStore(tmp_path/'preview.db');record,_=store.accept(map_wazuh_alert(event),True)
        app=SimpleNamespace(state=SimpleNamespace(store=store,ai_slots=asyncio.Semaphore(1)))
        def analyze_preview(current,*args):
            current['grounded_response']={'status':'available','incident_id':'INV-1',
                'knowledge_guidance':{'playbook_id':'PB-1','source':'lab.txt','passages':[{'id':'G1','text':'Monitor the host.'}]},
                'actions':[{'status':'proposed','action':'increase_monitoring','target':'007',
                            'reason':'Theo dõi máy.', 'guidance_ids':['G1']}]}
            return {'incident_id':'INV-1','verdict':'inconclusive','recommendations':['Gợi ý không nguồn']},{}
        with patch('api.app.analyze',side_effect=analyze_preview), patch('api.app.send_investigation_alert') as notify:
            task=asyncio.create_task(ai_worker(app))
            for _ in range(100):
                await asyncio.sleep(.01)
                if notify.called:break
            task.cancel();await asyncio.gather(task,return_exceptions=True)
        notify.assert_called_once()
        saved=store.get(record['id']);assert saved['grounded_response']['incident_id']=='INV-1'
        message=format_investigation_alert(notify.call_args.args[0])
        assert 'PB-1' in message and 'Theo dõi máy.' in message and 'Monitor the host.' in message
        assert 'Gợi ý không nguồn' not in message
    asyncio.run(run())
