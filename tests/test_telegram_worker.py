import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from api.app import ai_worker
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
                if store.get(record["id"])["ai_status"] == "completed":
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
