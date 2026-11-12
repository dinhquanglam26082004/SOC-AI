from unittest.mock import Mock, patch

import pytest

from common.telegram_notifier import format_investigation_alert, send_investigation_alert


def test_sends_completed_investigation_and_playbook_without_markdown(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "soc-chat")
    response = Mock()
    response.json.return_value = {"ok": True}
    record = {
        "id": "alert-1",
        "rule": {"description": "SSH brute force"},
        "agent": {"name": "ubuntu-lab"},
        "investigation_report": {
            "incident_type": "SSH brute force",
            "verdict": "malicious",
            "confidence": 0.9,
            "findings": [{"statement": "Repeated failed SSH logins."}],
            "unknowns": ["Source ownership is unverified."],
            "recommendations": ["Review access and block the source if confirmed."],
        },
        "playbook_proposal": {
            "status": "matched",
            "playbook_name": "SSH Brute Force Response",
            "playbook_text": "1. Validate source. 2. Block if confirmed.",
            "notes": "Existing playbook retrieved; no action was executed.",
        },
    }

    with patch("common.telegram_notifier.requests.post", return_value=response) as post:
        assert send_investigation_alert(record)

    args, kwargs = post.call_args
    assert args == ("https://api.telegram.org/bottest-token/sendMessage",)
    assert kwargs["json"]["chat_id"] == "soc-chat"
    assert "Confidence" not in kwargs["json"]["text"]
    assert "Tool history unavailable" in kwargs["json"]["text"]
    assert "RECORDED MEASUREMENTS" not in kwargs["json"]["text"]
    assert "parse_mode" not in kwargs["json"]
    assert kwargs["timeout"] == (3, 8)
    response.raise_for_status.assert_called_once_with()


def test_notification_is_disabled_without_configuration(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    with patch("common.telegram_notifier.requests.post") as post:
        assert not send_investigation_alert({})
    post.assert_not_called()


def test_partial_configuration_is_rejected(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    with pytest.raises(RuntimeError, match="required"):
        send_investigation_alert({})


def test_telegram_api_rejection_is_reported(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "soc-chat")
    response = Mock()
    response.json.return_value = {"ok": False}
    with patch("common.telegram_notifier.requests.post", return_value=response):
        with pytest.raises(RuntimeError, match="rejected"):
            send_investigation_alert({})


def test_notification_message_is_capped():
    message = format_investigation_alert({
        "investigation_report": {
            "reasoning": "x" * 10_000,
            "findings": [{"statement": "x" * 10_000}],
            "recommendations": ["x" * 10_000],
        },
        "playbook_proposal": {"notes": "x" * 10_000},
    })
    assert len(message) <= 4000


def test_zeek_measurements_are_not_misrepresented_as_window_totals():
    msg=format_investigation_alert({'source_product':'zeek','log_type':'conn',
        'zeek_data':{'orig_pkts':3,'resp_pkts':0,'duration':0.5},
        'investigation_report':{'tool_outcomes':[{'tool':'search_zeek_connections','status':'truncated','count':20,'total_matched':100}]}})
    assert '3 / 0' in msg and 'not the total for the attack window' in msg
    assert 'Window-wide packet count, rate and duration: unavailable' in msg
    assert '100 matching retained records' in msg and 'truncated' in msg
    assert 'Confidence' not in msg


def test_valid_sensor_summary_labels_unit():
    msg=format_investigation_alert({'dos_summary':{'metric':'http_requests','observed':100,'window_seconds':10,
        'observed_per_second':10.,'source_count':2,'source_count_capped':True}})
    assert '100 in 10 seconds' in msg and '10.00 observations/second' in msg
    assert 'not packet counts' in msg and 'count capped' in msg


def test_authentication_message_shows_scoped_evidence_and_truncation():
    msg = format_investigation_alert({'rule': {'id': '5712', 'level': 7, 'description': 'SSH failure'},
        'agent': {'name': 'ubuntu', 'ip': '192.0.2.4'}, 'username': 'victim',
        'investigation_report': {'tool_outcomes': [{'tool': 'search_auth_events', 'status': 'truncated',
            'count': 2, 'total_matched': 15, 'authentication_summary': {'groups': [
                {'username': 'victim', 'source_ip': '192.0.2.7', 'failure_count': 3, 'success_count': 0, 'unknown_count': 1}]}}]}})
    assert 'User: victim' in msg and 'Failed: 3 | Success: 0 | Unknown: 1' in msg
    assert '2 returned / 15 matching retained records' in msg
    assert 'Some tool results are incomplete' in msg and 'not unique attempts' in msg
