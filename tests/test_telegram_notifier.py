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
    assert "Verdict: malicious" in kwargs["json"]["text"]
    assert "Confidence: 90%" in kwargs["json"]["text"]
    assert "SSH Brute Force Response" in kwargs["json"]["text"]
    assert "1. Validate source." in kwargs["json"]["text"]
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
