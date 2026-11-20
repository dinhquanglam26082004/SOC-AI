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
            "incident_id": "INV-1",
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
        "grounded_response": {"status":"available", "incident_id":"INV-1",
            "knowledge_guidance":{"playbook_id":"PB-SSH", "source":"ssh.txt", "passages":[{"id":"G1","text":"Review the source."}]},
            "actions":[{"status":"proposed","action":"block_ip","target":"192.0.2.7",
                        "reason":"Review access and block the source if confirmed.","guidance_ids":["G1"]}]},
    }

    with patch("common.telegram_notifier.requests.post", return_value=response) as post:
        assert send_investigation_alert(record)

    args, kwargs = post.call_args
    assert args == ("https://api.telegram.org/bottest-token/sendMessage",)
    assert kwargs["json"]["chat_id"] == "soc-chat"
    assert "Confidence" not in kwargs["json"]["text"]
    text = kwargs["json"]["text"]
    assert "SỐ LIỆU GHI NHẬN" not in text
    assert "SSH brute force" in text and "Độc hại" in text
    assert "Review access and block the source if confirmed." in text
    assert 'Nguồn: PB-SSH · ssh.txt' in text and '[G1]' in text
    assert "ĐÁNH GIÁ CỦA AI" in text
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
    assert '3 / 0' in msg and 'không phải tổng lưu lượng' in msg
    assert 'search_zeek_connections (bị cắt)' in msg
    assert '100 gói' not in msg
    assert 'Confidence' not in msg


def test_valid_sensor_summary_labels_unit():
    msg=format_investigation_alert({'dos_summary':{'metric':'http_requests','observed':100,'window_seconds':10,
        'observed_per_second':10.,'source_count':2,'source_count_capped':True}})
    assert '100 quan sát trong 10 giây' in msg
    assert '100 gói' not in msg


def test_authentication_message_shows_scoped_evidence_and_truncation():
    msg = format_investigation_alert({'rule': {'id': '5712', 'level': 7, 'description': 'SSH failure'},
        'agent': {'name': 'ubuntu', 'ip': '192.0.2.4'}, 'username': 'victim',
        'investigation_report': {'tool_outcomes': [{'tool': 'search_auth_events', 'status': 'truncated',
            'count': 2, 'total_matched': 15, 'authentication_summary': {'groups': [
                {'username': 'victim', 'source_ip': '192.0.2.7', 'failure_count': 3, 'success_count': 0, 'unknown_count': 1}]}}]}})
    assert 'victim · 192.0.2.7: thất bại: 3 | thành công: 0 | không rõ: 1' in msg
    assert 'search_auth_events (bị cắt)' in msg
    assert 'Một số kết quả bị cắt' in msg and 'không nhất thiết là số lần thử duy nhất' in msg


def test_skipped_repeat_is_not_reported_as_a_second_tool_execution():
    msg=format_investigation_alert({'investigation_report':{'tool_outcomes':[
        {'tool':'search_auth_events','status':'ok','count':3},
        {'tool':'search_auth_events','status':'skipped','error':'tool_already_used','count':0}]}})
    assert '🛠 Công cụ: search_auth_events' in msg
    assert 'Đã bỏ qua gọi lại: search_auth_events' in msg
    assert 'skipped' not in msg and 'tool_already_used' not in msg


def test_assessment_and_recommendations_are_taken_from_each_report():
    a = format_investigation_alert({'investigation_report': {'incident_id':'INV-1','verdict': 'inconclusive',
        'reasoning': 'DNS tunneling chưa được xác nhận.',
        'findings': [{'statement': 'Truy vấn DNS đã ghi nhận.', 'evidence_ids': ['EV-123']}],
        'recommendations': ['Gợi ý cũ chưa gắn nguồn.'], 'needs_analyst': True},
        'grounded_response':{'status':'available','incident_id':'INV-1',
            'knowledge_guidance':{'playbook_id':'PB-DNS','source':'dns.txt','passages':[{'id':'G1','text':'Monitor DNS.'}]},
            'actions':[{'status':'proposed','action':'increase_monitoring','target':'example.test',
                        'reason':'Kiểm tra truy vấn tới example.test.','guidance_ids':['G1']}]}})
    b = format_investigation_alert({'investigation_report': {'verdict': 'inconclusive',
        'reasoning': 'SSH brute force chưa được xác nhận.', 'recommendations': []}})
    assert 'DNS tunneling chưa được xác nhận.' in a and 'EV-123' not in a
    assert 'Kiểm tra truy vấn tới example.test.' in a and 'Cần chuyên viên xem xét' in a
    assert 'Gợi ý cũ chưa gắn nguồn.' not in a and 'PB-DNS' in a
    assert 'SSH brute force chưa được xác nhận.' in b
    assert 'Chưa có gợi ý phản ứng gắn nguồn' in b and 'example.test' not in b


def test_telegram_ignores_unreferenced_and_other_incident_recommendations():
    record={'investigation_report':{'incident_id':'INV-current','recommendations':['Gợi ý không nguồn']},
        'grounded_response':{'status':'available','incident_id':'INV-other',
            'knowledge_guidance':{'playbook_id':'PB-X','passages':[{'id':'G1','text':'Monitor.'}]},
            'actions':[{'status':'proposed','action':'increase_monitoring','target':'host','guidance_ids':['G1']}]}}
    msg=format_investigation_alert(record)
    assert 'Gợi ý không nguồn' not in msg and 'PB-X' not in msg
    assert 'Chưa có gợi ý phản ứng gắn nguồn' in msg


def test_dns_summary_uses_its_actual_scope_not_rule_window():
    msg = format_investigation_alert({
        'rule': {'id': '100153', 'description': 'Nghi DNS tunneling trong 120s'},
        'zeek_data': {'qtype_name': 'NULL'},
        'investigation_report': {'verdict': 'inconclusive', 'tool_outcomes': [{
            'tool': 'summarize_dns_activity', 'status': 'ok', 'dns_summary': {
                'matched_records': 80, 'unique_queries': 65,
                'query_types': {'A': 30, 'CNAME': 10, 'MX': 8, 'NULL': 25},
                'scope': {'domain': 'tunnel.lab.local', 'since': '2026-11-20T00:39:00Z',
                          'until': '2026-11-20T01:09:00Z', 'window_seconds': 1800}}}]}})
    assert '80 bản ghi đã lưu' in msg and '65 tên truy vấn khác nhau' in msg
    assert '2026-11-20T00:39:00Z → 2026-11-20T01:09:00Z' in msg
    assert 'Loại query: NULL: 25, A: 30' in msg and 'trùng lặp' in msg
    assert '80 bản ghi trong 120' not in msg
    assert len(msg) < 1200


def test_partial_flow_summary_preserves_scope_and_missing_packet_fields():
    msg = format_investigation_alert({'investigation_report': {'tool_outcomes': [{
        'tool': 'summarize_zeek_flows', 'status': 'ok', 'flow_summary': {
            'flow_observations': 20, 'scope': {'since': '10:00Z', 'until': '10:05Z'},
            'totals': {'orig_pkts': 30, 'resp_pkts': 2}, 'missing_fields': {'orig_pkts': 3, 'resp_pkts': 0}}}]}})
    assert 'Flow: 20 quan sát đã lưu' in msg and '10:00Z → 10:05Z' in msg
    assert '30 / 2' in msg and 'thiếu trường: 3 / 0' in msg


def test_unavailable_dns_summary_does_not_create_numbers():
    msg = format_investigation_alert({'investigation_report': {'tool_outcomes': [
        {'tool': 'summarize_dns_activity', 'status': 'unavailable'}]}})
    assert 'summarize_dns_activity (không khả dụng)' in msg
    assert 'DNS: 0' not in msg


def test_long_identifiers_are_shortened_and_tool_failure_is_visible():
    alert_id = 'WAZUH-' + 'a' * 64
    msg = format_investigation_alert({'investigation_report': {
        'reasoning': 'Cảnh báo ' + alert_id + ' cần kiểm tra.',
        'tool_outcomes': [{'tool': f'tool_{n}', 'status': 'ok'} for n in range(6)] + [
            {'tool': 'important_dns', 'status': 'error'}]}})
    assert alert_id not in msg and 'Cảnh báo [ID] cần kiểm tra.' in msg
    assert 'important_dns (lỗi)' in msg
