import pytest

from agents import playbook_agent


def test_returns_existing_playbook_verbatim_without_model_call(tmp_path, monkeypatch):
    source = "PB-SSH-001_ssh_bruteforce.txt"
    expected = (
        "PLAYBOOK ID: PB-SSH-001\n\n"
        "NAME:\nSSH Brute Force Response\n\n"
        "TRIGGER:\nRepeated failed SSH logins.\n\n"
        "RESPONSE:\n1. Block the source IP."
    )
    (tmp_path / source).write_text(expected, encoding="utf-8")
    monkeypatch.setattr(playbook_agent, "PLAYBOOK_ROOT", tmp_path)
    calls = []

    def retrieve(query, top_k):
        calls.append((query, top_k))
        return [
            {"text": "RESPONSE: 1. Block the source IP.", "metadata": {
                "type": "playbooks", "source": source, "chunk_idx": 2,
            }},
        ]

    monkeypatch.setattr(playbook_agent, "_retrieve_playbooks", retrieve)
    report = {
        "_alert_id": "alert-1",
        "verdict": "malicious",
        "incident_type": "SSH brute force",
    }

    result = playbook_agent.propose_playbook(report)

    assert len(calls) == 1 and calls[0][1] == 16
    assert result["status"] == "matched"
    assert result["playbook_id"] == "PB-SSH-001"
    assert result["playbook_name"] == "SSH Brute Force Response"
    assert result["playbook_source"] == source
    assert result["playbook_text"] == expected
    assert result["actions"] == []


@pytest.mark.parametrize("verdict", ["benign", "inconclusive"])
def test_does_not_select_playbook_for_non_malicious_verdict(verdict, monkeypatch):
    def unexpected_retrieval(*args, **kwargs):
        raise AssertionError("Should not retrieve a response playbook")

    monkeypatch.setattr(playbook_agent, "_retrieve_playbooks", unexpected_retrieval)

    result = playbook_agent.propose_playbook({
        "verdict": verdict,
        "incident_type": "Unknown security event",
    })

    assert result["status"] == "not_applicable"
    assert result["playbook_id"] is None
    assert result["playbook_text"] is None


def test_returns_not_found_when_no_existing_playbook_matches(monkeypatch):
    monkeypatch.setattr(playbook_agent, "_retrieve_playbooks", lambda *args, **kwargs: [])

    result = playbook_agent.propose_playbook({
        "verdict": "malicious",
        "incident_type": "unknown incident",
    })

    assert result["status"] == "not_found"
    assert result["playbook_id"] is None
    assert result["actions"] == []


def test_rejects_source_outside_playbook_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_agent, "PLAYBOOK_ROOT", tmp_path)
    monkeypatch.setattr(
        playbook_agent,
        "_retrieve_playbooks",
        lambda *args, **kwargs: [{"metadata": {
            "type": "playbooks", "source": "..\\outside.txt",
        }}],
    )

    with pytest.raises(ValueError, match="invalid source filename"):
        playbook_agent.propose_playbook({"verdict": "malicious"})


def test_dos_playbook_is_an_existing_selectable_source(monkeypatch):
    source = "PB-DOS-001_denial_of_service.txt"
    monkeypatch.setattr(
        playbook_agent,
        "_retrieve_playbooks",
        lambda *args, **kwargs: [
            {"metadata": {"type": "playbooks", "source": "PB-MAL-001_malware_detection.txt"}},
            {"metadata": {"type": "playbooks", "source": source}},
        ],
    )

    result = playbook_agent.propose_playbook({
        "verdict": "malicious",
        "incident_type": "suspected DoS",
    })

    assert result["status"] == "matched"
    assert result["playbook_id"] == "PB-DOS-001"
    assert result["playbook_name"] == "Suspected Denial of Service Response"
    assert "not proof that the service is unavailable" in result["playbook_text"]
    assert "Human approval" in result["playbook_text"]
    assert result["actions"] == []


def test_dos_report_does_not_fall_back_to_unrelated_playbook(monkeypatch):
    monkeypatch.setattr(
        playbook_agent,
        "_retrieve_playbooks",
        lambda *args, **kwargs: [{"metadata": {
            "type": "playbooks", "source": "PB-MAL-001_malware_detection.txt",
        }}],
    )

    result = playbook_agent.propose_playbook({
        "verdict": "inconclusive",
        "incident_type": "Suspected DDoS",
    })

    assert result["status"] == "not_found"
    assert result["playbook_id"] is None


def test_inconclusive_dos_can_retrieve_playbook_without_claiming_confirmation(monkeypatch):
    source = "PB-DOS-001_denial_of_service.txt"
    monkeypatch.setattr(
        playbook_agent,
        "_retrieve_playbooks",
        lambda *args, **kwargs: [{"metadata": {
            "type": "playbooks", "source": source,
        }}],
    )

    result = playbook_agent.propose_playbook({
        "verdict": "inconclusive",
        "incident_type": "Suspected DoS",
        "unknowns": ["Service impact is unverified."],
    })

    assert result["status"] == "matched"
    assert "remains inconclusive" in result["notes"]
    assert result["actions"] == []


@pytest.mark.parametrize(
    "alert",
    [
        {"rule": {"id": "100142", "groups": ["zeek_detection", "zeek_dos"]}},
        {"rule": {"id": "100164", "groups": ["zeek_detection", "zeek_dos_summary"]}},
        {"detection": {"category": "suspected_dos"}},
    ],
)
def test_trusted_dos_alert_selects_dos_playbook_for_generic_inconclusive_report(monkeypatch, alert):
    source = "PB-DOS-001_denial_of_service.txt"
    queries = []

    def retrieve(query, top_k):
        queries.append(query)
        return [
            {"metadata": {"type": "playbooks", "source": "PB-MAL-001_malware_detection.txt"}},
            {"metadata": {"type": "playbooks", "source": source}},
        ]

    monkeypatch.setattr(playbook_agent, "_retrieve_playbooks", retrieve)

    result = playbook_agent.propose_playbook(
        {"verdict": "inconclusive", "incident_type": "Network anomaly"},
        alert=alert,
    )

    assert result["status"] == "matched"
    assert result["playbook_id"] == "PB-DOS-001"
    assert "suspected DoS" in queries[0]
    assert "remains inconclusive" in result["notes"]
