import json
from copy import deepcopy
import agents.rootkit_evidence as rootkit_evidence
from agents.investigation_tools import LocalTools
from agents.investigation_context import evidence_summary, pack_evidence
from agents.investigation_store import InvestigationStore
from agents.investigation_schema import Limits
from common.event_store import EventStore
from wazuh_integration.mapper import ai_eligible, map_wazuh_alert


BOOT = '11111111-1111-4111-8111-111111111111'


def raw_event(rule_id, timestamp='2026-11-25T01:00:00Z', data=None, full_log=''):
    return {
        'id': f'rootkit-{rule_id}-{timestamp}', 'timestamp': timestamp,
        'agent': {'id': '007', 'name': 'ubuntu', 'ip': '192.0.2.7'},
        'manager': {'name': 'manager'},
        'rule': {'id': str(rule_id), 'level': 7 if str(rule_id) == '521' else 3,
                 'description': 'Hidden process' if str(rule_id) == '521' else 'Endpoint observation',
                 'groups': ['rootcheck'] if str(rule_id) == '521' else ['endpoint_snapshot']},
        'full_log': full_log, 'data': data or {},
    }


def envelope(pid=123, finding='visible_process', boot=BOOT, observed='2026-11-25T01:00:03Z',
             wazuh_string=False):
    snapshot = {
        'producer': 'soc-ai-rootkit-snapshot-v1', 'observed_at': observed,
        'boot_id': boot, 'scan': {'mode': 'targeted', 'target_pid': pid},
        'suspects': [{'pid': pid, 'tgid': pid, 'finding': finding,
                      'kill0': 'exists', 'proc_visible': finding == 'visible_process',
                      'ps_visible': finding == 'visible_process',
                      'ps_thread_visible': finding == 'visible_process',
                      'recheck_kill0': 'exists', 'recheck_proc_visible': finding == 'visible_process',
                      'recheck_ps_visible': finding == 'visible_process',
                      'identity': {'pid': pid, 'tgid': pid, 'start_ticks': 42}}],
        'modules': {'visible_count': 10, 'kernel_taint': 0},
    }
    return {'producer': snapshot['producer'], 'observed_at': observed,
            'target_pid': str(pid) if wazuh_string else pid, 'finding': finding,
            'snapshot_json': json.dumps(snapshot)}


def rootkit_lab(tmp_path):
    store = EventStore(tmp_path / 'events.db')
    audit = InvestigationStore(tmp_path / 'audit.db')
    trigger = map_wazuh_alert(raw_event('521', full_log="Process '123' hidden from /proc"))
    store.accept(trigger, False)
    run = audit.create(trigger['id'], Limits().model_dump())
    return store, audit, trigger, LocalTools(store, audit, run['id'], trigger), run


def test_snapshot_is_decoded_but_raw_event_is_preserved_and_telemetry_is_not_ai_eligible():
    raw = raw_event('100206', data=envelope(wazuh_string=True))
    raw['timestamp'] = '2026-11-25T01:00:04.000+0000'
    raw['location'] = '/var/log/soc-ai-rootkit-snapshot.json'
    raw['rule']['groups'] = ['local', 'kernel_monitoring', 'endpoint_snapshot']
    raw['full_log'] = json.dumps(raw['data'])
    record = map_wazuh_alert(raw)
    assert record['rootkit_snapshot']['scan']['target_pid'] == 123
    assert record['rootkit_snapshot']['boot_id'] == BOOT
    assert record['rootkit_snapshot']['target_pid'] == 123
    assert record['raw_event']['data']['target_pid'] == '123'
    assert record['raw_event'] == raw
    assert record['event_kind'] == 'telemetry'
    assert not ai_eligible(record)
    high_level = raw_event('100206', data=envelope())
    high_level['rule']['level'] = 15
    assert not ai_eligible(map_wazuh_alert(high_level))


def test_invalid_snapshot_is_retained_but_not_used_as_evidence():
    bad = envelope()
    bad['snapshot_json'] = '{not-json'
    record = map_wazuh_alert(raw_event('100206', data=bad))
    assert 'rootkit_snapshot' not in record
    assert record['rootkit_snapshot_error'] == 'invalid_snapshot_schema'
    assert record['raw_event']['data']['snapshot_json'] == '{not-json'


def test_snapshot_schema_rejects_invalid_pid_timestamp_and_boot():
    for mutate in (
        lambda value: value.update(target_pid='123x'),
        lambda value: value.update(target_pid=' 123'),
        lambda value: value.update(target_pid=True),
        lambda value: value.update(observed_at='2026-11-25T01:00:03'),
        lambda value: value.update(snapshot_json=value['snapshot_json'].replace(BOOT, 'not-a-boot-id')),
        lambda value: value.update(snapshot_json=value['snapshot_json'].replace('"target_pid": 123', '"target_pid": 456')),
    ):
        data = envelope()
        mutate(data)
        record = map_wazuh_alert(raw_event('100206', data=data))
        assert 'rootkit_snapshot' not in record
        assert record['rootkit_snapshot_error'] == 'invalid_snapshot_schema'


def test_rootkit_search_prioritizes_valid_snapshot_and_classifies_telemetry(tmp_path):
    store = EventStore(tmp_path / 'events.db')
    audit = InvestigationStore(tmp_path / 'audit.db')
    trigger = map_wazuh_alert(raw_event('521', full_log="Process '123' hidden from /proc"))
    snapshot = map_wazuh_alert(raw_event('100206', timestamp='2026-11-25T01:00:04Z', data=envelope()))
    taint = map_wazuh_alert(raw_event('100201', timestamp='2026-11-25T01:00:05Z', data={'message': 'kernel-taint-check'}))
    store.accept(trigger, False)
    store.accept(snapshot, False)
    store.accept(taint, False)
    run = audit.create(trigger['id'], Limits().model_dump())
    tools = LocalTools(store, audit, run['id'], trigger)
    result = tools.execute('search_rootkit_evidence', {'limit': 1})
    assert result['status'] == 'truncated'
    assert result['items'][0]['rootkit_snapshot']['target_pid'] == 123
    assert result['items'][0]['rootkit_evidence_class'] == 'endpoint_observation'
    assert result['snapshot_count'] == 1
    assert result['positive_snapshot_count'] == 0
    assert result['related_alert_count'] == 1


def test_late_snapshot_uses_observed_at_window_not_wazuh_arrival_time(tmp_path):
    store = EventStore(tmp_path / 'events.db')
    audit = InvestigationStore(tmp_path / 'audit.db')
    trigger = map_wazuh_alert(raw_event('521', full_log="Process '123' hidden from /proc"))
    late = map_wazuh_alert(raw_event('100206', timestamp='2026-11-25T02:00:00Z',
                                    data=envelope(wazuh_string=True)))
    store.accept(trigger, False)
    store.accept(late, False)
    run = audit.create(trigger['id'], Limits().model_dump())
    result = LocalTools(store, audit, run['id'], trigger).execute('search_rootkit_evidence', {})
    assert result['snapshot_count'] == 1


def test_snapshot_pid_reuse_is_not_positive_confirmation(tmp_path):
    store = EventStore(tmp_path / 'events.db')
    audit = InvestigationStore(tmp_path / 'audit.db')
    trigger = map_wazuh_alert(raw_event('521', full_log="Process '123' hidden from /proc"))
    reused = envelope(pid=123, finding='identity_changed')
    reused['snapshot_json'] = reused['snapshot_json'].replace('"start_ticks": 42', '"start_ticks": 99')
    snapshot = map_wazuh_alert(raw_event('100206', timestamp='2026-11-25T01:00:04Z', data=reused))
    store.accept(trigger, False)
    store.accept(snapshot, False)
    run = audit.create(trigger['id'], Limits().model_dump())
    result = LocalTools(store, audit, run['id'], trigger).execute('search_rootkit_evidence', {})
    assert result['snapshot_count'] == 1
    assert result['positive_snapshot_count'] == 0


def test_wrong_agent_and_thread_observations_do_not_confirm_trigger(tmp_path):
    store = EventStore(tmp_path / 'events.db')
    audit = InvestigationStore(tmp_path / 'audit.db')
    trigger = map_wazuh_alert(raw_event('521', full_log="Process '123' hidden from /proc"))
    thread_data = envelope(pid=123, finding='stable_process_visibility_discrepancy')
    thread_data['snapshot_json'] = thread_data['snapshot_json'].replace('"tgid": 123', '"tgid": 456')
    thread = map_wazuh_alert(raw_event('100206', timestamp='2026-11-25T01:00:04Z', data=thread_data))
    other_agent = map_wazuh_alert(raw_event('100206', timestamp='2026-11-25T01:00:05Z', data=envelope()))
    other_agent['agent'] = {'id': '008', 'name': 'other', 'ip': '192.0.2.8'}
    store.accept(trigger, False)
    store.accept(thread, False)
    store.accept(other_agent, False)
    run = audit.create(trigger['id'], Limits().model_dump())
    result = LocalTools(store, audit, run['id'], trigger).execute('search_rootkit_evidence', {})
    assert result['snapshot_count'] == 1
    assert result['positive_snapshot_count'] == 0


def test_wazuh_string_pid_filters_shell_snapshot_and_records_schema_errors(tmp_path):
    store, audit, trigger, tools, _ = rootkit_lab(tmp_path)
    shell_raw = raw_event('100206', '2026-11-25T01:00:04Z', envelope(pid=105271, wazuh_string=True))
    shell_raw['full_log'] = json.dumps(shell_raw['data'])
    shell = map_wazuh_alert(shell_raw)
    matching = map_wazuh_alert(raw_event('100206', '2026-11-25T01:00:05Z',
                                         envelope(pid=123, wazuh_string=True)))
    wrong_agent_raw = raw_event('100206', '2026-11-25T01:00:06Z',
                                envelope(pid=123, wazuh_string=True))
    wrong_agent_raw['agent']['id'] = '008'
    wrong_agent = map_wazuh_alert(wrong_agent_raw)
    invalid_data = envelope(pid=123, wazuh_string=True)
    invalid_data['snapshot_json'] = '{bad-json'
    invalid = map_wazuh_alert(raw_event('100206', '2026-11-25T01:00:07Z', invalid_data))
    for record in (shell, matching, wrong_agent, invalid):
        store.accept(record, False)
    result = tools.execute('search_rootkit_evidence', {'limit': 10})
    assert result['target_pid'] == 123
    assert result['snapshot_count'] == 1
    assert result['invalid_snapshot_count'] == 1
    assert result['invalid_snapshot_source_ids'] == [invalid['id']]
    assert result['related_alert_count'] == 0
    assert [item['id'] for item in result['items']] == [matching['id']]
    assert all(item['id'] not in {shell['id'], wrong_agent['id'], invalid['id']} for item in result['items'])
    assert store.get(shell['id'])['raw_event'] == shell_raw
    summary = evidence_summary(audit.evidence(tools.incident_id)[0])['data']['rootkit_snapshot']
    assert summary['target_pid'] == 123 and summary['finding'] == 'visible_process'
    assert summary['boot_id'] == BOOT
    assert summary['boot_id_status'] == 'reported_by_endpoint_not_cross_verified'
    assert summary['observed_at'] == '2026-11-25T01:00:03Z'
    assert summary['observation_limit']
    context = pack_evidence(audit.evidence(tools.incident_id), 3000)
    assert context['evidence'][0]['data']['rootkit_snapshot']['target_pid'] == 123


def test_existing_schema_error_row_is_reparsed_without_rewriting_raw_event(tmp_path):
    store, _, _, tools, _ = rootkit_lab(tmp_path)
    old = map_wazuh_alert(raw_event('100206', '2026-11-25T01:00:04Z',
                                    envelope(pid=123, wazuh_string=True)))
    old.pop('rootkit_snapshot')
    old['rootkit_snapshot_error'] = 'invalid_snapshot_schema'
    store.accept(old, False)
    result = tools.execute('search_rootkit_evidence', {})
    assert result['snapshot_count'] == 1
    assert result['items'][0]['rootkit_snapshot']['target_pid'] == 123
    assert store.get(old['id'])['rootkit_snapshot_error'] == 'invalid_snapshot_schema'


def test_alert_archive_duplicate_keeps_source_ids_and_one_evidence_id(tmp_path):
    store, audit, _, tools, _ = rootkit_lab(tmp_path)
    first_raw = raw_event('100206', '2026-11-25T01:00:04Z',
                          envelope(pid=123, wazuh_string=True))
    archive_raw = deepcopy(first_raw)
    archive_raw['id'] = 'archive-copy-of-same-observation'
    archive_raw['_soc_stream'] = 'archives'
    first = map_wazuh_alert(first_raw)
    archive = map_wazuh_alert(archive_raw)
    store.accept(archive, False)
    store.accept(first, False)
    result = tools.execute('search_rootkit_evidence', {})
    assert result['snapshot_count'] == 1
    assert result['total_matched'] == 2 and result['consolidated_count'] == 1
    assert result['duplicate_record_count'] == 1
    assert len(result['items']) == 1
    assert result['items'][0]['id'] == first['id']
    assert set(result['items'][0]['rootkit_source_record_ids']) == {first['id'], archive['id']}
    assert len(audit.evidence(tools.incident_id)) == 1
    assert store.get(archive['id'])['raw_event']['data'] == archive_raw['data']


def test_identical_kernel_taint_is_compacted_with_original_ids(tmp_path):
    store, audit, _, tools, _ = rootkit_lab(tmp_path)
    ids = []
    for index in range(5):
        raw = raw_event('100201', f'2026-11-25T01:0{index}:00Z',
                        full_log='kernel_taint current=12288 baseline=12288 changed=no')
        record = map_wazuh_alert(raw)
        store.accept(record, False)
        ids.append(record['id'])
        if index == 2:
            archived_raw = deepcopy(raw)
            archived_raw['id'] = 'archive-taint-copy'
            archived_raw['_soc_stream'] = 'archives'
            archived = map_wazuh_alert(archived_raw)
            store.accept(archived, False)
            ids.append(archived['id'])
    result = tools.execute('search_rootkit_evidence', {'limit': 1})
    assert result['total_matched'] == 6 and result['consolidated_count'] == 1
    assert result['duplicate_record_count'] == 1
    assert result['periodic_taint_record_count'] == 4
    assert result['returned_count'] == 1 and not result['truncated']
    summary = result['items'][0]['rootkit_telemetry_summary']
    assert summary['source_record_count'] == 6 and summary['observation_count'] == 5
    assert set(summary['source_record_ids_sample']) == set(ids)
    context = evidence_summary(audit.evidence(tools.incident_id)[0])['data']
    assert context['rootkit_telemetry_summary']['observation_count'] == 5
    assert all(store.get(record_id) for record_id in ids)


def test_matching_snapshot_is_prioritized_ahead_of_large_taint_burst(tmp_path):
    store, _, _, tools, _ = rootkit_lab(tmp_path)
    for index in range(205):
        raw = raw_event('100201', f'2026-11-25T01:00:{index // 4:02d}Z',
                        full_log=f'kernel-taint-check sample={index}')
        raw['id'] = f'taint-{index}'
        store.accept(map_wazuh_alert(raw), False)
    snapshot = map_wazuh_alert(raw_event('100206', '2026-11-25T01:10:00Z',
                                        envelope(pid=123, wazuh_string=True)))
    store.accept(snapshot, False)
    result = tools.execute('search_rootkit_evidence', {'limit': 1})
    assert result['items'][0]['id'] == snapshot['id']
    assert result['snapshot_count'] == 1
    assert result['total_matched'] == 206 and result['truncated']


def test_candidate_cap_is_explicit_and_still_selects_matching_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(rootkit_evidence, 'MAX_CANDIDATES', 3)
    store, _, _, tools, _ = rootkit_lab(tmp_path)
    for index in range(5):
        raw = raw_event('100201', f'2026-11-25T01:0{index}:00Z',
                        full_log=f'kernel-taint-check sample={index}')
        store.accept(map_wazuh_alert(raw), False)
    matching_data = envelope(pid=123, wazuh_string=True)
    matching_data['target_pid'] = '000123'
    matching = map_wazuh_alert(raw_event('100206', '2026-11-25T01:10:00Z', matching_data))
    store.accept(matching, False)
    result = tools.execute('search_rootkit_evidence', {'limit': 1})
    assert result['items'][0]['id'] == matching['id']
    assert result['candidate_limit_reached']
    assert result['total_matched_is_lower_bound'] and result['truncated']


def test_matching_discrepancy_precedes_visible_process_with_small_limit(tmp_path):
    store, _, _, tools, _ = rootkit_lab(tmp_path)
    visible = map_wazuh_alert(raw_event('100206', '2026-11-25T01:00:04Z',
                                        envelope(pid=123, wazuh_string=True)))
    positive = map_wazuh_alert(raw_event('100206', '2026-11-25T01:00:05Z',
                                         envelope(pid=123, finding='stable_process_visibility_discrepancy',
                                                  observed='2026-11-25T01:00:04Z', wazuh_string=True)))
    store.accept(visible, False)
    store.accept(positive, False)
    result = tools.execute('search_rootkit_evidence', {'limit': 1})
    assert result['items'][0]['id'] == positive['id']
    assert result['positive_snapshot_count'] == 1
    assert result['snapshot_count'] == 2
