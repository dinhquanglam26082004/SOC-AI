from agents.investigation_schema import Limits
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools
from agents.investigation_context import compact_auth_summary
from common.event_store import EventStore
from common.investigation_index import migrate
from evaluation.investigation_cases import raw
from wazuh_integration.mapper import map_wazuh_alert


def test_auth_summary_counts_one_sshd_attempt_not_related_pam_and_aggregate_records(tmp_path):
    store = EventStore(tmp_path / 'events.sqlite3')
    audit = InvestigationStore(tmp_path / 'investigations.sqlite3')

    ssh = raw(20)
    ssh.update(decoder={'name': 'sshd'}, predecoder={'program_name': 'sshd'},
               full_log='Failed password for lab-user from 198.51.100.8 port 54321 ssh2')
    alert = map_wazuh_alert(ssh)
    store.accept(alert, False)

    pam = raw(21)
    pam.update(decoder={'name': 'pam'}, predecoder={'program_name': 'sshd'},
               full_log='pam_unix(sshd:auth): authentication failure; rhost=198.51.100.8 user=lab-user')
    pam['rule'].update(id='5503', description='PAM: User login failed')
    store.accept(map_wazuh_alert(pam), False)

    aggregate = raw(22)
    aggregate.update(decoder={'name': 'syslog'}, predecoder={'program_name': 'sshd'},
                     full_log='sshd: more authentication failures;')
    aggregate['rule'].update(id='2502', description='Repeated login failures')
    store.accept(map_wazuh_alert(aggregate), False)

    repeated_aggregate = raw(23)
    repeated_aggregate.update(decoder={'name': 'syslog'}, predecoder={'program_name': 'sshd'},
                              full_log='sshd: more authentication failures;')
    repeated_aggregate['rule'].update(id='2502', description='Repeated login failures')
    store.accept(map_wazuh_alert(repeated_aggregate), False)

    run = audit.create(alert['id'], Limits().model_dump())
    tools = LocalTools(store, audit, run['id'], alert)
    result = tools.execute('search_auth_events', {})
    group = next(g for g in result['authentication_summary']['groups']
                 if g['username'] == 'lab-user' and g['source_ip'] == '198.51.100.8')
    assert group['failure_count'] == 1
    assert group['failure_record_count'] == 4
    assert group['unclassified_failure_record_count'] == 3


def test_legacy_auth_summaries_are_not_represented_as_attempt_counts():
    summary = compact_auth_summary({
        'groups': [{'username': 'lab-user', 'failure_count': 3, 'success_count': 1,
                    'failure_before_success': True}],
        'count_unit': 'Retained normalized records, not unique authentication sessions.',
    })
    group = summary['groups'][0]
    assert group['failure_count'] == 'unavailable' and group['failure_record_count'] == 3
    assert group['success_count'] == 'unavailable' and group['success_record_count'] == 1
    assert group.get('failure_before_success') is None
    assert 'attempt counts are unavailable' in summary['count_unit']


def test_existing_auth_fact_table_is_migrated_and_backfilled(tmp_path):
    store = EventStore(tmp_path / 'events.sqlite3')
    event = raw(30)
    event.update(decoder={'name': 'sshd'}, predecoder={'program_name': 'sshd'},
                 full_log='Failed password for lab-user from 198.51.100.8 port 54321 ssh2')
    record = map_wazuh_alert(event)
    store.accept(record, False)

    with store.connect() as db:
        db.execute('ALTER TABLE authentication_facts DROP COLUMN attempt_outcome')
        db.execute("DELETE FROM migrations WHERE name='authentication_attempt_facts_v1'")
        migrate(db)
        row = db.execute('SELECT attempt_outcome FROM authentication_facts WHERE id=?',
                         (record['id'],)).fetchone()
    assert row[0] == 'failure'
