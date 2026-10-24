import base64
from copy import deepcopy
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from common.event_store import EventStore, QueueFull
from common.log_index import LEGACY_UNIFIED, utc_stamp


def record(i, zeek=False, kind='alert'):
    stamp = f'2026-10-20T01:{i//60:02}:{i%60:02}.000000Z'
    value = {'id': f'WAZUH-{i:05}', 'source': 'wazuh', 'timestamp': stamp, 'received_at': stamp,
             'created_at': stamp, 'event_kind': kind, 'ai_status': 'skipped',
             'rule': {'id': '100122', 'level': 8, 'description': 'scan evidence', 'groups': ['zeek_detection'] if zeek else ['attack']},
             'agent': {'id': '001', 'name': 'sensor-alpha', 'ip': '192.0.2.7'},
             'src_ip': '192.0.2.10', 'dst_ip': '192.0.2.20', 'severity': 'MEDIUM',
             'raw_event': {'full_log': 'payload-only-needle'}}
    if zeek:
        value.update(source_product='zeek', log_type='notice' if kind=='alert' else 'http',
                     zeek_data={'host': 'lab.invalid'})
    return value


def legacy_page(db, limit=17, before=None, source=None, log_type=None, kind=None):
    filters, params = [], []
    for col, value in (('origin', source), ('log_type', log_type), ('kind', kind)):
        if value:
            filters.append(col+'=?')
            params.append(value)
    where = ' WHERE '+' AND '.join(filters) if filters else ''
    page_where, page_params = where, list(params)
    if before:
        stamp, identifier = json.loads(base64.urlsafe_b64decode(before).decode())
        page_where += (' AND ' if page_where else ' WHERE ')+'(received_at < ? OR (received_at=? AND id < ?))'
        page_params.extend((stamp, stamp, identifier))
    rows = db.execute(LEGACY_UNIFIED+'SELECT * FROM unified'+page_where+' ORDER BY received_at DESC,id DESC LIMIT ?', (*page_params, limit+1)).fetchall()
    page = rows[:limit]
    return {'ids': [r['id'] for r in page],
            'total': db.execute(LEGACY_UNIFIED+'SELECT COUNT(*) FROM unified'+where, params).fetchone()[0],
            'total_all': db.execute(LEGACY_UNIFIED+'SELECT COUNT(*) FROM unified').fetchone()[0],
            'log_types': [r[0] for r in db.execute(LEGACY_UNIFIED+'SELECT DISTINCT log_type FROM unified'+(' WHERE origin=?' if source else '')+' ORDER BY log_type', [source] if source else [])],
            'cursor': base64.urlsafe_b64encode(json.dumps([page[-1]['received_at'], page[-1]['id']]).encode()).decode() if len(rows)>limit else None}


@pytest.fixture
def populated(tmp_path):
    path = tmp_path/'runtime.sqlite3'
    store = EventStore(path)
    # Simulate the old schema population, then remove only the new migration/index.
    with store.connect() as db:
        for i in range(240):
            r = record(i, zeek=i%3!=0, kind='telemetry' if i%2==0 else 'alert')
            if r.get('source_product') == 'zeek':
                db.execute('INSERT INTO zeek_logs VALUES(?,?,?,?,?)', (r['id'], r['log_type'], r['agent']['name'], r['received_at'], json.dumps(r)))
            if r.get('source_product') != 'zeek' or r['event_kind']=='alert':
                r['investigation_report'] = {'current': True}
                db.execute('INSERT INTO events VALUES(?,?)', (r['id'], json.dumps(r)))
        db.execute('DROP TABLE log_index')
        db.execute("DELETE FROM migrations WHERE name='log_index_v1'")
    return EventStore(path)


@pytest.mark.parametrize('filters', [{}, {'source':'zeek'}, {'source':'wazuh'}, {'kind':'alert'},
                                    {'source':'zeek','log_type':'http','kind':'telemetry'}])
def test_legacy_equivalence_and_pagination(populated, filters):
    seen, cursor = [], None
    while True:
        with populated.connect() as db:
            old = legacy_page(db, before=cursor, **filters)
        new = populated.list_logs(limit=17, before=cursor, **filters)
        assert [r['id'] for r in new['logs']] == old['ids']
        for k in ('total', 'total_all', 'log_types'):
            assert new[k] == old[k]
        assert new['next_cursor'] == old['cursor']
        seen.extend(old['ids'])
        cursor = new['next_cursor']
        if not cursor:
            break
    assert len(seen)==len(set(seen))==new['total']
    for r in populated.list_logs(kind='alert')['logs']:
        assert r['investigation_report'] == {'current': True}


@pytest.mark.parametrize('zeek', [True, False])
def test_archive_upgrade_and_transaction(tmp_path, zeek):
    s = EventStore(tmp_path/'s.sqlite3')
    r = record(1, zeek=zeek, kind='telemetry')
    s.accept(deepcopy(r), False)
    alert = deepcopy(r)
    alert['event_kind'] = 'alert'
    alert['received_at'] = '2026-10-20T01:01:00Z'
    s.accept(alert, True)
    page = s.list_logs(kind='alert')
    assert page['total_all']==page['total']==1
    assert page['logs'][0]['ai_status']=='queued'
    assert s.queue_stats()=={'queued':1}
    assert s.accept(deepcopy(r), False)[1]
    assert s.list_logs(kind='alert')['total']==1


def test_filters_metadata_and_cursor(populated):
    result = populated.list_logs(since='2026-10-20T08:01:00+07:00', until='2026-10-20T01:01:09Z', q='SENSOR-ALPHA 192.0.2.10')
    assert result['total']==10
    assert populated.list_logs(q='payload-only-needle')['total']==0
    assert populated.list_logs(source='zeek',q='lab.invalid')['total']==160
    old_cursor = base64.urlsafe_b64encode(json.dumps(['2026-10-20T01:01:09+00:00', 'WAZUH-00069']).encode()).decode()
    assert populated.list_logs(before=old_cursor)['logs'][0]['id']=='WAZUH-00068'
    for cursor in ('bad', base64.urlsafe_b64encode(b'["bad","id"]').decode()):
        with pytest.raises(ValueError, match='Invalid log cursor'):
            populated.list_logs(before=cursor)
    with pytest.raises(ValueError, match='since'):
        populated.list_logs(since='2026-10-21T00:00:00Z',until='2026-10-20T00:00:00Z')


def test_migration_twice_and_backup(populated):
    path = populated.path
    assert list((__import__('pathlib').Path(path).parent/'backups').glob('*.sqlite3'))
    first = populated.list_logs()
    again = EventStore(path)
    assert again.list_logs()==first
    with again.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM migrations WHERE name='log_index_v1'").fetchone()[0]==1


def test_order_normalizes_old_offsets(tmp_path):
    s = EventStore(tmp_path/'s.sqlite3')
    a, b = record(1), record(2)
    a['received_at']='2026-10-20T08:00:01+07:00'
    s.accept(a,False)
    s.accept(b,False)
    assert [r['id'] for r in s.list_logs()['logs']]==[b['id'],a['id']]
    assert utc_stamp(a['received_at'])=='2026-10-20T01:00:01.000000Z'


def test_index_and_source_rollback_together(tmp_path):
    s = EventStore(tmp_path/'full.sqlite3', max_jobs=0)
    with pytest.raises(QueueFull):
        s.accept(record(1,zeek=True), True)
    assert s.list_logs()['total_all']==0
    assert s.list_zeek_logs()['total']==0
    assert s.queue_stats()=={}


def test_backfill_normalizes_old_timestamps(populated):
    with populated.connect() as db:
        db.execute("UPDATE zeek_logs SET received_at=? WHERE id=?", ('2026-10-20T08:00:02+07:00','WAZUH-00002'))
        db.execute('DROP TABLE log_index')
        db.execute("DELETE FROM migrations WHERE name='log_index_v1'")
    s = EventStore(populated.path)
    with s.connect() as db:
        assert db.execute('SELECT received_at FROM log_index WHERE id=?',('WAZUH-00002',)).fetchone()[0]=='2026-10-20T01:00:02.000000Z'


def test_alert_pagination_and_log_api(populated, monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN','test-only')
    with TestClient(create_app(populated.path, workers=False)) as client:
        first = client.get('/api/alerts?limit=5').json()
        second = client.get('/api/alerts',params={'limit':5,'before':first['next_cursor']}).json()
        assert not set(r['id'] for r in first['alerts']) & set(r['id'] for r in second['alerts'])
        response = client.get('/api/logs',params={'limit':25,'source':'zeek','q':'lab.invalid','since':'2026-10-20T01:00:00Z'})
        assert response.status_code==200 and len(response.json()['logs'])==25
        assert client.get('/api/logs?before=bad').status_code==400
        assert client.get('/api/logs?since=bad').status_code==400


def test_page_plan(populated):
    with populated.connect() as db:
        for where, args in (('',[]), (' WHERE origin=?',['zeek']),
                            (' WHERE origin=? AND log_type=?',['zeek','http']),
                            (' WHERE origin=? AND kind=?',['zeek','telemetry']),
                            (' WHERE log_type=? AND kind=?',['http','telemetry']),
                            (' WHERE origin=? AND log_type=? AND kind=?',['zeek','http','telemetry'])):
            details = ' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT id,origin,log_type,kind,received_at FROM log_index'+where+' ORDER BY received_at DESC,id DESC LIMIT 100', args))
            assert 'TEMP B-TREE' not in details and 'events' not in details
