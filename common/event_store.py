"""Transactional alerts/jobs; additive migration preserves the old snapshot table."""
import json
import base64
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path
from common.runtime_store import RuntimeStore
from common.investigation_index import migrate as migrate_investigation_index, write_index as write_investigation_index
from common.log_index import backup_before_migration, migrate_index, upsert_index, utc_stamp
from wazuh_integration.mapper import is_security_alert, fim_manual_only, is_dns_long_label_candidate
from wazuh_integration.collection_policy import WAZUH_LOG_TYPES, ZEEK_LOG_TYPES


class QueueFull(Exception):
    pass


def _similar_alert_key(record):
    """Return a conservative incident scope, or None when it is not identifiable."""
    if record.get('event_kind') != 'alert':
        return None
    agent = str((record.get('agent') or {}).get('id') or '').strip()
    manager = str((record.get('manager') or {}).get('name') or '').strip()
    rule = record.get('rule') or {}
    rule_id = str(rule.get('id') or '').strip()
    level = rule.get('level')
    if not agent or not manager or not rule_id or level is None:
        return None
    source = str(record.get('source_product') or record.get('source') or '').strip()
    if not source:
        return None
    base = (manager, agent, source, rule_id, str(level))
    src = str(record.get('src_ip') or '').strip()
    dst = str(record.get('dst_ip') or '').strip()
    port = str(record.get('dst_port') or '').strip()
    user = str(record.get('username') or '').strip()
    process = str(record.get('process') or '').strip()
    path = str(record.get('file_path') or '').strip()
    data = record.get('zeek_data') or {}
    if not isinstance(data, dict):
        return None
    raw_event = record.get('raw_event') or {}
    raw_data = raw_event.get('data') if isinstance(raw_event, dict) else {}
    raw_data = raw_data if isinstance(raw_data, dict) else {}
    full_log = str(raw_event.get('full_log') or '') if isinstance(raw_event, dict) else ''
    if rule_id in {'101200', '101201', '101202'}:
        if rule_id == '101200':
            match = re.search(r'\bnew user:\s*name=([^,\s]+)', full_log, re.I)
            account = (match.group(1) if match else
                       raw_data.get('username') or raw_data.get('user') or raw_data.get('targetUserName'))
            return base + ('account_creation', account) if account else None
        match = re.search(r"\badd\s+['\"]([^'\"]+)['\"]\s+to group\s+['\"]([^'\"]+)['\"]", full_log, re.I)
        if match:
            account, group = match.group(1), match.group(2)
        else:
            match = re.search(r'\buser\s+([^\s]+)\s+added by\s+([^\s]+)\s+to group\s+([^\s]+)', full_log, re.I)
            account = (match.group(1) if match else
                       raw_data.get('dstuser') or raw_data.get('target_user') or raw_data.get('targetUserName'))
            group = match.group(3) if match else 'sudo'
        if not account:
            return None
        # usermod and gpasswd are two ways to produce the same privilege change.
        return (manager, agent, source, 'linux_sudo_membership', str(level),
                'account_privilege', str(account).strip().lower(), str(group).strip().lower())
    if source == 'zeek' and record.get('log_type') == 'dns':
        query = str(data.get('query') or '').strip().rstrip('.').lower()
        labels = query.split('.')
        qtype = str(data.get('qtype_name') or '').strip().upper()
        if not src or not dst or not port.isdigit() or not qtype or len(labels) < 2 or not all(labels):
            return None
        # A tunnel rotates the first label. Keep the full remaining suffix so
        # different target domains are never merged merely by IP and rule.
        domain = '.'.join(labels[1:]) if len(labels) >= 3 else query
        return base + ('dns', src, dst, str(int(port)), domain, qtype)
    if source == 'zeek' and rule_id in {'100142', '100145'}:
        if not dst or not port.isdigit() or (rule_id == '100142' and not src):
            return None
        return base + ('dos', src if rule_id == '100142' else '', dst, str(int(port)))
    if path:
        return base + ('file', path, str(record.get('file_event') or ''), user, process)
    if src and dst:
        return base + ('network', src, dst, port, user, process, str(data.get('proto') or ''))
    if src and user:
        return base + ('auth', src, user, dst, port, process)
    return None


def _time_seconds(value):
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return stamp.timestamp() if stamp.tzinfo is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _same_active_investigation(representative, candidate):
    key = _similar_alert_key(representative)
    if key is None or key != _similar_alert_key(candidate):
        return False
    ref = _time_seconds(representative.get('timestamp'))
    event = _time_seconds(candidate.get('timestamp'))
    if ref is None or event is None or event < ref - 300:
        return False
    if abs(event - ref) <= 300:
        return True
    # Later arrivals may belong to a long-running incident. Do not merge an
    # older backlog item solely because it happens to share an identity.
    started = _time_seconds((representative.get('ai_progress') or {}).get('started_at'))
    received = _time_seconds(candidate.get('received_at'))
    return started is not None and received is not None and received >= started


class EventStore:
    def __init__(self, path, max_jobs=1000):
        self.path, self.max_jobs = str(path), max_jobs
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        backup_before_migration(path)
        backup_before_migration(path, 'investigation_index_v1')
        backup_before_migration(path, 'authentication_facts_v1')
        legacy = RuntimeStore(str(path)).load()
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ai_jobs(event_id TEXT PRIMARY KEY REFERENCES events(id),
              state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, error TEXT, updated REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS migrations(name TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS runtime_control(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS zeek_logs(
              id TEXT PRIMARY KEY,log_type TEXT NOT NULL,agent_name TEXT NOT NULL,
              received_at TEXT NOT NULL,payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS zeek_logs_type ON zeek_logs(log_type);
            CREATE INDEX IF NOT EXISTS zeek_logs_time ON zeek_logs(received_at DESC,id DESC);
            CREATE INDEX IF NOT EXISTS ai_jobs_state_updated ON ai_jobs(state,updated);
            ''')
            if not db.execute("SELECT 1 FROM migrations WHERE name='legacy_snapshot'").fetchone():
                for key, record in legacy.get('alerts', {}).items():
                    db.execute('INSERT OR IGNORE INTO events VALUES(?,?)', (key, json.dumps(record)))
                for key, record in legacy.get('cases', {}).items():
                    db.execute('INSERT OR IGNORE INTO cases VALUES(?,?)', (key, json.dumps(record)))
                db.execute("INSERT INTO migrations VALUES('legacy_snapshot')")

        with self.connect() as db:
            migrate_index(db)
        with self.connect() as db:
            migrate_investigation_index(db)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def recover(self):
        with self.connect() as db:
            for row in db.execute("SELECT event_id FROM ai_jobs WHERE state='running'").fetchall():
                record = json.loads(db.execute('SELECT payload FROM events WHERE id=?', (row[0],)).fetchone()[0])
                record['ai_status'] = 'queued'
                record['ai_progress'] = {'stage': 'queued', 'queued_at': time.time(), 'restarted': True}
                db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), row[0]))
            db.execute("UPDATE ai_jobs SET state='queued',updated=? WHERE state='running'", (time.time(),))

    @staticmethod
    def _ai_paused(db):
        row = db.execute("SELECT value FROM runtime_control WHERE key='ai_paused'").fetchone()
        return bool(row and row[0] == '1')

    def ai_paused(self):
        with self.connect() as db:
            return self._ai_paused(db)

    def set_ai_paused(self, paused):
        if type(paused) is not bool:
            raise ValueError('paused must be boolean')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO runtime_control(key,value) VALUES('ai_paused',?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", ('1' if paused else '0',))
        return paused

    def _related_dos_job(self, db, record):
        """Find a recent representative without suppressing or deleting alerts."""
        rule=str((record.get('rule') or {}).get('id',''))
        if record.get('source_product')!='zeek' or rule not in {'100142','100145'}:
            return None
        agent=str((record.get('agent') or {}).get('id') or '')
        src,dst,port=record.get('src_ip'),record.get('dst_ip'),record.get('dst_port')
        if not agent or not dst or not str(port or '').isdigit() or (rule=='100142' and not src):
            return None
        anchor=datetime.fromisoformat(record['timestamp'].replace('Z','+00:00'))
        since=utc_stamp((anchor-timedelta(minutes=5)).isoformat())
        until=utc_stamp((anchor+timedelta(minutes=5)).isoformat())
        query='''SELECT j.event_id, j.state, i.event_time FROM investigation_event_index i
            JOIN ai_jobs j ON j.event_id=i.id JOIN events e ON e.id=i.id
            WHERE i.agent_id=? AND i.event_time>=? AND i.event_time<=?
              AND j.state IN ('queued','running','completed')
              AND json_extract(e.payload,'$.source_product')='zeek'
              AND CAST(json_extract(e.payload,'$.rule.id') AS TEXT)=?
              AND i.dst_ip=? AND CAST(json_extract(e.payload,'$.dst_port') AS TEXT)=?'''
        params=[agent,since,until,rule,dst,str(port)]
        if rule=='100142':
            query+=' AND i.src_ip=?';params.append(src)
        query+=' ORDER BY ABS(julianday(i.event_time)-julianday(?)), i.id LIMIT 1'
        params.append(utc_stamp(record['timestamp']))
        return db.execute(query,params).fetchone()

    @staticmethod
    def _mark_grouped(record, representative):
        key = _similar_alert_key(record)
        scope = key[5] if key else ''
        details = {
            'dns': 'Cùng manager, agent, rule, mức độ, IP nguồn, IP đích, cổng, domain cha và loại DNS.',
            'dos': 'Cùng manager, agent, rule, mức độ, đích và phạm vi nguồn theo rule DoS.',
            'file': 'Cùng manager, agent, rule, mức độ, đường dẫn, loại thay đổi và người/tác vụ nếu có.',
            'network': 'Cùng manager, agent, rule, mức độ, IP nguồn, IP đích và các trường liên quan.',
            'auth': 'Cùng manager, agent, rule, mức độ, IP nguồn, tài khoản và các trường liên quan.',
            'account_creation': 'Cùng manager, agent, rule và tài khoản Linux được tạo.',
            'account_privilege': 'Cùng manager, agent, tài khoản và nhóm sudo.',
        }
        record['ai_status'] = 'skipped'
        record['ai_skip_reason'] = 'Đã gộp với cảnh báo cùng phạm vi; không chạy AI riêng. AI có thể chưa đọc log này.'
        record['ai_group'] = {'representative_alert_id': representative['id'],
                              'representative_state': 'running',
                              'policy': 'active_similarity', 'match': details.get(scope, '')}
        record.pop('ai_progress', None)
        return record

    @staticmethod
    def _duplicate_source_representative(db, candidate):
        raw = candidate.get('raw_event') or {}
        if not isinstance(raw, dict):
            return None
        full_log = raw.get('full_log')
        location = raw.get('location')
        if not isinstance(full_log, str) or not full_log.strip() or not isinstance(location, str) or not location:
            return None
        rows = db.execute("""SELECT j.event_id,j.state,e.payload FROM ai_jobs j
            JOIN events e ON e.id=j.event_id
            WHERE j.state IN ('queued','running','completed')
              AND j.updated>=?
              AND json_extract(e.payload,'$.timestamp')=?
              AND json_extract(e.payload,'$.manager.name')=?
              AND json_extract(e.payload,'$.agent.id')=?
              AND json_extract(e.payload,'$.raw_event.location')=?
              AND json_extract(e.payload,'$.raw_event.full_log')=?
            ORDER BY CASE j.state WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END,j.updated
            LIMIT 10""", (time.time() - 300, candidate.get('timestamp'), (candidate.get('manager') or {}).get('name'),
                          (candidate.get('agent') or {}).get('id'), location, full_log)).fetchall()
        for row in rows:
            representative = json.loads(row['payload'])
            if representative.get('id') != candidate.get('id'):
                return row, representative
        return None

    @staticmethod
    def _mark_duplicate_source(record, representative, state):
        record['ai_status'] = 'skipped'
        record['ai_skip_reason'] = 'Đã gộp bản ghi trùng của cùng một sự kiện nguồn; không chạy AI lần hai.'
        record['ai_group'] = {
            'representative_alert_id': representative['id'],
            'representative_state': state,
            'policy': 'exact_source_event',
            'match': 'Cùng Agent, thời điểm, nguồn log và nội dung log gốc.',
        }
        record.pop('ai_progress', None)
        return record

    def _active_representative(self, db, candidate):
        if _similar_alert_key(candidate) is None:
            return None
        rows = db.execute("""SELECT e.payload FROM ai_jobs j JOIN events e ON e.id=j.event_id
                           WHERE j.state='running' ORDER BY j.updated""").fetchall()
        for row in rows:
            representative = json.loads(row['payload'])
            if _same_active_investigation(representative, candidate):
                return representative
        return None

    def _group_queued_for(self, db, representative):
        if _similar_alert_key(representative) is None:
            return 0
        rows = db.execute("""SELECT j.event_id,e.payload FROM ai_jobs j JOIN events e ON e.id=j.event_id
                           WHERE j.state='queued' AND j.event_id<>?""", (representative['id'],)).fetchall()
        count = 0
        for row in rows:
            candidate = json.loads(row['payload'])
            if candidate.get('ai_manual_request') or not _same_active_investigation(representative, candidate):
                continue
            self._mark_grouped(candidate, representative)
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(candidate, ensure_ascii=False), row['event_id']))
            db.execute("UPDATE ai_jobs SET state='skipped',error=NULL,updated=? WHERE event_id=? AND state='queued'",
                       (time.time(), row['event_id']))
            count += 1
        return count

    def _group_queued_with_running(self, db):
        rows = db.execute("""SELECT e.payload FROM ai_jobs j JOIN events e ON e.id=j.event_id
                           WHERE j.state='running' ORDER BY j.updated""").fetchall()
        return sum(self._group_queued_for(db, json.loads(row['payload'])) for row in rows)

    def group_queued_with_running(self):
        """Coalesce already-queued matches without deleting alerts or interrupting AI."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            return self._group_queued_with_running(db)

    def accept(self, record, eligible):
        record['ai_allowed'] = is_security_alert(record)
        eligible = bool(eligible and record['ai_allowed'])
        record['ai_skip_reason'] = (None if eligible else
            'Not a security alert; retained as log only' if not record['ai_allowed'] else
            'DNS long-label candidate requires manual investigation to avoid repeated AI jobs' if is_dns_long_label_candidate(record) else
            'FIM path outside automatic critical-path policy; manual investigation available' if fim_manual_only(record) else
            'Below automatic investigation policy; manual investigation available')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if eligible and self._ai_paused(db):
                eligible = False
                record['ai_skip_reason'] = 'AI đang tạm dừng; có thể đưa cảnh báo vào hàng đợi thủ công.'
            cutoff = db.execute("SELECT value FROM runtime_control WHERE key='reset_before'").fetchone()
            if cutoff and datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00')) < datetime.fromisoformat(cutoff[0]):
                record.update(ai_status='skipped', ai_skip_reason='Before reset cutoff', _ignored_before_reset=True)
                return record, False
            if record.get('source_product') == 'zeek':
                old_log = db.execute('SELECT payload FROM zeek_logs WHERE id=?', (record['id'],)).fetchone()
                record['ai_status'] = 'skipped' if record.get('event_kind') == 'telemetry' else record.get('ai_status', 'skipped')
                db.execute('INSERT OR IGNORE INTO zeek_logs VALUES(?,?,?,?,?)',
                           (record['id'], record['log_type'], record['agent']['name'], record['received_at'], json.dumps(record)))
                if record.get('event_kind') == 'telemetry':
                    if not old_log:
                        self._update_log_index(db, record)
                    return (json.loads(old_log[0]), True) if old_log else (record, False)
            old = db.execute('SELECT payload FROM events WHERE id=?', (record['id'],)).fetchone()
            if old:
                previous = json.loads(old[0])
                if previous.get('event_kind') != 'telemetry' or record.get('event_kind') != 'alert':
                    return previous, True
                # An archive may arrive before the corresponding alert. Upgrade
                # the same event without creating a second log or losing AI state.
                record['received_at'] = previous.get('received_at', record['received_at'])
            if eligible:
                duplicate = (None if record.get('ai_manual_request')
                             else self._duplicate_source_representative(db, record))
                active = self._active_representative(db, record) if not duplicate else None
                if duplicate:
                    job, representative = duplicate
                    eligible = False
                    self._mark_duplicate_source(record, representative, job['state'])
                elif active:
                    eligible=False
                    self._mark_grouped(record, active)
                else:
                    representative=self._related_dos_job(db,record)
                    if representative:
                        eligible=False
                        record['ai_group']={'representative_alert_id':representative['event_id'],
                            'representative_state':representative['state'], 'window_seconds':300,
                            'match':'same agent, rule, destination and port'+(', source' if str(record['rule']['id'])=='100142' else '')}
                        record['ai_skip_reason']='Grouped with a related DoS alert within 5 minutes; manual investigation available'
            if eligible and self._pending(db) >= self.max_jobs:
                raise QueueFull('AI queue full; source must retry')
            record['ai_status'] = 'queued' if eligible else 'skipped'
            if eligible:
                record['ai_progress'] = {'stage': 'queued', 'queued_at': time.time()}
            db.execute('INSERT INTO events VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload', (record['id'], json.dumps(record)))
            if eligible:
                db.execute("INSERT INTO ai_jobs VALUES(?,'queued',0,NULL,?)", (record['id'], time.time()))
            self._update_log_index(db, record)
        return record, False

    def _pending(self, db):
        return db.execute("SELECT COUNT(*) FROM ai_jobs WHERE state IN ('queued','running')").fetchone()[0]

    @staticmethod
    def _generation(db):
        row = db.execute("SELECT value FROM runtime_control WHERE key='reset_generation'").fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def _current_job(cls, db, record):
        job = db.execute('SELECT state FROM ai_jobs WHERE event_id=?', (record['id'],)).fetchone()
        return bool(job and job['state'] == 'running'
                    and record.get('_job_generation') == cls._generation(db))

    def clear_logs_and_alerts(self, request_id):
        """Atomically clear the SOC event store and fence older deliveries and jobs.

        The investigation audit database, cases and the source logs are separate
        records and are intentionally left untouched.
        """
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute("SELECT value FROM runtime_control WHERE key='last_log_reset_id'").fetchone()
            if previous and previous[0] == request_id:
                result = db.execute("SELECT value FROM runtime_control WHERE key='last_log_reset_result'").fetchone()
                return json.loads(result[0])
            cutoff = datetime.now(timezone.utc).isoformat()
            generation = self._generation(db) + 1
            counts = {
                'logs': db.execute('SELECT COUNT(*) FROM log_index').fetchone()[0],
                'alerts': db.execute("SELECT COUNT(*) FROM events WHERE COALESCE(json_extract(payload,'$.event_kind'),'alert')!='telemetry'").fetchone()[0],
                'queued_jobs': db.execute("SELECT COUNT(*) FROM ai_jobs WHERE state='queued'").fetchone()[0],
                'running_jobs': db.execute("SELECT COUNT(*) FROM ai_jobs WHERE state='running'").fetchone()[0],
            }
            for table in ('ai_jobs', 'authentication_facts', 'investigation_event_index', 'log_index', 'zeek_logs', 'events'):
                db.execute('DELETE FROM ' + table)
            # Old snapshots can still contain copies of event and response data.
            # Preserve cases and other runtime state while removing those collections.
            row = db.execute('SELECT payload FROM runtime_state WHERE id=1').fetchone()
            if row:
                legacy = json.loads(row[0])
                if not isinstance(legacy, dict):
                    raise ValueError('Invalid legacy runtime snapshot')
                for key in ('alerts', 'logs', 'zeek_logs', 'responses'):
                    legacy.pop(key, None)
                db.execute('UPDATE runtime_state SET payload=? WHERE id=1', (json.dumps(legacy, ensure_ascii=False),))
            result = {'cleared_at': cutoff, 'deleted': counts}
            for key, value in (('reset_before', cutoff), ('reset_generation', str(generation)),
                               ('last_log_reset_id', request_id), ('last_log_reset_result', json.dumps(result))):
                db.execute('INSERT INTO runtime_control VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))
            return result

    def list_events(self, limit=100, before=None, severity=None, status=None, search=None):
        if not 1 <= limit <= 1000:
            raise ValueError('Alert limit must be between 1 and 1000')
        where = ["COALESCE(json_extract(payload,'$.event_kind'),'alert')!='telemetry'"]
        params = []
        if before is not None:
            if type(before) is not int or before < 1:
                raise ValueError('Invalid alert cursor')
            where.append('rowid<?')
            params.append(before)
        for path, value in (('$.severity', severity.upper() if severity else None), ('$.ai_status', status)):
            if value:
                where.append('json_extract(payload,?)=?')
                params.extend((path, value))
        if search:
            where.append('instr(lower(payload),lower(?))>0')
            params.append(search)
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT payload FROM events WHERE '
                    +' AND '.join(where)+' ORDER BY rowid DESC LIMIT ?', (*params, limit))]

    def event_cursor(self, event_id):
        with self.connect() as db:
            row = db.execute('SELECT rowid FROM events WHERE id=?', (event_id,)).fetchone()
            return row[0] if row else None

    def event_metrics(self):
        with self.connect() as db:
            counts = {str(r[0]).lower(): r[1] for r in db.execute("SELECT json_extract(payload,'$.severity'),COUNT(*) FROM events WHERE COALESCE(json_extract(payload,'$.event_kind'),'alert')!='telemetry' GROUP BY json_extract(payload,'$.severity')")}
        return {'total': sum(counts.values()), **{s: counts.get(s, 0) for s in ('critical', 'high', 'medium', 'low')}}

    def event_summaries(self):
        # Time series needs three scalar fields, never full source/AI payloads.
        with self.connect() as db:
            for row in db.execute("SELECT json_extract(payload,'$.created_at'),json_extract(payload,'$.timestamp'),json_extract(payload,'$.severity') FROM events WHERE COALESCE(json_extract(payload,'$.event_kind'),'alert')!='telemetry'"):
                yield dict(zip(('created_at', 'timestamp', 'severity'), row))

    def log_stats(self):
        with self.connect() as db:
            latest = db.execute('SELECT received_at FROM log_index ORDER BY received_at DESC,id DESC LIMIT 1').fetchone()
            zeek_latest = db.execute("SELECT received_at FROM log_index WHERE origin='zeek' ORDER BY received_at DESC,id DESC LIMIT 1").fetchone()
            total = db.execute('SELECT COUNT(*) FROM log_index').fetchone()[0]
            count = db.execute("SELECT COUNT(*) FROM log_index WHERE origin='zeek'").fetchone()[0]
            types = [r[0] for r in db.execute("SELECT DISTINCT log_type FROM log_index WHERE origin='zeek' ORDER BY log_type")]
            revision = db.execute("SELECT COUNT(*),COALESCE(MAX(rowid),0) FROM events WHERE COALESCE(json_extract(payload,'$.event_kind'),'alert')!='telemetry'").fetchone()
        return {'total': total, 'last_received_at': latest[0] if latest else None,
                'alert_revision': ':'.join(str(x) for x in revision),
                'zeek': {'total': count, 'log_types': types, 'last_received_at': zeek_latest[0] if zeek_latest else None}}

    def investigation_status(self):
        with self.connect() as db:
            return [{'id': r[0], 'ai_status': r[1], 'ai_progress': json.loads(r[2] or '{}'), 'ai_error': r[3],
                     'investigation':json.loads(r[4] or '{}')}
                    for r in db.execute("SELECT e.id,json_extract(e.payload,'$.ai_status'),json_extract(e.payload,'$.ai_progress'),json_extract(e.payload,'$.ai_error'),json_extract(e.payload,'$.investigation') FROM ai_jobs j JOIN events e ON e.id=j.event_id WHERE j.state IN ('queued','running') OR j.updated>? ORDER BY j.updated DESC LIMIT 50", (time.time()-60,))]

    def list_zeek_logs(self, limit=100, before=None, log_type=None):
        # A rowid cursor keeps pagination stable while new logs arrive.
        where, params = [], []
        if before is not None:
            where.append('rowid < ?')
            params.append(before)
        if log_type:
            where.append('log_type = ?')
            params.append(log_type)
        clause = ' WHERE ' + ' AND '.join(where) if where else ''
        with self.connect() as db:
            rows = db.execute('SELECT rowid,payload FROM zeek_logs' + clause + ' ORDER BY rowid DESC LIMIT ?', (*params, limit + 1)).fetchall()
            page = rows[:limit]
            return {'logs': [json.loads(row['payload']) for row in page],
                    'next_cursor': page[-1]['rowid'] if len(rows) > limit else None,
                    'total': db.execute('SELECT COUNT(*) FROM zeek_logs').fetchone()[0],
                    'log_types': [r[0] for r in db.execute('SELECT DISTINCT log_type FROM zeek_logs ORDER BY log_type')]}

    def get(self, event_id):
        with self.connect() as db:
            row = db.execute('SELECT payload FROM events WHERE id=?', (event_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def _update_log_index(self, db, record):
        write_investigation_index(db, record)
        if record.get('source_product') == 'zeek':
            z = db.execute('SELECT received_at,log_type FROM zeek_logs WHERE id=?', (record['id'],)).fetchone()
            e = db.execute('SELECT payload FROM events WHERE id=?', (record['id'],)).fetchone()
            current = json.loads(e[0]) if e else record
            upsert_index(db, current, origin='zeek', log_type=z['log_type'],
                         received_at=z['received_at'], kind=(current.get('event_kind') or 'alert') if e else 'telemetry')
        elif record.get('source') == 'wazuh':
            upsert_index(db, record)

    def list_logs(self, limit=100, before=None, source=None, log_type=None, kind=None,
                  since=None, until=None, q=None, selected_only=False):
        source = source.strip().lower() if source and source.strip() else None
        if not 1 <= limit <= 500:
            raise ValueError('Log limit must be between 1 and 500')
        filters, params = [], []
        selected_filter, selected_params = '', []
        if selected_only:
            zeek_types, wazuh_types = sorted(ZEEK_LOG_TYPES), sorted(WAZUH_LOG_TYPES)
            selected_filter = ('((origin=? AND log_type IN (' + ','.join('?' for _ in zeek_types)
                               + ')) OR (origin=? AND log_type IN (' + ','.join('?' for _ in wazuh_types) + ')))')
            selected_params = ['zeek', *zeek_types, 'wazuh', *wazuh_types]
            filters.append(selected_filter)
            params.extend(selected_params)
        for column, value in (('origin', source), ('log_type', log_type), ('kind', kind)):
            if value:
                filters.append(column + '=?')
                params.append(value)
        since, until = utc_stamp(since) if since else None, utc_stamp(until) if until else None
        if since and until and since > until:
            raise ValueError('since must be earlier than or equal to until')
        for operator, value in (('>=', since), ('<=', until)):
            if value:
                filters.append('received_at'+operator+'?')
                params.append(value)
        for word in (q or '').casefold().split():
            filters.append('instr(search_text,?)>0')
            params.append(word)
        where = ' WHERE ' + ' AND '.join(filters) if filters else ''
        page_where, page_params = where, list(params)
        if before:
            try:
                cursor = json.loads(base64.b64decode(before.encode(), altchars=b'-_', validate=True).decode())
                if (not isinstance(cursor, list) or len(cursor) != 2
                        or not all(isinstance(v, str) for v in cursor) or len(cursor[0]) > 64 or len(cursor[1]) > 128):
                    raise ValueError()
                stamp, event_id = utc_stamp(cursor[0]), cursor[1]
            except (ValueError, UnicodeError) as exc:
                raise ValueError('Invalid log cursor: expected base64 [UTC timestamp, id]') from exc
            page_where += (' AND ' if page_where else ' WHERE ') + '(received_at,id)<(?,?)'
            page_params.extend((stamp, event_id))
        with self.connect() as db:
            db.execute('BEGIN')
            rows = db.execute('SELECT id,origin,log_type,kind,received_at FROM log_index' + page_where
                              + ' ORDER BY received_at DESC,id DESC LIMIT ?', (*page_params, limit+1)).fetchall()
            page = rows[:limit]
            payloads = {}
            if page:
                ids = [row['id'] for row in page]
                placeholders = ','.join('?' for _ in ids)
                for table in ('zeek_logs', 'events'):
                    payloads.update((r['id'], r['payload']) for r in db.execute(
                        'SELECT id,payload FROM '+table+' WHERE id IN ('+placeholders+')', ids))
            records = []
            for row in page:
                record = json.loads(payloads[row['id']])
                record.update(log_origin=row['origin'], log_type=row['log_type'], event_kind=row['kind'])
                records.append(record)
            cursor = base64.urlsafe_b64encode(json.dumps([page[-1]['received_at'], page[-1]['id']]).encode()).decode() if len(rows)>limit else None
            # Exact counts from compact metadata. No cache: atomic reads and no stale totals.
            total = db.execute('SELECT COUNT(*) FROM log_index'+where, params).fetchone()[0]
            all_count = db.execute('SELECT COUNT(*) FROM log_index' + (' WHERE ' + selected_filter if selected_filter else ''), selected_params).fetchone()[0]
            type_filters = ([selected_filter] if selected_filter else []) + (['origin=?'] if source else [])
            type_where = ' WHERE ' + ' AND '.join(type_filters) if type_filters else ''
            type_params = [*selected_params, *([source] if source else [])]
            types = [r[0] for r in db.execute('SELECT DISTINCT log_type FROM log_index'+type_where+' ORDER BY log_type', type_params)]
            return {'logs': records, 'next_cursor': cursor, 'total': total, 'total_all': all_count, 'log_types': types}

    def claim(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if self._ai_paused(db):
                return None
            self._group_queued_with_running(db)
            # Authentication and other operational alerts must not wait behind
            # an initial SCA inventory burst. Keep FIFO within equal priority.
            row = db.execute("""SELECT j.event_id FROM ai_jobs j
                JOIN events e ON e.id=j.event_id WHERE j.state='queued'
                ORDER BY CASE WHEN EXISTS (
                    SELECT 1 FROM json_each(e.payload, '$.rule.groups') WHERE value='sca'
                ) THEN 1 ELSE 0 END,
                CAST(COALESCE(json_extract(e.payload, '$.rule.level'), 0) AS INTEGER) DESC,
                j.updated LIMIT 1""").fetchone()
            if not row:
                return None
            record = json.loads(db.execute('SELECT payload FROM events WHERE id=?', (row[0],)).fetchone()[0])
            record['_job_generation'] = self._generation(db)
            record['ai_status'] = 'running'
            record.pop('investigation_report', None)
            record.pop('playbook_proposal', None)
            queued = record.get('ai_progress', {})
            now = time.time()
            record['ai_progress'] = {'stage': 'starting', 'step': 0, 'total_steps': 6,
                                     'started_at': now, 'stage_started_at': now,
                                     'queued_at': queued.get('queued_at'),
                                     'restarted': queued.get('restarted', False)}
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), row[0]))
            db.execute("UPDATE ai_jobs SET state='running', attempts=attempts+1,updated=? WHERE event_id=?", (time.time(), row[0]))
            self._group_queued_for(db, record)
            return record

    def progress(self, record, stage, step, model):
        now = time.time()
        previous = record.get('ai_progress', {})
        if previous.get('stage_started_at'):
            previous.setdefault('stage_seconds', {})[previous['stage']] = round(now - previous['stage_started_at'], 2)
        record.setdefault('ai_progress', {}).update(
            stage=stage, step=step, total_steps=6, stage_started_at=now,
            updated_at=now, model=model)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not self._current_job(db, record):
                return False
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), record['id']))
        return True

    def finish(self, record, error=None):
        record['ai_status'] = 'failed' if error else 'completed'
        record['ai_error'] = error
        progress = record.setdefault('ai_progress', {})
        now = time.time()
        progress['finished_at'] = now
        if progress.get('stage_started_at'):
            progress.setdefault('stage_seconds', {})[progress['stage']] = round(now - progress['stage_started_at'], 2)
        if progress.get('started_at'):
            progress['elapsed_seconds'] = round(now - progress['started_at'], 2)
        if error:
            progress['failed_stage'] = progress.get('stage')
        progress['stage'] = 'failed' if error else 'completed'
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not self._current_job(db, record):
                return False
            if error is None:
                self._group_queued_for(db, record)
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), record['id']))
            db.execute('UPDATE ai_jobs SET state=?,error=?,updated=? WHERE event_id=?', (record['ai_status'], error, time.time(), record['id']))
        return True

    def skip(self, record, reason):
        record.update(ai_status='skipped', ai_allowed=False, ai_skip_reason=reason)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not self._current_job(db, record):
                return False
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), record['id']))
            db.execute("UPDATE ai_jobs SET state='skipped',error=NULL,updated=? WHERE event_id=?", (time.time(), record['id']))
        return True

    def retry(self, event_id):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT payload FROM events WHERE id=?', (event_id,)).fetchone()
            if not row:
                raise KeyError(event_id)
            record = json.loads(row[0])
            if not is_security_alert(record):
                raise ValueError('Only security alerts can be investigated; ordinary logs are excluded')
            job = db.execute('SELECT state, attempts, updated FROM ai_jobs WHERE event_id=?', (event_id,)).fetchone()
            if job and job[0] in ('queued', 'running', 'completed'):
                return False
            if job and (job[1] >= 5 or time.time() - job[2] < 10):
                raise ValueError('Retry limited to 5 attempts with a 10 second cooldown')
            if self._pending(db) >= self.max_jobs:
                raise QueueFull()
            record['ai_status'], record['ai_error'] = 'queued', None
            record['ai_skip_reason'] = None
            record['ai_manual_request'] = True
            record.pop('ai_group', None)
            record['ai_progress'] = {'stage': 'queued', 'queued_at': time.time()}
            record.pop('investigation_report', None)
            record.pop('playbook_proposal', None)
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), event_id))
            db.execute("INSERT INTO ai_jobs VALUES(?,'queued',0,NULL,?) ON CONFLICT(event_id) DO UPDATE SET state='queued',error=NULL,updated=excluded.updated", (event_id, time.time()))
            return True

    def queue_stats(self):
        with self.connect() as db:
            return dict(db.execute('SELECT state,COUNT(*) FROM ai_jobs GROUP BY state').fetchall())

    def list_cases(self):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT payload FROM cases')]

    def save_case(self, case):
        with self.connect() as db:
            db.execute('INSERT INTO cases VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload', (case['id'], json.dumps(case)))
