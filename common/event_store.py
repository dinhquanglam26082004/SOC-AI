"""Transactional alerts/jobs; additive migration preserves the old snapshot table."""
import json
import base64
import sqlite3
import time
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from common.runtime_store import RuntimeStore
from common.investigation_index import migrate as migrate_investigation_index, write_index as write_investigation_index
from common.log_index import backup_before_migration, migrate_index, upsert_index, utc_stamp
from wazuh_integration.mapper import is_security_alert


class QueueFull(Exception):
    pass


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

    def accept(self, record, eligible):
        record['ai_allowed'] = is_security_alert(record)
        eligible = bool(eligible and record['ai_allowed'])
        record['ai_skip_reason'] = (None if eligible else
            'Not a security alert; retained as log only' if not record['ai_allowed'] else
            'Below automatic investigation policy; manual investigation available')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
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
                  since=None, until=None, q=None):
        source = source.strip().lower() if source and source.strip() else None
        if not 1 <= limit <= 500:
            raise ValueError('Log limit must be between 1 and 500')
        filters, params = [], []
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
            all_count = db.execute('SELECT COUNT(*) FROM log_index').fetchone()[0]
            type_where, type_params = (' WHERE origin=?', [source]) if source else ('', [])
            types = [r[0] for r in db.execute('SELECT DISTINCT log_type FROM log_index'+type_where+' ORDER BY log_type', type_params)]
            return {'logs': records, 'next_cursor': cursor, 'total': total, 'total_all': all_count, 'log_types': types}

    def claim(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
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
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), record['id']))

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
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), record['id']))
            db.execute('UPDATE ai_jobs SET state=?,error=?,updated=? WHERE event_id=?', (record['ai_status'], error, time.time(), record['id']))

    def skip(self, record, reason):
        record.update(ai_status='skipped', ai_allowed=False, ai_skip_reason=reason)
        with self.connect() as db:
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(record), record['id']))
            db.execute("UPDATE ai_jobs SET state='skipped',error=NULL,updated=? WHERE event_id=?", (time.time(), record['id']))

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
