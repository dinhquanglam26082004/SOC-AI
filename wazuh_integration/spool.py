"""SQLite spool shared by the Manager integration and one forwarder instance."""
import json
import os
from pathlib import Path
import sqlite3
import time
from contextlib import contextmanager


class Spool:
    def __init__(self, path='/spool/queue.sqlite3', max_bytes=268435456):
        self.path, self.max_bytes = str(path), int(max_bytes)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS queue(
              id INTEGER PRIMARY KEY, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
              attempts INTEGER NOT NULL DEFAULT 0, next_try REAL NOT NULL DEFAULT 0, error TEXT);
              CREATE TABLE IF NOT EXISTS stats(key TEXT PRIMARY KEY,value REAL NOT NULL);
            ''')
        try:
            os.chmod(self.path, 0o660)
        except PermissionError:
            pass  # group writer may not own the file created by the other container

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        # DELETE journaling: cross-container shared volume; FULL fsync before acknowledgement.
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def put(self, raw):
        payload = json.dumps(raw, ensure_ascii=False)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            # Account for reusable pages; delivered rows must not permanently consume capacity.
            page_size = db.execute('PRAGMA page_size').fetchone()[0]
            pages = db.execute('PRAGMA page_count').fetchone()[0]
            free = db.execute('PRAGMA freelist_count').fetchone()[0]
            size = (pages - free) * page_size
            if size + len(payload.encode()) + 16384 > self.max_bytes:
                raise RuntimeError('Spool full: source alert retained in Manager logs; operator recovery required')
            db.execute('INSERT INTO queue(payload) VALUES(?)', (payload,))

    def ready(self):
        with self.connect() as db:
            row = db.execute("SELECT * FROM queue WHERE state='pending' AND next_try<=? ORDER BY id LIMIT 1", (time.time(),)).fetchone()
            return dict(row) if row else None

    def complete(self, job_id):
        with self.connect() as db:
            db.execute('DELETE FROM queue WHERE id=?', (job_id,))
            db.execute("INSERT INTO stats VALUES('sent',1) ON CONFLICT(key) DO UPDATE SET value=value+1")
            db.execute("INSERT INTO stats VALUES('last_success',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (time.time(),))

    def fail(self, row, permanent, reason):
        attempts = row['attempts'] + 1
        with self.connect() as db:
            db.execute('UPDATE queue SET state=?,attempts=?,next_try=?,error=? WHERE id=?',
                       ('dead' if permanent else 'pending', attempts, time.time() + min(300, 2 ** min(attempts, 8)), reason, row['id']))
            db.execute("INSERT INTO stats VALUES('errors',1) ON CONFLICT(key) DO UPDATE SET value=value+1")

    def stats(self):
        with self.connect() as db:
            counts = dict(db.execute('SELECT state,COUNT(*) FROM queue GROUP BY state').fetchall())
            values = dict(db.execute('SELECT key,value FROM stats').fetchall())
        return {'pending': counts.get('pending', 0), 'dead_letter': counts.get('dead', 0),
                'sent': values.get('sent', 0), 'errors': values.get('errors', 0),
                'last_success': values.get('last_success')}

    def replay(self, job_id):
        with self.connect() as db:
            db.execute("UPDATE queue SET state='pending',next_try=0,error=NULL WHERE id=? AND state='dead'", (job_id,))


def integration(alert_path):
    """Exit success only after a durable write, or an explicit forwarding filter skip."""
    raw = json.loads(Path(alert_path).read_text(encoding='utf-8'))
    rule = raw.get('rule', {})
    zeek_transport = ('zeek_telemetry' in rule.get('groups', [])
                      and '/zeek/logs/current/' in str(raw.get('location', '')))
    allow = {x.strip() for x in os.getenv('WAZUH_FORWARD_GROUP_ALLOWLIST', '').split(',') if x.strip()}
    if not zeek_transport and rule.get('level', 0) < int(os.getenv('WAZUH_FORWARD_MIN_LEVEL', '3')):
        return
    if not zeek_transport and allow and not allow.intersection(rule.get('groups', [])):
        return
    Spool(os.getenv('WAZUH_SPOOL_PATH', '/spool/queue.sqlite3'), os.getenv('WAZUH_SPOOL_MAX_BYTES', '268435456')).put(raw)
