"""Additive log metadata migration; legacy CTE is used only for backfill/comparison."""
import json
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from contextlib import closing


def utc_stamp(value):
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError()
        return stamp.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError('Expected a timezone-aware ISO timestamp') from exc


def search_metadata(record, log_type):
    agent, data = record.get('agent') or {}, record.get('zeek_data') or {}
    values = [log_type, agent.get('name'), agent.get('ip'), record.get('src_ip'), record.get('dst_ip'),
              record.get('username'), (record.get('rule') or {}).get('description')]
    values.extend(data.get(k) for k in ('host', 'query', 'server_name'))
    return '\n'.join(str(x)[:1024] for x in values if x is not None).casefold()


def upsert_index(db, record, *, origin=None, log_type=None, kind=None, received_at=None):
    origin = origin or ('zeek' if record.get('source_product') == 'zeek' else 'wazuh')
    log_type = log_type or record.get('log_type') or (record.get('raw_event') or {}).get('location') or 'wazuh'
    kind = kind or record.get('event_kind') or 'alert'
    received_at = utc_stamp(received_at or record.get('received_at') or record.get('timestamp'))
    db.execute('''INSERT INTO log_index(id,origin,log_type,kind,received_at,search_text) VALUES(?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET origin=excluded.origin,log_type=excluded.log_type,
        kind=excluded.kind,received_at=excluded.received_at,search_text=excluded.search_text''',
               (record['id'], origin, log_type, kind, received_at, search_metadata(record, log_type)))


def migrate_index(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS log_index(
            id TEXT PRIMARY KEY,origin TEXT NOT NULL,log_type TEXT NOT NULL,
            kind TEXT NOT NULL,received_at TEXT NOT NULL,search_text TEXT NOT NULL DEFAULT '');
        CREATE INDEX IF NOT EXISTS log_index_time ON log_index(received_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS log_index_filter ON log_index(origin,log_type,kind,received_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS log_index_origin_time ON log_index(origin,received_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS log_index_origin_type_time ON log_index(origin,log_type,received_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS log_index_origin_kind_time ON log_index(origin,kind,received_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS log_index_type_time ON log_index(log_type,received_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS log_index_kind_time ON log_index(kind,received_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS ai_jobs_state ON ai_jobs(state);
    ''')
    db.execute('BEGIN IMMEDIATE')
    if db.execute("SELECT 1 FROM migrations WHERE name='log_index_v1'").fetchone():
        return
    # Stream existing payloads once; preserve the old CTE metadata and events priority.
    rows = db.execute(LEGACY_UNIFIED + '''SELECT u.*,COALESCE(e.payload,z.payload) AS payload
        FROM unified u LEFT JOIN events e ON e.id=u.id LEFT JOIN zeek_logs z ON z.id=u.id''')
    for row in rows:
        record = json.loads(row['payload'])
        # Very old rows without timestamps sort first historically (empty string).
        # Map that sentinel to UTC year 1; malformed nonempty dates abort migration.
        stamp = row['received_at'] or '0001-01-01T00:00:00Z'
        upsert_index(db, record, origin=row['origin'], log_type=row['log_type'],
                     kind=row['kind'], received_at=stamp)
    db.execute("INSERT INTO migrations VALUES('log_index_v1')")


def backup_before_migration(path):
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return None
    with closing(sqlite3.connect(path)) as source:
        if source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='migrations'").fetchone():
            if source.execute("SELECT 1 FROM migrations WHERE name='log_index_v1'").fetchone():
                return None
        backup = path.parent / 'backups' / ('pre-log-index-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f') + '.sqlite3')
        backup.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(backup)) as target:
            source.backup(target)
    return str(backup)

LEGACY_UNIFIED = """WITH unified AS (
            SELECT z.id, 'zeek' AS origin, z.log_type, z.received_at,
                   CASE WHEN e.id IS NULL THEN 'telemetry' ELSE COALESCE(json_extract(e.payload,'$.event_kind'),'alert') END AS kind
            FROM zeek_logs z LEFT JOIN events e ON e.id=z.id
            UNION ALL
            SELECT e.id,
                   CASE WHEN json_extract(e.payload,'$.source_product')='zeek' THEN 'zeek' ELSE 'wazuh' END,
                   COALESCE(json_extract(e.payload,'$.log_type'),json_extract(e.payload,'$.raw_event.location'),'wazuh'),
                   COALESCE(json_extract(e.payload,'$.received_at'),json_extract(e.payload,'$.timestamp'),''),
                   COALESCE(json_extract(e.payload,'$.event_kind'),'alert')
            FROM events e WHERE json_extract(e.payload,'$.source')='wazuh'
              AND NOT EXISTS(SELECT 1 FROM zeek_logs z WHERE z.id=e.id)
        ) """
