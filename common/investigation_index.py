"""Structured event-time lookup for read-only investigation tools."""
import json
from common.log_index import utc_stamp
from common.auth_events import write_auth_fact


def write_index(db, record):
    if record.get('source') != 'wazuh':
        return
    raw = record.get('raw_event') or {}
    rule = record.get('rule') or {}
    decoder = str((raw.get('decoder') or {}).get('name', ''))
    groups = set(rule.get('groups') or [])
    auth = record.get('source_product') != 'zeek' and (
        bool(groups.intersection({'authentication_failed','authentication_success','authentication','invalid_login','sshd','pam'}))
        or decoder.startswith(('sshd','pam')) or str(record.get('event_id')) in {'4624','4625'})
    agent = record.get('agent') or {}
    write_auth_fact(db,record,auth)
    db.execute('''INSERT INTO investigation_event_index VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET event_time=excluded.event_time,agent_id=excluded.agent_id,
        src_ip=excluded.src_ip,dst_ip=excluded.dst_ip,username=excluded.username,category=excluded.category,
        log_type=excluded.log_type''', (record['id'], utc_stamp(record.get('timestamp') or record.get('created_at')),
        str(agent.get('id') or ''), record.get('src_ip'), record.get('dst_ip'), record.get('username'),
        'auth' if auth else 'network' if record.get('source_product')=='zeek' else 'endpoint',
        str(record.get('log_type') or raw.get('location') or decoder or 'wazuh')))


def migrate(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS investigation_event_index(
        id TEXT PRIMARY KEY,event_time TEXT NOT NULL,agent_id TEXT NOT NULL,src_ip TEXT,dst_ip TEXT,
        username TEXT,category TEXT NOT NULL,log_type TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS investigation_agent_time ON investigation_event_index(agent_id,event_time,id);
        CREATE INDEX IF NOT EXISTS investigation_agent_category_time ON investigation_event_index(agent_id,category,event_time,id);
        CREATE TABLE IF NOT EXISTS authentication_facts(id TEXT PRIMARY KEY,outcome TEXT NOT NULL);
    ''')
    db.execute('BEGIN IMMEDIATE')
    if not db.execute("SELECT 1 FROM migrations WHERE name='investigation_index_v1'").fetchone():
        for row in db.execute('''SELECT COALESCE(e.payload,z.payload) FROM log_index l
            LEFT JOIN events e ON e.id=l.id LEFT JOIN zeek_logs z ON z.id=l.id'''):
            write_index(db, json.loads(row[0]))
        db.execute("INSERT INTO migrations VALUES('investigation_index_v1')")
    if not db.execute("SELECT 1 FROM migrations WHERE name='authentication_facts_v1'").fetchone():
        for row in db.execute('''SELECT COALESCE(e.payload,z.payload) FROM investigation_event_index i
            LEFT JOIN events e ON e.id=i.id LEFT JOIN zeek_logs z ON z.id=i.id WHERE i.category='auth' '''):
            write_auth_fact(db,json.loads(row[0]),True)
        db.execute("INSERT INTO migrations VALUES('authentication_facts_v1')")
