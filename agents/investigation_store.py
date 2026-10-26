"""Durable audit/evidence separate from the log database and graph checkpoints."""
from contextlib import contextmanager
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid
from agents.investigation_schema import WorkflowError


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class InvestigationStore:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        if Path(path).is_file():
            with closing(sqlite3.connect(path)) as source:
                if source.execute("SELECT 1 FROM sqlite_master WHERE name='investigations'").fetchone() and (
                        not source.execute("SELECT 1 FROM sqlite_master WHERE name='workflow_steps'").fetchone() or
                        not source.execute("SELECT 1 FROM sqlite_master WHERE name='analyst_reviews'").fetchone()):
                    backup=Path(path).parent/'backups'/('pre-investigation-activity-'+str(time.time_ns())+'.sqlite3')
                    backup.parent.mkdir(exist_ok=True)
                    with closing(sqlite3.connect(backup)) as target:
                        source.backup(target)
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS investigations(
                id TEXT PRIMARY KEY,alert_id TEXT NOT NULL,status TEXT NOT NULL,started REAL NOT NULL,
                updated REAL NOT NULL,summary TEXT NOT NULL,report TEXT);
                CREATE INDEX IF NOT EXISTS investigations_alert ON investigations(alert_id,started DESC);
                CREATE TABLE IF NOT EXISTS evidence(
                incident_id TEXT NOT NULL,id TEXT NOT NULL,event_time TEXT,kind TEXT NOT NULL,payload TEXT NOT NULL,
                PRIMARY KEY(incident_id,id));
                CREATE INDEX IF NOT EXISTS evidence_time ON evidence(incident_id,event_time,id);
                CREATE TABLE IF NOT EXISTS calls(
                incident_id TEXT NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,
                state TEXT NOT NULL,started REAL NOT NULL,finished REAL,args TEXT NOT NULL,result TEXT,
                PRIMARY KEY(incident_id,id));
                CREATE INDEX IF NOT EXISTS calls_incident ON calls(incident_id,started,id);
                CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY,owner TEXT NOT NULL,expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS workflow_steps(
                id INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT NOT NULL,node TEXT NOT NULL,
                state TEXT NOT NULL,started REAL NOT NULL,finished REAL);
                CREATE INDEX IF NOT EXISTS workflow_steps_incident ON workflow_steps(incident_id,started,id);
                CREATE TABLE IF NOT EXISTS analyst_reviews(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,
                    created REAL NOT NULL,decision TEXT NOT NULL,notes TEXT NOT NULL,evidence_ids TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS analyst_reviews_incident ON analyst_reviews(incident_id,created);
                CREATE INDEX IF NOT EXISTS investigations_review ON investigations(json_extract(summary,'$.review_status'),updated DESC);
                CREATE TABLE IF NOT EXISTS audit_migrations(name TEXT PRIMARY KEY);
            ''')
            db.execute('BEGIN IMMEDIATE')
            if not db.execute("SELECT 1 FROM audit_migrations WHERE name='analyst_handoff_v1'").fetchone():
                rows=db.execute("SELECT id,summary FROM investigations WHERE status IN ('completed','failed')").fetchall()
                for row in rows:
                    summary=json.loads(row['summary'])
                    if summary.get('review_status') is None:
                        summary.update(needs_analyst=True,review_status='pending',
                            review_reasons=['Historical investigation predates the current evidence-review policy; analyst review is required.'])
                        db.execute('UPDATE investigations SET summary=? WHERE id=?',(encode(summary),row['id']))
                db.execute("INSERT INTO audit_migrations VALUES('analyst_handoff_v1')")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def recover_leases(self):
        # Only called once by the single-worker app startup, never by tool requests.
        with self.connect() as db:
            db.execute('DELETE FROM leases')

    @contextmanager
    def lease(self, alert_id, seconds):
        owner = uuid.uuid4().hex
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT expires FROM leases WHERE id=?',(alert_id,)).fetchone()
            if row and row[0]>time.time():
                raise WorkflowError('investigation_busy','Another worker owns this investigation')
            db.execute('INSERT OR REPLACE INTO leases VALUES(?,?,?)',(alert_id,owner,time.time()+seconds+120))
        try:
            yield
        finally:
            with self.connect() as db:
                db.execute('DELETE FROM leases WHERE id=? AND owner=?',(alert_id,owner))

    def current(self, alert_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM investigations WHERE alert_id=? ORDER BY started DESC LIMIT 1',(alert_id,)).fetchone()
            return self._row(row) if row else None

    def _row(self, row):
        return {**dict(row),'summary':json.loads(row['summary']), 'report':json.loads(row['report']) if row['report'] else None}

    def create(self, alert_id, limits):
        incident_id = 'INV-'+uuid.uuid4().hex
        now = time.time()
        summary = {'incident_id':incident_id,'alert_id':alert_id,'workflow_version':'2',
                   'node':'triage','steps':0,'model_calls':0,'tool_calls':0,
                   'started_at':now,'limits':limits,'stop_reason':None,'verdict':None}
        with self.connect() as db:
            db.execute('INSERT INTO investigations VALUES(?,?,?,?,?,?,NULL)',
                       (incident_id,alert_id,'running',now,now,encode(summary)))
            db.execute('INSERT INTO workflow_steps(incident_id,node,state,started) VALUES(?,?,?,?)',
                       (incident_id,'triage','running',now))
        return self.current(alert_id)

    def review(self,incident_id,decision,notes,evidence_ids):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM investigations WHERE id=?',(incident_id,)).fetchone()
            if not row:raise KeyError('Investigation not found')
            if row['status'] not in {'completed','failed'}:raise ValueError('Wait until investigation is completed')
            allowed={r[0] for r in db.execute('SELECT id FROM evidence WHERE incident_id=?',(incident_id,))}
            if set(evidence_ids)-allowed:raise ValueError('Review cites evidence outside this investigation')
            now=time.time();review={'id':'REV-'+uuid.uuid4().hex,'created':now,'decision':decision,
                'notes':notes,'evidence_ids':evidence_ids,'actor':'local-analyst'}
            db.execute('INSERT INTO analyst_reviews VALUES(?,?,?,?,?,?)',
                (review['id'],incident_id,now,decision,notes,encode(evidence_ids)))
            summary={**json.loads(row['summary']),'review_status':'reviewed','needs_analyst':False,'analyst_review':review}
            db.execute('UPDATE investigations SET summary=?,updated=? WHERE id=?',(encode(summary),now,incident_id))
            return summary

    def pending_reviews(self,limit=20,offset=0):
        with self.connect() as db:
            rows=db.execute("""SELECT id,alert_id,summary,updated FROM investigations r
                WHERE json_extract(summary,'$.review_status')='pending' AND NOT EXISTS(
                  SELECT 1 FROM investigations newer WHERE newer.alert_id=r.alert_id AND newer.started>r.started)
                ORDER BY updated DESC,id LIMIT ? OFFSET ?""",(limit+1,offset)).fetchall()
            return {'items':[{**dict(r),'summary':json.loads(r['summary'])} for r in rows[:limit]],
                    'next_offset':offset+limit if len(rows)>limit else None}

    def update(self, incident_id, values, status='running', report=None):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT summary FROM investigations WHERE id=?',(incident_id,)).fetchone()
            summary={**json.loads(row[0]),**values}
            if 'node' in values:
                active=db.execute('SELECT id,node FROM workflow_steps WHERE incident_id=? AND finished IS NULL ORDER BY id DESC LIMIT 1',(incident_id,)).fetchone()
                if not active or active['node']!=values['node']:
                    now=time.time()
                    if active:
                        db.execute('UPDATE workflow_steps SET state=?,finished=? WHERE id=?',
                                   ('error' if status=='failed' else 'completed',now,active['id']))
                    terminal=status in {'failed','completed'}
                    db.execute('INSERT INTO workflow_steps(incident_id,node,state,started,finished) VALUES(?,?,?,?,?)',
                               (incident_id,values['node'],'error' if status=='failed' else 'completed' if terminal else 'running',now,now if terminal else None))
            db.execute('UPDATE investigations SET status=?,updated=?,summary=?,report=COALESCE(?,report) WHERE id=?',
                       (status,time.time(),encode(summary),encode(report) if report is not None else None,incident_id))
        return summary

    def counts(self, incident_id):
        with self.connect() as db:
            return dict(db.execute('SELECT kind,COUNT(*) FROM calls WHERE incident_id=? GROUP BY kind',(incident_id,)).fetchall())

    def call(self, incident_id, call_id, kind, name, args, maximum, callback):
        """Reserve before dispatch. Completed calls replay; interrupted calls never silently rerun."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT state,result FROM calls WHERE incident_id=? AND id=?',(incident_id,call_id)).fetchone()
            if old:
                if old['state']=='completed':
                    return json.loads(old['result'])
                if kind!='tool' or old['state']!='running':
                    raise WorkflowError('interrupted_call','A reserved model call did not finish; explicitly retry as a new investigation')
            used=db.execute('SELECT COUNT(*) FROM calls WHERE incident_id=? AND kind=?',(incident_id,kind)).fetchone()[0]
            if not old and used>=maximum:
                raise WorkflowError(kind+'_budget','Call budget exhausted')
            if not old:
                db.execute('INSERT INTO calls VALUES(?,?,?,?,?,?,NULL,?,NULL)',
                           (incident_id,call_id,kind,name,'running',time.time(),encode(args)))
        try:
            result=callback()
        except Exception as exc:
            with self.connect() as db:
                db.execute('UPDATE calls SET state=?,finished=?,result=? WHERE incident_id=? AND id=?',
                           ('error',time.time(),encode({'error':type(exc).__name__,'detail':str(exc)[:1200]}),incident_id,call_id))
            raise
        with self.connect() as db:
            db.execute('UPDATE calls SET state=?,finished=?,result=? WHERE incident_id=? AND id=?',
                       ('completed',time.time(),encode(result),incident_id,call_id))
        return result

    def add_evidence(self, incident_id, source_id, kind, payload, tool, args):
        evidence_id='EV-'+hashlib.sha256((kind+'\0'+source_id).encode()).hexdigest()[:24]
        item={'evidence_id':evidence_id,'evidence_type':kind,'source':payload.get('source','soc-ai-sqlite'),
              'source_record_id':source_id,'event_time':payload.get('event_time'),
              'collected_at':datetime.now(timezone.utc).isoformat(), 'tool':tool,'query':args,'data':payload}
        with self.connect() as db:
            db.execute('INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?)',
                       (incident_id,evidence_id,item['event_time'],kind,encode(item)))
        return evidence_id

    def detail(self, incident_id, section='evidence', limit=20, offset=0):
        if section not in {'evidence','tools','models','activity'}:
            raise ValueError('Unknown investigation section')
        with self.connect() as db:
            row=db.execute('SELECT * FROM investigations WHERE id=?',(incident_id,)).fetchone()
            if not row:
                return None
            if section=='activity':
                rows=db.execute('''SELECT 'stage' AS kind,CAST(id AS TEXT) AS id,node AS name,state,started,finished,NULL AS args,NULL AS result
                    FROM workflow_steps WHERE incident_id=? UNION ALL
                    SELECT kind,id,name,state,started,finished,args,result FROM calls WHERE incident_id=?
                    ORDER BY started,kind,id LIMIT ? OFFSET ?''',(incident_id,incident_id,limit+1,offset)).fetchall()
                items=[self.activity_item(r,terminal=row['status'] in {'failed','completed'}) for r in rows[:limit]]
                total=db.execute('SELECT (SELECT COUNT(*) FROM workflow_steps WHERE incident_id=?)+(SELECT COUNT(*) FROM calls WHERE incident_id=?)',(incident_id,incident_id)).fetchone()[0]
            elif section=='evidence':
                rows=db.execute('SELECT payload FROM evidence WHERE incident_id=? ORDER BY event_time,id LIMIT ? OFFSET ?',
                                (incident_id,limit+1,offset)).fetchall()
                items=[json.loads(r[0]) for r in rows[:limit]]
                total=db.execute('SELECT COUNT(*) FROM evidence WHERE incident_id=?',(incident_id,)).fetchone()[0]
            else:
                kind='tool' if section=='tools' else 'model'
                rows=db.execute('SELECT * FROM calls WHERE incident_id=? AND kind=? ORDER BY started,id LIMIT ? OFFSET ?',
                                (incident_id,kind,limit+1,offset)).fetchall()
                items=[{**dict(r),'args':json.loads(r['args']),'result':json.loads(r['result']) if r['result'] else None} for r in rows[:limit]]
                total=db.execute('SELECT COUNT(*) FROM calls WHERE incident_id=? AND kind=?',(incident_id,kind)).fetchone()[0]
            return {**self._row(row),'section':section,'items':items,'total':total,
                    'next_offset':offset+limit if len(rows)>limit else None}

    @staticmethod
    def activity_item(row,terminal=False):
        item={k:row[k] for k in ('id','kind','name','state','started','finished')}
        if terminal and item['state']=='running':
            item['state']='interrupted'
        result=json.loads(row['result']) if row['result'] else {}
        if row['kind']=='tool':
            item.update(query=json.loads(row['args']),outcome=result.get('status'),
                        result_count=len(result.get('items',[])),error=result.get('error'),
                        evidence_ids=[e['evidence_id'] for e in result.get('items',[]) if 'evidence_id' in e])
            if result.get('authentication_summary'):
                summary=result['authentication_summary']
                item['authentication_summary']={**summary,'groups':summary['groups'][:10],
                    'display_truncated':len(summary['groups'])>10}
        elif row['kind']=='model':
            message=result.get('message') or {}
            item.update(selected_tools=[{'name':(c.get('function') or {}).get('name'),
                        'arguments':(c.get('function') or {}).get('arguments',{})} for c in message.get('tool_calls',[])],
                        error=result.get('detail') if row['state']=='error' else None)
        return item

    def evidence(self, incident_id):
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT payload FROM evidence WHERE incident_id=? ORDER BY event_time,id',(incident_id,))]
