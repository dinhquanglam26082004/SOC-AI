"""Response plans: persistence, per-action analyst decisions, and simulated (dry-run) execution.

Live execution is intentionally not implemented: RESPONSE_EXECUTION_MODE other than 'simulate'
is refused. Every simulated action is appended to the runtime response history.
"""
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path


class PlanConflict(ValueError):
    pass


def has_guidance(plan, action):
    source = plan.get('knowledge_guidance') or {}
    passages = source.get('passages') or []
    ids = {p.get('id') for p in passages if isinstance(p, dict) and p.get('text')}
    refs = action.get('guidance_ids') or []
    return bool(source.get('playbook_id') and source.get('source') and source.get('sha256')
                and refs and all(ref in ids for ref in refs))


class ResponseStore:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS response_plans(
                id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, incident_id TEXT, created REAL NOT NULL,
                updated REAL NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL)''')
            db.execute('CREATE INDEX IF NOT EXISTS response_plans_alert ON response_plans(alert_id, created)')

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _row(row):
        return {**json.loads(row['payload']), 'id': row['id'], 'status': row['status'],
                'created': row['created'], 'updated': row['updated']}

    def create(self, alert_id, incident_id, plan):
        now = time.time()
        plan_id = 'RP-' + uuid.uuid4().hex
        payload = {**plan, 'alert_id': alert_id, 'incident_id': incident_id, 'decisions': []}
        with self._lock, self.connect() as db:
            db.execute('INSERT INTO response_plans VALUES(?,?,?,?,?,?,?)',
                       (plan_id, alert_id, incident_id, now, now, 'proposed', json.dumps(payload, ensure_ascii=False)))
        return self.get(plan_id)

    def get(self, plan_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM response_plans WHERE id=?', (plan_id,)).fetchone()
        return self._row(row) if row else None

    def latest(self, alert_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM response_plans WHERE alert_id=? ORDER BY created DESC LIMIT 1',
                             (alert_id,)).fetchone()
        return self._row(row) if row else None

    def _save(self, db, plan, status):
        now = time.time()
        payload = {k: v for k, v in plan.items() if k not in {'id', 'status', 'created', 'updated'}}
        db.execute('UPDATE response_plans SET payload=?, status=?, updated=? WHERE id=?',
                   (json.dumps(payload, ensure_ascii=False), status, now, plan['id']))

    def decide(self, plan_id, approve, decline, notes='', actor='local-analyst'):
        with self._lock, self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM response_plans WHERE id=?', (plan_id,)).fetchone()
            if not row:
                raise KeyError(plan_id)
            plan = self._row(row)
            if plan['status'] == 'executed':
                raise PlanConflict('Kế hoạch đã được thực thi (mô phỏng); hãy tạo kế hoạch mới.')
            actions = {a['id']: a for a in plan['actions']}
            overlap = set(approve) & set(decline)
            if overlap:
                raise PlanConflict('Một hành động không thể vừa duyệt vừa từ chối: ' + ', '.join(sorted(overlap)))
            for action_id in list(approve) + list(decline):
                if action_id not in actions:
                    raise PlanConflict('Không có hành động ' + action_id + ' trong kế hoạch.')
                if action_id in approve and actions[action_id]['status'] == 'rejected':
                    raise PlanConflict(f'Hành động {action_id} đã bị cổng chính sách chặn; không thể duyệt.')
                if action_id in approve and not has_guidance(plan, actions[action_id]):
                    raise PlanConflict(f'Hành động {action_id} chưa có trích dẫn playbook hợp lệ; hãy lập lại kế hoạch.')
            for action_id in approve:
                actions[action_id]['status'] = 'approved'
            for action_id in decline:
                if actions[action_id]['status'] != 'rejected':
                    actions[action_id]['status'] = 'declined'
            plan['decisions'].append({'at': time.time(), 'actor': actor, 'approve': list(approve),
                                      'decline': list(decline), 'notes': notes[:2000]})
            self._save(db, plan, 'reviewed')
        return self.get(plan_id)

    def execute(self, plan_id, history_store, actor='local-analyst'):
        mode = os.getenv('RESPONSE_EXECUTION_MODE', 'simulate').lower()
        if mode != 'simulate':
            raise NotImplementedError('Chỉ hỗ trợ chế độ mô phỏng; chưa cấu hình adapter thực thi thật.')
        with self._lock, self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM response_plans WHERE id=?', (plan_id,)).fetchone()
            if not row:
                raise KeyError(plan_id)
            plan = self._row(row)
            if plan['status'] == 'executed':
                raise PlanConflict('Kế hoạch đã được thực thi (mô phỏng).')
            approved = [a for a in plan['actions'] if a['status'] == 'approved']
            if not approved:
                raise PlanConflict('Chưa có hành động nào được analyst duyệt.')
            if any(not has_guidance(plan, action) for action in approved):
                raise PlanConflict('Kế hoạch có hành động chưa dẫn playbook hợp lệ; hãy lập lại kế hoạch.')
            now = time.time()
            records = []
            guidance = plan['knowledge_guidance']
            passages = {p['id']:p for p in guidance['passages'] if isinstance(p,dict) and p.get('id')}
            for action in approved:
                action['status'] = 'simulated'
                action['executed_at'] = now
                records.append({'id': 'RA-' + uuid.uuid4().hex, 'plan_id': plan_id, 'alert_id': plan['alert_id'],
                                'incident_id': plan.get('incident_id'), 'action': action['action'],
                                'target': action['target'], 'status': 'simulated', 'mode': 'simulate',
                                'created_at': now, 'approved_by': actor, 'command': action['command'],
                                'rollback': action['rollback'], 'phase': action['phase'], 'impact': action['impact'],
                                'evidence_ids': action['evidence_ids'], 'guidance_ids': action['guidance_ids'],
                                'knowledge_guidance': {**{k:guidance.get(k) for k in ('playbook_id','title','source','sha256')},
                                                       'passages':[passages[ref] for ref in action['guidance_ids']]}})
            self._save(db, plan, 'executed')
        state = history_store.load()
        state['responses'] = (state.get('responses') or []) + records
        state['responses'] = state['responses'][-500:]
        history_store.save(state)
        return {'plan': self.get(plan_id), 'executed': records}
