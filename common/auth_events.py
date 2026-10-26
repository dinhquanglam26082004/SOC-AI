"""Conservative authentication facts, computed from collected records, never from LLM text."""
import re


def auth_outcome(record):
    groups=set((record.get('rule') or {}).get('groups') or [])
    code=str(record.get('event_id') or '')
    failed=bool(groups & {'authentication_failed','invalid_login'}) or code=='4625'
    success='authentication_success' in groups or code=='4624'
    raw=record.get('raw_event') or {}
    decoder=str((raw.get('decoder') or {}).get('name',''))
    if decoder.startswith('sshd'):
        text=str(raw.get('full_log') or '')
        failed=failed or bool(re.search(r'\b(?:Failed (?:password|publickey)|Invalid user)\b',text))
        success=success or bool(re.search(r'\bAccepted (?:password|publickey)\b',text))
    return 'unknown' if failed==success else 'failure' if failed else 'success'


def write_auth_fact(db,record,auth):
    if auth:
        db.execute('INSERT INTO authentication_facts VALUES(?,?) ON CONFLICT(id) DO UPDATE SET outcome=excluded.outcome',
                   (record['id'],auth_outcome(record)))
    else:
        db.execute('DELETE FROM authentication_facts WHERE id=?',(record['id'],))
