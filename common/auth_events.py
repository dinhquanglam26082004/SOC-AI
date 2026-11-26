"""Conservative authentication facts, computed from collected records, never from LLM text."""
import re


SSH_FAILED_ATTEMPT = re.compile(
    r'\bFailed (?:password|publickey|keyboard-interactive(?:/pam)?) '
    r'for .+ from \S+ port \d+ ssh2\b',
    re.IGNORECASE,
)
SSH_SUCCESSFUL_ATTEMPT = re.compile(
    r'\bAccepted (?:password|publickey|keyboard-interactive(?:/pam)?) '
    r'for .+ from \S+ port \d+ ssh2\b',
    re.IGNORECASE,
)


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


def auth_attempt_outcome(record):
    """Classify only source records that identify one protocol-level auth attempt."""
    event_id = str(record.get('event_id') or '')
    if event_id == '4625':
        return 'failure'
    if event_id == '4624':
        return 'success'

    raw = record.get('raw_event') or {}
    decoder = str((raw.get('decoder') or {}).get('name', ''))
    program = str((raw.get('predecoder') or {}).get('program_name', ''))
    if not decoder.startswith('sshd') and not program.startswith('sshd'):
        return None

    text = str(raw.get('full_log') or '')
    if SSH_FAILED_ATTEMPT.search(text):
        return 'failure'
    if SSH_SUCCESSFUL_ATTEMPT.search(text):
        return 'success'
    return None


def write_auth_fact(db,record,auth):
    if auth:
        db.execute('''INSERT INTO authentication_facts(id,outcome,attempt_outcome) VALUES(?,?,?)
                   ON CONFLICT(id) DO UPDATE SET outcome=excluded.outcome,
                   attempt_outcome=excluded.attempt_outcome''',
                   (record['id'],auth_outcome(record),auth_attempt_outcome(record)))
    else:
        db.execute('DELETE FROM authentication_facts WHERE id=?',(record['id'],))
