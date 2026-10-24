"""Clear operational SOC-AI data after stopping app, forwarder and Manager.

Usage: python scripts/reset_runtime.py --confirm
Only the repository's data/soc_runtime.sqlite3 is modified. No secrets, Agent
keys, RAG collection or Ollama volume are changed. A backup is always made.
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sqlite3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm', action='store_true', help='Confirm clearing operational records')
    args = parser.parse_args()
    if not args.confirm:
        parser.error('Stop SOC-AI services, then provide --confirm to clear runtime data')
    root = Path(__file__).resolve().parent.parent
    target = (root / 'data' / 'soc_runtime.sqlite3').resolve()
    if not target.is_relative_to(root / 'data') or not target.is_file():
        raise SystemExit('Expected existing data/soc_runtime.sqlite3 inside this repository')
    backups = root / 'data' / 'backups'
    backups.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc)
    backup = backups / ('before-runtime-reset-' + now.strftime('%Y%m%dT%H%M%S%fZ') + '.sqlite3')
    db = sqlite3.connect(target, timeout=30)
    try:
        with sqlite3.connect(backup) as copy:
            db.backup(copy)
        counts = {}
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        with db:
            db.execute('PRAGMA foreign_keys=ON')
            for table in ('ai_jobs', 'cases', 'log_index', 'zeek_logs', 'events', 'runtime_state'):
                if table in tables:
                    counts[table] = db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                    db.execute('DELETE FROM ' + table)
            db.execute('CREATE TABLE IF NOT EXISTS runtime_control(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute("INSERT INTO runtime_control VALUES('reset_before',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (now.isoformat(),))
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        db.execute('VACUUM')
        print('Backup:', backup)
        print('Cleared rows:', counts)
        print('Ignore source events older than:', now.isoformat())
    finally:
        db.close()


if __name__ == '__main__':
    main()
