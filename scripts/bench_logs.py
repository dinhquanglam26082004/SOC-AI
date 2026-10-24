"""Read benchmarks, query plans and optional consistent backup; no AI calls.

python scripts/bench_logs.py --db PATH --out data/bench-before.json --backup PATH
Run inside the app container for the real Docker volume, not a Windows copy.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.event_store import EventStore
from common.log_index import LEGACY_UNIFIED, utc_stamp


class Cursor:
    def __init__(self, cursor, start, entry):
        self.cursor, self.start, self.entry = cursor, start, entry

    def done(self):
        self.entry['ms'] = (time.perf_counter() - self.start) * 1000

    def fetchall(self):
        value = self.cursor.fetchall()
        self.done()
        return value

    def fetchone(self):
        value = self.cursor.fetchone()
        self.done()
        return value

    def __iter__(self):
        yield from self.cursor
        self.done()

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class Connection:
    def __init__(self, db, entries):
        self.db, self.entries = db, entries

    def execute(self, sql, params=()):
        entry = {'sql': sql, 'params': list(params)}
        self.entries.append(entry)
        start = time.perf_counter()
        cursor = self.db.execute(sql, params)
        entry['ms'] = (time.perf_counter() - start) * 1000
        return Cursor(cursor, start, entry)

    def __getattr__(self, name):
        return getattr(self.db, name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--backup')
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--verify-legacy', action='store_true', help='Compare all IDs/pages to the legacy query on a frozen copy')
    args = parser.parse_args()
    path = Path(args.db)
    with sqlite3.connect(path) as db:
        if args.backup:
            backup = Path(args.backup)
            backup.parent.mkdir(parents=True, exist_ok=True)
            if backup.exists():
                raise RuntimeError('Refusing to overwrite backup')
            with sqlite3.connect(backup) as target:
                db.backup(target)
        info = {'at': datetime.now(timezone.utc).isoformat(), 'db_bytes': path.stat().st_size,
                'wal_bytes': Path(str(path)+'-wal').stat().st_size if Path(str(path)+'-wal').exists() else 0,
                'counts': {t: db.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('events', 'zeek_logs')},
                'wal_autocheckpoint': db.execute('PRAGMA wal_autocheckpoint').fetchone()[0]}
    store = EventStore(path)
    if args.verify_legacy:
        with store.connect() as db:
            old = db.execute(LEGACY_UNIFIED+'SELECT * FROM unified ORDER BY received_at DESC,id DESC').fetchall()
        expected = [r['id'] for r in old]
        normalized = [r['id'] for r in sorted(old, key=lambda r: (utc_stamp(r['received_at']),r['id']), reverse=True)]
        actual, cursor = [], None
        while True:
            page = store.list_logs(limit=500, before=cursor)
            actual.extend(r['id'] for r in page['logs'])
            cursor = page['next_cursor']
            if not cursor:
                break
        assert actual == normalized and len(actual)==len(set(actual))==page['total_all']
        info['legacy_comparison'] = {'rows': len(actual), 'raw_order_equal': expected==actual,
                                     'normalized_order_equal': True, 'no_duplicates_or_omissions': True}
    original = store.connect
    entries = []

    @contextmanager
    def traced():
        with original() as db:
            yield Connection(db, entries)

    store.connect = traced
    timings, samples = {}, []
    calls = {'list_logs': lambda: store.list_logs(limit=100), 'list_events': store.list_events,
             'list_zeek_logs': store.list_zeek_logs, 'queue_stats': store.queue_stats}
    for name, call in calls.items():
        runs = []
        for i in range(args.runs):
            entries.clear()
            start = time.perf_counter()
            call()
            runs.append((time.perf_counter()-start)*1000)
            if name == 'list_logs':
                samples.append([dict(x) for x in entries])
        timings[name] = {'median_ms': statistics.median(runs), 'runs_ms': runs}
    queries = []
    with sqlite3.connect(path) as db:
        for i, entry in enumerate(samples[-1]):
            sql = entry['sql']
            if ('FROM unified' not in sql and 'FROM log_index' not in sql) or 'SELECT' not in sql:
                continue
            values = [s[i]['ms'] for s in samples if len(s) > i and s[i]['sql'] == sql]
            plan = db.execute('EXPLAIN QUERY PLAN '+sql, entry['params']).fetchall()
            queries.append({'sql': sql, 'median_ms': statistics.median(values), 'plan': plan})
        info['checkpoint_passive'] = list(db.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone())
    # Measure FULL transaction cost only in an isolated database on the same volume.
    with tempfile.TemporaryDirectory(prefix='bench-write-', dir=path.parent) as root:
        with sqlite3.connect(Path(root)/'sample.sqlite3') as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE sample(payload TEXT)')
            db.commit()
            totals, commits = [], []
            for _ in range(20):
                start = time.perf_counter()
                db.execute('INSERT INTO sample VALUES(?)', ('x'*4096,))
                commit = time.perf_counter()
                db.commit()
                commits.append((time.perf_counter()-commit)*1000)
                totals.append((time.perf_counter()-start)*1000)
        info['isolated_full_write'] = {'median_transaction_ms': statistics.median(totals),
                                      'median_commit_ms': statistics.median(commits), 'samples': 20}
    result = {'info': info, 'timings': timings, 'queries': queries}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'info': info, 'timings': timings,
                      'queries': [{'ms': x['median_ms'], 'plan': x['plan']} for x in queries]}, indent=2))


if __name__ == '__main__':
    main()
