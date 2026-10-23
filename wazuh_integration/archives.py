"""Read complete Manager archive lines into the durable delivery spool.

The first record identifies a logical file even after rotation/compression.
Offsets refer to uncompressed bytes, and commit atomically with each queue row.
Only one forwarder may read a given spool.
"""
import gzip
import hashlib
import json
from pathlib import Path
import time


class ArchiveReader:
    def __init__(self, path, spool):
        self.path = Path(path)
        self.spool = spool
        self.scanned = {}
        self.candidates = []
        self.discovered = 0
        self.status = {'state': 'waiting', 'enqueued': 0, 'last_read_at': None}

    def poll(self, limit=200):
        if time.monotonic() - self.discovered > 30 or not self.candidates:
            # Retained daily files cover rotation while the forwarder was down.
            retained = list(self.path.parent.rglob('ossec-archive-*.json*'))
            self.candidates = sorted((p for p in retained if p.is_file() and
                                      (p.suffix == '.json' or p.name.endswith('.json.gz'))),
                                     key=lambda p: (p.stat().st_mtime_ns, str(p)))
            self.candidates.append(self.path)
            self.discovered = time.monotonic()
        count = 0
        found = False
        for path in self.candidates:
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue
            found = True
            signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
            if self.scanned.get(str(path)) == signature:
                continue
            opener = gzip.open if path.name.endswith('.gz') else open
            try:
                with opener(path, 'rb') as source:
                    first = source.readline()
                    if not first.endswith(b'\n'):
                        continue
                    stream = hashlib.sha256(first).hexdigest()
                    offset = self.spool.archive_offset(stream)
                    source.seek(offset)
                    while count < limit:
                        start = source.tell()
                        line = source.readline()
                        if not line:
                            self.scanned[str(path)] = signature
                            break
                        if not line.endswith(b'\n'):
                            break  # writer has not completed this event yet
                        try:
                            raw = json.loads(line)
                            if not isinstance(raw, dict):
                                raise ValueError('Archive record is not an object')
                            self.spool.put_archive(raw, stream, source.tell())
                        except Exception:
                            self.status.update(state='error', file=str(path), offset=start)
                            raise  # checkpoint stays before the failed line
                        count += 1
                        self.status.update(state='running', file=str(path), offset=source.tell(),
                                           enqueued=self.status['enqueued'] + 1, last_read_at=time.time())
            except FileNotFoundError:
                continue  # rotation between stat and open; rediscover next poll
            if count >= limit:
                break
        self.status['state'] = 'running' if found else 'waiting'
        return count
