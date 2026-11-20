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


def line_boundary(source, offset, max_rewind=1024 * 1024):
    """Replay the containing record if a persisted byte offset is not a line boundary.

    Never move a checkpoint here: the spool advances it atomically after enqueue.
    Fail closed if the checkpoint lies beyond EOF or the line start is too far away.
    """
    if offset <= 0:
        return 0
    source.seek(offset - 1)
    previous = source.read(1)
    if not previous:
        raise ValueError('Archive checkpoint is beyond available data')
    if previous == b'\n':
        return offset
    cursor = offset
    floor = max(0, offset - max_rewind)
    while cursor > floor:
        start = max(floor, cursor - 8192)
        source.seek(start)
        chunk = source.read(cursor - start)
        index = chunk.rfind(b'\n')
        if index >= 0:
            return start + index + 1
        cursor = start
    if floor == 0:
        return 0
    raise ValueError('Archive checkpoint is inside an oversized line')


class ArchiveReader:
    def __init__(self, path, spool):
        self.path = Path(path)
        self.spool = spool
        self.scanned = {}
        self.candidates = []
        self.discovered = 0
        self.replay_streams = {}
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
                    if path.name.endswith('.gz') and offset:
                        source.seek(offset - 1)
                        if not source.read(1):
                            # A retained compressed file is shorter than the old stream
                            # checkpoint. Its identity cannot be assumed: replay it from
                            # the beginning under a stable content-derived checkpoint.
                            key = (str(path), signature)
                            replay = self.replay_streams.get(key)
                            if replay is None:
                                digest = hashlib.sha256()
                                with path.open('rb') as compressed:
                                    for chunk in iter(lambda: compressed.read(1024 * 1024), b''):
                                        digest.update(chunk)
                                replay = stream + ':gzip-replay:' + digest.hexdigest()
                                self.replay_streams[key] = replay
                            stream = replay
                            offset = self.spool.archive_offset(stream)
                            self.status.update(replay_file=str(path), replay_reason='checkpoint_beyond_compressed_archive')
                    try:
                        start_offset = line_boundary(source, offset)
                    except ValueError:
                        self.status.update(state='error', file=str(path), offset=offset)
                        raise
                    if start_offset != offset:
                        self.status.update(recovered_from_offset=offset, recovered_to_offset=start_offset)
                    source.seek(start_offset)
                    while count < limit:
                        start = source.tell()
                        line = source.readline()
                        if not line:
                            self.scanned[str(path)] = signature
                            break
                        if not line.endswith(b'\n'):
                            break  # writer has not completed this event yet
                        try:
                            # Some rotated archives contain zero padding before an
                            # otherwise complete JSON line. Recover only that exact
                            # case: parsing must still succeed and the original file
                            # remains untouched. Any other corruption still stops at
                            # this checkpoint rather than dropping a record.
                            unpadded = line.lstrip(b'\x00')
                            raw = json.loads(unpadded)
                            if not isinstance(raw, dict):
                                raise ValueError('Archive record is not an object')
                            self.spool.put_archive(raw, stream, source.tell())
                            if len(unpadded) != len(line):
                                self.status['nul_padded_records_recovered'] = self.status.get('nul_padded_records_recovered', 0) + 1
                                self.status.update(last_nul_padding_file=str(path), last_nul_padding_offset=start,
                                                   last_nul_padding_bytes=len(line) - len(unpadded))
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
