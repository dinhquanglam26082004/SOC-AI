import hashlib
import gzip
import json
import sqlite3

import pytest

from wazuh_integration.archives import ArchiveReader, line_boundary
from wazuh_integration.spool import Spool


def set_cursor(spool, stream, offset):
    with spool.connect() as db:
        db.execute('INSERT INTO archive_cursors VALUES (?, ?)', (stream, offset))


def test_mid_record_checkpoint_replays_complete_record(tmp_path):
    path = tmp_path / 'archives.json'
    first = b'{"id":"first"}\n'
    second = b'{"id":"second","message":"security event"}\n'
    third = b'{"id":"third"}\n'
    path.write_bytes(first + second + third)
    spool = Spool(tmp_path / 'spool.sqlite3')
    stream = hashlib.sha256(first).hexdigest()
    set_cursor(spool, stream, len(first) + 5)
    reader = ArchiveReader(path, spool)

    assert reader.poll() == 2
    with sqlite3.connect(spool.path) as db:
        records = [json.loads(row[0]) for row in db.execute('SELECT payload FROM queue ORDER BY id')]
    assert [record['id'] for record in records] == ['second', 'third']
    assert spool.archive_offset(stream) == len(first + second + third)
    assert reader.status['recovered_to_offset'] == len(first)


def test_malformed_record_is_not_skipped(tmp_path):
    path = tmp_path / 'archives.json'
    first = b'{"id":"first"}\n'
    path.write_bytes(first + b'not-json\n' + b'{"id":"later"}\n')
    spool = Spool(tmp_path / 'spool.sqlite3')
    stream = hashlib.sha256(first).hexdigest()
    set_cursor(spool, stream, len(first))
    reader = ArchiveReader(path, spool)

    with pytest.raises(json.JSONDecodeError):
        reader.poll()
    assert spool.archive_offset(stream) == len(first)
    assert reader.status['state'] == 'error'


def test_nul_padded_complete_record_is_recovered_without_losing_events(tmp_path):
    path = tmp_path / 'archives.json'
    first = b'{"id":"first"}\n'
    padded = b'\x00' * 867 + b'{"id":"recovered"}\n'
    later = b'{"id":"later"}\n'
    path.write_bytes(first + padded + later)
    spool = Spool(tmp_path / 'spool.sqlite3')
    stream = hashlib.sha256(first).hexdigest()
    set_cursor(spool, stream, len(first))
    reader = ArchiveReader(path, spool)

    assert reader.poll() == 2
    with sqlite3.connect(spool.path) as db:
        records = [json.loads(row[0]) for row in db.execute('SELECT payload FROM queue ORDER BY id')]
    assert [record['id'] for record in records] == ['recovered', 'later']
    assert spool.archive_offset(stream) == len(first + padded + later)
    assert reader.status['nul_padded_records_recovered'] == 1
    assert path.read_bytes() == first + padded + later


def test_checkpoint_beyond_eof_is_not_advanced(tmp_path):
    path = tmp_path / 'archives.json'
    first = b'{"id":"first"}\n'
    path.write_bytes(first)
    spool = Spool(tmp_path / 'spool.sqlite3')
    stream = hashlib.sha256(first).hexdigest()
    set_cursor(spool, stream, len(first) + 100)
    reader = ArchiveReader(path, spool)

    with pytest.raises(ValueError, match='beyond available data'):
        reader.poll()
    assert spool.archive_offset(stream) == len(first) + 100


def test_rewind_bound_prevents_skipping_large_record(tmp_path):
    path = tmp_path / 'large'
    path.write_bytes(b'x' * 100)
    with path.open('rb') as stream:
        with pytest.raises(ValueError, match='oversized line'):
            line_boundary(stream, 90, max_rewind=20)


def test_shorter_compressed_archive_replays_with_separate_persistent_cursor(tmp_path):
    retained = tmp_path / 'ossec-archive-11.json.gz'
    first = b'{"id":"first"}\n'
    with gzip.open(retained, 'wb') as target:
        target.write(first + b'{"id":"second"}\n')
    spool = Spool(tmp_path / 'spool.sqlite3')
    old_stream = hashlib.sha256(first).hexdigest()
    set_cursor(spool, old_stream, 9999)

    reader = ArchiveReader(tmp_path / 'archives.json', spool)
    assert reader.poll() == 2
    assert reader.status['replay_reason'] == 'checkpoint_beyond_compressed_archive'
    assert spool.archive_offset(old_stream) == 9999
    assert ArchiveReader(tmp_path / 'archives.json', spool).poll() == 0
    with sqlite3.connect(spool.path) as db:
        records = [json.loads(row[0])['id'] for row in db.execute('SELECT payload FROM queue ORDER BY id')]
    assert records == ['first', 'second']
