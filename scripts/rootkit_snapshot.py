#!/usr/bin/env python3
"""Bounded, read-only Linux PID observation. Emits one JSON line to stdout.
No process is modified. Signal 0 is an existence/permission probe only.
The outer envelope uses scalar fields for Wazuh's JSON decoder.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from datetime import datetime, timezone

PRODUCER = 'soc-ai-rootkit-snapshot-v1'
PROC = Path('/proc')


def read_text(path):
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def identity(pid):
    status = read_text(PROC / str(pid) / 'status')
    stat = read_text(PROC / str(pid) / 'stat')
    if status is None or stat is None:
        return None
    try:
        fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
        # The comm field can contain spaces or parentheses; stat field 22 is starttime.
        rest = stat[stat.rindex(')') + 1:].split()
        return {'pid': int(fields['Pid']), 'tgid': int(fields['Tgid']),
                'start_ticks': int(rest[19])}
    except (ValueError, KeyError, IndexError):
        return None


def probe(pid):
    try:
        os.kill(pid, 0)
        return 'exists'
    except ProcessLookupError:
        return 'not_found'
    except PermissionError:
        return 'permission_denied'
    except OSError:
        return 'error'


def proc_listed(pid):
    try:
        with os.scandir(PROC) as entries:
            return any(e.name == str(pid) for e in entries)
    except OSError:
        return None


def ps_listed(pid, threads=False):
    args = ['/usr/bin/ps', '-eL', '-o', 'lwp='] if threads else ['/usr/bin/ps', '-e', '-o', 'pid=']
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=3,
                                check=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        return str(pid) in result.stdout.split()
    except (OSError, subprocess.SubprocessError):
        return None


def sample(pid):
    before = identity(pid)
    result = {'kill0': probe(pid), 'proc_visible': proc_listed(pid),
              'ps_visible': ps_listed(pid), 'ps_thread_visible': ps_listed(pid, True)}
    after = identity(pid)
    result['identity'] = before if before is not None and before == after else None
    return result


def classify(pid, first, second, boot_stable):
    a, b = first['identity'], second['identity']
    if not boot_stable:
        return 'identity_unverified'
    if a and b and a != b:
        return 'identity_changed'
    if any(x and x['tgid'] != pid for x in (a, b)):
        return 'thread_not_process_leader'
    if first['kill0'] == second['kill0'] == 'not_found':
        return 'not_found'
    if a is None or b is None or a['pid'] != pid or a['tgid'] != pid:
        return 'identity_unverified'
    if all(s['kill0'] == 'exists' and s['proc_visible'] is False
           and s['ps_visible'] is False and s['ps_thread_visible'] is False
           for s in (first, second)):
        return 'stable_process_visibility_discrepancy'
    if all(s['kill0'] == 'exists' and s['proc_visible'] is True
           and s['ps_visible'] is True for s in (first, second)):
        return 'visible_process'
    return 'inconclusive_observation'


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', required=True, type=int, help='Explicit target PID from an alert or a benign test')
    args = parser.parse_args()
    pid_max = read_text(PROC / 'sys/kernel/pid_max')
    try:
        limit = min(int(pid_max), 4194304) if pid_max is not None else 4194304
    except ValueError:
        limit = 4194304
    if not 1 <= args.pid <= limit:
        parser.error('PID outside supported range')
    if os.geteuid() != 0:
        parser.error('Run as root on the authorized Ubuntu endpoint')
    pid = args.pid
    boot = read_text(PROC / 'sys/kernel/random/boot_id')
    started = utc_now()
    first = sample(pid)
    time.sleep(0.5)
    second = sample(pid)
    boot_after = read_text(PROC / 'sys/kernel/random/boot_id')
    boot_stable = bool(boot and boot == boot_after)
    finding = classify(pid, first, second, boot_stable)
    taint = read_text(PROC / 'sys/kernel/tainted')
    try:
        taint = int(taint)
    except (TypeError, ValueError):
        taint = None
    modules = read_text(PROC / 'modules')
    obs = {'pid': pid, 'finding': finding, **first,
           **{'recheck_' + k: v for k, v in second.items()}}
    snapshot = {'producer': PRODUCER, 'observed_at': utc_now(), 'started_at': started,
                'boot_id': boot.strip() if boot else None,
                'scan': {'mode': 'targeted', 'target_pid': pid}, 'suspects': [obs],
                'modules': {'visible_count': len(modules.splitlines()) if modules is not None else None,
                            'kernel_taint': taint},
                'interpretation': 'Local kernel-dependent observation; not independent forensic proof. '
                                  'proc_visible means directory enumeration; null means unavailable.'}
    envelope = {'producer': PRODUCER, 'observed_at': snapshot['observed_at'],
                'target_pid': pid, 'finding': finding,
                'snapshot_json': json.dumps(snapshot, separators=(',', ':'), ensure_ascii=True)}
    print(json.dumps(envelope, separators=(',', ':'), ensure_ascii=True))


if __name__ == '__main__':
    main()
