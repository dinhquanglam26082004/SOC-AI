"""Safely switch only ubuntu-agent's shared Zeek dns.log reader to JSON.

Run inside the Wazuh Manager. By default this only previews whether a change is
needed; pass --apply to validate, back up, and atomically update agent.conf.
"""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET


TARGET = Path('/var/ossec/etc/shared/default/agent.conf')
DNS_LOG = '/opt/zeek/logs/current/dns.log'
AGENT_NAME = '^ubuntu-agent$'
AGENT_BLOCK = re.compile(r'<agent_config\b[^>]*>.*?</agent_config\s*>', re.DOTALL)
LOCALFILE_BLOCK = re.compile(r'<localfile\b[^>]*>.*?</localfile\s*>', re.DOTALL)
FORMAT = re.compile(r'(<log_format\s*>)\s*syslog\s*(</log_format\s*>)')


def with_dns_json(original):
    """Return the same configuration with only the targeted reader changed."""
    root = ET.fromstring('<shared>' + original + '</shared>')
    agents = [a for a in root.findall('agent_config') if a.get('name') == AGENT_NAME]
    if len(agents) != 1:
        raise ValueError('Expected exactly one ubuntu-agent configuration')
    readers = [f for f in agents[0].findall('localfile') if (f.findtext('location') or '').strip() == DNS_LOG]
    if len(readers) != 1:
        raise ValueError('Expected exactly one centralized dns.log reader')
    formats = readers[0].findall('log_format')
    if len(formats) != 1:
        raise ValueError('Expected exactly one dns.log log_format')
    current = (formats[0].text or '').strip()
    if current == 'json':
        return original
    if current != 'syslog':
        raise ValueError('Unexpected dns.log log_format: ' + current)

    candidates = []
    for agent in AGENT_BLOCK.finditer(original):
        if ET.fromstring(agent.group()).get('name') != AGENT_NAME:
            continue
        for localfile in LOCALFILE_BLOCK.finditer(agent.group()):
            node = ET.fromstring(localfile.group())
            if (node.findtext('location') or '').strip() == DNS_LOG:
                candidates.append((agent.start() + localfile.start(), agent.start() + localfile.end(), localfile.group()))
    if len(candidates) != 1:
        raise ValueError('Cannot identify exactly one dns.log reader in the source text')
    start, end, block = candidates[0]
    new_block, count = FORMAT.subn(r'\1json\2', block)
    if count != 1:
        raise ValueError('Cannot replace dns.log log_format unambiguously')
    updated = original[:start] + new_block + original[end:]
    ET.fromstring('<shared>' + updated + '</shared>')
    return updated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Validate, back up and apply the change')
    args = parser.parse_args()
    original = TARGET.read_text(encoding='utf-8')
    updated = with_dns_json(original)
    if updated == original:
        print('ubuntu-agent dns.log already uses json; nothing changed.')
        return
    if not args.apply:
        print('Preview: ubuntu-agent dns.log would change from syslog to json; no file changed.')
        return

    info = TARGET.stat()
    fd, temp_path = tempfile.mkstemp(prefix='.soc-dns-', suffix='.conf', dir='/var/ossec/etc')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as output:
            output.write(updated)
        os.chown(temp_path, info.st_uid, info.st_gid)
        os.chmod(temp_path, info.st_mode & 0o777)
        subprocess.run(['/var/ossec/bin/verify-agent-conf', '-f', temp_path], check=True)
        if TARGET.read_text(encoding='utf-8') != original:
            raise RuntimeError('Agent configuration changed during validation; nothing applied')
        backups = Path('/var/ossec/etc/.soc-backups')
        backups.mkdir(mode=0o700, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = backups / ('agent.conf.before-dns-json-' + stamp)
        shutil.copy2(TARGET, backup)
        os.replace(temp_path, TARGET)
        print('Updated ubuntu-agent dns.log to json. Backup:', backup)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


if __name__ == '__main__':
    main()
