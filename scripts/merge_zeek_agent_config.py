"""Replace only the old Zeek wildcard block in a Wazuh shared agent.conf.

Run inside the Manager after copying this script and zeek-all-agent.conf there.
Abort rather than modify a configuration that does not match the expected shape.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

TARGET = Path('/var/ossec/etc/shared/default/agent.conf')
TEMPLATE = Path('/tmp/soc-zeek-agent.conf')
EXPECTED = {'dns', 'conn', 'http', 'ssh', 'ssl', 'notice', 'files', 'dhcp', 'weird'}


def parse(text):
    return ET.fromstring('<shared>' + text + '</shared>')


def main():
    original = TARGET.read_text(encoding='utf-8')
    template = TEMPLATE.read_text(encoding='utf-8')
    target_xml, template_xml = parse(original), parse(template)
    agents = [node for node in target_xml if node.tag == 'agent_config'
              and node.get('name') == '^ubuntu-agent$']
    templates = list(template_xml)
    if len(agents) != 1 or len(templates) != 1 or templates[0].get('name') != '^ubuntu-agent$':
        raise ValueError('Agent configuration scope does not match')
    paths = [item.findtext('location', '') for item in templates[0].findall('localfile')]
    allowed = {'/opt/zeek/logs/current/' + name + '.log' for name in EXPECTED}
    if len(paths) != len(allowed) or set(paths) != allowed:
        raise ValueError('Template must contain exactly the nine selected Zeek files')
    existing = [item.findtext('location', '') for item in agents[0].findall('localfile')]
    if existing.count('/opt/zeek/logs/current/*.log') != 1:
        raise ValueError('Expected one Zeek wildcard in ubuntu-agent configuration')
    pattern = re.compile(r'<localfile\b[^>]*>(?:(?!</localfile>).)*'
                         r'<location>\s*/opt/zeek/logs/current/\*\.log\s*</location>'
                         r'(?:(?!</localfile>).)*</localfile>', re.DOTALL)
    matches = list(pattern.finditer(original))
    if len(matches) != 1:
        raise ValueError('Expected one unambiguous wildcard block')
    block = re.search(r'<agent_config\b[^>]*>(.*)</agent_config>', template, re.DOTALL)
    if not block:
        raise ValueError('Invalid template')
    match = matches[0]
    merged = original[:match.start()] + block.group(1).strip() + original[match.end():]
    parse(merged)
    mode = TARGET.stat()
    fd, path = tempfile.mkstemp(prefix='soc-agent-', suffix='.conf', dir='/var/ossec/etc')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as output:
            output.write(merged)
        os.chown(path, mode.st_uid, mode.st_gid)
        os.chmod(path, mode.st_mode & 0o777)
        subprocess.run(['/var/ossec/bin/verify-agent-conf', '-f', path], check=True)
        if TARGET.read_text(encoding='utf-8') != original:
            raise RuntimeError('Agent configuration changed during validation')
        os.replace(path, TARGET)
        print('Replaced only the Zeek wildcard; other configuration was preserved.')
    finally:
        if os.path.exists(path):
            os.unlink(path)


if __name__ == '__main__':
    main()
