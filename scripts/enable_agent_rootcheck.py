"""Enable only ubuntu-agent rootcheck while preserving shared Agent settings.

Run in Wazuh Manager. Verify the merged XML before atomically replacing agent.conf.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

TARGET = Path('/var/ossec/etc/shared/default/agent.conf')
AGENT_NAME = '^ubuntu-agent$'


def merge_rootcheck(text):
    ET.fromstring('<shared>' + text + '</shared>')
    blocks = list(re.finditer(r'<agent_config\b[^>]*>.*?</agent_config\s*>', text, re.DOTALL))
    targets = [m for m in blocks if ET.fromstring(m.group()).get('name') == AGENT_NAME]
    if len(targets) != 1:
        raise ValueError('Expected exactly one ubuntu-agent configuration')
    match = targets[0]
    block = match.group()
    rootchecks = list(re.finditer(r'<rootcheck\b[^>]*>.*?</rootcheck\s*>', block, re.DOTALL))
    if len(ET.fromstring(block).findall('rootcheck')) != len(rootchecks):
        raise ValueError('Unsupported rootcheck section requires manual review')
    if len(rootchecks) > 1:
        raise ValueError('Multiple rootcheck sections require manual review')
    if rootchecks:
        root = rootchecks[0]
        root_text = root.group()
        disabled = list(re.finditer(r'<disabled>\s*(yes|no)\s*</disabled>', root_text, re.IGNORECASE))
        if len(disabled) > 1:
            raise ValueError('Multiple rootcheck disabled settings require manual review')
        if disabled:
            d = disabled[0]
            root_text = root_text[:d.start()] + '<disabled>no</disabled>' + root_text[d.end():]
        elif '<disabled' in root_text:
            raise ValueError('Unsupported rootcheck disabled setting')
        else:
            opening = re.search(r'<rootcheck\b[^>]*>', root_text)
            root_text = root_text[:opening.end()] + '<disabled>no</disabled>' + root_text[opening.end():]
        block = block[:root.start()] + root_text + block[root.end():]
    else:
        opening = re.search(r'<agent_config\b[^>]*>', block)
        block = block[:opening.end()] + '\n  <rootcheck><disabled>no</disabled></rootcheck>' + block[opening.end():]
    result = text[:match.start()] + block + text[match.end():]
    ET.fromstring('<shared>' + result + '</shared>')
    return result


def main():
    original = TARGET.read_text(encoding='utf-8')
    merged = merge_rootcheck(original)
    if merged == original:
        print('Rootcheck was already enabled in the shared Agent configuration.')
        return
    current = TARGET.stat()
    fd, temporary = tempfile.mkstemp(prefix='soc-rootcheck-', suffix='.conf', dir='/var/ossec/etc')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as output:
            output.write(merged)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, current.st_uid, current.st_gid)
        os.chmod(temporary, current.st_mode & 0o777)
        subprocess.run(['/var/ossec/bin/verify-agent-conf', '-f', temporary], check=True)
        if TARGET.read_text(encoding='utf-8') != original:
            raise RuntimeError('Shared Agent configuration changed during validation')
        os.replace(temporary, TARGET)
        print('Enabled rootcheck for ubuntu-agent; other shared settings were preserved.')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
