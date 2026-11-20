"""Publish verified Wazuh status alongside Docker's existing readiness check."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

REQUIRED = ['wazuh-analysisd', 'wazuh-remoted', 'wazuh-authd', 'wazuh-integratord', 'wazuh-db']
AGENT_LINE = re.compile(r'^\s*ID:\s*([^,]+),\s*Name:\s*(.*?),\s*IP:\s*([^,]+),\s*(.*?)\s*$')


def parse_agents(output):
    if 'List of available agents:' not in output:
        raise ValueError('Unrecognized agent_control output')
    agents = []
    for line in output.splitlines():
        match = AGENT_LINE.match(line)
        if match and match.group(1).strip() != '000':
            agent_id, name, ip, state = (value.strip() for value in match.groups())
            agents.append({'id': agent_id, 'name': name, 'registered_ip': ip, 'status': state})
    return agents


def check():
    manager = {'state': 'unknown', 'components': {}, 'ports': {}}
    agents = {'state': 'unknown', 'items': []}
    try:
        result = subprocess.run(['/var/ossec/bin/wazuh-control', 'status'], capture_output=True, text=True, timeout=4)
        manager['components'] = {name: name + ' is running' in result.stdout for name in REQUIRED}
        for port in (1514, 1515):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                    manager['ports'][str(port)] = True
            except OSError:
                manager['ports'][str(port)] = False
        manager['state'] = 'ready' if (all(manager['components'].values())
                                       and all(manager['ports'].values())) else 'not_ready'
    except (OSError, subprocess.TimeoutExpired):
        manager['state'] = 'unknown'
    try:
        result = subprocess.run(['/var/ossec/bin/agent_control', '-l'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            agents = {'state': 'ok', 'items': parse_agents(result.stdout)}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return {'updated': time.time(), 'manager': manager, 'agents': agents}


def main():
    status = check()
    try:
        target = Path('/spool/manager-status.json')
        temporary = target.with_suffix('.tmp')
        temporary.write_text(json.dumps(status), encoding='utf-8')
        os.chmod(temporary, 0o644)
        temporary.replace(target)
    except OSError as exc:
        print('Unable to publish manager status:', type(exc).__name__, file=sys.stderr)
    return 0 if status['manager']['state'] == 'ready' else 1


if __name__ == '__main__':
    sys.exit(main())
