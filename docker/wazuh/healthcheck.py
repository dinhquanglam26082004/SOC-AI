import socket
import subprocess
import sys
result = subprocess.run(['/var/ossec/bin/wazuh-control', 'status'], capture_output=True, text=True)
required = ['wazuh-analysisd', 'wazuh-remoted', 'wazuh-authd', 'wazuh-integratord', 'wazuh-db']
if any(name + ' is running' not in result.stdout for name in required):
    sys.exit(1)
for port in (1514, 1515):
    with socket.create_connection(('127.0.0.1', port), timeout=2):
        pass
