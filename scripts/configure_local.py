"""Create local secrets and a consistent low-memory config; preserve other settings."""
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parent.parent
env = ROOT / '.env'
lines = env.read_text(encoding='utf-8').splitlines() if env.exists() else (ROOT / '.env.example').read_text(encoding='utf-8').splitlines()
values = {line.split('=', 1)[0].strip(): line.split('=', 1)[1] for line in lines if '=' in line and not line.lstrip().startswith('#')}
values.setdefault('WAZUH_WEBHOOK_TOKEN', '')
values.setdefault('WAZUH_ENROLLMENT_PASSWORD', '')
for key in ('WAZUH_WEBHOOK_TOKEN', 'WAZUH_ENROLLMENT_PASSWORD'):
    if not values[key].strip():
        values[key] = secrets.token_hex(24)
values.update(WAZUH_ENABLED='true', OLLAMA_MODEL='qwen3:8b', AGENT_MODEL='qwen3:8b', OLLAMA_MODEL_ALIAS='qwen3_8b', AI_MAX_CONCURRENCY='1', OLLAMA_NUM_CTX='4096', OLLAMA_NUM_PREDICT='1024', OLLAMA_TIMEOUT='900')
values = {k: v for k, v in values.items() if not k.startswith('ZEEK_') and k not in ('SOC_API_TOKEN', 'COPILOT_MODEL')}
env.write_text('\n'.join(f'{k}={v}' for k,v in values.items()) + '\n', encoding='utf-8')
folder = ROOT / 'secrets'
folder.mkdir(exist_ok=True)
(folder / 'authd.pass').write_text(values['WAZUH_ENROLLMENT_PASSWORD'] + '\n', encoding='utf-8', newline='\n')
print('Updated .env and secrets/authd.pass. Secret values are not displayed.')
