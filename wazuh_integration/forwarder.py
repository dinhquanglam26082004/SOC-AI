"""At-least-once HTTP delivery. Run a single instance per spool volume."""
import argparse
import json
import logging
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
from wazuh_integration.spool import Spool

logger = logging.getLogger(__name__)


def deliver(spool, target, token, timeout=10):
    row = spool.ready()
    if row is None:
        return False
    req = urllib.request.Request(target, data=row['payload'].encode(), headers={'Content-Type': 'application/json', 'X-Webhook-Token': token}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            receipt = json.loads(response.read(65536))
            if response.status not in (200, 201, 202) or receipt.get('durable') is not True:
                raise ValueError('Missing durable receipt')
        spool.complete(row['id'])
    except urllib.error.HTTPError as exc:
        permanent = 400 <= exc.code < 500 and exc.code not in (408, 425, 429)
        spool.fail(row, permanent, 'http_' + str(exc.code))
    except (OSError, ValueError):
        spool.fail(row, False, 'transport_or_receipt_error')
    return True


def write_status(spool, path):
    root = Path(path)
    failure = Path(spool.path).parent / 'integration-error'
    status = {**spool.stats(), 'updated': time.time(), 'integration_error': failure.exists()}
    status['state'] = 'error' if failure.exists() or status.get('dead_letter') else 'running'
    tmp = root.with_suffix('.tmp')
    tmp.write_text(json.dumps(status), encoding='utf-8')
    tmp.replace(root)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--replay', type=int)
    parser.add_argument('--import-jsonl', help='Explicit recovery from a Manager retained alerts JSONL file; duplicates are safe')
    args = parser.parse_args()
    spool = Spool(os.getenv('WAZUH_SPOOL_PATH', '/spool/queue.sqlite3'), os.getenv('WAZUH_SPOOL_MAX_BYTES', '268435456'))
    if args.replay is not None:
        spool.replay(args.replay)
        return
    if args.import_jsonl:
        from wazuh_integration.spool import integration
        # Reuse the forwarding filter; each line gets a durable commit.
        import tempfile
        with open(args.import_jsonl, encoding='utf-8') as source, tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
            temp_path = temp.name
            try:
                for line in source:
                    if not line.strip():
                        continue
                    json.loads(line)  # stop, never silently discard malformed source
                    Path(temp_path).write_text(line, encoding='utf-8')
                    integration(temp_path)
            finally:
                Path(temp_path).unlink(missing_ok=True)
        return
    token = os.environ.get('WAZUH_WEBHOOK_TOKEN', '').strip()
    if not token:
        raise RuntimeError('WAZUH_WEBHOOK_TOKEN required')
    target = os.getenv('WAZUH_FORWARDER_TARGET_URL', 'http://soc-ai-app:8100/wazuh')
    path = os.getenv('WAZUH_FORWARDER_STATUS_FILE', '/spool/status.json')
    while True:
        try:
            # Drain a bounded batch; one row/second cannot keep up with Zeek logs.
            for _ in range(100):
                if not deliver(spool, target, token):
                    break
                write_status(spool, path)
            write_status(spool, path)
        except Exception:
            logger.error('Forwarder storage failure; check disk and spool permissions')
            # heartbeat becomes stale if status cannot be persisted
        time.sleep(1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
