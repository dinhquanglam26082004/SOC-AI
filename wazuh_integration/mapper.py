"""Normalize source evidence without inferring attacker identity."""
from datetime import datetime, timezone
from hashlib import sha256
import os
import ipaddress


def network_ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def map_wazuh_alert(raw):
    if not isinstance(raw, dict):
        raise ValueError('Expected a JSON object')
    rule, agent, manager = (raw.get(k) for k in ('rule', 'agent', 'manager'))
    if not all(isinstance(v, dict) for v in (rule, agent, manager)):
        raise ValueError('rule, agent and manager must be objects')
    for obj, keys in ((raw, ('id', 'timestamp')), (rule, ('id', 'description')), (agent, ('id', 'name')), (manager, ('name',))):
        if any(not isinstance(obj.get(k), str) or not obj[k].strip() for k in keys):
            raise ValueError('Missing required source identifiers or description')
    level = rule.get('level')
    if type(level) is not int or not 0 <= level <= 15:
        raise ValueError('rule.level must be an integer from 0 to 15')
    groups = rule.get('groups', [])
    if not isinstance(groups, list) or any(not isinstance(g, str) for g in groups):
        raise ValueError('rule.groups must be a string array')
    stamp = datetime.fromisoformat(raw['timestamp'].replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('timestamp must include a timezone')
    data = raw.get('data', {})
    if not isinstance(data, dict):
        raise ValueError('data must be an object')
    win = data.get('win', {})
    if not isinstance(win, dict):
        raise ValueError('data.win must be an object')
    system, event = win.get('system', {}), win.get('eventdata', {})
    if not isinstance(system, dict) or not isinstance(event, dict):
        raise ValueError('Windows event fields must be objects')
    syscheck = raw.get('syscheck', {})
    if not isinstance(syscheck, dict):
        raise ValueError('syscheck must be an object')
    source_id = manager['name'] + '\x00' + raw['id']
    received = utc_now()
    record = {
        'id': 'WAZUH-' + sha256(source_id.encode()).hexdigest(),
        'source': 'wazuh', 'source_event_id': raw['id'],
        'timestamp': stamp.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'received_at': received, 'created_at': received,
        'agent': agent, 'manager': manager, 'rule': rule,
        'mitre': rule.get('mitre'), 'event_id': system.get('eventID'),
        'username': event.get('targetUserName') or event.get('subjectUserName') or data.get('dstuser') or data.get('srcuser'),
        'process': event.get('newProcessName') or event.get('image') or data.get('process'),
        'file_path': syscheck.get('path'), 'file_event': syscheck.get('event'),
        'src_ip': network_ip(data.get('srcip') or event.get('ipAddress') or event.get('sourceIp')),
        'dst_ip': network_ip(data.get('dstip') or event.get('destinationIp')),
        'src_port': data.get('srcport') or event.get('ipPort'),
        'dst_port': data.get('dstport') or event.get('destinationPort'),
        'raw_event': raw, 'ai_status': 'skipped',
        'severity': 'CRITICAL' if level >= 13 else 'HIGH' if level >= 10 else 'MEDIUM' if level >= 7 else 'LOW',
    }
    # Keep the authenticated transport as Wazuh. The original producer is Zeek;
    # Zeek itself does not assign the numeric severity used by the Manager rule.
    location = raw.get('location', '')
    if ('zeek_telemetry' in groups or 'zeek_notice' in groups) and isinstance(location, str) and '/zeek/logs/current/' in location and location.endswith('.log'):
        record['source_product'] = 'zeek'
        record['transport'] = 'wazuh'
        record['log_type'] = location.rsplit('/', 1)[-1][:-4]
        record['event_kind'] = 'alert' if 'zeek_notice' in groups else 'telemetry'
        record['zeek_data'] = data
        record['raw_line'] = raw.get('full_log')
        record['severity_origin'] = 'wazuh_delivery_rule'
        record['zeek_notice'] = {
            key: data[key] for key in ('note', 'msg', 'sub', 'uid', 'ts', 'src', 'dst', 'p', 'proto', 'actions')
            if key in data
        }
        # Wazuh expands dotted JSON keys (id.orig_h) into a nested id object.
        endpoints = data.get('id') if isinstance(data.get('id'), dict) else {}
        record['src_ip'] = network_ip(data.get('src') or data.get('id.orig_h') or endpoints.get('orig_h'))
        record['dst_ip'] = network_ip(data.get('dst') or data.get('id.resp_h') or endpoints.get('resp_h'))
        record['src_port'] = data.get('id.orig_p', endpoints.get('orig_p'))
        record['dst_port'] = data.get('p') or data.get('id.resp_p', endpoints.get('resp_p'))
    record['ai_allowed'] = is_security_alert(record)
    record['event_kind'] = 'alert' if record['ai_allowed'] else 'telemetry'
    return record


def is_security_alert(record):
    """Hard boundary shared by ingestion, manual retry and the AI worker."""
    if record.get('source') != 'wazuh' or record.get('event_kind') == 'telemetry':
        return False
    rule = record.get('rule', {})
    groups = set(rule.get('groups', []))
    if record.get('source_product') == 'zeek':
        note = str(record.get('zeek_notice', {}).get('note', ''))
        return ('zeek_notice' in groups and bool(note)
                and not note.startswith(('CaptureLoss::', 'ChecksumOffloading::')))
    if groups.intersection({'sca', 'syscollector', 'dpkg', 'package', 'package_management', 'inventory'}):
        return False
    if str(rule.get('id')) in {'591', '5501', '5502', '5402'}:
        return False  # rotation, ordinary PAM sessions and successful sudo
    security_groups = {'syscheck', 'authentication_failed', 'invalid_login', 'rootcheck',
                       'malware', 'web_attack', 'attack', 'intrusion_detection', 'virus',
                       'trojan', 'ransomware', 'exploit', 'yara', 'suricata', 'snort'}
    rules = {x.strip() for x in os.getenv('WAZUH_AI_RULE_ALLOWLIST', '').split(',') if x.strip()}
    return (rule.get('level', 0) >= 7 or bool(groups.intersection(security_groups))
            or str(rule.get('id')) == '5404' or str(rule.get('id')) in rules)


def ai_eligible(record):
    if not is_security_alert(record):
        return False
    rules = {x.strip() for x in os.getenv('WAZUH_AI_RULE_ALLOWLIST', '').split(',') if x.strip()}
    groups = {x.strip() for x in os.getenv('WAZUH_AI_GROUP_ALLOWLIST', 'syscheck').split(',') if x.strip()}
    rule = record['rule']
    return (rule['level'] >= int(os.getenv('WAZUH_AI_MIN_LEVEL', '7'))
            or rule['id'] in rules or bool(groups.intersection(rule.get('groups', []))))
