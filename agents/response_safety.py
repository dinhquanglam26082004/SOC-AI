"""Safety checks for response targets, including previously saved plans."""
from copy import deepcopy
import ipaddress
import os


def block_ip_reason(target, alert):
    """Reject protected or unverifiable IP targets without inferring attacker identity."""
    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return 'Địa chỉ IP cần chặn không hợp lệ.'
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return 'Địa chỉ IP nằm trong phạm vi được bảo vệ.'
    record = alert if isinstance(alert, dict) else {}
    manager = record.get('manager') if isinstance(record.get('manager'), dict) else {}
    protected = [manager.get('ip'), *os.getenv('RESPONSE_PROTECTED_TARGETS', '').split(',')]
    for value in protected:
        try:
            if address == ipaddress.ip_address(str(value).strip()):
                return 'Địa chỉ IP nằm trong danh sách được bảo vệ.'
        except ValueError:
            continue
    agent = record.get('agent') if isinstance(record.get('agent'), dict) else {}
    try:
        agent_ip = ipaddress.ip_address(str(agent.get('ip') or '').strip())
    except ValueError:
        return 'Không xác định được IP của Agent để kiểm tra mục tiêu chặn.'
    if agent_ip.is_unspecified or agent_ip.is_multicast or agent_ip.is_loopback:
        return 'Không xác định được IP của Agent để kiểm tra mục tiêu chặn.'
    if address == agent_ip:
        return 'Không được chặn IP của Agent đang được giám sát.'
    return None


def safe_plan_view(plan, alert):
    """Mark unsafe legacy proposals in the response without rewriting history."""
    view = deepcopy(plan)
    if view.get('status') == 'executed':
        return view
    for action in view.get('actions') or []:
        if action.get('action') != 'block_ip' or action.get('status') not in {'proposed', 'approved'}:
            continue
        reason = block_ip_reason(action.get('target'), alert)
        if reason:
            action['status'] = 'rejected'
            action['policy_reasons'] = list(dict.fromkeys([*(action.get('policy_reasons') or []), reason]))
    return view
