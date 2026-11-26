"""Kernel-module evidence uses the retained Rule 100200 Wazuh observation."""
from zoneinfo import ZoneInfo

from agents.investigation_context import evidence_summary, pack_evidence
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import observation
from wazuh_integration.mapper import map_wazuh_alert


MODULE_LOG = (
    'type=SYSCALL msg=audit(1795601939.531:1116784): arch=c000003e syscall=313 success=yes exit=0 '
    'a0=3 a1=5e4f360ffe52 a2=0 a3=700076804b20 items=0 ppid=179771 pid=179772 auid=1000 '
    'uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=77 comm="insmod" '
    'exe="/usr/bin/kmod" subj=unconfined key="kernel_module_load"\x1dARCH=x86_64 SYSCALL=finit_module '
    'AUID="victim" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" '
    'FSGID="root" type=KERN_MODULE msg=audit(1795601939.531:1116784): name="diamorphine" '
    'type=PROCTITLE msg=audit(1795601939.531:1116784): '
    'proctitle=7375646F00696E736D6F64006469616D6F727068696E652E6B6F'
)
AUDIT_DATA = {
    'type':'SYSCALL', 'id':'1116784', 'arch':'c000003e', 'syscall':'313',
    'success':'yes', 'exit':'0', 'ppid':'179771', 'pid':'179772',
    'auid':'1000', 'uid':'0', 'gid':'0', 'euid':'0', 'suid':'0',
    'fsuid':'0', 'egid':'0', 'sgid':'0', 'fsgid':'0', 'tty':'pts1',
    'session':'77', 'command':'insmod', 'exe':'/usr/bin/kmod',
    'key':'kernel_module_load',
}


def wazuh_module_event(rule_id='100200', full_log=MODULE_LOG):
    return {
        'id':'1795601941.2057479', 'timestamp':'2026-11-25T10:19:01.357+0000',
        'rule':{'id':rule_id,'level':3,'description':'Kernel module load operation observed',
                'groups':['local','kernel_monitoring','soc_ai','kernel_module_activity']},
        'agent':{'id':'002','name':'ubuntu-soc-server','ip':'192.168.60.138'},
        'manager':{'name':'soc-manager'},
        'full_log':full_log, 'data':{'audit':AUDIT_DATA.copy()},
        'location':'/var/log/audit/audit.log',
    }


def test_real_rule_100200_module_name_reaches_final_context(tmp_path):
    raw = wazuh_module_event()
    record = map_wazuh_alert(raw)
    assert record['id'] == 'WAZUH-369b61276127bf2c9f7c84d565cca84f7b59674b2e0227e6020a874930fd5abe'
    assert record['raw_event'] == raw
    observed = observation(record)
    assert observed['full_log'] == MODULE_LOG and not observed['summary_truncated']
    module = observed['kernel_module_activity']
    assert module == {
        'audit_id':'1116784', 'syscall':'313', 'command':'insmod',
        'executable':'/usr/bin/kmod', 'success':'yes', 'exit':'0',
        'uid':'0', 'auid':'1000', 'audit_epoch':'1795601939.531',
        'syscall_name':'finit_module', 'module_name':'diamorphine',
    }

    audit = InvestigationStore(tmp_path / 'audit.db')
    run = audit.create('alert-521', {})
    evidence_id = audit.add_evidence(run['id'], record['id'], 'observed', observed,
                                     'search_rootkit_evidence', {})
    assert evidence_id == 'EV-c4f414a8d86f51861f4161bc'
    saved = audit.evidence(run['id'])[0]
    compact = evidence_summary(saved, ZoneInfo('Asia/Ho_Chi_Minh'))
    assert compact['event_time'] == '2026-11-25T10:19:01.357000Z'
    assert compact['event_time_local'] == '2026-11-25T17:19:01.357000+07:00'
    assert compact['data']['kernel_module_activity']['module_name'] == 'diamorphine'
    assert 'audit' not in compact['data'] and 'log_excerpt' not in compact['data']
    packed = pack_evidence([saved], 4143, ZoneInfo('Asia/Ho_Chi_Minh'))
    assert packed['allowed_factual_evidence_ids'] == [evidence_id]
    assert packed['evidence'][0]['data']['kernel_module_activity']['module_name'] == 'diamorphine'
    assert saved['data']['full_log'] == MODULE_LOG


def test_missing_or_mismatched_module_record_is_not_invented():
    raw = wazuh_module_event('100205',
        'type=SYSCALL msg=audit(1795601939.531:1116784): syscall=176 success=no exit=-1 '
        'comm="rmmod" exe="/usr/bin/kmod" SYSCALL=delete_module')
    result = observation(map_wazuh_alert(raw))
    assert 'module_name' not in result['kernel_module_activity']
    assert 'log_excerpt' in evidence_summary({'data':result,'evidence_id':'EV-test',
        'evidence_type':'observed','event_time':result['event_time'],
        'source_record_id':result['id']})['data']

    mismatched = wazuh_module_event(full_log=MODULE_LOG.replace(
        'type=KERN_MODULE msg=audit(1795601939.531:1116784)',
        'type=KERN_MODULE msg=audit(1795601939.531:9999999)'))
    result = observation(map_wazuh_alert(mismatched))
    assert 'module_name' not in result['kernel_module_activity']


def test_rule_100205_uses_recorded_unload_fields_only():
    raw = wazuh_module_event('100205', MODULE_LOG.replace(
        'syscall=313', 'syscall=176').replace('SYSCALL=finit_module', 'SYSCALL=delete_module')
        .replace('comm="insmod"', 'comm="rmmod"').replace('name="diamorphine"', 'name="example_module"'))
    raw['data']['audit'].update(syscall='176', command='rmmod')
    module = observation(map_wazuh_alert(raw))['kernel_module_activity']
    assert module['syscall'] == '176' and module['syscall_name'] == 'delete_module'
    assert module['command'] == 'rmmod' and module['module_name'] == 'example_module'
    assert module['success'] == 'yes' and module['exit'] == '0'
