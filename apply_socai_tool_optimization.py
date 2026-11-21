#!/usr/bin/env python3
"""Guarded, minimal patch for SOC-AI tool calls (public main, Nov 20 2026).

Usage:
    python apply_socai_tool_optimization.py --check --repo .
    python apply_socai_tool_optimization.py --apply --repo .

No network required. Does not touch DB, Docker volumes or Git history.
"""
from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
import shutil
import sys

HELPER = '''"""Normalize tool arguments for equivalent read-only SOC investigation queries.

This does not grant permission or widen scope: LocalTools.execute still enforces
Pydantic validation and the agent, IP and time restrictions.
"""
from common.log_index import utc_stamp


def normalized_tool_args(name, arguments, models, *, agent, since, until):
    """Canonicalize Pydantic defaults and UTC times before creating a cache key.

    Invalid or malformed arguments remain unchanged so execute() rejects them.
    In particular, NEVER replace a foreign agent_id with the incident agent.
    """
    if name not in models or not isinstance(arguments, dict):
        return arguments
    try:
        params = models[name].model_validate(arguments).model_dump()
    except (ValueError, TypeError):
        return arguments
    if 'agent_id' in params and params['agent_id'] is None:
        params['agent_id'] = agent
    for key, default in (('since', since), ('until', until)):
        if key in params:
            value = params[key] if params[key] is not None else default
            try:
                params[key] = utc_stamp(value)
            except (ValueError, TypeError):
                params[key] = value
    for key in ('baseline_since', 'baseline_until'):
        if params.get(key) is not None:
            try:
                params[key] = utc_stamp(params[key])
            except (ValueError, TypeError):
                pass
    return params
'''


def replace_once(source: str, old: str, new: str, label: str) -> str:
    n = source.count(old)
    if n != 1:
        raise RuntimeError(f'{label}: expected 1 matching code fragment; found {n}. No files were changed.')
    return source.replace(old, new, 1)


def patched_graph(source: str) -> str:
    source = replace_once(
        source,
        'from agents.investigation_profiles import tools_for, context_hint, baseline_calls\n',
        'from agents.investigation_profiles import tools_for, context_hint, baseline_calls\n'
        'from agents.tool_call_policy import normalized_tool_args\n',
        'import helper',
    )
    source = replace_once(
        source,
        'Mỗi tool chỉ được chạy một lần trong cuộc điều tra, kể cả khi đổi tham số hoặc lần trước bị lỗi. Chọn phạm vi phù hợp ngay từ đầu.',
        'Không gọi lại truy vấn tương đương; chỉ đọc chi tiết Evidence ID khác hoặc tinh chỉnh truy vấn khi kết quả trước bị cắt. Nếu tool lỗi tham số, được sửa tham số rồi thử lại.',
        'tool prompt policy',
    )
    old = '''def used_tool_names(state):
    """Tool attempts in the checkpoint, excluding calls prevented before dispatch."""
    not_dispatched = {'missing_scope_or_budget', 'tool_budget', 'time_budget'}
    return {item['tool'] for item in state.get('observations', [])
            if item.get('tool') and item.get('error') not in not_dispatched}

def available_tool_names(state, allowed=None):
    used = used_tool_names(state)
    names = allowed if allowed is not None else [name for name in MODELS if name != 'get_alert']
    return [name for name in names if name != 'get_alert' and name not in used]
'''
    new = '''# A successful or completed read counts as used, not malformed or rejected requests.
COMPLETED_TOOL_STATUSES = {'ok', 'empty', 'truncated', 'unavailable'}


def used_tool_names(state):
    return {item['tool'] for item in state.get('observations', [])
            if item.get('tool') and item.get('status') in COMPLETED_TOOL_STATUSES
            and item.get('error') not in {'time_budget', 'tool_budget', 'missing_scope_or_budget'}}


def available_tool_names(state, allowed=None):
    observations = state.get('observations', [])
    used = used_tool_names(state)
    counts = {name: sum(item.get('tool') == name and
                        item.get('status') in COMPLETED_TOOL_STATUSES
                        for item in observations) for name in used}
    refinable = {item['tool'] for item in observations
                 if item.get('tool') and item.get('truncated')
                 and item.get('status') in COMPLETED_TOOL_STATUSES}
    names = allowed if allowed is not None else [name for name in MODELS if name != 'get_alert']
    return [name for name in names if name != 'get_alert'
            and counts.get(name, 0) < (3 if name == 'get_event_details' else 2)
            and (name not in used or name == 'get_event_details' or name in refinable)]
'''
    source = replace_once(source, old, new, 'tool availability rules')
    old = '''    def tool(self,name,args,explanation=None):
        key='tool-'+hashlib.sha256(encode([name,args]).encode()).hexdigest()[:32]
'''
    new = '''    def tool_signature(self, name, args):
        canonical = normalized_tool_args(name, args, MODELS,
            agent=self.tools.agent, since=self.tools.since, until=self.tools.until)
        key = 'tool-' + hashlib.sha256(encode([name, canonical]).encode()).hexdigest()[:32]
        return canonical, key

    def tool(self,name,args,explanation=None):
        canonical, key = self.tool_signature(name, args)
'''
    source = replace_once(source, old, new, 'canonical call key')
    source = replace_once(
        source,
        'result=self.tools.execute(name,args,timeout=min(remaining,self.limits.tool_seconds))',
        'result=self.tools.execute(name,canonical,timeout=min(remaining,self.limits.tool_seconds))',
        'canonical tool execution',
    )
    source = replace_once(
        source,
        "return self.audit.call(self.id,key,'tool',name,args,None if self.limits.progress_mode else self.limits.tool_calls,dispatch)",
        "return self.audit.call(self.id,key,'tool',name,canonical,None if self.limits.progress_mode else self.limits.tool_calls,dispatch)",
        'canonical audit call',
    )
    source = replace_once(
        source,
        "observations=[{'tool':'get_alert','status':result['status']}]",
        "observations=[{'tool':'get_alert','status':result['status']}]",
        'get_alert unchanged sentinel',
    )
    source = replace_once(
        source,
        "observations.append({'tool':'summarize_zeek_flows','status':aggregate['status'],",
        "observations.append({'tool':'summarize_zeek_flows','status':aggregate['status'],\n"
        "                    'request_key':self.tool_signature('summarize_zeek_flows',args)[1],",
        'flow automatic signature',
    )
    source = replace_once(
        source,
        "entry={'tool':name,'status':result['status'],'error':result.get('error'),",
        "entry={'tool':name,'request_key':self.tool_signature(name,args)[1],\n"
        "                   'status':result['status'],'error':result.get('error'),",
        'baseline automatic signature',
    )
    old = '''        used=used_tool_names(state)
        for pending in state['pending']:
            if pending['name'] in used:
                result=self.tools.envelope('skipped',error='tool_already_used',
                                           detail='Tool đã chạy trong cuộc điều tra này.')
            else:
                try:
                    result=self.tool(pending['name'],pending['args'],pending.get('explanation'))
                except WorkflowError as exc:
                    if exc.code!='tool_budget': raise
                    stop='tool_budget'; result=self.tools.envelope('unavailable',error=stop)
                if result.get('error') not in {'tool_budget','time_budget'}:
                    used.add(pending['name'])
            observations.append({'tool':pending['name'],'status':result['status'],
                                  'error':result.get('error'),'count':len(result.get('items',[])),
                                  'truncated':result.get('truncated',False)})
'''
    new = '''        completed = [o for o in observations if o.get('status') in COMPLETED_TOOL_STATUSES
                     and o.get('error') not in {'time_budget','tool_budget','missing_scope_or_budget'}]
        seen = {o['request_key'] for o in completed if o.get('request_key')}
        counts = {n: sum(o.get('tool') == n for o in completed)
                  for n in {o.get('tool') for o in completed}}
        refinable = {o.get('tool') for o in completed if o.get('truncated')}
        for pending in state['pending']:
            name = pending['name']
            _, request_key = self.tool_signature(name, pending['args'])
            limit = 3 if name == 'get_event_details' else 2
            if request_key in seen:
                result=self.tools.envelope('skipped',error='equivalent_query_already_completed',
                    detail='Truy vấn tương đương đã hoàn tất; dùng Evidence hiện có.')
            elif counts.get(name, 0) >= limit or (counts.get(name, 0) >= 1
                    and name != 'get_event_details' and name not in refinable):
                result=self.tools.envelope('skipped',error='tool_query_limit',
                    detail='Tool đã có dữ liệu; chỉ truy vấn lại khi kết quả bị cắt.')
            else:
                try:
                    result=self.tool(name,pending['args'],pending.get('explanation'))
                except WorkflowError as exc:
                    if exc.code!='tool_budget': raise
                    stop='tool_budget'; result=self.tools.envelope('unavailable',error=stop)
                if result.get('status') in COMPLETED_TOOL_STATUSES and result.get('error') not in {
                        'tool_budget','time_budget','missing_scope_or_budget'}:
                    seen.add(request_key)
                    counts[name] = counts.get(name, 0) + 1
                    if result.get('truncated'):
                        refinable.add(name)
            observations.append({'tool':name,'request_key':request_key,'status':result['status'],
                                  'error':result.get('error'),'count':len(result.get('items',[])),
                                  'truncated':result.get('truncated',False)})
'''
    source = replace_once(source, old, new, 'guarded tool dispatch')
    return source


def main():
    parser = argparse.ArgumentParser(description='Safe SOC-AI tool-call optimization')
    parser.add_argument('--repo', type=Path, default=Path('.'))
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--check', action='store_true', help='Validate patch points without writing')
    g.add_argument('--apply', action='store_true', help='Back up and write files')
    opts = parser.parse_args()
    root = opts.repo.resolve()
    graph = root/'agents'/'investigation_graph.py'
    helper = root/'agents'/'tool_call_policy.py'
    if not graph.is_file():
        parser.error(f'Cannot find {graph}. Run from the SOC-AI repository.')
    if helper.exists():
        parser.error(f'{helper} already exists. Review it manually before applying.')
    source = graph.read_text(encoding='utf-8')
    updated = patched_graph(source)
    # Nothing is written until every anchor matches and both files compile.
    compile(updated, str(graph), 'exec')
    compile(HELPER, str(helper), 'exec')
    if opts.check:
        print('OK: patch applies cleanly; no files changed.')
        return
    backup = root.parent/('SOC-AI-tool-backup-'+datetime.now().strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True, exist_ok=False)
    shutil.copy2(graph, backup/'investigation_graph.py')
    try:
        graph.write_text(updated, encoding='utf-8')
        helper.write_text(HELPER, encoding='utf-8')
    except Exception:
        shutil.copy2(backup/'investigation_graph.py', graph)
        if helper.exists():
            helper.unlink()
        raise
    print('Applied: agents/investigation_graph.py, created agents/tool_call_policy.py')
    print(f'Backup original: {backup}')
    print('Review GitHub Desktop Changes and run project tests before rebuilding Docker.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, SyntaxError) as exc:
        print(f'FAILED: {exc}', file=sys.stderr)
        sys.exit(1)
