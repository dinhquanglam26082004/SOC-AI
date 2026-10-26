"""Run isolated cases: contract mode uses mocks; only explicit live mode measures the local model."""
import argparse
import json
from pathlib import Path
import tempfile
import time
from agents.investigation_graph import InvestigationGraph
from agents.investigation_schema import Limits
from agents.investigation_store import InvestigationStore
from common.event_store import EventStore
from common.config import AGENT_MODEL
from evaluation.investigation_cases import cases
from wazuh_integration.mapper import map_wazuh_alert


def run_case(case,mode):
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='soc-quality-') as temp:
        path=Path(temp);store=EventStore(path/'logs.sqlite3');audit=InvestigationStore(path/'audit.sqlite3')
        events=[map_wazuh_alert(raw) for raw in case['events']]
        for event in events:store.accept(event,False)
        def mock(messages,**kwargs):
            if not kwargs.get('schema'):
                return {'message':{'content':'','tool_calls':[{'function':{'name':case['expected_tool'],'arguments':{}}}]}}
            run=audit.current(events[0]['id']);refs=[e['evidence_id'] for e in audit.evidence(run['id'])]
            return {'message':{'content':json.dumps({'incident_type':'Evaluation only','verdict':case['expected_verdict'],
                'reasoning':case['description'],'confidence':None,
                'findings':[{'statement':'Collected records require review.','evidence_ids':refs}],
                'hypotheses':[],'unknowns':['Authorization requires analyst verification.'],
                'recommendations':['Review the evidence.']})}}
        graph=InvestigationGraph(store,audit,model=AGENT_MODEL,client=mock if mode=='contract' else None,
            limits=Limits(rounds=1,model_calls=3,repair_calls=1,tool_calls=4,seconds=240))
        item={'case':case['id'],'expected_verdict':case['expected_verdict'],'mode':mode}
        try:
            report=graph.run_alert(events[0]);run=audit.current(events[0]['id'])
            tools=audit.detail(run['id'],'tools',limit=100)['items']
            names=[t['name'] for t in tools]
            item.update(completed=report.get('generated_by')!='workflow_budget_stop',workflow_completed=True,
                report=report,verdict=report['verdict'],model_verdict=report.get('model_verdict'),needs_analyst=report['needs_analyst'],
                expected_tool_selected=case['expected_tool'] in names,tools=names,
                invalid_tool_requests=sum(t['result'].get('error') in {'tool_not_allowed','invalid_scope_or_arguments'} for t in tools),
                counts=audit.counts(run['id']),stop_reason=report['stop_reason'],
                verification=report['verification_checks'],authentication=[o['authentication_summary'] for o in report['tool_outcomes'] if 'authentication_summary' in o])
        except Exception as exc:
            item.update(completed=False,error=str(exc)[:1000])
            run=audit.current(events[0]['id'])
            if run:
                item['diagnostic_responses']=[{'name':call['name'],'state':call['state'],
                    'response':(call.get('result') or {}).get('message',{}).get('content','')[:5000]}
                    for call in audit.detail(run['id'],'models',100)['items']]
        item['seconds']=round(time.monotonic()-started,2)
        return item


def summarize(items,mode):
    completed=[i for i in items if i['completed']]
    metrics=None
    if mode=='live':
        metrics={'completed':len(completed),'total':len(items),
            'verdict_matches':sum(i['verdict']==i['expected_verdict'] for i in completed),
            'raw_model_verdict_available':sum(i.get('model_verdict') is not None for i in completed),
            'raw_model_verdict_matches':sum(i.get('model_verdict')==i['expected_verdict'] for i in completed),
            'expected_tool_selected':sum(i['expected_tool_selected'] for i in completed),
            'invalid_tool_requests':sum(i['invalid_tool_requests'] for i in completed),
            'inconclusive_on_malicious_case':sum(i['verdict']=='inconclusive' and i['expected_verdict']=='malicious' for i in completed),
            'false_benign':sum(i['verdict']=='benign' and i['expected_verdict']!='benign' for i in completed)}
    return {'mode':mode,'quality_metrics':metrics,'items':items,
        'limitations':'Contract mode is not model accuracy. Live results describe this small synthetic set only; no authorized-benign connector is available. Evidence-ID validity is schema-checked, not proof of semantic correctness.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['contract','live'],default='contract')
    parser.add_argument('--case',nargs='+',default=['all'],choices=['all']+[c['id'] for c in cases()])
    parser.add_argument('--output',required=True)
    args=parser.parse_args();items=[]
    for case in cases():
        if 'all' not in args.case and case['id'] not in args.case:continue
        item=run_case(case,args.mode);items.append(item)
        print(json.dumps({'case':case['id'],'completed':item['completed'],'verdict':item.get('verdict'),'seconds':item['seconds']}),flush=True)
        Path(args.output).parent.mkdir(parents=True,exist_ok=True)
        Path(args.output).write_text(json.dumps(summarize(items,args.mode),indent=2),encoding='utf-8')


if __name__=='__main__':main()
