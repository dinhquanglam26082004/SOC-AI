import asyncio
from contextlib import asynccontextmanager
import hmac
import json
import logging
import os
from pathlib import Path
import time
import uuid
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import requests

from common.config import AGENT_MODEL, OLLAMA_HOST, CHROMA_PATH, CHROMA_COLLECTION_NAME
from common.event_store import EventStore, QueueFull
from common.alert_timeseries import build_alert_buckets
from wazuh_integration.mapper import map_wazuh_alert, ai_eligible, is_security_alert

ROOT = Path(__file__).resolve().parent.parent
logger = logging.getLogger(__name__)


def reject_json_constant(value):
    raise ValueError('Non-finite JSON number')


def analyze(record, on_progress=None, store=None, audit=None):
    if not is_security_alert(record):
        raise ValueError('AI investigation requires a security alert')
    if os.getenv('AI_WORKFLOW','langgraph')=='langgraph':
        from agents.investigation_graph import InvestigationGraph
        def compact(summary):
            return {k:v for k,v in summary.items() if k not in {'hypotheses','verification'}}
        def progress(stage,step,summary):
            record['investigation']=compact(summary)
            if on_progress:
                on_progress(stage,step)
        report=InvestigationGraph(store,audit,model=AGENT_MODEL,on_progress=progress).run_alert(record)
        current=audit.current(record['id'])
        record['investigation']=compact(current['summary'])
        # Timeline/history remain in the dossier DB; event payload and status polling stay compact.
        report={k:v for k,v in report.items() if k not in {'timeline','verification_checks'}}
        report['tool_outcomes']=[{k:v for k,v in item.items() if k!='authentication_summary'} for item in report.get('tool_outcomes',[])]
        # Response recommendations are separate from the bounded investigation.
        proposal={'status':'not_requested','actions':[],
                  'notes':'Review investigation recommendations. No response action has been executed.'}
        record['investigation_report']=report
        if os.getenv('AI_PLAYBOOK_ENABLED','false').lower()=='true':
            try:
                from agents.playbook_agent import propose_playbook
                proposal=propose_playbook(report,model=AGENT_MODEL,on_progress=on_progress)
            except Exception as exc:
                proposal={'status':'failed','error':type(exc).__name__,'actions':[]}
        return report,proposal
    from agents.investigation_agent import investigate
    from agents.playbook_agent import propose_playbook
    report = investigate(record, model=AGENT_MODEL, on_progress=on_progress)
    record['investigation_report'] = report
    try:
        proposal = propose_playbook(report, model=AGENT_MODEL, on_progress=on_progress)
    except Exception as exc:
        proposal = {'status':'failed','error':type(exc).__name__,'actions':[]}
    if on_progress:
        on_progress('saving', 6)
    return report, proposal


async def ai_worker(app):
    store = app.state.store
    while True:
        try:
            record = await asyncio.to_thread(store.claim)
        except Exception:
            logger.error('AI job storage unavailable; worker will retry')
            await asyncio.sleep(3)
            continue
        if not record:
            await asyncio.sleep(.5)
            continue
        if not is_security_alert(record):
            await asyncio.to_thread(store.skip, record, 'Not a security alert; no model call made')
            continue
        error = None
        try:
            async with app.state.ai_slots:
                report, proposal = await asyncio.to_thread(
                    analyze, record, lambda stage, step: store.progress(record, stage, step, AGENT_MODEL),
                    store, getattr(app.state,'investigation_store',None))
            record['investigation_report'], record['playbook_proposal'] = report, proposal
            # The source rule severity is never overwritten by an inference.
        except asyncio.CancelledError:
            raise  # leave running job recoverable on next startup
        except Exception as exc:
            logger.warning('AI job failed (%s)', type(exc).__name__)
            from agents.investigation_schema import WorkflowError
            error = str(exc) if isinstance(exc,WorkflowError) else 'AI workflow failed ('+type(exc).__name__+'); inspect saved investigation diagnostics'
            audit=getattr(app.state,'investigation_store',None)
            try:
                current=audit.current(record['id']) if audit else None
            except Exception:
                current=None
            if current:
                record['investigation']=current['summary']
        while True:
            try:
                await asyncio.to_thread(store.finish, record, error)
                break
            except Exception:
                logger.error('AI result commit unavailable; retaining running job and retrying')
                await asyncio.sleep(3)


def create_app(db_path=None, workers=True):
    @asynccontextmanager
    async def lifespan(app):
        enabled = os.getenv('WAZUH_ENABLED', 'true').lower() == 'true'
        if enabled and not os.getenv('WAZUH_WEBHOOK_TOKEN', '').strip():
            raise RuntimeError('WAZUH_WEBHOOK_TOKEN is required when WAZUH_ENABLED=true')
        app.state.store = EventStore(db_path or os.getenv('RUNTIME_DB_PATH', str(ROOT / 'data/soc_runtime.sqlite3')), int(os.getenv('AI_QUEUE_LIMIT', '1000')))
        workflow=os.getenv('AI_WORKFLOW','langgraph')
        if workflow not in {'legacy','langgraph'}:
            raise RuntimeError('AI_WORKFLOW must be legacy or langgraph')
        from agents.investigation_store import InvestigationStore
        audit_path=Path(app.state.store.path).with_name('soc_investigations.sqlite3')
        app.state.investigation_store=InvestigationStore(audit_path)
        if workers:
            app.state.investigation_store.recover_leases()
        app.state.store.recover()
        slots=1 if workflow=='langgraph' else max(1,min(4,int(os.getenv('AI_MAX_CONCURRENCY','1'))))
        app.state.ai_slots = asyncio.Semaphore(slots)
        tasks = [asyncio.create_task(ai_worker(app)) for _ in range(slots)] if workers else []
        app.state.worker_tasks = tasks
        yield
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(title='SOC-AI Wazuh Endpoint Operations', version='3.0.0', lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:8100,http://127.0.0.1:8100').split(','), allow_methods=['GET','POST','PATCH'], allow_headers=['Content-Type','X-Webhook-Token'])

    @app.get('/health')
    def health():
        return {'status': 'ok', 'service': 'soc-ai', 'ai_queue': app.state.store.queue_stats(),
                'ai_workers_alive': sum(not t.done() for t in app.state.worker_tasks)}

    @app.post('/wazuh', status_code=202)
    async def ingest(request: Request):
        if os.getenv('WAZUH_ENABLED', 'true').lower() != 'true':
            raise HTTPException(503, 'Wazuh source disabled')
        token = os.getenv('WAZUH_WEBHOOK_TOKEN', '').strip()
        if not token or not hmac.compare_digest(request.headers.get('X-Webhook-Token', '').encode(), token.encode()):
            raise HTTPException(401, 'Invalid webhook credentials')
        if request.headers.get('content-type', '').split(';')[0].strip() != 'application/json':
            raise HTTPException(415, 'Expected application/json')
        limit = int(os.getenv('WAZUH_MAX_PAYLOAD_BYTES', '262144'))
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > limit:
                raise HTTPException(413, 'Payload too large')
        try:
            record = map_wazuh_alert(json.loads(body, parse_constant=reject_json_constant))
        except (ValueError, TypeError, OverflowError, UnicodeDecodeError):
            raise HTTPException(422, 'Invalid Wazuh alert schema')
        try:
            saved, duplicate = await asyncio.to_thread(app.state.store.accept, record, ai_eligible(record))
        except QueueFull:
            raise HTTPException(503, 'AI queue full; retry delivery', headers={'Retry-After': '30'})
        except Exception:
            logger.error('Durable ingestion failed')
            raise HTTPException(503, 'Storage unavailable; retry delivery')
        return {'id': saved['id'], 'duplicate': duplicate, 'durable': True,
                'ignored': saved.get('_ignored_before_reset', False), 'ai_status': saved['ai_status']}

    @app.get('/api/zeek/logs')
    def zeek_logs(limit: int = Query(100, ge=1, le=500), before: int = Query(None, ge=1), log_type: str = None):
        return app.state.store.list_zeek_logs(limit=limit, before=before, log_type=log_type)

    @app.get('/api/logs')
    def unified_logs(limit: int = Query(100, ge=1, le=500), before: str = Query(None, max_length=512),
                     source: Literal['zeek', 'wazuh'] | None = None,
                     log_type: str = Query(None, max_length=512),
                     kind: Literal['alert', 'telemetry'] | None = None,
                     since: str = Query(None, max_length=64), until: str = Query(None, max_length=64),
                     q: str = Query(None, max_length=512)):
        try:
            return app.state.store.list_logs(limit=limit, before=before, source=source, log_type=log_type, kind=kind, since=since, until=until, q=q)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get('/api/alerts')
    def alerts(severity: str = None, status: str = None, search: str = None,
               limit: int = Query(100, ge=1, le=500), before: int = Query(None, ge=1)):
        rows = app.state.store.list_events(limit=limit+1, before=before, severity=severity, status=status, search=search)
        items = rows[:limit]
        cursor = app.state.store.event_cursor(items[-1]['id']) if len(rows)>limit else None
        return {'alerts': items, 'next_cursor': cursor, 'metrics': app.state.store.event_metrics(), 'active_model': {'name': AGENT_MODEL}}

    @app.get('/api/alerts/timeseries')
    def timeseries(time_range: str = '24h'):
        try:
            return {'buckets': build_alert_buckets(app.state.store.event_summaries(), time_range)}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get('/api/alerts/{alert_id}')
    def alert(alert_id: str):
        record = app.state.store.get(alert_id)
        if not record:
            raise HTTPException(404, 'Alert not found')
        return record

    @app.post('/api/alerts/{alert_id}/investigate', status_code=202)
    def retry(alert_id: str):
        record = app.state.store.get(alert_id)
        if record and not is_security_alert(record):
            raise HTTPException(403, 'AI investigates security alerts only; ordinary logs are excluded')
        try:
            queued = app.state.store.retry(alert_id)
            return {'queued': queued, 'alert': app.state.store.get(alert_id)}
        except KeyError:
            raise HTTPException(404, 'Alert not found')
        except (ValueError, QueueFull):
            raise HTTPException(409, 'Job already processed, cooldown, attempt limit or queue full')

    @app.get('/api/cases')
    def cases():
        items = app.state.store.list_cases()
        return {'cases': items, 'stats': {'total': len(items)}}

    @app.get('/api/alerts/{alert_id}/investigation')
    def investigation_summary(alert_id: str):
        item=app.state.investigation_store.current(alert_id)
        if not item:
            raise HTTPException(404,'No saved graph investigation')
        return {'id':item['id'],'status':item['status'],'summary':item['summary']}

    @app.get('/api/investigations/{incident_id}')
    def investigation_detail(incident_id: str,section: Literal['evidence','tools','models','activity']='evidence',
                             limit: int=Query(20,ge=1,le=100),offset: int=Query(0,ge=0,le=100000)):
        item=app.state.investigation_store.detail(incident_id,section,limit,offset)
        if not item:
            raise HTTPException(404,'Investigation not found')
        # Raw prompts/model responses stay in the local audit DB, not the browser API.
        if section=='models':
            item['items']=[{k:v for k,v in row.items() if k not in {'args','result'}} for row in item['items']]
        return item

    @app.get('/api/investigations')
    def pending_investigations(limit: int=Query(20,ge=1,le=100),offset: int=Query(0,ge=0,le=100000)):
        return app.state.investigation_store.pending_reviews(limit,offset)

    from agents.investigation_schema import AnalystReview

    @app.post('/api/investigations/{incident_id}/review',status_code=201)
    def analyst_review(incident_id: str,body: AnalystReview):
        try:
            summary=app.state.investigation_store.review(incident_id,body.decision,body.notes,body.evidence_ids)
        except KeyError:
            raise HTTPException(404,'Investigation not found')
        except ValueError as exc:
            raise HTTPException(409,str(exc))
        with app.state.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT payload FROM events WHERE id=?',(summary['alert_id'],)).fetchone()
            if row:
                record=json.loads(row[0]);record['investigation']=summary
                db.execute('UPDATE events SET payload=? WHERE id=?',(json.dumps(record),summary['alert_id']))
        return {'summary':summary}

    @app.get('/api/cases/{case_id}')
    def case(case_id: str):
        item = next((c for c in app.state.store.list_cases() if c['id'] == case_id), None)
        if item is None:
            raise HTTPException(404, 'Case not found')
        return item

    @app.post('/api/cases', status_code=201)
    def create_case(body: dict):
        if not isinstance(body.get('title'), str) or not body['title'].strip():
            raise HTTPException(422, 'Case title required')
        item = {**body, 'id': 'CASE-' + uuid.uuid4().hex, 'created_at': time.time()}
        app.state.store.save_case(item)
        return item

    @app.patch('/api/cases/{case_id}')
    def update_case(case_id: str, body: dict):
        item = case(case_id)
        item.update({k: v for k, v in body.items() if k in ('title','description','status','severity','assignee','notes')})
        app.state.store.save_case(item)
        return item

    @app.get('/api/response/history')
    def responses():
        from common.runtime_store import RuntimeStore
        return {'history': RuntimeStore(app.state.store.path).load().get('responses', [])}

    @app.post('/api/response/execute')
    def execute():
        raise HTTPException(501, 'AI provides recommendations only; no response adapter is configured')

    @app.get('/api/sources/status')
    def sources():
        stats = app.state.store.log_stats()
        forwarder = None
        status_file = os.getenv('WAZUH_FORWARDER_STATUS_FILE', '')
        if status_file:
            try:
                forwarder = json.loads(Path(status_file).read_text())
                forwarder['stale'] = time.time() - forwarder['updated'] > 30
            except (OSError, ValueError, KeyError):
                forwarder = {'state': 'unknown', 'stale': True}
        return {'source': 'wazuh', 'last_received_at': stats['last_received_at'], 'forwarder': forwarder, 'log_total': stats['total'],
                'zeek': stats['zeek'], 'alert_revision': stats['alert_revision'],
                'investigations': app.state.store.investigation_status(),
                'manager_status': 'unknown (no authenticated status query)', 'agent_status': 'unknown (no authenticated status query)',
                'ai_queue': app.state.store.queue_stats()}

    @app.get('/api/knowledge/chunks')
    def knowledge_chunks(q: str = Query('', max_length=200),
                         doc_type: str = Query('', max_length=64),
                         limit: int = Query(25, ge=1, le=50),
                         offset: int = Query(0, ge=0, le=1000000)):
        from rag.browse import browse_chunks
        try:
            return browse_chunks(query=q.strip(), doc_type=doc_type.strip(),
                                 limit=limit, offset=offset)
        except Exception:
            logger.exception('Knowledge browsing failed')
            raise HTTPException(503, 'Knowledge index unavailable. Check the ChromaDB collection and ingestion setup.')

    @app.get('/api/knowledge/chunk')
    def knowledge_chunk(id: str = Query(..., min_length=1, max_length=512)):
        from rag.browse import read_chunk
        try:
            item = read_chunk(id)
        except Exception:
            logger.exception('Knowledge chunk read failed')
            raise HTTPException(503, 'Knowledge index unavailable')
        if item is None:
            raise HTTPException(404, 'Indexed chunk not found')
        return item

    @app.get('/api/system/status')
    def system_status():
        from rag.query import embedding_status, _get_collection
        try:
            r = requests.get(OLLAMA_HOST + '/api/tags', timeout=3)
            r.raise_for_status()
            ollama = {'connected': True, 'models': [m['name'] for m in r.json().get('models', [])]}
        except requests.RequestException:
            ollama = {'connected': False, 'models': []}
        try:
            count = _get_collection().count()
            chroma = {'connected': True, 'count': count}
        except Exception:
            chroma = {'connected': False, 'count': 0}
        return {'ollama': ollama, 'chromadb': chroma, 'rag_embedding': embedding_status(), 'agent_model': AGENT_MODEL}

    @app.get('/')
    def dashboard():
        return FileResponse(ROOT / 'web/index.html')

    return app


app = create_app()
