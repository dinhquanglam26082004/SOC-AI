"""Read-only alert search for the SOC chat, independent of investigation scope."""

from datetime import datetime, timezone
import ipaddress
import json
import sqlite3
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from common.log_index import utc_stamp


class AlertSearch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    rule_id: str | None = Field(default=None, min_length=1, max_length=32)
    agent: str | None = Field(default=None, min_length=1, max_length=128)
    ip: str | None = Field(default=None, min_length=1, max_length=64)
    severity: Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] | None = None
    keyword: str | None = Field(default=None, min_length=1, max_length=128)
    since: str | None = Field(default=None, max_length=64)
    until: str | None = Field(default=None, max_length=64)
    page: int = Field(default=1, ge=1, le=900000000000000000)
    page_size: int = Field(default=8, ge=1, le=10)
    snapshot_max_rowid: int | None = Field(default=None, ge=0, le=9223372036854775807)
    snapshot_generation: int | None = Field(default=None, ge=0)

    @field_validator('rule_id', mode='before')
    @classmethod
    def rule_as_text(cls, value):
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return value

    @field_validator('ip')
    @classmethod
    def valid_ip(cls, value):
        return str(ipaddress.ip_address(value)) if value else value

    @field_validator('since', 'until')
    @classmethod
    def valid_timestamp(cls, value):
        return utc_stamp(value) if value else value

    @model_validator(mode='after')
    def ordered_time(self):
        if self.since and self.until and self.since > self.until:
            raise ValueError('since must be before until')
        if (self.snapshot_max_rowid is None) != (self.snapshot_generation is None):
            raise ValueError('snapshot fields must be provided together')
        return self


class AlertDetail(BaseModel):
    model_config = ConfigDict(extra='forbid')
    alert_id: str = Field(min_length=1, max_length=128)


TOOL_MODELS = {'search_alerts': AlertSearch, 'get_alert_details': AlertDetail}
DESCRIPTIONS = {
    'search_alerts': (
        'Read stored SOC security alerts across the whole retained database. '
        'Use exact rule_id, exact agent name or ID, exact IP, severity, literal keyword '
        'and/or timezone-aware ISO event times only when requested. Omit filters for all '
        'alerts. Returns exact filtered totals, severity and top-rule statistics, plus a '
        'bounded page of records. page starts at 1. To continue a prior query, keep '
        'its filters, snapshot_max_rowid and snapshot_generation and use next_page.'),
    'get_alert_details': (
        'Read one stored SOC alert by its full alert_id. Use only an ID supplied by '
        'the user or returned by search_alerts. It never changes an alert or starts an investigation.'),
}


def definitions():
    """Provide a small Ollama-compatible schema without Pydantic titles/defaults."""
    def compact(value):
        if isinstance(value, dict):
            return {key: compact(item) for key, item in value.items()
                    if key not in {'title', 'default'}}
        if isinstance(value, list):
            return [compact(item) for item in value]
        return value
    return [{'type': 'function', 'function': {'name': name, 'description': DESCRIPTIONS[name],
                                               'parameters': compact(model.model_json_schema())}}
            for name, model in TOOL_MODELS.items()]


def _short(value, length=160):
    return str(value or '')[:length]


def compact_alert(record, *, detail=False):
    rule, agent = record.get('rule') or {}, record.get('agent') or {}
    item = {'id': record.get('id'), 'time': record.get('timestamp'),
            'agent': agent.get('name'), 'agent_id': agent.get('id'),
            'rule_id': str(rule.get('id') or ''), 'level': rule.get('level'),
            'description': _short(rule.get('description')),
            'severity': record.get('severity'), 'ai_status': record.get('ai_status'),
            'src_ip': record.get('src_ip'), 'dst_ip': record.get('dst_ip')}
    if detail:
        report, raw = record.get('investigation_report') or {}, record.get('raw_event') or {}
        item.update(dst_port=record.get('dst_port'), src_port=record.get('src_port'),
                    received_at=record.get('received_at'), groups=rule.get('groups') or [],
                    raw_log_excerpt=_short(raw.get('full_log'), 700),
                    investigation={'verdict': report.get('verdict'),
                                   'reasoning': _short(report.get('reasoning'), 500)} if report else None)
    return item


def search_alerts(store, args):
    filters = ["COALESCE(json_extract(e.payload,'$.event_kind'),'alert')!='telemetry'"]
    params = []
    for field, value in (('$.rule.id', args.rule_id), ('$.severity', args.severity)):
        if value is not None:
            filters.append('CAST(json_extract(e.payload, ?) AS TEXT)=?')
            params.extend((field, value))
    if args.agent:
        filters.append("(casefold(json_extract(e.payload,'$.agent.name'))=? OR json_extract(e.payload,'$.agent.id')=?)")
        params.extend((args.agent.casefold(), args.agent))
    if args.ip:
        filters.append("(? IN (json_extract(e.payload,'$.src_ip'), json_extract(e.payload,'$.dst_ip'), json_extract(e.payload,'$.agent.ip')))")
        params.append(args.ip)
    if args.keyword:
        filters.append("instr(casefold(COALESCE(json_extract(e.payload,'$.rule.description'),'') || ' ' || "
                       "COALESCE(json_extract(e.payload,'$.zeek_data.query'),'') || ' ' || "
                       "COALESCE(json_extract(e.payload,'$.log_type'),'')), ?)>0")
        params.append(args.keyword.casefold())
    for operator, value in (('>=', args.since), ('<=', args.until)):
        if value:
            filters.append("julianday(json_extract(e.payload,'$.timestamp')) " + operator + ' julianday(?)')
            params.append(value)
    with store.connect() as db:
        db.create_function('casefold', 1, lambda value: str(value or '').casefold())
        db.execute('BEGIN')
        generation = store._generation(db)
        if args.snapshot_generation is not None and args.snapshot_generation != generation:
            raise SnapshotExpired()
        anchor = args.snapshot_max_rowid
        if anchor is None:
            anchor = db.execute('SELECT COALESCE(MAX(rowid),0) FROM events').fetchone()[0]
        filters.append('e.rowid<=?')
        params.append(anchor)
        where = ' AND '.join(filters)
        total = db.execute('SELECT COUNT(*) FROM events e WHERE ' + where, params).fetchone()[0]
        rows = db.execute('SELECT e.payload FROM events e WHERE ' + where +
                          ' ORDER BY e.rowid DESC LIMIT ? OFFSET ?',
                          (*params, args.page_size, (args.page - 1) * args.page_size)).fetchall()
        severity = {str(row[0] or 'UNKNOWN'): row[1] for row in db.execute(
            "SELECT json_extract(e.payload,'$.severity'), COUNT(*) FROM events e WHERE " + where + ' GROUP BY 1', params)}
        top_rules = [{'rule_id': str(row[0] or ''), 'count': row[1]} for row in db.execute(
            "SELECT json_extract(e.payload,'$.rule.id'), COUNT(*) AS n FROM events e WHERE " + where +
            ' GROUP BY 1 ORDER BY n DESC, 1 LIMIT 6', params)]
    more = args.page * args.page_size < total
    scope = {**args.model_dump(exclude_none=True), 'snapshot_max_rowid': anchor,
             'snapshot_generation': generation}
    return {'ok': True, 'scope': scope,
            'scope_note': 'Canh bao da luu trong SOC; thoi gian la thoi diem su kien. '
                          'Tong dem ap dung cho bo loc, khong phai chi trang nay.',
            'total': total, 'returned': len(rows), 'has_more': more,
            'next_page': args.page + 1 if more else None,
            'severity_counts': severity, 'top_rules': top_rules,
            'top_rules_note': 'Toi da 6 rule co nhieu canh bao nhat.',
            'alerts': [compact_alert(json.loads(row[0])) for row in rows],
            'queried_at_utc': datetime.now(timezone.utc).isoformat()}


def get_alert_details(store, args):
    record = store.get(args.alert_id)
    if not record or record.get('event_kind') == 'telemetry':
        return {'ok': True, 'found': False, 'alert_id': args.alert_id,
                'scope_note': 'Khong tim thay canh bao nay trong du lieu SOC hien duoc luu.'}
    return {'ok': True, 'found': True, 'alert': compact_alert(record, detail=True),
            'scope_note': 'Chi tiet duoc rut gon; xem canh bao trong SOC de doi chieu log goc.'}


class SnapshotExpired(Exception):
    pass


def execute(store, name, arguments):
    if name not in TOOL_MODELS:
        return {'ok': False, 'error': 'Cong cu khong duoc ho tro.'}
    try:
        if not isinstance(arguments, dict):
            raise ValueError('arguments must be an object')
        parsed = TOOL_MODELS[name].model_validate(arguments)
        return search_alerts(store, parsed) if name == 'search_alerts' else get_alert_details(store, parsed)
    except SnapshotExpired:
        return {'ok': False, 'error': 'Du lieu canh bao da duoc lam moi; hay bat dau tim kiem lai.'}
    except (ValidationError, ValueError, TypeError, OverflowError):
        return {'ok': False, 'error': 'Tham so khong hop le; kiem tra IP, ngay gio co mui gio va so trang.'}
    except sqlite3.Error:
        return {'ok': False, 'error': 'Khong the doc du lieu canh bao trong SOC.'}
