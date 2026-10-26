"""Validated graph outputs and explicit resource limits."""
import os
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    statement: str = Field(min_length=1, max_length=600)
    status: Literal['open', 'supported', 'refuted', 'inconclusive'] = 'open'
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    id: str = Field(default='',max_length=32)
    supporting: list[str] = Field(default_factory=list,max_length=20)
    refuting: list[str] = Field(default_factory=list,max_length=20)
    question: str = Field(default='',max_length=600)


class ReviewDecision(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    hypotheses: list[Hypothesis] = Field(default_factory=list,max_length=5)
    need_more: bool
    question: str = Field(default='',max_length=600)


class AnalystReview(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    decision: Literal['malicious','benign','inconclusive']
    notes: str = Field(min_length=20,max_length=4000)
    evidence_ids: list[str] = Field(min_length=1,max_length=20)


class Finding(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    statement: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)


class InvestigationReport(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    incident_type: str = Field(min_length=1, max_length=200)
    verdict: Literal['malicious', 'benign', 'inconclusive']
    reasoning: str = Field(min_length=1, max_length=3000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    findings: list[Finding] = Field(max_length=20)
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=10)
    unknowns: list[str] = Field(max_length=20)
    recommendations: list[str] = Field(max_length=15)


class Limits(BaseModel):
    rounds: int = Field(default=3, ge=1, le=10)
    model_calls: int = Field(default=4, ge=1, le=10)
    tool_calls: int = Field(default=6, ge=1, le=20)
    repair_calls: int = Field(default=1, ge=0, le=1)
    seconds: float = Field(default=900, ge=1, le=3600)
    tool_seconds: float = Field(default=15, ge=0.01, le=60)
    context_chars: int = Field(default=9000, ge=2000, le=16000)

    @classmethod
    def configured(cls):
        return cls(**{key: os.environ[env] for key, env in {
            'rounds':'AI_GRAPH_MAX_ROUNDS', 'model_calls':'AI_GRAPH_MAX_MODEL_CALLS',
            'tool_calls':'AI_GRAPH_MAX_TOOL_CALLS', 'seconds':'AI_GRAPH_TIMEOUT',
            'tool_seconds':'AI_TOOL_TIMEOUT', 'context_chars':'AI_GRAPH_CONTEXT_CHARS'}.items() if env in os.environ})


class WorkflowError(RuntimeError):
    def __init__(self, code, detail):
        self.code, self.detail = code, str(detail)[:1000]
        super().__init__(f'{code}: {self.detail}')


def ollama_report_schema():
    """Avoid llama.cpp grammar repetition explosion; full limits still validate in Pydantic."""
    def clean(value):
        if isinstance(value,dict):
            return {k:clean(v) for k,v in value.items() if k not in {'minLength','maxLength','title','default'}}
        if isinstance(value,list):
            return [clean(v) for v in value]
        return value
    return clean(InvestigationReport.model_json_schema())
