"""
Client goi Qwen3-8B qua Ollama local (API /api/chat).
Ca 2 agent (Investigation, Playbook) deu goi qua module nay -
chi khac nhau o system_prompt, khong can chay 2 model.
"""
import json
import os
import re
import requests

from common.config import OLLAMA_HOST, OLLAMA_MODEL, OLLAMA_TIMEOUT


def chat_messages(messages, *, tools=None, schema=None, timeout=None, model=None):
    """Native Ollama multi-turn tools/schema API; preserve the message for audit/replay."""
    payload = {'model':model or OLLAMA_MODEL,'messages':messages,'stream':False,'think':False,
               'options':{'temperature':0.1,'num_ctx':int(os.getenv('OLLAMA_NUM_CTX','4096')),
                          'num_predict':int(os.getenv('OLLAMA_NUM_PREDICT','1024'))}}
    if tools:
        payload['tools']=tools
    if schema:
        payload['format']=schema
    seconds=max(.01,min(float(timeout or OLLAMA_TIMEOUT),float(OLLAMA_TIMEOUT)))
    from agents.investigation_schema import WorkflowError
    try:
        response=requests.post(f'{OLLAMA_HOST}/api/chat',json=payload,timeout=seconds)
    except requests.Timeout as exc:
        raise WorkflowError('ollama_timeout','Local model request exceeded its remaining time allowance') from exc
    except requests.RequestException as exc:
        raise WorkflowError('ollama_unavailable',type(exc).__name__) from exc
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        try: detail=response.json().get('error',response.reason)
        except (ValueError,AttributeError): detail=response.reason
        raise WorkflowError('ollama_http_error',f'{response.status_code}: {detail}') from exc
    try:
        body=response.json()
    except ValueError as exc:
        raise WorkflowError('invalid_model_response','Ollama response was not JSON') from exc
    message=body.get('message')
    if not isinstance(message,dict) or not isinstance(message.get('content',''),str):
        raise WorkflowError('invalid_model_response','Ollama returned an invalid message')
    return {'message':message,'done_reason':body.get('done_reason'),
            'eval_count':body.get('eval_count'),'eval_duration':body.get('eval_duration')}


def chat(system_prompt: str, user_prompt: str, model: str = None,
         temperature: float = 0.1, timeout: int = None, format: str = None) -> str:
    """Goi model, tra ve text tho."""
    model = model or OLLAMA_MODEL
    options = {
        "temperature": temperature,
        "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "1024")),
        "num_predict": int(os.getenv("OLLAMA_NUM_PREDICT", "512")),
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "think": False,
        "options": options,
    }
    if format:
        payload["format"] = format

    resp = requests.post(
        f"{OLLAMA_HOST}/api/chat",
        json=payload,
        timeout=timeout if timeout is not None else OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["message"]["content"]


def chat_json(system_prompt: str, user_prompt: str, model: str = None,
              temperature: float = 0.1) -> dict:
    """Goi model, ky vong tra ve JSON hop le."""
    raw = chat(system_prompt, user_prompt, model=model, temperature=temperature, format="json")
    # 1. Thu parse truc tiep
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # 2. Don dep markdown fences neu co
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.MULTILINE).strip()
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # 3. Tim khoi JSON {...}
    match = re.search(r"\{[\s\S]*\}", raw)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    return {"_parse_error": True, "raw_response": raw}
