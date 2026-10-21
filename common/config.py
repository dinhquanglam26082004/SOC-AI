"""
Doc cau hinh tu file .env va quan ly registry model AI cho he thong SOC-AI.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# ─── Registry cac model duoc ho tro ────────────────────────────────────────
AVAILABLE_MODELS: dict[str, dict] = {
    "qwen3_8b": {
        "name": "qwen3:8b",
        "label": "Qwen3-8B (Investigation / Playbook)",
        "size": "8B · Q4_K_M · khoảng 5.2 GB tải xuống",
        "desc": "Điều tra và đề xuất playbook; tốc độ phụ thuộc CPU/GPU và RAM.",
    },
    "qwen3": {
        "name": "qwen3:8b",
        "label": "Qwen3-8B",
        "size": "8B · Q4_K_M",
        "desc": "Alias cho Qwen3-8B.",
    },
}

AGENT_MODEL = os.getenv("AGENT_MODEL", "qwen3:8b")
DEFAULT_MODEL_ALIAS = "qwen3_8b"


def resolve_model(alias: str) -> str:
    """Tra ve ten model Ollama chinh xac tu alias."""
    if alias in AVAILABLE_MODELS:
        return AVAILABLE_MODELS[alias]["name"]
    return alias


def get_model_label(alias: str) -> str:
    """Tra ve nhan hien thi dep tren giao dien."""
    entry = AVAILABLE_MODELS.get(alias)
    if entry:
        return entry["label"]
    return alias.split("/")[-1][:32]


_alias_env = os.getenv("OLLAMA_MODEL_ALIAS", "")
_model_env = os.getenv("OLLAMA_MODEL", "")

if _alias_env and _alias_env in AVAILABLE_MODELS:
    ACTIVE_MODEL_ALIAS = _alias_env
    OLLAMA_MODEL = resolve_model(_alias_env)
elif _model_env:
    OLLAMA_MODEL = _model_env
    ACTIVE_MODEL_ALIAS = next(
        (k for k, v in AVAILABLE_MODELS.items() if v["name"] == _model_env),
        "custom",
    )
else:
    ACTIVE_MODEL_ALIAS = DEFAULT_MODEL_ALIAS
    OLLAMA_MODEL = resolve_model(DEFAULT_MODEL_ALIAS)

# Timeout config (mac dinh 600s)
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "600"))

# ChromaDB Config
_REPO_ROOT = Path(__file__).resolve().parent.parent
_chroma_raw = os.getenv("CHROMA_PATH", "")
CHROMA_PATH = (
    str(Path(_chroma_raw).resolve())
    if _chroma_raw and Path(_chroma_raw).is_absolute()
    else str(_REPO_ROOT / "rag" / "chroma_db")
)

CHROMA_COLLECTION_NAME = os.getenv("CHROMA_COLLECTION_NAME", "soc_knowledge")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
