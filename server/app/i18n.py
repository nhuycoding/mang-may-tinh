"""Lightweight server-side i18n loader for KidGate Dashboard (Vietnamese / English)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import Request

I18N_DIR = Path(__file__).resolve().parents[2] / "dashboard" / "i18n"
LANG_COOKIE_NAME = "kidgate_lang"
SUPPORTED_LANGS = ("en", "vi")


@lru_cache(maxsize=4)
def load_translations(lang: str) -> dict[str, Any]:
    """Load translation dictionary JSON for `lang`, falling back to `en`."""
    code = lang if lang in SUPPORTED_LANGS else "en"
    path = I18N_DIR / f"{code}.json"
    if not path.exists():
        path = I18N_DIR / "en.json"
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_language(request: Request) -> str:
    """Resolve language from query param `?lang=`, cookie `kidgate_lang`, or default `en`."""
    q_lang = (request.query_params.get("lang") or "").strip().lower()
    if q_lang in SUPPORTED_LANGS:
        return q_lang
    c_lang = (request.cookies.get(LANG_COOKIE_NAME) or "").strip().lower()
    if c_lang in SUPPORTED_LANGS:
        return c_lang
    return "en"
