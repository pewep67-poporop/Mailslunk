"""Indicator rule file loader - deterministic, testable, offline."""
import json
from functools import lru_cache
from pathlib import Path

_RULES_PATH = Path(__file__).resolve().parent / "rules" / "indicators.json"


@lru_cache(maxsize=1)
def load() -> dict:
    return json.loads(_RULES_PATH.read_text(encoding="utf-8"))


def url_rules() -> dict:
    return load()["url"]


def content_rules() -> dict:
    return load()["content"]


def weights() -> dict:
    return load()["weights"]
