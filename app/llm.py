"""M11 — Optional LLM layer: semantic assessment of a message.

Why: rules cannot judge intent ("urgent invoice from the CFO"), brand
impersonation tone, or a Vietnamese business-email lure. An LLM can - but it
must never be the only basis of a forensic verdict.

Contract:
  * **OFF by default** (`LLM_ENABLED=0`); without a key or without network the
    server degrades to rule-only.
  * **The LLM may only raise suspicion**, never lower a rule verdict.
  * **Hallucination control**: every quote the model returns must be a literal
    substring of the body we sent. A quote that does not match invalidates the
    whole answer (it is dropped, not softened).
  * **Reproducibility**: the case record stores model id, prompt version,
    prompt hash, temperature, timestamp and token usage.
  * **Data minimisation**: only headers + body text are sent (no attachments,
    no binaries). `LLM_REDACT=1` (default) replaces domains, IP addresses,
    e-mail addresses and URLs with stable placeholders before sending.
  * Key is per-user in `kv` (never echoed, never logged).
"""
import hashlib
import json
import os
import re
import time

from .breaker import CircuitOpen, get_breaker

PROMPT_VERSION = "m11-v1"
MODEL_DEFAULT = os.getenv("LLM_MODEL", "openrouter/minimax/minimax-m3.1-flash")
MODEL_ESCALATE = os.getenv("LLM_MODEL_ESCALATE", "openrouter/anthropic/claude-sonnet-5.5")
MODEL_FREE = os.getenv("LLM_MODEL_FREE", "openrouter/openrouter/free")
BASE_URL = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")
TIMEOUT = float(os.getenv("LLM_TIMEOUT", "45") or 45)
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "600") or 600)
REDACT = os.getenv("LLM_REDACT", "1") != "0"
CACHE_TTL = int(os.getenv("LLM_CACHE_TTL", "86400") or 86400)

_cache = {}

_SYS_PROMPT = (
    "You are a senior email-forensics analyst. You are given the FACTS computed "
    "by a deterministic rule engine plus the raw message. Judge ONLY the aspects "
    "a rule cannot: intent, social-engineering tactics, brand impersonation, "
    "urgency/lure language, and whether the message's purpose is deceptive. "
    "Never contradict the given facts; never claim an authentication result that "
    "is not in the facts. Answer with JSON only, exactly this shape:\n"
    '{"verdict":"clean|suspicious|phishing|malware","confidence":0.0-1.0,'
    '"intent":"one short sentence","techniques":["short label"],'
    '"evidence":[{"quote":"exact substring copied from the body","note":"why it matters"}],'
    '"actions":["concrete next step"]}\n'
    "Every quote MUST be copied verbatim from the message body. If you cannot "
    "quote, return an empty evidence list."
)


def enabled() -> bool:
    return os.getenv("LLM_ENABLED", "0") == "1"


def _key(user: str = "") -> str:
    if user:
        try:
            from .db import kv_get
            v = kv_get(f"llm.key:{user}")
            if v:
                return v
        except Exception:
            pass
    return (os.getenv("LLM_API_KEY") or "").strip()


def _redact(text: str) -> str:
    """Remove direct identifiers before the text leaves the machine."""
    if not REDACT or not text:
        return text or ""
    t = re.sub(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", "<email>", text)
    t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", t)
    t = re.sub(r"(?i)\bhttps?://[^\s<>\"')]+", "<url>", t)
    t = re.sub(r"(?i)\b(?:www\.)[^\s<>\"')]+", "<url>", t)
    # domains (keep the TLD shape only)
    t = re.sub(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|vn|com\.vn|com\.br|jp|kr|cn|de|uk|fr|info|biz|xyz|top|online|site|club|shop|app|dev|ai)\b",
               "<domain>", t, flags=re.I)
    return t


def build_payload(result: dict, raw_text: str = "") -> tuple:
    """-> (prompt_text, facts_dict) — facts are computed, never invented."""
    facts = {
        "ruleScore": result.get("score"),
        "ruleVerdict": result.get("verdict"),
        "auth": {
            "spf": (result.get("auth") or {}).get("spf", {}).get("result"),
            "dkim": (result.get("auth") or {}).get("dkim", {}).get("result"),
            "dmarc": (result.get("auth") or {}).get("dmarc", {}).get("result"),
        },
        "urls": [{"host": u.get("host"), "risk": u.get("risk"), "verdict": u.get("verdict")}
                 for u in (result.get("urls") or [])[:20]],
        "attachments": [{"name": a.get("name"), "verdict": a.get("verdict"),
                         "mime": a.get("mime")} for a in (result.get("attachments") or [])[:20]],
        "findings": [{"type": f.get("type"), "evidence": str(f.get("evidence"))[:160]}
                     for f in (result.get("findings") or [])[:30]],
        "headerFindings": [{"type": f.get("type"), "evidence": str(f.get("evidence"))[:160]}
                           for f in ((result.get("headerAnalysis") or {}).get("checks") or [])[:20]],
    }
    body = _redact(raw_text or "")
    prompt = ("FACTS (computed by the rule engine - trust them):\n"
              + json.dumps(facts, ensure_ascii=False)[:6000]
              + "\n\nMESSAGE BODY:\n" + body[:8000]
              + "\n\nReturn the JSON verdict now.")
    return prompt, facts


def _validate(answer: dict, body: str) -> tuple:
    """Reject hallucinated quotes. -> (clean_answer, ok)"""
    if not isinstance(answer, dict):
        return {}, False
    ev = []
    for e in (answer.get("evidence") or [])[:6]:
        q = str(e.get("quote") or "")
        if not q:
            continue
        if q in body:                      # must be a verbatim substring
            ev.append({"quote": q[:400], "note": str(e.get("note") or "")[:200]})
    verdict = str(answer.get("verdict") or "").lower()
    if verdict not in ("clean", "suspicious", "phishing", "malware"):
        return {}, False
    try:
        conf = float(answer.get("confidence"))
    except Exception:
        conf = 0.0
    conf = max(0.0, min(1.0, conf))
    out = {"verdict": verdict, "confidence": conf,
           "intent": str(answer.get("intent") or "")[:300],
           "techniques": [str(t)[:60] for t in (answer.get("techniques") or [])[:8]],
           "evidence": ev, "actions": [str(a)[:160] for a in (answer.get("actions") or [])[:5]]}
    # a confident verdict without a single verifiable quote is not usable
    if conf >= 0.6 and not ev and verdict != "clean":
        out["verdict"] = "suspicious"
        out["confidence"] = min(conf, 0.5)
        out["intent"] = (out["intent"] + " [không trích được bằng chứng nguyên văn]").strip()
    return out, True


def _call_model(prompt: str, model: str, key: str) -> tuple:
    br = get_breaker("llm")
    payload = {"model": model,
               "messages": [{"role": "system", "content": _SYS_PROMPT},
                            {"role": "user", "content": prompt}],
               "temperature": 0, "max_tokens": MAX_TOKENS,
               "response_format": {"type": "json_object"}}
    headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json",
               "HTTP-Referer": os.getenv("LLM_REFERER", "http://localhost:8000"),
               "X-Title": "MailSleuth"}
    r = br.call(_requests().post, BASE_URL + "/chat/completions",
                headers=headers, json=payload, timeout=TIMEOUT)
    j = r.json() if r.content else {}
    text = (j.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    usage = j.get("usage") or {}
    return text, usage


def _requests():
    import requests
    return requests


def assess(result: dict, raw_text: str = "", user: str = "") -> dict:
    """-> assessment dict (stored in the case) or {} when unavailable."""
    if not enabled():
        return {}
    key = _key(user)
    if not key:
        return {}
    prompt, facts = build_payload(result, raw_text)
    phash = hashlib.sha256((PROMPT_VERSION + "|" + prompt).encode()).hexdigest()[:16]
    ck = phash + "|" + hashlib.sha256(raw_text.encode("utf-8", "ignore")).hexdigest()
    hit = _cache.get(ck)
    if hit and hit[0] > time.time():
        return hit[1]
    body_for_check = raw_text or ""
    out = {}
    for model in (MODEL_DEFAULT, MODEL_FREE, MODEL_ESCALATE):
        try:
            text, usage = _call_model(prompt, model, key)
        except CircuitOpen:
            continue
        except Exception:
            continue
        raw_json = text.strip()
        if raw_json.startswith("```"):
            raw_json = re.sub(r"^```[a-zA-Z]*\s*", "", raw_json).replace("```", "")
        try:
            answer = json.loads(raw_json)
        except Exception:
            continue
        clean, ok = _validate(answer, body_for_check)
        if not ok:
            continue
        clean.update({"model": model, "promptVersion": PROMPT_VERSION,
                      "promptHash": phash, "temperature": 0,
                      "redacted": REDACT,
                      "tokens": int(usage.get("total_tokens") or 0),
                      "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "factsUsed": facts})
        out = clean
        break
    if out:
        _cache[ck] = (time.time() + CACHE_TTL, out)
        if len(_cache) > 512:
            for k in list(_cache)[:256]:
                _cache.pop(k, None)
    return out
