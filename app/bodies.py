"""Message body previews (M8 — storage for the per-message detail view).

The UI lists every message of a case (EML/MBOX/MSG/TXT/Maildir) and, when the
analyst expands one, asks the server for its headers and body. Bodies are
therefore written to disk next to the case instead of being embedded in the
SQLite row, so a 1000-message mailbox never turns into one multi-megabyte JSON
document.

Layout (DATA_DIR/messages/<case_id>/):
    <idx>.hdr  raw header block (UTF-8, capped)
    <idx>.txt  plain-text body (UTF-8)
    <idx>.html sanitised HTML body
    <idx>.json meta: hasText/hasHtml/truncated/omitted/textBytes/htmlBytes

Limits mirror the Node server (server/messages.js):
    BODY_MAX_BYTES   512 KB per message
    BODY_TOTAL_BYTES 32 MB per case (shared budget, oldest messages get cut off)

HTML is sanitised before it is stored: scripts/styles/iframes are dropped with
their content, every attribute is removed, <a>/<img> become <span>. The UI
additionally renders it inside a sandboxed iframe with a strict CSP.
"""
import html as html_mod
import os
import re
from html.parser import HTMLParser
from pathlib import Path

from .db import data_dir

BODY_MAX_BYTES = int(os.getenv("BODY_MAX_BYTES", str(512 * 1024)))
BODY_TOTAL_BYTES = int(os.getenv("BODY_TOTAL_BYTES", str(32 * 1024 * 1024)))
RAW_MAX = 1_000_000  # characters kept from a single body part before processing

ALLOWED_TAGS = {
    "p", "br", "div", "span", "strong", "b", "em", "i", "u", "s", "ul", "ol", "li",
    "blockquote", "pre", "code", "h1", "h2", "h3", "h4", "h5", "h6", "table",
    "thead", "tbody", "tr", "th", "td", "hr",
}
DROP_WITH_CONTENT = {"script", "style", "textarea", "option", "iframe", "object", "embed", "form"}
REWRITE_TO_SPAN = {"a", "img"}


class _Sanitizer(HTMLParser):
    """Allow-list HTML sanitiser (stdlib only, no extra dependency)."""

    def __init__(self, keep_tags: bool = True):
        super().__init__(convert_charrefs=True)
        self.keep_tags = keep_tags
        self.out = []
        self._skip_stack = []

    @property
    def skipping(self) -> bool:
        return bool(self._skip_stack)

    def handle_starttag(self, tag, attrs):
        t = (tag or "").lower()
        if self.skipping:
            if t in DROP_WITH_CONTENT:
                self._skip_stack.append(t)
            return
        if t in DROP_WITH_CONTENT:
            self._skip_stack.append(t)
            return
        if t in REWRITE_TO_SPAN:
            self.out.append("<span>")
            return
        if t in ALLOWED_TAGS:
            self.out.append("<" + t + ">")

    def handle_startendtag(self, tag, attrs):
        t = (tag or "").lower()
        if self.skipping:
            return
        if t in DROP_WITH_CONTENT:
            return
        if t in REWRITE_TO_SPAN:
            self.out.append("<span></span>")
            return
        if t in ALLOWED_TAGS:
            self.out.append("<" + t + ">")

    def handle_endtag(self, tag):
        t = (tag or "").lower()
        if self.skipping:
            if self._skip_stack and t == self._skip_stack[-1]:
                self._skip_stack.pop()
            return
        if t in REWRITE_TO_SPAN:
            self.out.append("</span>")
            return
        if t in ALLOWED_TAGS:
            self.out.append("</" + t + ">")

    def handle_data(self, data):
        if self.skipping or not data:
            return
        self.out.append(html_mod.escape(data))

    def result(self) -> str:
        return "".join(self.out)


def sanitize_html(src: str) -> str:
    """Keep a safe subset of tags; drop everything else (and its content)."""
    if not src:
        return ""
    p = _Sanitizer()
    try:
        p.feed(src)
        p.close()
    except Exception:
        return ""
    out = p.result()
    return "" if not out.strip() else out


def html_to_text(src: str) -> str:
    """Rough plain-text rendering of an HTML body (used when no text/plain part)."""
    if not src:
        return ""
    spaced = re.sub(r"(?i)<(?:br|/p|/div|/li|/tr|/h[1-6]|/blockquote)\b[^>]*>", "\n", src)
    stripped = re.sub(r"(?s)<[^>]+>", " ", spaced)
    txt = html_mod.unescape(stripped)
    txt = re.sub(r"[ \t\r\f\v]+", " ", txt)
    txt = re.sub(r"\n\s*\n\s*\n+", "\n\n", txt)
    return txt.strip()


def extract_bodies(name: str, raw: bytes) -> tuple:
    """(text, html) for one message. .msg goes through extract-msg, others via MIME."""
    low = (name or "").lower()
    if low.endswith(".msg"):
        try:
            import extract_msg
            import io as _io
            with _io.BytesIO(raw) as fh:
                m = extract_msg.MessageMessage(fh)
                body = getattr(m, "body", "") or ""
                hbody = getattr(m, "html_body", "") or ""
                if isinstance(hbody, bytes):
                    hbody = hbody.decode("utf-8", "ignore")
                return str(body or ""), str(hbody or "")
        except Exception:
            return "", ""
    try:
        from email import policy
        from email.parser import BytesParser
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return "", ""
    texts, htmls = [], []
    try:
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                fn = (part.get_filename() or "").lower()
                if fn.endswith((".html", ".htm")):
                    try:
                        htmls.append(part.get_content())
                    except Exception:
                        pass
                continue
            ct = part.get_content_type()
            try:
                if ct == "text/plain":
                    texts.append(part.get_content())
                elif ct in ("text/html", "application/xhtml+xml"):
                    htmls.append(part.get_content())
            except Exception:
                pass
    except Exception:
        pass
    text = "\n".join(t for t in texts if t)
    html = "\n".join(h for h in htmls if h)
    return text, html


def extract_headers(name: str, raw: bytes, limit: int = 64 * 1024) -> str:
    """Return the literal header block (evidence, not a reconstruction).

    MSG files expose their headers through extract-msg; everything else is
    parsed headersonly so body bytes never influence the result.
    """
    low = (name or "").lower()
    if low.endswith(".msg"):
        try:
            import extract_msg
            import io as _io
            with _io.BytesIO(raw) as fh:
                m = extract_msg.MessageMessage(fh)
                pairs = []
                for k, v in (m.header.items() if hasattr(m, "header") else []):
                    pairs.append(f"{k}: {v}")
                return "\n".join(pairs)[:limit]
        except Exception:
            return ""
    try:
        from email import policy
        from email.parser import BytesParser
        msg = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        return "\n".join(f"{k}: {v}" for k, v in msg.items())[:limit]
    except Exception:
        return ""


def _slice_bytes(s: str, max_bytes: int) -> str:
    """Cut a string to at most max_bytes UTF-8 bytes without breaking a char."""
    if not s or max_bytes <= 0:
        return ""
    data = s.encode("utf-8")
    if len(data) <= max_bytes:
        return s
    out = data[:max_bytes]
    while out:
        try:
            return out.decode("utf-8")
        except UnicodeDecodeError:
            out = out[:-1]
    return ""


def build_body(name: str, raw: bytes, budget: dict) -> dict:
    """-> {text, html, hasText, hasHtml, truncated, omitted, textBytes, htmlBytes}"""
    if not budget or budget.get("left", 0) <= 0:
        return {"text": "", "html": "", "hasText": False, "hasHtml": False,
                "truncated": False, "omitted": True, "textBytes": 0, "htmlBytes": 0}
    text, html = extract_bodies(name, raw)
    text = (text or "")[:RAW_MAX]
    html = (html or "")[:RAW_MAX]
    if not text and html:
        text = html_to_text(html)
    if html:
        html = sanitize_html(html)
    text = (text or "").strip()
    allowed = max(0, min(BODY_MAX_BYTES, budget["left"]))
    text_cap = allowed // 2 if html else allowed
    text_out = _slice_bytes(text, text_cap)
    html_out = _slice_bytes(html, max(0, allowed - len(text_out.encode("utf-8"))))
    truncated = len(text_out) < len(text) or len(html_out) < len(html)
    used = len(text_out.encode("utf-8")) + len(html_out.encode("utf-8"))
    budget["left"] = max(0, budget["left"] - used)
    return {"text": text_out, "html": html_out,
            "hasText": bool(text_out), "hasHtml": bool(html_out),
            "truncated": truncated, "omitted": False,
            "textBytes": len(text_out.encode("utf-8")),
            "htmlBytes": len(html_out.encode("utf-8"))}


def case_dir(case_id: str) -> Path:
    return data_dir() / "messages" / str(case_id)


def save_bodies(case_id: str, items: list) -> list:
    """items = [(index, name, raw_bytes)] -> list of meta dicts (aligned to index)."""
    d = case_dir(case_id)
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except Exception:
        pass
    budget = {"left": BODY_TOTAL_BYTES}
    metas = []
    for item in items:
        idx, name, raw = item
        body = build_body(name, raw, budget)
        try:
            headers = extract_headers(name, raw)
            if headers:
                (d / f"{idx}.hdr").write_text(headers, encoding="utf-8")
            if body["text"]:
                (d / f"{idx}.txt").write_text(body["text"], encoding="utf-8")
            if body["html"]:
                (d / f"{idx}.html").write_text(body["html"], encoding="utf-8")
            (d / f"{idx}.json").write_text(
                '{"hasText": %s, "hasHtml": %s, "truncated": %s, "omitted": %s, '
                '"textBytes": %d, "htmlBytes": %d}' % (
                    "true" if body["hasText"] else "false",
                    "true" if body["hasHtml"] else "false",
                    "true" if body["truncated"] else "false",
                    "true" if body["omitted"] else "false",
                    body["textBytes"], body["htmlBytes"]),
                encoding="utf-8")
            for p in d.glob(f"{idx}.*"):
                try:
                    os.chmod(p, 0o600)
                except Exception:
                    pass
        except Exception:
            body = {"text": "", "html": "", "hasText": False, "hasHtml": False,
                    "truncated": False, "omitted": True, "textBytes": 0, "htmlBytes": 0}
        metas.append({"index": idx, **{k: body[k] for k in
                                       ("hasText", "hasHtml", "truncated", "omitted",
                                        "textBytes", "htmlBytes")},
                      "preview": (body.get("text") or "")[:500]})
    return metas


def read_body(case_id: str, index: int) -> dict:
    """-> {index, text, html, hasText, hasHtml, truncated, omitted, ...} or None."""
    d = case_dir(case_id)
    txt = d / f"{index}.txt"
    htm = d / f"{index}.html"
    hdr = d / f"{index}.hdr"
    meta_path = d / f"{index}.json"
    if not txt.exists() and not htm.exists() and not hdr.exists():
        return None
    meta = {}
    try:
        import json
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        meta = {}
    return {
        "index": index,
        "headers": hdr.read_text(encoding="utf-8", errors="ignore") if hdr.exists() else "",
        "text": txt.read_text(encoding="utf-8", errors="ignore") if txt.exists() else "",
        "html": htm.read_text(encoding="utf-8", errors="ignore") if htm.exists() else "",
        "hasText": txt.exists(),
        "hasHtml": htm.exists(),
        "truncated": bool(meta.get("truncated")),
        "omitted": bool(meta.get("omitted")),
        "textBytes": meta.get("textBytes"),
        "htmlBytes": meta.get("htmlBytes"),
    }


def delete_case_bodies(case_id: str) -> None:
    """Remove every stored body of a case (called when the case is deleted)."""
    d = case_dir(case_id)
    try:
        for p in d.glob("*"):
            try:
                p.unlink()
            except Exception:
                pass
        d.rmdir()
    except Exception:
        pass


def rebuild_body(case_id: str, index: int, evidence: bytes, fmt: str) -> dict:
    """Re-derive one body from the stored evidence blob (fallback path).

    Mirrors the Node server: when the stored body files are missing (e.g. the
    SQLite row was copied without DATA_DIR/messages), the message is parsed
    again from the forensic copy.
    """
    from .parsers import iter_mbox_messages
    name = f"{case_id}.eml"
    raw = evidence
    low = (fmt or "").lower()
    if low == "mbox":
        parts = []
        for m in iter_mbox_messages(raw):
            try:
                parts.append(m.as_bytes())
            except Exception:
                pass
        if index < 0 or index >= len(parts):
            return None
        raw = parts[index]
    elif low == "msg":
        name = f"{case_id}.msg"
    budget = {"left": BODY_TOTAL_BYTES}
    body = build_body(name, raw, budget)
    d = case_dir(case_id)
    d.mkdir(parents=True, exist_ok=True)
    headers = extract_headers(name, raw)
    if headers:
        (d / f"{index}.hdr").write_text(headers, encoding="utf-8")
    if body["text"]:
        (d / f"{index}.txt").write_text(body["text"], encoding="utf-8")
    if body["html"]:
        (d / f"{index}.html").write_text(body["html"], encoding="utf-8")
    return read_body(case_id, index)
