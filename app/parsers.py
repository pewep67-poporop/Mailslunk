"""Parsers — EML/MBOX/MSG/TXT and Linux Maildir-style messages.

PST/OST is deliberately **not** parsed here. The investigator extracts mail
with an external tool (readpst/libpst, Outlook export, etc.) and imports the
resulting EML/MBOX/Maildir tree. This keeps the server free of native PST
dependencies and of the old WSL/pypff bridge.

Format detection is content-aware so extensionless Maildir files
(``cur/1712345678.M123P456.host``) are accepted as individual messages.
"""
import email
import mailbox
import os
import re
import tempfile
from email import policy
from email.parser import BytesParser
import ipaddress as ipmod

EXT_RE = re.compile(r"\.(eml|emlx|mht|mhtml|msg|mbox|mbx|txt)$", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FORMAT_BY_EXT = {
    ".eml": "eml", ".emlx": "eml", ".mht": "eml", ".mhtml": "eml",
    ".msg": "msg", ".mbox": "mbox", ".mbx": "mbox", ".txt": "txt",
}


class ParseError(Exception):
    """Stable error code consumed by /api/analyze."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def is_private(ip: str) -> bool:
    try:
        a = ipmod.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except Exception:
        return True


def extract_ips(headers_text: str):
    ips = []
    for h in re.findall(r"(?im)^Received:.*", headers_text or ""):
        for ip in _IP_RE.findall(h):
            if is_private(ip):
                continue
            if ip not in ips:
                ips.append(ip)
    return ips


def _header_text(msg) -> str:
    try:
        return "\n".join(f"{k}: {v}" for k, v in msg.items())
    except Exception:
        return ""


def _body_text(msg, limit: int = 8192) -> str:
    """Plain-text preview that also works for multipart/mixed messages."""
    try:
        if not msg.is_multipart():
            payload = msg.get_payload(decode=True)
            if payload:
                return payload[:limit].decode(msg.get_content_charset() or "utf-8", "replace")
        # Prefer text/plain, then text/html (tags stripped minimally).
        for want in ("text/plain", "text/html"):
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_type() != want:
                    continue
                if part.get_content_disposition() == "attachment":
                    continue
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                text = payload[:limit].decode(part.get_content_charset() or "utf-8", "replace")
                if want == "text/html":
                    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
                    text = re.sub(r"(?s)<[^>]+>", " ", text)
                    text = re.sub(r"\s+", " ", text)
                return text
    except Exception:
        pass
    return ""


def parse_eml_bytes(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = _header_text(msg)
    return {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "cc": str(msg.get("Cc", "")),
        "bcc": str(msg.get("Bcc", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "originIPs": extract_ips(headers),
        "replyTo": str(msg.get("Reply-To", "")),
        "returnPath": str(msg.get("Return-Path", "")),
        "body": _body_text(msg),
    }


def parse_text_bytes(raw: bytes) -> dict:
    """A .txt may be a saved EML or plain prose; support both."""
    head = raw[:8192].decode("utf-8", "replace")
    if re.search(r"(?im)^(from|received|return-path|subject|date|message-id):", head):
        try:
            return parse_eml_bytes(raw)
        except Exception:
            pass
    return {
        "from": "", "to": "", "cc": "", "bcc": "",
        "subject": "(plain text)", "date": "", "message_id": "",
        "originIPs": extract_ips(head), "replyTo": "", "returnPath": "",
        "body": head[:8192],
    }


def detect_client(name: str, raw: bytes) -> dict:
    """Identify the mail platform from the file name and real headers only.

    Returns {"key", "label"} where key is one of outlook, exchange, thunderbird,
    apple, gmail, maildir, mbox, generic. No guessing from body text.
    """
    low = (name or "").lower()
    if low.endswith(".msg"):
        return {"key": "outlook", "label": "Microsoft Outlook (MSG)"}
    if "/cur/" in low.replace("\\", "/") or "/new/" in low.replace("\\", "/"):
        return {"key": "maildir", "label": "Linux Maildir"}
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        h = {str(k).lower(): str(v) for k, v in msg.items()}
    except Exception:
        h = {}
    xm = (h.get("x-mailer") or "").lower()
    ua = (h.get("user-agent") or "").lower()
    if "microsoft outlook" in xm or "microsoft outlook" in ua or "x-ms-exchange" in " ".join(h):
        return {"key": "outlook", "label": "Microsoft Outlook"}
    if h.get("x-ms-exchange-organization-authas") or h.get("x-ms-exchange-antispam-message-info"):
        return {"key": "exchange", "label": "Microsoft Exchange"}
    if "thunderbird" in xm or "thunderbird" in ua:
        return {"key": "thunderbird", "label": "Mozilla Thunderbird"}
    if "apple" in xm or "mail.app" in xm or "mac os x" in xm:
        return {"key": "apple", "label": "Apple Mail"}
    if "gmail" in xm or "google" in xm:
        return {"key": "gmail", "label": "Gmail"}
    if h.get("x-mailer") or h.get("user-agent"):
        return {"key": "generic", "label": (h.get("x-mailer") or h.get("user-agent"))[:80]}
    return {"key": "generic", "label": "RFC 822 / EML"}


def iter_mbox_messages(raw: bytes):
    """Yield email.message objects from raw MBOX bytes.

    mailbox.mbox needs a real path, so the upload is staged in a private temp
    file and removed when iteration ends.
    """
    fd, path = tempfile.mkstemp(prefix="ms-mbox-", suffix=".mbox")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        mbox = mailbox.mbox(path, create=False)
        try:
            for m in mbox:
                yield m
        finally:
            mbox.close()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def parse_mbox_bytes(raw: bytes) -> list:
    out = []
    for m in iter_mbox_messages(raw):
        try:
            msg_raw = m.as_bytes()
        except Exception:
            msg_raw = raw
        try:
            item = parse_eml_bytes(msg_raw)
        except Exception:
            item = {"from": str(m.get("From", "")), "to": str(m.get("To", "")),
                    "subject": str(m.get("Subject", "")), "date": str(m.get("Date", "")),
                    "message_id": str(m.get("Message-ID", "")),
                    "originIPs": extract_ips(_header_text(m)), "body": ""}
        item["_raw"] = msg_raw
        out.append(item)
    return out


def sniff_format(name: str, raw: bytes) -> str:
    """Return eml|mbox|msg|txt, or '' when the bytes are not a mail message."""
    ext = os.path.splitext((name or "").lower())[1]
    if ext in _FORMAT_BY_EXT:
        return _FORMAT_BY_EXT[ext]
    if ext:
        return ""
    head = (raw or b"")[:65536]
    if head.startswith(b"From ") and b"\nFrom:" in head:
        return "mbox"
    low = head.lower()
    if (b"\nfrom:" in low or b"\nreceived:" in low or b"\nreturn-path:" in low
            or b"\nsubject:" in low or b"\ndate:" in low):
        return "eml"
    if head and b"\x00" not in head[:4096]:
        return "txt"
    return ""


def load_messages(name: str, raw: bytes) -> list:
    fmt = sniff_format(name, raw)
    if fmt == "mbox":
        return parse_mbox_bytes(raw)
    if fmt == "msg":
        import io as _io
        import extract_msg
        with _io.BytesIO(raw) as f:
            m = extract_msg.MessageMessage(f)
            headers = "\n".join(str(v) for v in m.header.values()) if hasattr(m, "header") else ""
            return [{"from": str(m.sender or ""), "to": str(m.to or ""),
                     "cc": str(m.cc or ""), "bcc": str(m.bcc or ""),
                     "subject": str(m.subject or ""), "date": str(m.date or ""),
                     "message_id": "", "originIPs": extract_ips(headers),
                     "replyTo": "", "returnPath": "", "body": str(m.body or "")[:8192]}]
    if fmt == "txt":
        return [parse_text_bytes(raw)]
    if fmt == "eml":
        return [parse_eml_bytes(raw)]
    raise ParseError("format_mismatch")
