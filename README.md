# Mailslunk

> **MailSleuth — bản Python (FastAPI) song song với bản Node.js.**
> Phát triển lại toàn bộ pipeline điều tra email: header forensics, SPF/DKIM/DMARC,
> SMTP routing, phishing URL, malware attachment, IOC, body preview, reputation,
> AI/ML — trong khi **bản Node.js gốc (`../mailsleuth`) giữ nguyên 100%**.

---

## TOC / Mục lục

- [Overview / Tổng quan](#overview)
- [Capabilities / Năng lực](#capabilities)
- [Project structure / Cấu trúc dự án](#project-structure)
- [Quick start / Cài đặt nhanh](#quick-start)
- [Environment variables / Biến môi trường](#environment-variables)
- [Main API / API chính](#main-api)
- [Testing / Kiểm thử](#testing)
- [Screenshots / Hình ảnh](#screenshots)
- [Deployment / Kịch bản triển khai](#deployment)
- [License / Bản quyền & ghi chú](#license)

---

## Overview / Tổng quan

**Mailslunk** là bản nâng cấp / song song codebase **Python (FastAPI)** cho hệ thống
MailSleuth — một công cụ phân tích email chuyên nghiệp dùng cho **digital forensics** và
**cyber threat intelligence** nội bộ.

| | Node.js (gốc) | Python (Mailslunk) |
|---|---|---|
| Trạng thái | **90% giữ nguyên** | **100% song song** |
| PST/OST | `readpst` qua child_process | `readpst` subprocess + magic `!BDN` |
| Body preview (M8) | – | `data/messages/<case_id>/` + endpoint |
| Auth rewrite (M2) | – | pyspf + dkimpy + DMARC full |
| Reputation (M9) | – | URLhaus/VirusTotal/Safe Browsing |
| AI/ML (M10–M11) | – | sklearn + ONNX / LLM |

Server Python là **drop-in** cho pipeline: cùng schema SQLite (`users`, `cases`,
`audit`, `kv`), cùng evidence layout (`evidence/`, `quarantine/`, `messages/`).

---

## Capabilities / Năng lực

### Module điều tra

1. **Header forensics** (`H-xxx`) — From/Return-Path, Reply-To, Message-ID,
   header lặp, display-name spoof, lệch múi giờ Date/Received.
2. **SPF / DKIM / DMARC xác thực thực tế** (`A-xxx`) — pyspf + dkimpy trên raw
   evidence; DMARC policy + alignment; tự tra khóa DKIM; upstream AR.
3. **SMTP routing** (`R-xxx`) — theo từng hop, delay, vòng lặp, missing From,
   private IP hop.
4. **Phishing URL** (`U-xxx`) — IP-host, punycode/homoglyph, lookalike brand
   (Levenshtein), bait keyword, URLhaus blocklist.
5. **Malware attachment** (`A-xxx`) — hash MD5/SHA1/SHA256, magic vs MIME,
   EICAR, zip bomb, VBA macro (olevba), PDF active content, quarantine.
6. **IOC** — JSON / CSV defang / **STIX 2.1** export.

### Module mở rộng

7. **Xem nội dung thư (M8)** — body text + HTML đã khử XSS lưu trong
   `data/messages/<case_id>/{idx}.{txt,html,json}`; endpoint
   `GET /api/case/{case_id}/message/{idx}`.
8. **Reputation (M9, tắt mặc định)** — URLhaus · VirusTotal (hash-lookup) ·
   Google Safe Browsing. Chỉ URL/SHA-256 rời khỏi máy; key per-user trong `kv`;
   circuit breaker khi provider lỗi.
9. **Bộ phân loại AI đã train (M10, tắt mặc định)** — 58 feature từ M1–M6 →
   `mlScore` + `topFactors`; model sai schema bị từ chối nạp; chỉ **nâng** cảnh báo,
   không hạ kết luận rule.
10. **Đánh giá ngữ nghĩa LLM (M11, tắt mặc định)** — nhiệm vụ ý định + giải thích;
    trích dẫn bằng chứng phải khớp nguyên văn; nội dung gửi đi được ẩn danh.

### Gửi SIEM (M7)

- **Wazuh** — syslog RFC 5424 + CEF, UDP/514 push.
- **Elastic** — `_bulk` NDJSON ECS.
- **Splunk** — HEC (`mailsleuth` sourcetype).
- Export 6 định dạng: JSON / CSV / ECS / CEF / RFC5424 / STIX.

### Tài liệu

- Báo cáo HTML EN/VI 9 mục + CSV 23 cột.
- Bản đồ OSM 5.5cm + MapGlot (per-user key).

---

## Project structure / Cấu trúc dự án

```
mailslunk/
├── app/            # FastAPI backend (Python)
│   ├── main.py             # core pipeline, endpoints, health, watchdog
│   ├── headers.py          # M1 header forensics (H-xxx)
│   ├── authcheck.py        # M2 SPF/DKIM/DMARC (A-xxx)
│   ├── routing.py          # M3 SMTP routing (R-xxx)
│   ├── urls.py             # M4 phishing URL (U-xxx)
│   ├── attachments.py      # M5 malware attachment (A-xxx)
│   ├── ioc.py              # IOC (JSON/CSV/STIX)
│   ├── bodies.py           # M8 body preview
│   ├── reputation.py       # M9 threat feeds
│   ├── ml.py               # M10 inference
│   ├── ml_features.py     # M10 feature vector (58 feature)
│   ├── llm.py              # M11 semantic layer
│   ├── siem.py             # M7 SIEM export
│   ├── report.py           # HTML/CSV báo cáo
│   └── db.py               # SQLite storage
├── public/         # Frontend (vanilla JS + HTML/CSS)
│   └── img/        # Hình ảnh nền / nhân vật
├── tests/          # 13 bộ kiểm thử (12 PASS + ML e2e)
├── tools/          # train / build features / verify / deploy / purge / fetch
├── deploy/         # systemd unit hardened
├── data/           # runtime storage (gitignored)
├── Dockerfile
├── requirements.txt
├── README.md
└── HUONG_DAN_SETUP_PYTHON.md
```

---

## Quick start / Cài đặt nhanh

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
# UI: http://127.0.0.1:8000   |   API docs: /api/docs
```

Linux (systemd):

```bash
sudo cp deploy/mailsleuth.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mailsleuth
```

Yêu cầu: `sudo apt install pst-utils` (bản Linux cần `readpst` thật).

---

## Environment variables / Biến môi trường

| Variable / Biến | Default / Mặc định | Description / Mô tả |
|---|---|---|
| `ADMIN_PASS` | `ChangeMe-Admin-123456` | Mật khẩu admin (đổi trước khi deploy) |
| `DATA_DIR` | `./data` | Thư mục dữ liệu runtime |
| `GEOIP_DIR` | `../mailsleuth/geoip` | GeoLite2 |
| `LIVE_DNS` | `1` | Bật tra DNS thật cho SPF/DKIM/DMARC |
| `LIVE_DNS_DOMAINS` | `5` | Số domain / bộ duy nhất |
| `GEO_IPS` | `20` | Số IP cần geo |
| `COOKIE_SECURE` | `0` | Secure cookie (HTTPS) |
| `REPUTATION_ENABLED` | `0` | Bật M9 |
| `ML_ENABLED` | `0` | Bật M10 |
| `LLM_ENABLED` | `0` | Bật M11 |
| `BREAKER_FAIL_THRESHOLD` | `5` | Circuit breaker |
| `WATCHDOG_INTERVAL` / `WATCHDOG_FAILS` | `60` / `3` | Watchdog tự phục hồi |

Xem `HUONG_DAN_SETUP_PYTHON.md` đầy đủ.

---

## Main API / API chính

| Method | Path | Description / Mô tả |
|---|---|---|
| POST | `/api/analyze` | Upload + phân tích (PST/MBOX/EML/MSG/TXT) |
| GET | `/api/cases` | Lịch sử case |
| GET | `/api/case/{id}/message/{idx}` | Body preview M8 |
| GET | `/api/settings/reputation` | Trạng thái reputation M9 |
| GET | `/api/health?deep=1` | Health deep (components, breakers, ML) |
| GET | `/api/export/siem?...` | Export SIEM |
| POST | `/api/report` | Báo cáo HTML/CSV |

Xem đầy đủ trong `/api/docs` khi chạy server.

---

## Testing / Kiểm thử

```bash
# chạy TOÀN BỘ bộ kiểm thử (12 bộ, ~346 assert)
powershell -ExecutionPolicy Bypass -File tests\run-all.ps1
```

Các bộ: PST/OST, backend regress, avatar API/UI, UI controls, audit, auth M2,
layers (breaker/ML/LLM), **leak-audit**, **resilience**, **ML e2e**, auth live API.

---

## Screenshots / Hình ảnh

<p align="center">
  <img src="public/img/detective.jpg" width="480" alt="Mailslunk detective" />
</p>

<p align="center">
  <img src="public/img/matrix-code.jpg" width="480" alt="Mailslunk matrix" />
</p>

<p align="center">
  <img src="public/img/detective-lens.png" width="480" alt="Mailslunk lens" />
</p>

<p align="center">
  <img src="public/img/detective-clean.png" width="480" alt="Mailslunk clean" />
</p>

---

## Deployment / Kịch bản triển khai

1. Cài `pst-utils` trên Linux: `sudo apt install pst-utils`.
2. Copy unit: `sudo cp deploy/mailsleuth.service /etc/systemd/system/`.
3. Đặt `ADMIN_PASS` thật, bật `LIVE_DNS=1`, cấu hình key reputation/LLM.
4. Bật tầng cần thiết: `ML_ENABLED=1`, `LLM_ENABLED=1`, `REPUTATION_ENABLED=1`.

---

## License / Bản quyền & ghi chú

- Pipeline rule là **deterministic** — ML/LLM chỉ **nâng** cảnh báo.
- Không rò dữ liệu: reputation chỉ gửi URL/SHA-256; LLM payload được ẩn danh;
  feature vector không chứa chuỗi thô.
- Vệ sinh dấu vết: `python tools/purge.py --apply --days 30`.

---

*Mailslunk — v2.2 — 13/11/2026*
