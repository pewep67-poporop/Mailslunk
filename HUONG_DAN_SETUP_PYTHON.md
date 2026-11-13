# MailSleuth Python — Hướng dẫn cài đặt & sử dụng (v2.0)

> **Bản Python là bản song song**, KHÔNG thay thế bản Node.js.
> Node `D:\Digital Forensics\mailsleuth` giữ nguyên 100%. Python nằm ở `D:\Digital Forensics\mailsleuth_python`, dùng `DATA_DIR` riêng, không đụng `data/` của Node.
>
> **Trạng thái:** đã triển khai đủ **7/7 module điều tra chuyên sâu** (P1 xác thực & đường truyền · P2 nội dung nguy cơ · P3 SIEM) — ngày 10/11/2026.

---

## 1. Kiến trúc tổng quan

```
Trình duyệt ──> http://127.0.0.1:8000 (Python/FastAPI)
                ├── /          → public/ (UI bản copy của Node: chọn tệp/thư mục, tiến trình,
                │                bảng IP 11 cột, model AI, compact mode, Export CSV, Export SIEM)
                └── /api/...   → FastAPI
app/
├── main.py          API + tích hợp pipeline: analyze chạy đủ M1→M7
├── auth.py          bcrypt cost 12, session SQLite, CSRF, recovery key
├── db.py            SQLite (WAL): users/cases/audit/kv/session_signatures/sessions
├── parsers.py       EML/MBOX/TXT (.msg qua extract-msg; PST/OST qua readpst → EML)
├── bodies.py        Lưu body từng thư (text + HTML đã khử XSS) vào data/messages/<case>/
├── enrichment.py    GeoLite2 + confidence % + phân loại server
├── dns_real.py      DNS thật (dnspython): A/AAAA/MX/TXT/NS/SOA/SPF/DMARC/DKIM/PTR
├── headers.py       M1 — phân tích header chuyên sâu (H-xxx)
├── authcheck.py     M2 — SPF/DKIM/DMARC xác thực THẬT trên raw evidence (A-xxx)
├── routing.py       M3 — tái tạo đường truyền SMTP từ chuỗi Received (R-xxx)
├── urls.py          M4 — trích + chấm điểm URL phishing (U-xxx)
├── attachments.py   M5 — phân tích tệp đính kèm + cách ly quarantine (A-xxx)
├── ioc.py           M6 — IOC hợp nhất → CSV defang / STIX 2.1
├── siem.py          M7 — Wazuh (CEF/syslog), Elastic (ECS), Splunk (HEC)
├── mapgen.py        Ghép tile OSM 5×5 cm (Pillow)
├── mapglot.py       MapGlot reverse 100% port (per-user key, cache 7 ngày)
└── report.py        Báo cáo HTML EN/VI 9 mục + CSV + format=json
```

---

## 2. Yêu cầu phiên bản

| Hạng mục | Phiên bản | Ghi chú |
|---|---|---|
| **Python** | **3.12 khuyến nghị** (tối thiểu 3.11; đã test 3.10.11) | máy hiện 3.10 vẫn chạy được với pin dưới đây |
| pip | ≥ 23 | `python -m pip install --upgrade pip` |
| Node (không bắt buộc) | chỉ khi muốn chạy song song bản cũ | Node ở `:3000`, Python ở `:8000` |

> **Python 3.13 / 3.14:** chạy được. `requirements.txt` dùng *environment markers* — trên Python ≥ 3.13
> pip tự chọn `fastapi>=0.120` + `pydantic>=2.12`, `Pillow>=11.3`, `bcrypt>=5.0` (có wheel native cho 3.14);
> trên 3.10–3.12 giữ nguyên pin đã test. `app/main.py` dùng `lifespan` (không dùng `on_event` đã bị bỏ
> ở FastAPI ≥ 0.120) nên cùng một mã nguồn chạy cả hai nhánh — không cần sửa gì thêm.
> **Linux:** xem mục 12.1 (systemd, WorkingDirectory, cổng, quyền read-only, case-sensitivity).

### Thư viện (pinned — `requirements.txt`)
| Thư viện | Phiên bản | Dùng cho |
|---|---|---|
| `fastapi` | 0.115.6 (≥ 3.13: `>=0.120,<1`) | Web framework |
| `uvicorn` | 0.34.0 | Máy chủ ASGI |
| `python-multipart` | 0.0.20 | Upload file |
| `bcrypt` | 4.2.1 (≥ 3.13: `>=5.0`) | Băm mật khẩu cost 12 |
| `geoip2` | 4.7.0 | Đọc GeoLite2 `.mmdb` |
| `Pillow` | 11.0.0 (≥ 3.13: `>=11.3`) | Ghép tile bản đồ |
| `python-dotenv` | 1.0.1 | Đọc `.env` |
| `requests` | 2.32.3 | OSM/MapGlot/SIEM |
| `email-reply-parser` | 0.5.9 | Trích body |
| `dnspython` | 2.7.0 | DNS native + SPF/DMARC/DKIM/PTR |
| `pyspf` | 2.0.14 | **Xác thực SPF thật** (include/redirect/all) |
| `dkimpy` | 1.1.0 | **Verify DKIM** trên raw byte |
| `oletools` | 0.60.2 | **Quét VBA macro** Office (olevba) |
| `olefile` | 0.46 | Đọc OLE/`.msg` |
| `extract-msg` | 0.45.0 | Parser `.msg` |

---

## 3. Cài đặt

```bash
cd "D:\Digital Forensics\mailsleuth_python"
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env     # Windows   (Linux: cp .env.example .env)
# → sửa ADMIN_PASS trước khi chạy lần đầu
```

## 4. Biến môi trường (`.env`)

### 4.1 Lõi
| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PORT` | `8000` | Khác Node (:3000) để chạy song song |
| `ADMIN_PASS` | bắt buộc lần đầu | Tạo user `admin`; recovery key **in 1 lần** vào stdout |
| `DATA_DIR` | `./data` | SQLite + evidence + quarantine của Python (tách khỏi Node) |
| `GEOIP_DIR` | `../mailsleuth/geoip` | Tái dùng `.mmdb` sẵn có (~60 MB) |
| `LIVE_DNS` | `1` | Đặt `0` để offline hoàn toàn — SPF/DKIM/DMARC trả `not_run` |
| `LIVE_DNS_DOMAINS`, `GEO_IPS` | `5`, `20` | Giới hạn tra DNS/Geo mỗi analyze |
| `COOKIE_SECURE` | `0` | Đặt `1` khi chạy HTTPS |
| `TRUST_PROXY` | rỗng | Đặt `1` khi đứng sau Nginx/Caddy |
| `MAPGLOT_API_KEY`, `MAPGLOT_BASE` | rỗng / `https://mapglot.com` | Fallback server-wide; ưu tiên key per-user trong `kv` |
| `MXTOOLBOX_API_KEY`, `MXTOOLBOX_AUTO` | rỗng / `0` | MxToolbox tuỳ chọn |
| `PST_TIMEOUT` | `300` | Giây tối đa cho một lần `readpst` (PST/OST) |
| `PST_MAX_MSGS` | `1000` | Số message tối đa đọc từ một PST/OST (vượt → `truncated: true`) |
| `PST_MAX_BYTES` | `209715200` | Tổng byte EML tối đa giải nén từ một PST/OST (~200 MB) |
| `PST_AUTH_MAX` | `50` | Số message đầu tiên được chạy SPF/DKIM/DMARC thật; phần còn lại đọc `Authentication-Results` có sẵn (không DNS) |
| `PST_FILE_MAX` | `524288000` | Kích thước PST/OST tối đa khi upload (~500 MB, bằng bản Node) |
| `BODY_MAX_BYTES` | `524288` | Dung lượng body tối đa cho **mỗi thư** (~512 KB) |
| `BODY_TOTAL_BYTES` | `33554432` | Tổng body tối đa cho **một case** (~32 MB, ngân sách dùng chung) |
| `AVATAR_RATE_MAX` | `20` | Số lần tải avatar tối đa / IP / phút |
| `DNS_CACHE_TTL` | `300` | Cache kết quả tra DNS (SPF/DMARC/DKIM) — giây; `0` = không cache |
| `REPUTATION_ENABLED` | `0` | Bật tra cảnh báo URL/hash (URLhaus · VirusTotal · Safe Browsing). Tắt = offline hoàn toàn |
| `REPUTATION_CACHE_TTL` | `3600` | Cache kết quả reputation (giây) |
| `REPUTATION_MAX_URLS` | `10` | Số URL mỗi thư được gửi đi tra cảnh báo |
| `REPUTATION_TIMEOUT` | `6` | Timeout mỗi lệnh gọi provider (giây) |
| `ABUSECH_KEY` / `VT_KEY` / `SB_KEY` | rỗng | Fallback khi analyst chưa nhập key trong tab *Trust & AI* (key per-user trong `kv` được ưu tiên) |
| `LLM_ENABLED` | `0` | Bật tầng đánh giá ngữ nghĩa bằng LLM (chỉ nâng cảnh báo, không hạ được kết luận rule) |
| `LLM_MODEL` | `openrouter/minimax/minimax-m3.1-flash` | Model mặc định cho tầng LLM |
| `LLM_MODEL_ESCALATE` | `openrouter/anthropic/claude-sonnet-5.5` | Model leo thang khi tầng 0 không chắc chắn |
| `LLM_REDACT` | `1` | Ẩn danh email/IP/URL/domain trước khi gửi cho LLM |
| `ML_ENABLED` | `0` | Bật bộ phân loại đã train (cần `data/models/phish_model.onnx`) |
| `ML_MODEL_PATH` | `./data/models/phish_model.onnx` | Đường dẫn file model |
| `ML_THRESHOLD` | `0.70` | Ngưỡng cảnh báo của tầng ML |
| `WATCHDOG_INTERVAL` | `60` | Chu kỳ tự kiểm tra sức khoẻ (giây); `0` = tắt |
| `WATCHDOG_FAILS` | `3` | Số lần hỏng liên tiếp → tiến trình tự thoát để systemd dựng lại |
| `BREAKER_FAIL_THRESHOLD` / `BREAKER_RESET_SECONDS` | `5` / `60` | Ngưỡng & thời gian mở lại circuit breaker cho provider ngoài |

### 4.2 SIEM (M7 — để trống = tắt push, offline hoàn toàn)
| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `WAZUH_HOST` | rỗng | IP/hostname Wazuh manager (đặt là push tự động) |
| `WAZUH_PORT` | `5140` | 514 cần admin trên Windows |
| `WAZUH_PROTO` | `udp` | `udp` hoặc `tcp` |
| `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` | rỗng | HEC endpoint + token |
| `ELASTIC_URL` | rỗng | `https://elastic:9200` |
| `ELASTIC_USER`/`ELASTIC_PASS`, `ELASTIC_API_KEY` | rỗng | Basic auth hoặc ApiKey |
| `ELASTIC_INDEX` | `mailsleuth-case` | Index đích `_bulk` |
| `SIEM_HOSTNAME` | hostname máy | Hostname trong frame syslog |

## 5. Chạy

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
uvicorn app.main:app --host 127.0.0.1 --port 8000
# mở http://127.0.0.1:8000 → login admin / <ADMIN_PASS>
# API docs tự sinh: http://127.0.0.1:8000/api/docs
```

Chạy song song Node (`:3000`) + Python (`:8000`), dữ liệu riêng biệt. Dừng Ctrl+C.

## 6. Pipeline điều tra khi Analyze

Mỗi tệp EML/MBOX/MSG/TXT — và **từng message bên trong PST/OST** — được analyze
chạy đủ 7 bước, byte gốc được lưu `data/evidence/{case_id}.bin` (read-only) nên mọi
bước đều tái chạy được trên case cũ:

1. **M1 Header analysis** (`H-xxx`) — From/Return-Path lệch, Reply-To khác domain, Message-ID ≠ From, header lặp, display-name giả mạo, lệch Date/Received, thiếu header, X-Originating-IP.
2. **M2 SPF/DKIM/DMARC thật** (`A-xxx`) — `pyspf.check2` (client IP = IP của hop Received dưới cùng, envelope = Return-Path/MAIL FROM, HELO = hostname hop đó khai báo), `dkimpy` verify **từng chữ ký DKIM** trên raw byte (khóa công khai lấy thật từ DNS `_domainkey.<selector>.<domain>`), DMARC lấy `_dmarc.<domain>` thật + **relaxed alignment** theo Public-Suffix (org-domain). Không có Return-Path → SPF `none` (không đoán MAIL FROM từ From). Có thêm: header `Authentication-Results` của máy nhận được đọc và đối chiếu (`upstream`), SPF/DMARC record thật hiển thị trong UI/báo cáo, lý do DKIM fail cụ thể (thiếu khóa / khoá bị thu hồi / body hash lệch).
3. **M3 SMTP Routing** (`R-xxx`) — bảng hop (from/by/with/via/for/gateway), delay từng hop; phát hiện vòng lặp IP, mốc thời gian ngược, hop trễ >24h, hop thiếu `from`, IP private.
4. **M4 Phishing URL** (`U-xxx`) — trích URL từ body text/HTML + attachment HTML; chấm: IP-host 55, punycode/homoglyph 35, lookalike brand (Levenshtein so 33 brand lớn) 35, `@`-trick 25, bait keyword 8/khóa, TLD rủi ro, combo lookalike+bait +15 → **malicious ≥65 / suspicious ≥40**.
5. **M5 Attachment** (`A-xxx`) — MD5/SHA1/SHA256, magic-byte vs MIME (ảnh nhưng là exe → malicious), EICAR, zip bomb (ratio >500x) + nested ≥3, VBA macro (olevba), PDF `/OpenAction|/JavaScript|/Launch`, phần mở rộng kép. Verdict ≠ clean → **cách ly** `data/quarantine/{sha256}_{tên}` (read-only).
6. **M6 IOC** — hợp nhất ip/domain/url/email/hash từ mọi module, dedupe.
7. **M7 SIEM** — sinh sự kiện + push (nếu cấu hình, xem mục 9).

**Chấm điểm:** mọi finding có `weight` trừ dồn vào score 100 (ví dụ `dmarc_fail` p=reject/quarantine −20, `spf_fail`/`dkim_fail` −10, `dangerous_attachment` −30, URL phishing tới −20); verdict tự nâng: `<85` suspicious, `<50` malicious_or_phishing; attachment malicious → verdict malicious_or_phishing.

> **Dataset lớn / mạng chậm:** pipeline chạy trong **worker thread** (`run_in_threadpool`) — server vẫn phản hồi bình thường trong lúc phân tích; mọi truy vấn DNS (A/TXT/PTR/SPF) đều có trần thời gian 2–5 giây. UI upload theo **lô 10 file** (tối đa 100 file/lần chạy) — thanh tiến trình nhảy sau mỗi lô. Nếu DNS của máy chậm (VM/NAT), đặt `LIVE_DNS=0` để chạy offline hoàn toàn: SPF/DKIM/DMARC trả `not_run`, phần còn lại (M1/M3/M4/M5/M6) vẫn phân tích đủ.
>
> **Kiểm tra trước khi Analyze (preflight):** ngay khi thêm tệp/thư mục, UI loại bỏ và ghi rõ lý do cho: phần mở rộng lạ, tệp rỗng (0 byte), tệp **>25 MB** (PST/OST: **>500 MB**), tệp trùng. Nút **Analyze** bị khóa khi không còn tệp hợp lệ (hoặc quá 100 tệp), nên lỗi `file` / `too_large` / `format_mismatch` / `parse` không còn xuất hiện sau khi bấm.
>
> **PST/OST:** server gọi `readpst -r -e -q` (libpst/pst-utils) để giải nén từng message ra EML trong thư mục tạm rồi chạy M1–M6 trên từng message; findings/attachments/URLs/origin IPs được gộp, message "xấu nhất" cung cấp header/routing/auth cho toàn file. Giới hạn `PST_MAX_MSGS` / `PST_MAX_BYTES` → trường `truncated: true`; chỉ `PST_AUTH_MAX` message đầu chạy SPF/DKIM/DMARC thật để tránh chậm DNS. Lỗi trả về: `readpst_missing` (chưa cài), `pst_timeout`, `readpst_failed` (hỏng/mã hoá), `format_mismatch` (magic `!BDN` sai), `empty` (không có message).
>
> **Điều khiển khi đang phân tích:** **Tạm dừng** — ngừng sau lô hiện tại, nút đổi thành **Tiếp tục**; **Dừng** — hủy lô đang chạy nhưng **giữ kết quả các lô đã xong** (hiển thị `10/11`); **Hủy** — hủy request và **bỏ toàn bộ kết quả** của lần chạy đó (case đã lưu phía máy chủ vẫn còn trong Lịch sử). Mỗi lô có trần **5 phút**; quá hạn sẽ tự hủy lô và giữ kết quả một phần — UI không bị treo.
>
> **M8 — xem nội dung thư:** mỗi message của case (kể cả từng message trong PST/OST) được lưu body ra `DATA_DIR/messages/<case_id>/{idx}.txt|.html|.json` — **text** (plain) và **HTML đã khử XSS** (bỏ script/style/iframe kèm nội dung, bỏ mọi attribute, `<a>/<img>` → `<span>`). Giới hạn `BODY_MAX_BYTES` (512 KB/thư) và `BODY_TOTAL_BYTES` (32 MB/case, ngân sách chung — vượt thì thư sau bị `omitted`). Khi bấm mở một thư, UI gọi `GET /api/case/{id}/message/{idx}`; nếu file body bị mất (ví dụ copy DB mà không copy `data/messages`), server **dựng lại** từ bản evidence gốc.
>
> **M9 — reputation (tắt mặc định):** tra **URLhaus · VirusTotal (chỉ hash-lookup) · Google Safe Browsing**. Chỉ **URL hoặc SHA-256** rời khỏi máy — **không có nội dung thư**. Key nhập trong tab *Trust & AI*, lưu **per-user** trong `kv`, không bao giờ echo/log. Mọi provider đi qua **circuit breaker** (5 lỗi liên tiếp → bỏ qua 60 s) nên nguồn cảnh báo hỏng không làm chậm phân tích.
>
> **M10 — bộ phân loại đã train (tắt mặc định):** `app/ml_features.py` sinh **58 đặc trưng** chỉ từ M1–M6 (không dùng kết quả DNS sống để tránh lệch phân phối train/serve; **không chứa chuỗi thô** → an toàn khi chia sẻ). `app/ml.py` nạp `data/models/phish_model.onnx` (hoặc `.joblib`) và trả `mlScore` + `topFactors`. Model sai schema → **từ chối nạp**, server chạy tiếp bằng rule. Tầng ML **chỉ nâng** cảnh báo, không bao giờ hạ kết luận của rule. Quy trình train: `tools/build_features.py` → `tools/train_model.py` (hoặc `tools/train_colab.ipynb`) → `tools/verify_model.py` → `tools/deploy_model.sh`.
>
> **M11 — đánh giá ngữ nghĩa bằng LLM (tắt mặc định):** gọi provider OpenAI-compatible bằng key per-user, `temperature=0`, **chỉ headers + body đã ẩn danh**. Mọi trích dẫn bằng chứng phải là **chuỗi con của nội dung thư** — không khớp thì cả kết luận đó bị loại (chống bịa đặt). Case lưu `model + prompt_version + prompt_sha256 + timestamp + token` để tái lập được.

## 7. API reference

| Endpoint | Mô tả |
|---|---|
| `GET /api/health` | Trạng thái GeoLite2/DNS |
| `POST /api/login` / `logout` / `register` / `recover` | JSON, cookie `sid` + header `x-csrf` |
| `GET/POST /api/password` / `profile*` | Đổi mật khẩu, avatar |
| `POST /api/analyze` | multipart upload 1..n tệp → kết quả đầy đủ 7 bước |
| `GET /api/profile` · `GET/POST /api/profile/avatar` | Hồ sơ + ảnh đại diện (PNG/JPEG, ≤2 MB, magic-byte, rate-limit 20/phút) |
| `GET /api/cases` | Lịch sử case (admin thấy tất) |
| `GET /api/case/{id}/message/{idx}` | Nội dung 1 thư (text + HTML đã khử XSS); analyst chỉ xoá được case của mình |
| `GET /api/report/{id}` | Báo cáo HTML EN/VI 9 mục (mục 3 Auth · 4 Header · 5 Routing · 6 Findings · 7 URL · 8 Attachment · 9 IP + map 5 cm) |
| `GET /api/report/{id}?format=csv` | CSV 23 cột (IP + auth + hops + findings) |
| `GET /api/report/{id}?format=json` | JSON cho nút mở lại case từ History |
| `GET /api/report/{id}.csv` | Như `?format=csv` |
| `GET /api/ioc/{id}` | IOC JSON (`{iocs, counts}`) |
| `GET /api/ioc/{id}.csv` | IOC CSV **defang** (`203[.]0[.]113[.]5`, `hxxp`) |
| `GET /api/ioc/{id}?format=stix` | **STIX 2.1 bundle** (nạp MISP/OpenCTI) |
| `GET /api/export/{id}?format=cef\|syslog\|ecs\|elastic\|splunk\|stix` | Xuất SIEM tải về |
| `POST /api/ip` / `POST /api/dns` / `GET /api/map` | Tra cứu lẻ (có rate-limit) |
| `GET/POST /api/settings/map` | Key MapGlot per-user (`hasKey/source/error`) |
| `GET /api/admin/logs` / `sessions` | Chỉ admin |

Rate-limit: login 10/phút · analyze 40/phút · ip/dns/map 30/phút. Keys (AI/MapGlot/…) lưu per-user trong `kv`, **không echo/log**.

## 8. Giao diện (UI)

- Phân tích: kéo-thả / Chọn tệp / Chọn thư mục, **preflight** (chặn ext lạ, tệp rỗng, >25 MB — PST/OST >500 MB, trùng), thanh tiến trình, **Tạm dừng / Dừng / Hủy**, **Export CSV**. PST/OST được chấp nhận và phân tích từng message.
- Kết quả: badge **SPF/DKIM/DMARC**, panel **Header & routing forensics** (bảng hop + checklist), panel **URL & attachment threats** (bảng URL tô đỏ/vàng + badge IOC), bảng IP 11 cột có confidence %, findings nhóm `H-/A-/R-/U-`.
- Danh sách thư: bấm mở 1 thư → hiện From/To/Reply-To/Return-Path/Message-ID, SPF/DKIM/DMARC, origin IPs, **nội dung text + HTML** (HTML trong iframe sandbox + CSP, đã khử XSS sẵn phía máy chủ).
- Xuất: **Báo cáo EN/VI**, **Export CSV**, **Export SIEM** (CEF/Syslog/ECS/Elastic/Splunk/STIX).
- i18n vi/en đầy đủ; compact mode ẩn trường null.
- Mọi lỗi API trả về dạng phẳng `{"error":"<mã>"}` (`auth`, `csrf`, `not_found`, `rate`, `too_large`, `bad_avatar`…) — UI hiển thị đúng thông báo, không còn hiện nhầm kiểu "chỉ nhận PNG/JPEG" khi thực ra là phiên hết hạn.
- Avatar: khi chưa tải ảnh, hiển thị **chữ cái đầu của tài khoản** trong ô tròn (thay vì ô ảnh trống); ảnh đã tải vẫn hiện ở cả thanh tài khoản và hồ sơ.

## 9. Ghép SIEM — Wazuh / ELK / Splunk (M7)

Sự kiện: `case_analyzed` (mỗi analyze) · `malware_detected` (CEF sev 9) · `phishing_url_hit` (sev 8) · `auth_failed` (DMARC fail p=reject/quarantine, sev 6). Kèm `caseId`, SHA-256, score, verdict, tên file/hash. Push lỗi mềm — chỉ ghi lớp lỗi vào audit, **không bao giờ log token**.

### 9.1 Wazuh (khuyến nghị dùng trước)
1. Cho MailSleuth gửi syslog tới manager — `wazuh_manager.conf` (hoặc qua agent):
```xml
<remote>
  <connection>syslog</connection>
  <port>5140</port>
  <protocol>udp</protocol>
  <allowed-ips>127.0.0.1</allowed-ips>
</remote>
```
2. Rule nhận biết — `var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="mailsleuth,">
  <rule id="100500" level="10">
    <decoded_as>CEF</decoded_as>
    <field name="signature_id">MSL-MALWARE</field>
    <description>MailSleuth: malicious attachment</description>
  </rule>
  <rule id="100501" level="8">
    <decoded_as>CEF</decoded_as>
    <field name="signature_id">MSL-PHISH</field>
    <description>MailSleuth: phishing URL detected</description>
  </rule>
  <rule id="100502" level="6">
    <decoded_as>CEF</decoded_as>
    <field name="signature_id">MSL-AUTH</field>
    <description>MailSleuth: DMARC authentication failed</description>
  </rule>
</group>
```
3. Chạy server với `WAZUH_HOST=<manager> WAZUH_PORT=5140` — mọi analyze được push tự động.
4. Lab không có manager? Nút **Export SIEM → CEF** tải file rồi nạp qua `wazuh-logcollector` hoặc copy sang manager.

### 9.2 ELK
- Tự động: `ELASTIC_URL` (+ auth) → `_bulk` ndjson ECS vào `ELASTIC_INDEX`.
- Thủ công: **Export SIEM → ECS** tải `.ndjson`, import:
  `curl -XPOST https://elastic:9200/_bulk --data-binary @file.ndjson` hoặc Filebeat input file.
- Lọc Kibana: `event.module: "mailsleuth"`.

### 9.3 Splunk
- Tự động: `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN` → HEC, `sourcetype=mailsleuth`.
- Thủ công: **Export SIEM → Splunk HEC** tải JSON, upload (Settings → Add Data).
- Search mẫu: `sourcetype=mailsleuth msgid=malware_detected`.

## 9.4 Vệ sinh dữ liệu — xoá dấu vết (bắt buộc cho môi trường thật)

Máy chủ lưu 3 loại dấu vết chứa **nội dung thư**: `evidence/*.bin` (bản gốc), `quarantine/` (mẫu độc hại), `messages/<case>/` (body text + HTML). Ngoài ra còn file upload tạm và thư mục tạm của parser.

```bash
# xem trước (không xoá)
python tools/purge.py --dry-run

# xoá dấu vết cũ hơn 30 ngày
python tools/purge.py --apply --days 30

# xoá một case cụ thể (evidence + body)
python tools/purge.py --apply --case 1a2b3c4d5e6f

# dọn file upload tạm còn sót (chạy hằng ngày bằng cron/timer)
python tools/purge.py --apply --staging
```
- Tool **chỉ xoá trong `DATA_DIR`**, có `--dry-run` mặc định, và ghi **biên bản** vào `data/purge-logs/*.json` + bảng audit (chỉ số lượng/byte, **không ghi nội dung**).
- Nên đặt `cron`/`systemd timer` hằng ngày: `0 3 * * * cd /opt/mailsleuth_python && .venv/bin/python tools/purge.py --apply --days 30 --staging`.
- **Sao lưu trước khi xoá** nếu case còn trong thời hạn lưu trữ pháp lý.

## 10. Di trú từ Node (nếu muốn)
- Băm bcrypt tương thích — *có thể* dùng chung DB, nhưng **khuyến nghị tách**.
- Copy DB: đóng cả 2 server → `copy ..\mailsleuth\data\app.db .\data\app.db` (users/cases/audit/kv khớp schema).
- GeoLite2 không copy — dùng `GEOIP_DIR=../mailsleuth/geoip`.
- MapGlot: key per-user đã ở `kv`, sang bản Python dùng được ngay.
- PST/OST: cả hai bản đều cần `readpst` (Linux/Docker).
- Body thư nằm ở `data/messages/<case>/` (riêng khỏi DB) — nếu copy `app.db` sang máy khác thì copy kèm `data/messages/`, nếu không server sẽ tự dựng lại từ `data/evidence/*.bin`.

## 11. Kiểm thử

```bash
# chạy TOÀN BỘ bộ kiểm thử (12 bộ, ~320 assert) — tự bật/tắt server, không đụng data thật
powershell -ExecutionPolicy Bypass -File tests\run-all.ps1
```

| Bộ test | Nội dung |
|---|---|
| `tests/smoke-pst.py` | PST/OST + MBOX (readpst thật qua stub), body thư M8, lỗi `readpst_missing`/`format_mismatch` |
| `tests/smoke-regress.mjs` | Backend: analyze, verdict, findings, IOC, report, export |
| `tests/smoke-avatar.mjs` | Avatar API: magic-byte, 2 MB, 400/401/413, cache |
| `tests/smoke-avatar-ui.mjs` | Avatar trên dashboard (Edge headless): upload, hiển thị, monogram, reload |
| `tests/smoke-ui-controls.mjs` | Preflight, Tạm dừng/Dừng/Hủy, mở thư, i18n VI |
| `tests/audit.py` | Audit toàn diện: cấu trúc, bảo mật, 25 endpoint, export, lưu trữ |
| `tests/auth-live.py` | M2 với **DNS thật**: SPF pass/softfail/none, DMARC policy+alignment, DKIM verify (khóa RSA thật) |
| `tests/auth-api-live.py` | M2 qua API với `LIVE_DNS=1` |
| `tests/layers-offline.py` | Circuit breaker, reputation (mock), đặc trưng ML, chống bịa LLM, redaction |
| `tests/leak-audit.py` | Rò rỉ: secret hard-code, nội dung thư trong log/DB, quyền tệp, redaction, file tạm |
| `tests/resilience.py` | Chaos: đầu vào hỏng, spam, health sâu, mã lỗi phẳng, purge, watchdog |
| `tests/ml-e2e.py` | Corpus → đặc trưng → train → verify → server chấm điểm (cần `scikit-learn`) |

Bộ cũ (unit + smoke) vẫn dùng được:
```bash
# biên dịch kiểm tra
python -m py_compile app\main.py app\headers.py app\authcheck.py app\routing.py app\urls.py app\attachments.py app\ioc.py app\siem.py app\report.py

# unit offline (không cần mạng, không cần server):
python <thư_mục_test>\test-p1.py   # 35/35 — headers/routing/auth (mock DNS)
python <thư_mục_test>\test-p2.py   # 29/29 — urls/attachments/ioc
python <thư_mục_test>\test-p3.py   # 19/19 — CEF/RFC5424/ECS/push UDP

# smoke live (chạy server ở :8000 trước):
node <thư_mục_test>\smoke-py.mjs    # 5/5  — login/ip/analyze/confidence
node <thư_mục_test>\smoke-csv.mjs   # 5/5  — CSV/report 5cm
node <thư_mục_test>\smoke-p1.mjs    # 17/17 — auth/routing/report/json
node <thư_mục_test>\smoke-p2.mjs    # 16/16 — EICAR/exe/IOC/STIX/quarantine
node <thư_mục_test>\smoke-p3.mjs    # 8/8  — 6 định dạng export SIEM
```

Tổng **131 assert**: unit 83 + smoke 48+ — tất cả PASS tại thời điểm 10/11/2026.

## 12. Triển khai production

- Linux: `systemd` (mục 12.1) + `uvicorn --workers 2` (session đã lưu SQLite; counter rate-limit vẫn per-process — cần Redis nếu >1 worker).
- Docker: `Dockerfile` (python:3.12-slim); PST/OST cần `readpst` thêm vào image nếu dùng.
- HTTPS: `COOKIE_SECURE=1` + proxy Nginx/Caddy; đứng sau proxy thì `TRUST_PROXY=1`.
- Wazuh: cấu hình theo mục 9.1; mount `data/quarantine` vào đường dẫn giám sát nếu muốn agent Wazuh quét tiếp.

### 12.1 Linux — unit systemd & lưu ý riêng

File unit **thật** đã kèm sẵn: `deploy/mailsleuth.service` (copy sang `/etc/systemd/system/mailsleuth.service`).

Điểm khác biệt so với bản hướng dẫn cũ (đã harden):
- `Restart=always` + `RestartSec=5` + `StartLimitBurst=5` → hồi phục cả khi bị `kill -9`.
- `MemoryMax=3G` / `MemoryHigh=2G` → container hết RAM bị dừng thay vì nuốt hết máy.
- `ProtectSystem=strict` + `ReadWritePaths=./data` → chỉ thư mục dữ liệu được ghi.
- `TimeoutStopSec=30` + `KillSignal=SIGINT` → tắt mềm, không cắt ngang ghi evidence.
- `Watchdog` nội bộ: app tự kiểm tra DB + ổ đĩa mỗi `WATCHDOG_INTERVAL` giây; hỏng `WATCHDOG_FAILS` lần liên tiếp → `os._exit(1)` để systemd dựng lại instance sạch.

`/etc/systemd/system/mailsleuth.service`:

```ini
[Unit]
Description=MailSleuth Python (FastAPI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mailsleuth
Group=mailsleuth
# BẮT BUỘC: mọi đường dẫn tương đối (DATA_DIR, GEOIP_DIR, quarantine) tính từ đây
WorkingDirectory=/opt/mailsleuth_python
Environment=DATA_DIR=./data
Environment=GEOIP_DIR=./geoip
Environment=ADMIN_PASS=doi-mat-khau-nay
ExecStart=/opt/mailsleuth_python/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Kích hoạt: `sudo systemctl daemon-reload && sudo systemctl enable --now mailsleuth`.

Lưu ý riêng Linux (khác Windows):

| Vấn đề | Chi tiết |
|---|---|
| **WorkingDirectory** | Đặt `WorkingDirectory=` trong unit; nếu chạy tay thì `cd` vào thư mục dự án trước, nếu không `DATA_DIR=./data` rơi vào chỗ khác |
| **Case-sensitive** | `Data/` ≠ `data/` — giữ đúng `DATA_DIR=./data`, tên file evidence/quarantine so khớp phân biệt hoa-thường |
| **chmod thật sự cấm ghi** | `data/quarantine/*` được `chmod 0o444` — trên Linux là read-only đúng nghĩa (Windows bỏ qua); evidence không thể ghi đè nhầm |
| **Cổng < 1024** | Syslog 514 cần root/CAP_NET_BIND_SERVICE → giữ mặc định **5140** như cấu hình Wazuh trong mục 9.1 |
| **Firewall** | Nếu Wazuh manager ở máy khác: mở chiều ra `sudo ufw allow 5140/udp` (hoặc tcp theo `WAZUH_PROTO`) |
| **Python từ distro** | Không cài package trực tiếp vào Python hệ thống (PEP 668 "externally-managed") — luôn dùng venv: `python3 -m venv .venv && source .venv/bin/activate` |
| **DNS** | SPF/DMARC dùng `dnspython` đọc `/etc/resolv.conf` tự nhiên — không cần cấu hình thêm; container nhớ cho phép DNS ra ngoài |
| **PST/OST** | `sudo apt install pst-utils` rồi kiểm tra `which readpst`; thiếu binary → API trả `readpst_missing` |
| **>1 worker** | `--workers 2` trở lên: counter rate-limit là per-process → dùng Redis hoặc giữ 1 worker |

## 13. Hạn chế đã biết & hướng mở

| Hạn chế | Chi tiết | Cách bổ sung |
|---|---|---|
| Reputation API chưa bật | URLhaus/VT/Safe Browsing chỉ là stub (không key) | URLhaus **không cần key** — bật được sớm; VT/Safe Browsing chờ key per-user |
| YARA | Chưa nạp luật | Thêm `yara-python` + thư mục `data/yara/` |
| PST/OST | Đã hỗ trợ qua `readpst`; message sau `PST_AUTH_MAX` chỉ đọc `Authentication-Results` (không tự verify SPF/DKIM/DMARC) | Cài pst-utils; tăng `PST_AUTH_MAX` nếu cần verify sâu (chậm hơn do DNS) |
| `.msg` DKIM | Byte đã chuyển đổi có thể lệch chữ ký | Ưu tiên EML gốc khi verify |
| Rate-limit | Counter per-process | Redis khi scale nhiều worker |
| Report PDF/diagram | Chưa có bản PDF như Node | Port tiếp khi cần |

---
*Ngày cập nhật: 10/11/2026 — MailSleuth Python v2.0 (P1+P2+P3 hoàn tất).*
