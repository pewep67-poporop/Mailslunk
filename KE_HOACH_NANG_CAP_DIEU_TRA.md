# MailSleuth Python — Kế hoạch nâng cấp chuyên sâu điều tra (v2.0)

> **Trạng thái: P1 + P2 + P3 HOÀN THÀNH (2026-11-10) — kế hoạch đã triển khai đủ 7/7 module.**
> P1: M1 `headers.py` + M2 `authcheck.py` (SPF/DKIM/DMARC thật) + M3 `routing.py`.
> P2: M4 `urls.py` (phishing URL), M5 `attachments.py` (EICAR/exe/macro/zip bomb + quarantine), M6 `ioc.py` (CSV defang + STIX 2.1).
> P3: M7 `siem.py` (Wazuh syslog RFC5424+CEF tự push, Elastic _bulk ECS, Splunk HEC; export `?format=cef|syslog|ecs|elastic|splunk|stix`).
> Tests: unit P1 35/35 + P2 29/29 + P3 19/19; smoke P1 17/17 + P2 16/16 + P3 8/8 (+ UDP capture chứng minh auto-push); smoke gốc 5/5 + 5/5.

> Phạm vi: chỉ tác động `mailsleuth_python/`. Bản Node.js giữ nguyên. Mọi nguyên tắc cũ được giữ:
> key dịch vụ (AI/MapGlot/VT…) lưu per-user trong `kv`, **không echo/log**; `DATA_DIR` riêng;
> mặc định **offline-safe** (không gọi API ngoài trừ khi người dùng cấu hình key); mỗi tính năng
> mới đều có smoke test + hiển thị UI + đưa vào report/CSV.

---

## 1. Kiến trúc mở rộng

```
mailsleuth_python/app/
├── main.py            (giữ API cũ + endpoint mới: /api/headers, /api/auth, /api/routing,
│                       /api/urls, /api/attachments, /api/ioc, /api/export/…)
├── headers.py         [MỚI] Phân tích header chuyên sâu (M1)
├── authcheck.py       [MỚI] SPF/DKIM/DMARC xác thực THẬT (M2)
├── routing.py         [MỚI] Tái tạo đường truyền SMTP/hop (M3)
├── urls.py            [MỚI] Trích xuất + phân tích URL phishing (M4)
├── attachments.py     [MỚI] Phân tích tệp đính kèm/malware (M5)
├── ioc.py             [MỚI] IOC extraction + threat intel (M6)
├── siem.py            [MỚI] Xuất/đẩy SIEM: ECS, CEF, HEC, syslog, STIX (M7)
├── (giữ nguyên: auth, db, parsers, enrichment, dns_real, mapgen, mapglot, report)
```

Dữ liệu case đã lưu `data/evidence/{id}.bin` (raw byte gốc) → xác thực DKIM/SPF và
tái phân tích header chạy được **lại bất kỳ lúc nào** trên case cũ, không cần file gốc.

---

## 2. Chi tiết 7 module

### M1 — Email Header Analysis (`app/headers.py`)
| Hạng mục | Nội dung |
|---|---|
| Nguồn | Raw header từ evidence `.bin` (EML/MSG/MBOX), không qua parser làm mất byte |
| Kiểm tra | `From` vs `Return-Path` lệch; `Reply-To` khác domain `From`; display-name giả mạo (UTF-8, ký tự homograph); `Message-ID` domain ≠ `From`; `X-Originating-IP`/`X-Mailer`/`X-Priority`; header trùng lặp (dấu can thiệp); lệch múi giờ `Date` vs `Received` đầu tiên; `Received-SPF`/`Authentication-Results` cũ (nếu có) |
| Đầu ra | `{ "headers": [{name, value}], "checks": [{id, severity, evidence, citation}] }` — dạng `H-xxx`, ăn thẳng vào `findings` + điểm |
| Tích hợp | Tab "Headers" mới trong UI (bảng + badge đỏ/vàng/xanh), mục report, cột CSV, IOC tự trích |

### M2 — SPF / DKIM / DMARC xác thực thật (`app/authcheck.py`)
| Hạng mục | Nội dung |
|---|---|
| Thư viện | **`mail-auth`** (SPF+DKIM+DMARC một thư viện, đánh raw EML trực tiếp). Fallback: `pyspf` + `dkimpy` nếu mail-auth lỗi trên Python 3.10 |
| SPF | Check HELO + MAIL FROM, xử lý `include/redirect/all/~all/-all`, trả `pass/fail/softfail/none` |
| DKIM | Verify từng chữ ký `d=`, `s=`, body-hash, canonicalization trên raw byte (đã lưu evidence) |
| DMARC | Tra `_dmarc.<from-domain>`, alignment relaxed/strict, ghép kết quả SPF+DKIM → `pass/fail` tổng |
| Đầu ra | `{ "spf": {result, domain, reason}, "dkim": [{result, domain, selector}], "dmarc": {result, policy, aligned_domain} }` |
| Tích hợp | 3 badge SPF/DKIM/DMARC ở UI + report; `Authentication-Results` tổng hợp in kèm; fail DMARC → finding nghiêm trọng + cộng điểm; `authSeen` đúng nghĩa thay vì `false` cứng |
| DNS | Dùng `dns_real.py` (dnspython) sẵn có — không cần cấu hình thêm |

### M3 — SMTP & Email Routing (`app/routing.py`)
| Hạng mục | Nội dung |
|---|---|
| Phân tích | Ghép chuỗi `Received` **dưới-lên** thành bảng hop: `from / by / with / via / timestamp` |
| Anomaly | Delay bất thường từng hop; loop (IP lặp); hop thiếu `from`; IP private xuất hiện ở hop ngoài; `by` tự nhận mail server lạ; nhảy cóc quốc gia bất hợp lý |
| Phân loại | Nhận diện gateway phổ biến (Google/Microsoft/Proofpoint/Barracuda…), hop nội bộ vs ngoài |
| Geo-path | Đặt số hop lên **bản đồ OSM 5×5cm** sẵn có (marker #1→#N theo hướng thư đi) |
| Đầu ra | `{ "hops": [...], "anomalies": [...], "totalDelayMs": n }` — dạng `R-xxx` |
| Tích hợp | Tab "Routing" (timeline + bản đồ hop), mục report, CSV, SIEM event |

### M4 — Phishing URL Analysis (`app/urls.py`)
| Hạng mục | Nội dung |
|---|---|
| Trích xuất | Regex + BeautifulSoup/Lxml trên body text/HTML **và trong tệp đính kèm** (HTML/PDF text); decode HTML entity, URL-encode; refang `[.]`→`.` |
| Heuristic | Punycode/homoglyph; host là IP literal; TLD rủi ro; URL dài/sâu; mẹo `@`; từ khoá bait (`login/verify/otp/wallet`); **so domain với top-brand bằng Levenshtein** (paypa1↔paypal); không HTTPS |
| Reputation | URLhaus (miễn phí, không key), PhishTank/Google Safe Browsing/VirusTotal (cần key per-user/env) — chỉ bật khi có key |
| Redirect | TẮT mặc định; nếu bật chỉ `HEAD`, whitelist thời gian, không thực thi nội dung |
| Đầu ra | Mỗi URL: `{url, host, ip?(nếu resolve), risk 0-100, reasons[], reputation}` — dạng `U-xxx` |
| Tích hợp | Bảng URL trong UI (11→13 cột không đụng bảng IP, thêm bảng riêng), report, CSV, IOC tự hợp nhất |

### M5 — Malware Attachment Analysis (`app/attachments.py`)
| Hạng mục | Nội dung |
|---|---|
| Cơ bản | MD5/SHA1/SHA256, MIME vs **magic byte** mismatch, kích thước, tên file có mẹo double-extension |
| Entropy | Shannon entropy; >7.5 cảnh báo nén/mã hoá; zip bomb (tỉ lệ giải nén, nested archive) |
| Office | `oletools` → quét VBA macro (olevba), DDE, external link; PDF: JS/`/OpenAction`/`/Launch` |
| Reputation | VirusTotal **hash-lookup** (mặc định, không upload file), MalwareBazaar (miễn phí) |
| YARA | Tuỳ chọn `yara-python`, thư mục luật `data/yara/` — tự nạp `*.yar` |
| Cách ly | Copy bản gốc đặt tên `{sha256}` vào `data/quarantine/`, chmod read-only |
| Đầu ra | `{filename, hashes, magic, entropy, verdict(clean/suspicious/malicious), reasons[]}` — dạng `A-xxx` |
| Tích hợp | Bảng attachment UI + report + CSV + IOC hash tự trích |

### M6 — IOC & Threat Intelligence (`app/ioc.py`)
| Hạng mục | Nội dung |
|---|---|
| Trích | Hợp nhất từ mọi module: IP, domain, URL, email, hash, tên file — dedupe + defang chuẩn |
| Enrich | AbuseIPDB / OTX / VT (key per-user/env), URLhaus miễn phí; không key → dùng kết quả offline của M2–M5 |
| Xuất | `GET /api/ioc/{id}.csv`, **STIX 2.1 bundle JSON**, nhập vào báo cáo |
| Tích hợp | Tab IOC (bảng dạng/value/confidence), badge đếm IOC ở thanh kết quả |

### M7 — Correlation SIEM: Wazuh / ELK / Splunk (`app/siem.py`)
| Đích | Cách đẩy |
|---|---|
| **Elastic (ELK)** | JSON schema **ECS** → `POST https://host:9200/_bulk` (user/pass env) |
| **Splunk** | JSON → **HTTP Event Collector** `POST /services/collector/event` (token env `SPLUNK_HEC_TOKEN`) |
| **Wazuh** | CEF/JSON → **syslog** (RFC 5424) tới manager/agent (env `WAZUH_HOST`, port cấu hình được — 514 cần admin trên Windows nên mặc định 5140/UDP hoặc qua agent socket) |
| Xuất file | `GET /api/export/{id}?format=ecs|cef|stix|csv` — tải về nạp tay khi lab không có mạng |
| Sự kiện | `case.analyzed`, `auth.failed`, `phishing.url.hit`, `malware.detected`, `ioc.enriched` — kèm `case_id, sha256, score, verdict` |
| An toàn | Token/key chỉ đọc từ env/kv, không log/echo; đẩy qua HTTPS nếu có; retry 1 lần |
| Doc | Thêm mục "Ghép SIEM" vào `HUONG_DAN_SETUP_PYTHON.md`: wazuh-logcollector, Splunk HEC index, Elastic ingest pipeline |

---

## 3. Dependencies mới (ghim khi cài, kiểm tra trên Python 3.10 & 3.12)

| Thư viện | Dùng cho | Bắt buộc? |
|---|---|---|
| `mail-auth` | SPF/DKIM/DMARC verify raw EML | Có (P1) |
| `pyspf` + `dkimpy` | Fallback xác thực | Tự cài theo fallback |
| `beautifulsoup4` + `lxml` | Trích URL khỏi HTML | Có (P2) |
| `oletools` | Macro/VBA Office | Có (P2) |
| `yara-python` | Quét YARA | Tuỳ chọn (nếu cài được wheels trên Windows) |
| `stix2` | Xuất STIX bundle | Có (P3) |
| `requests` | đã có | — |

---

## 4. Lộ trình triển khai

| Phase | Nội dung | Tiêu chí nghiệm thu |
|---|---|---|
| **P1 — Lõi xác thực & đường truyền** | M1 + M2 + M3; UI badge SPF/DKIM/DMARC + bảng hops + header checks; report + CSV + findings/score cộng dồn; `authSeen` đúng | Unit test raw EML giả lập pass/fail từng cơ chế; smoke `/api/analyze` trả `auth.spf/dkim/dmarc` + `routing.hops`; UI có 3 badge |
| **P2 — Nội dung nguy cơ** | M4 + M5 + M6; bảng URL/attachment/IOC; quarantine; VT/URLhaus key per-user; IOC CSV/STIX | Smoke có EICAR + URL phishing mẫu → verdict đúng; hash đúng; IOC CSV tải được |
| **P3 — Hội nhập SIEM** | M7 exporter + push + docs 3 nền tảng | Export ECS/CEF/STIX hợp lệ (jsonschema check); smoke đẩy thành công tới 1 đích giả lập |

## 5. "Kiến tạo hoàn hảo thêm" (kèm theo từng phase)
- FastAPI tự sinh **OpenAPI `/docs`** — cập nhật mô tả từng endpoint mới (chất liệu tài liệu miễn phí).
- i18n vi/en cho toàn bộ chuỗi UI mới (badge, bảng, nút Export).
- Dockerfile thêm deps mới; hướng dẫn NSSM chạy service trên Windows.
- Enrichment chạy **song song** (async gather) cho nhiều IP/URL — giảm thời gian analyze case nhiều hop.
- Bộ smoke mở rộng: thêm `smoke-forensics.mjs` (P1) + `smoke-threats.mjs` (P2) chạy trọn flow.

## 6. Rủi ro & lưu ý
- **DKIM cần byte gốc chính xác** — đã lưu `evidence/{id}.bin`; MBOX/EML giữ nguyên byte, `.msg` chuyển đổi có thể mất chữ ký (ghi chú trong report).
- Reputation ngoài cần key/mạng — mặc định tắt, bật dần, **không upload file lên VT** (chỉ hash).
- Redirect-following URL tắt mặc định để tránh beacon ra ngoài.
- Syslog 514 yêu cầu admin trên Windows → dùng port cấu hình được/agent.
- Máy hiện Python 3.10.11: lxml/oletools/mail-auth đều có wheel — vẫn khuyến nghị 3.12 như hướng dẫn cũ.

## 7. Cần bạn quyết
1. Triển khai phase nào trước (P1 / P1+P2 / cả 3)?
2. Đã có sẵn key nào chưa: VirusTotal, AbuseIPDB, Safe Browsing, Splunk HEC? (chưa có thì làm stub + UI nhập key sau).
3. SIEM thật nào dùng trước: Wazuh, ELK hay Splunk — để viết docs + sample pipeline đúng nền tảng đó.
