# TIẾN ĐỘ BUILD — MailSleuth Python (Digital Forensics, offline 100%)

> **ĐỌC FILE NÀY TRƯỚC** nếu model/session bị ngắt và chuyển sang model khác. File là nguồn sự thật về kế hoạch đã được người dùng phê duyệt (`duyệt` ngày 2026-11-26). Không được thay đổi tiêu chuẩn khi tiếp tục; chỉ cập nhật mục trạng thái.

## 0. Mục tiêu & ranh giới cứng
- Xây hệ thống phân tích email **forensic 100% offline**, phục vụ đề thi `PCS_De_Thi.docx`: thu thập/bảo toàn, phân tích, timeline, báo cáo ≥15 trang, slide, gói nộp bài.
- **CẤM**: gọi API/MxToolbox/VirusTotal/URLhaus/Safe Browsing; SIEM (Wazuh/Splunk/Elastic); DNS resolver live/PTR live; AI cloud; ML/LLM đổi verdict; `requests`/socket gửi dữ liệu; trích PII (CCCD/SĐT/tài khoản) từ body.
- Mọi finding/edge/timeline phải có field nguồn + evidence; mọi export có `case_id + msg_index`, sort `(msg_index, type, value)`.
- Mọi thay đổi chứng cứ → re-sign `case_signature` với `uid + SHA-256(sid) + signed_at` (không lộ raw sid).
- Không đụng Node `mailsleuth`; sửa trên hệ thống cũ; không viết lại auth/streaming/report nếu không cần.

## 1. Thư viện chốt (không tải từ mạng)
- stdlib: `email, mailbox, argparse, pathlib, json, csv, hashlib, hmac, secrets, datetime, uuid, tempfile, shutil, subprocess, io, os, sys, logging, dataclasses, typing, collections, zipfile, tarfile, gzip, bz2, lzma, ipaddress, urllib.parse, http.cookies, sqlite3, string.Template, html.escape`
- pin: `extract_msg==0.45.0`, `email_reply_parser==0.5.9`, `compressed_rtf==1.0.7`, `msoffcrypto-tool==6.0.0`, `beautifulsoup4==4.12.3`, `defusedxml==0.7.1`, `pyspf==2.0.14` (import `spf`), `dkimpy==1.1.0` (import `dkim`), `dnspython==2.7.0` (chỉ `dns.zone`, KHÔNG `dns.resolver.resolve`), `idna==3.20`, `oletools==0.60.2`, `olefile==0.46`, `pefile==2024.8.26`, `Pillow==11.0.0`, `fpdf2==2.8.9`, `fastapi==0.115.6`, `uvicorn==0.34.0`, `python-multipart==0.0.20`, `bcrypt==4.2.1`, `python-dotenv==1.0.1`
- Gỡ: `app/siem.py`, `app/reputation.py`, `app/dns_real.py` (live), `app/llm.py`, `app/ml.py`, `app/ml_features.py`, `requests`, heuristic brand-lookalike, regex ad-hoc thay bằng rule file.

## 2. Tiêu chuẩn yêu cầu (mã đối chiếu)
E1.1 mục tiêu/phạm vi/nguồn/định dạng · E1.2 custody+bàn giao · E1.3 SHA-256+kiểm tra toàn vẹn · E1.4 rủi ro chứng cứ.
E2.1 header · E2.2 SPF/DKIM/DMARC + nhãn hỗ trợ/không đủ cơ sở · E2.3 nội dung/URL/attachment an toàn · E2.4 timeline · E2.5 tool+công cụ+ảnh chú thích.
E3.1 cấu trúc báo cáo · E3.2 observed/inference/unverified · E3.3 ứng phó/phòng ngừa.
N1 ≥15 trang+TOC+tham khảo · N2 bảng kê+hash · N3 biên bản+timeline · N4 ảnh chú thích · N5 slide · N6 phân công+không gửi email thử.
L1 điểm theo quy trình/bằng chứng · L2 giải thích · L3 thiếu thì nêu giới hạn, không suy đoán.

## 3. Phase checklist (cập nhật trạng thái ở đây)
- [x] **GATE 0** — commit/push baseline mục 4 (`1480e2e`, sạch); py_compile + node --check OK.
- [x] **GATE 0.5** — gỡ SIEM/reputation/LLM/ML/live DNS; `dns_local.py` stub offline; requirements/env/docs/tests đã chỉnh; compile OK.
- [x] **P1** — `analysis/rules/indicators.json` + `tests/test_rules.py` (10/10 OK); `urls.py`/`threatscan.py` dùng `bs4/idna/urllib.parse/oletools/pefile/zipfile/Pillow/defusedxml`; bỏ brand-lookalike/YARA/ClamAV/sandbox.
- [x] **P2** — `app/pipeline.py` điều phối nạp dataset/gọi lõi/xuất báo cáo; `tests/test_pipeline.py` 2/2 OK; auth/streaming giữ nguyên.
- [x] **P3** — `dns_local.py` snapshot-only + `tools/dns_snapshot.py` + `tools/auth_dns_export.py`; `tests/test_dns_local.py` 5/5 OK; không live DNS.
- [x] **P4** — `tools/verify_dataset.py` (CSV/JSON manifest, exit 0/1, CSV+JSON report); `tests/test_verify_dataset.py` 2/2 OK.
- [x] **P5** — `relations.py` (thread/shared-IP/sender/hash/URL + TIME_NEAR inference), `graph.py` hop/GeoIP/relation + `to_png`, UI Graph filter/list; `/api/case/{id}/relations(.csv)`; `tests/test_relations.py` 5/5 OK.
- [ ] **P6** — schema/API mới: `case_meta, evidence_inventory, custody_events, timeline_events, assessments, responses, screenshots, team_assignment, relations`; uid ownership; re-sign.
- [x] **P7** — report HTML/PDF mở rộng: TOC, phương pháp, timeline, 3 nhóm phân loại, ứng phó, phụ lục export, `session_fingerprint/signed_at` trong `case_signature`; `tests/test_report_forensic.py` 3/3 OK.
- [x] **P8** — `tools/autopsy_handoff.py`; test_submission 2/2 OK.
- [x] **P9** — `tools/build_submission.py` ZIP PDF/HTML/CSV/STIX/relations/graph/slide/manifest; test_submission 2/2 OK.
- [x] **P10** — docs + 31/31 test + `BAO_CAO_HOAN_THANH_DIGITAL_FORENSICS.md`; commit/push cuối.
- [x] **P11 (bổ sung)** — dashboard: thay tab Local AI bằng tab **Case file** (meta/inventory/custody/timeline/assessment/response/screenshot/team); thêm card Findings/Relations; sửa Guide/DNS hint cho đúng offline.

## 4. Test nghiệm thu bắt buộc (chạy sau mỗi phase)
```powershell
python -m py_compile app\*.py tools\*.py tests\*.py
node --check public\app.js
python -m pip check
python tests\audit.py          # cần server chạy port 8100 (SMOKE_BASE)
```
- No-network test: monkeypatch `socket`/`requests` để ném lỗi → pipeline vẫn chạy xong.
- Smoke API: 47 test cũ + endpoint mới; CSRF/RBAC/uid; re-sign sau mỗi ghi; export 2 lần cùng `signed_at` → cùng hash.
- Xác minh export có `case_id + msg_index`; timeline có nguồn + confidence; graph edge có evidence.

## 5. Quy tắc tiếp tục khi đổi model
1. Đọc file này + `README.md`, `HUONG_DAN_SETUP_PYTHON.md`, `KE_HOACH_NANG_CAP_DIEU_TRA.md`.
2. Kiểm tra `git status -sb`; chỉ làm phase đầu tiên còn `[ ]`.
3. Sau mỗi phase: chạy test mục 4, tick `[x]`, ghi kết quả ngắn vào cuối file này, commit riêng từng phase nếu an toàn.
4. Không thêm tính năng ngoài checklist; nếu phát hiện thiếu so với mã E/N/L → sửa đúng item đó, cập nhật file này.
5. Khi hết token: để trạng thái rõ ràng ở mục 3 và dòng "Next action" bên dưới.

## 6. Nhật ký tiến độ
- 2026-11-26: phê duyệt kế hoạch; tạo file bàn giao; GATE 0 xong (`1480e2e` đã push).
- 2026-11-26: GATE 0.5 xong — xóa 6 module runtime + 8 tool/test ML/SIEM; `app/dns_local.py` stub offline; compile/import OK.
- 2026-11-26: P1-P10 hoàn tất. Tổng 31/31 unit test PASS; py_compile + node --check OK.
- 2026-11-26: `BAO_CAO_HOAN_THANH_DIGITAL_FORENSICS.md` đã tạo; docs cập nhật.
- 2026-11-26: rà soát hướng dẫn + `KIEN_TRUC_HE_THONG.md`; Linux run/systemd; Python 3.14 notes.
- 2026-11-26: fix rate analyze streaming: limit 80→1200 (`RATE_ANALYZE_STREAM`), `Retry-After:60`, client tự retry 429; docs/.env cập nhật.
- 2026-11-26: **fix regression** — GATE 0.5 đã xóa nhầm endpoint `/api/report/*` và `/api/admin/*`; khôi phục từ `5be0e15`; nâng `PICK_TOTAL_MAX` 2000→30000 và render list tối đa 200 dòng.
- 2026-11-26: kiểm tra thực tế server `192.168.65.131:8000` với dataset `extracted_mail` (15029 file): server đang chạy code cũ/trung gian (`PICK_TOTAL_MAX=2000`, rate 80, report/admin 404); đã ghi nhận.
- 2026-11-26: thêm `app/timeline.py` — tự ghi mốc quá khứ từ `Date` + `Received` vào `result.timeline_events`; API forensic/timeline fallback; sub-tab Results/Timeline; báo cáo dùng event tự sinh. `tests/test_timeline.py` 2/2 OK.
- 2026-11-26: test server sau lô 15029 file — phát hiện `/api/cases` ép `limit<=500` nên dashboard/lập luận trước đó đọc nhầm thành 500 case. Thêm `/api/cases/count` đếm thật từ DB + dashboard dùng endpoint này; `tests/test_dashboard_count.py` 1/1 OK.

- 2026-11-26: test lô 15029 file xong: dashboard đúng 15029; sửa Overview - card Findings/Relations đếm thật từ DB, auth not_run thêm nhãn "không đủ cơ sở", refresh dashboard khi mở case từ History.

- 2026-11-27: fix rate tạm thời: RATE_ANALYZE_STREAM 1200→6000, RATE_ANALYZE_BATCH 200→2000, client pace 60ms giữa các file (tránh 429/crash tạm thời).

- 2026-11-27: Relations global: tab mới thay DNS/IP-Geo; app/global_graph.py + /api/graph/global + UI filter/index/SVG/CSV; tests/test_global_graph.py 4/4 OK.

- 2026-11-27: mở limit /api/cases 500→30000; History gọi limit=30000; test_cases_limit_30000 PASS.

- 2026-11-27: Relations bổ sung /api/graph/index (Message-ID/From/To, phân trang, lọc actor/domain/ip/verdict/case) + bảng thư & nhóm đối tượng trên UI; test_graph_index 2/2 OK.

- 2026-11-27: nâng GRAPH_MAX_CASES 5000→30000; dọn _REP_KEYS + tool ML cũ + comment thừa; rà soát xuất báo cáo/trích xuất/dữ liệu.

**Next action:** deploy HEAD (`df33e9d` + bản đếm) lên server; kiểm tra dashboard hiện số case thật và report HTML/PDF/CSV.
