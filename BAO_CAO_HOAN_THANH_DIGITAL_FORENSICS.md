# BÁO CÁO HOÀN THÀNH — MailSleuth Python (Digital Forensics)

- Ngày hoàn thành: 2026-11-26
- Tiêu chuẩn: `TIEN_DO_BUILD.md` (đã được phê duyệt `duyệt`)
- Đề tham chiếu: `PCS_De_Thi.docx` (thông tin cá nhân trong đề đã che)
- Phạm vi: **offline 100%**, không API/mạng; loại bỏ MxToolbox, SIEM, reputation, DNS live, AI/ML đổi verdict.

## 1. Đối chiếu yêu cầu → module → kiểm chứng

| Mã | Yêu cầu | Module/API | Test |
|---|---|---|---|
| E1.1 | Mục tiêu/phạm vi/nguồn/định dạng | `case_meta`, `pipeline.iter_dataset`, `tools/pst_extract.py`, Autopsy handoff | test_pipeline, test_submission |
| E1.2 | Bảo quản & bàn giao | `custody_events`, `tools/autopsy_handoff.py` | test_forensic_api, test_submission |
| E1.3 | SHA-256 & toàn vẹn | `case_signature`, `tools/verify_dataset.py`, manifest | test_report_forensic, test_verify_dataset |
| E1.4 | Rủi ro chứng cứ | `report._forensic_blocks` (mục giới hạn/rủi ro) | test_report_forensic |
| E2.1 | Header | `headers.py` | P1 smoke + import |
| E2.2 | SPF/DKIM/DMARC + hỗ trợ/không đủ cơ sở | `dns_local.py`, `authcheck.py`, `auth_dns_export.py` | test_dns_local |
| E2.3 | Nội dung/URL/attachment an toàn | `analysis/rules`, `urls.py`, `threatscan.py`, `bodies.py` | test_rules (10) |
| E2.4 | Timeline | `timeline_events`, `report` mục Timeline, `graph.OCCURRED_AT` | test_report_forensic |
| E2.5 | Công cụ + ảnh chú thích | `screenshots` API, `build_submission` | test_submission |
| E3.1 | Cấu trúc báo cáo ≥15 trang + TOC | `report.py` (20 mục) | test_report_forensic |
| E3.2 | Quan sát/suy luận/chưa đủ cơ sở | `assessments`, `report` mục 16 | test_forensic_api, test_report_forensic |
| E3.3 | Ứng phó/phòng ngừa | `response_actions`, `report` mục 17 | test_report_forensic |
| N1 | TOC/kết luận/tham khảo/≥15 trang | `report.py` | test_report_forensic |
| N2 | Bảng kê + hash + index | `evidence_inventory`, `ioc.py` (case_id+msg_index) | test_forensic_api |
| N3 | Biên bản + timeline export | `custody_events`, `timeline.csv` | test_submission |
| N4 | Ảnh chú thích | `screenshots`, ZIP | test_submission |
| N5 | Slide | `tools/build_submission.py` → `slide.html` | test_submission |
| N6 | Phân công/giới hạn | `team_assignment`, docs | test_forensic_api |
| L1-L3 | Quy trình/bằng chứng/không suy đoán | rule file + evidence_refs +_limits | test_rules |

## 2. Kết quả test

| Bộ test | Kết quả |
|---|---|
| `tests/test_rules.py` | 10/10 PASS |
| `tests/test_pipeline.py` | 2/2 PASS |
| `tests/test_dns_local.py` | 5/5 PASS |
| `tests/test_verify_dataset.py` | 2/2 PASS |
| `tests/test_relations.py` | 5/5 PASS |
| `tests/test_forensic_api.py` | 2/2 PASS |
| `tests/test_report_forensic.py` | 3/3 PASS |
| `tests/test_submission.py` | 2/2 PASS |
| **Tổng** | **31/31 PASS** |
| `py_compile` (app/analysis/tools/tests) | OK |
| `node --check public/app.js` | OK |

## 3. Kiểm tra offline

- Không import/gọi: `requests`, `siem`, `reputation`, `dns_real`, `llm`, `ml`, YARA/ClamAV/sandbox HTTP.
- DNS: `dns.zone.from_file` + snapshot JSON; `Authentication-Results` trong header là nguồn chính; thiếu → `not_run`.
- Không brand-lookalike/score cảm tính; mọi finding có `source_field`.
- Chữ ký: SHA-256 trên facts + `uid` + `SHA-256(sid)` + `signed_at` (không lộ raw session).

## 4. Giới hạn (phải ghi trong báo cáo điều tra)
- GeoLite2 cho vị trí gần đúng, không phản ánh quá khứ nếu dùng DB hiện tại.
- Không xác minh được IP/danh tính người gửi khi header Received bị thiếu → ghi rõ, không suy đoán.
- DKIM có thể không verify được nếu body/MIME đã thay đổi sau khi nhận.
- Autopsy/FTK là bước ngoài: hệ thống chỉ đóng gói chứng cứ + hướng dẫn, không tự chạy GUI.
- `TIME_NEAR` và map mũi tên là lớp suy luận/phụ (nét đứt), mặc định tắt trong kết luận.

## 5. Cách dùng nhanh

```powershell
# import snapshot DNS (nếu có)
python tools/dns_snapshot.py --zone snapshot.zone --origin example.com --out data/dns_snapshot.json
# kiểm dataset gốc
python tools/verify_dataset.py --manifest manifest.csv --root <thu_muc_dataset> --out ./verify
# chạy API
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
# xuất gói nộp bài / bàn giao Autopsy
python tools/build_submission.py <case_id> ./submission_<case_id>
python tools/autopsy_handoff.py <case_id> ./autopsy_<case_id>
```

## 6. Dashboard / giao diện (cập nhật bổ sung)
- Tab **Case file** thay tab Local AI cũ: xem meta/inventory/custody/timeline/assessment/response/screenshot/team qua API `/api/case/{id}/forensic/{kind}`.
- Dashboard thêm card **Findings** và **Relations**.
- Tab Results/Graph thêm bộ lọc quan hệ + danh sách cạnh có `evidence` + link tải `relations.csv`.
- Guide/DNS hint đã sửa để phản ánh chế độ offline (không `LIVE_DNS`, không AI cloud).

## 7. Xử lý lỗi rate khi analyze lô lớn
- `/api/analyze/stream` nhận mỗi file = 1 request; giới hạn tăng 80 → **1200 request/phút/IP** (`RATE_ANALYZE_STREAM`, cấu hình được).
- Server trả `429 {"error":"rate"}` kèm `Retry-After: 60`; client tự đợi và thử lại tối đa 6 lần, vẫn giữ Pause/Stop/Cancel.
- Reverse proxy/nginx nếu có `limit_req` riêng phải đối chiếu cùng giá trị này.

## 8. Tài liệu kiến trúc mới
`KIEN_TRUC_HE_THONG.md` — 8 sơ đồ Mermaid + giải thích chi tiết: thành phần tổng thể, luồng phân tích, schema 8 bảng pháp chứng, graph quan hệ, SPF/DKIM/DMARC/DNS offline, báo cáo & chữ ký, ranh giới bàn giao Autopsy/tool local, bản đồ tập tin và giới hạn. `HUONG_DAN_SETUP_PYTHON.md` đã rà soát lại (bỏ mọi tham chiếu `LIVE_DNS=1`, Local AI, SIEM).

## 9. Sự cố phát hiện khi kiểm tra server thực (192.168.65.131)
- Server đang chạy **code cũ/trung gian**: `PICK_TOTAL_MAX=2000`, rate stream 80/phút, `app.js` không có retry 429, `/api/report/*` và `/api/admin/*` trả 404 (bị xóa nhầm ở GATE 0.5).
- Dataset `extracted_mail` có **15.029 file .eml / 394,1 MB**; UI cũ chặn ở 2000 file → import không đủ. Lịch sử chỉ có 80 case, dừng quanh file 146/147 do rate 80.
- Đã sửa trong repo: khôi phục report/admin, nâng giới hạn 30.000 file, render danh sách tối đa 200 dòng, rate 1200 + Retry-After + client retry. **Cần deploy HEAD lên server và restart** thì mới có hiệu lực.

## 10. Timeline thời gian quá khứ từ dataset
- `app/timeline.py` tự trích `Date` và từng header `Received` (kèm `delayMs`) thành `timeline_events` với `source_field` + `confidence`.
- Thiếu mốc → ghi `unverified`, không suy đoán; không lấy thời gian từ tên file/thứ tự file.
- Hiển thị: sub-tab **Results → Timeline**, tab **Case file → timeline**, báo cáo mục **Timeline sự kiện** (PDF/HTML), export `timeline.csv`.

## 11. Kết luận
Hệ thống đã đáp ứng toàn bộ mã yêu cầu E1.1–E3.3, N1–N6, L1–L3 theo tiêu chuẩn đã chốt; mọi phát hiện đều truy được về chứng cứ gốc và được ký SHA-256 gắn phiên người dùng. Không có kết nối mạng trong toàn bộ luồng phân tích và xuất báo cáo.
