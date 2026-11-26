# MailSleuth Python (`mailsleuth_python`)

MailSleuth Python là bản **FastAPI** để phân tích/pháp chứng email (song song với bản Node gốc trong `../mailsleuth`, không thay thế). Hệ thống tập trung vào phân tích header/xác thực thư/định tuyến/URL/đính kèm, trích xuất chứng cứ, báo cáo có **chữ ký toàn vẹn SHA-256 (mộc số)**, và vận hành **offline-safe** (không bản đồ ngoài, AI chỉ local).

> Trạng thái: mã nguồn hiện tại trên nhánh `main` (đã nâng cấp streaming, quản trị/phân quyền, URL intel, đồ thị chứng cứ, map nội bộ, báo cáo đa ngôn ngữ).

## Tính năng chính

- **Định dạng nhập**: `.eml`, `.emlx`, `.mht/.mhtml`, `.msg`, `.mbox/.mbx`, `.txt` và cây thư mục **Maildir** (phát hiện theo nội dung, kể cả file không phần mở rộng). `PST/OST` **không** được phân tích trực tiếp trên server: điều tra viên trích xuất ra EML/MBOX/Maildir bằng công cụ ngoài (readpst/Outlook) rồi nạp vào hệ thống.
- **Streaming từng tệp** (`POST /api/analyze/stream`, NDJSON): tiến độ theo giai đoạn thực, hiển thị 3 dòng trạng thái + thanh biên độ + %, **Pause** (dừng sau tệp hiện tại), **Stop** (dừng lô nhưng giữ kết quả đã xong), **Cancel** (hủy và bỏ kết quả lô); lỗi dừng đúng tệp/vị trí và báo rõ.
- **Nền tảng & client**: nhận diện/ghi nhận nền tảng Windows/Linux (chọn hoặc auto) và client/nguồn (Outlook, Exchange, Thunderbird, Apple Mail, Gmail, Maildir, mbox, RFC822/EML...).
- **Báo cáo & toàn vẹn**: HTML/PDF/CSV/JSON theo ngôn ngữ `en/vi`; thống kê IP, DNS, SPF/DKIM/DMARC, routing, URL, IOC, đính kèm, đồ thị; **chữ ký SHA-256** trên dữ liệu vụ việc (fingerprint tái lập được) + **mộc số/con dấu** góc dưới bên phải; xác minh `GET /api/report/{id}/verify`. CSV trung hòa công thức (chống CSV injection).
- **URL intel (offline/local)**: xuất URL theo target/nguồn; nhập CSV/JSON/XML/TXT để **tái phân tích một lần** bằng rule/mẫu local và gộp verdict/rủi ro/lý do vào vụ việc (`/api/urls/import`), sau đó tái ký.
- **Đồ thị chứng cứ**: sơ đồ liên kết thực thể (message, tác nhân/địa chỉ, domain, IP, URL, tệp đính kèm/hash) dựng **chỉ từ chứng cứ** có trong kết quả, không suy diễn (`/api/case/{id}/graph`, `.svg`).
- **Bản đồ nội bộ**: bản đồ lược đồ (schematic) vẽ cục bộ từ tọa độ GeoLite2 của IP/Received — **không tile/không dịch vụ bản đồ ngoài**.
- **Tài khoản & phân quyền**: user (bcrypt, uid hex32 bất biến, SĐT, Key ID khôi phục một lần, đổi tên bằng token một lần do admin cấp); admin đăng nhập bằng mật khẩu, khóa/verifier tạo offline bằng `tools/admin_keygen.py` (PBKDF2-HMAC-SHA256 từ `password + SHA-256(username|CCCD)`, không lưu CCCD); tab Administration/Logs chỉ admin; chống leo thang ngang/dọc, CSRF cho thao tác ghi.

## Sơ đồ kiến trúc

```mermaid
flowchart TB
  subgraph Client["Trình duyệt (SPA - public/index.html, app.js, app.css)"]
    Stream[Streaming NDJSON client\n3 dòng + biên độ + % | Pause/Stop/Cancel]
    View[Results: Overview/Messages/URLs/Graph\nHeader/Body | Report/Verify | Export/Import]
  end

  subgraph API["FastAPI (app/main.py)"]
    Sec[Auth + session/CSRF + RBAC\nownership theo cases.uid]
    Analyze[/api/analyze/stream + /api/analyze/]
    Case[/api/cases, /api/case/*, /api/report/*, /api/urls/*, /api/map/]
  end

  subgraph Core["Pipeline & mô-đun (app/)"]
    Parse[parsers/bodies: EML/MSG/MBOX/Maildir/TXT\nclient & platform]
    Forensic[headers, authcheck, routing, urls, attachments, ioc]
    Intel[urlintel: rule local, import/merge\nCSV formula-safe]
    Viz[graph: entity/edge từ chứng cứ\nmapgen: schematic nội bộ]
    Rep[report: HTML/PDF/CSV/JSON\ncase_signature SHA-256 + seal]
  end

  subgraph Store["Lưu trữ (DATA_DIR)"]
    DB[(SQLite WAL: users/cases/audit/kv\nsessions/session_signatures/url_imports)]
    FS[(evidence/*.bin, messages/<case>/\nquarantine/, uploads/tmp/reports)]
    Geo[(GeoLite2 *.mmdb - local)]
  end

  Client <-->|HTTPS/HTTP + cookie sid + x-csrf| API
  Analyze --> Parse --> Forensic --> Enrich
  Forensic --> Intel --> Rep
  Enrich --> Viz --> Rep
  API <--> Core
  Core <--> DB
  Core <--> FS
  Enrich --> Geo
```

## Luồng xử lý (tóm tắt)

```mermaid
flowchart LR
  A[Chọn tệp/thư mục\n+ nền tảng] --> B[Preflight & upload tuần tự]
  B --> C[/analyze/stream: receive→parse→analyze→store/]
  C --> D[Trích header/body/đính kèm/URL/IP]
  D --> E[Header/Auth/DNS Routing URL Attachment IOC\n+ điểm/verdict]
  E --> F[GeoIP local + map nội bộ\n+ đồ thị thực thể]
  F --> G[Ký SHA-256 + lưu case (uid)\nevidence + bodies]
  G --> H[UI: Results/Messages/URLs/Graph\nReport HTML/PDF/CSV + Verify]
  H --> I[Export/Import URL\nrule local → merge → re-sign]
```

> Mô hình dữ liệu logic: **vụ việc/case** (sở hữu `uid`) → **messages** (nội dung/header/body, lưu `data/messages/<case>/`) → **entities** (actor/domain/IP/URL/attachment/hash) → **links/quan hệ** (CONTAINS/SENT/ORIGIN_IP/CONTAINS_URL/HAS_ATTACHMENT…), thể hiện qua `result.graph` và `/api/case/{id}/graph(.svg)`.

## Cài đặt nhanh

Yêu cầu: Python 3.10+ (khuyến nghị 3.12). GeoLite2 đặt tại `GEOIP_DIR` (mặc định `../mailsleuth/geoip`).

```powershell
cd "D:\Digital Forensics\mailsleuth_python"
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Khởi tạo quản trị viên (khuyến nghị, offline — **không** lưu CCCD): 

```powershell
python tools/admin_keygen.py --user admin --cccd <CCCD> --write-db --key-out .\admin.key
```

Chạy server:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
# http://127.0.0.1:8000
```

> `ADMIN_PASS` trong `.env` chỉ là bootstrap legacy/dev (nếu chưa có admin). Nên enroll bằng `admin_keygen.py` và bỏ/không dùng `ADMIN_PASS` ở môi trường thật.

## Biến môi trường (chính)

Xem đầy đủ trong `.env.example`.

| Biến | Mặc định | Ý nghĩa |
|---|---:|---|
| `PORT` | 8000 | Cổng HTTP |
| `DATA_DIR` | ./data | DB, evidence, messages, quarantine, uploads/tmp/reports |
| `GEOIP_DIR` | ../mailsleuth/geoip | Thư mục GeoLite2 `.mmdb` |
| `DNS_SNAPSHOT` | data/dns_snapshot.json | Snapshot DNS local cho SPF/DKIM/DMARC lịch sử; không live |
| `COOKIE_SECURE` | 0 | Đặt `1` khi chạy HTTPS |
| `THREATSCAN_ENABLED` | 1 | Bật quét nội dung độc hại offline (heuristic + engine local nếu có) |
| `THREATSCAN_TIMEOUT` | 15 | Timeout (giây) cho engine/tool quét |
| `THREATSCAN_MAX_BYTES` | 26214400 | Giới hạn byte quét mỗi tệp đính kèm |
| `SANDBOX_URL` | (rỗng) | Adapter sandbox cục bộ (chỉ localhost/private) |
| `BODY_MAX_BYTES` / `BODY_TOTAL_BYTES` | 512KB / 32MB | Giới hạn lưu body/thu và/vụ việc |

## API chính (rút gọn)

| Method | Path | Mô tả |
|---|---|---|
| POST | `/api/register`, `/api/login`, `/api/recover` | Đăng ký/đăng nhập (username|SĐT|uid)/khôi phục bằng Key ID |
| GET/POST | `/api/profile*`, `/api/profile/rename` | Hồ sơ, avatar, đổi tên (cần token một lần) |
| POST | `/api/analyze/stream` | Phân tích 1 tệp, trả NDJSON tiến độ + kết quả |
| POST | `/api/analyze` | Phân tích nhiều tệp (batch) |
| GET | `/api/cases` | Lịch sử vụ việc (theo sở hữu uid; admin xem tất cả) |
| GET | `/api/case/{id}/message/{idx}` | Header/body đã lưu/khử nguy hiểm |
| GET | `/api/case/{id}/urls(.csv)` | URL theo target + verdict |
| POST | `/api/urls/import` | Import & tái phân tích URL local, merge vào case, tái ký |
| GET | `/api/case/{id}/graph(.svg)` | Đồ thị thực thể từ chứng cứ |
| GET | `/api/report/{id}` (+`.pdf`,`.csv`), `/verify` | Báo cáo & xác minh chữ ký SHA-256 |
| POST | `/api/dns`, `/api/ip`, GET `/api/map` | Tra cứu/DNS/Geo (local) & bản đồ nội bộ |
| GET/POST | `/api/admin/*` | Quản trị (admin): users/stats/logs/sessions, cấp token đổi tên |

## Kiểm thử & kiểm tra nhanh

```powershell
python -m py_compile app\main.py app\report.py app\urlintel.py app\parsers.py app\db.py app\auth.py app\mapgen.py app\graph.py
node --check public\app.js
# Audit/script có sẵn trong tests/, tools/
```

## Bảo mật & ghi chú

- Mặc định **offline 100%**: không DNS live, không bản đồ/AI ngoài. Key/secret lưu per-user trong `kv`, không echo/log; CCCD **không** được lưu.
- Báo cáo trả về kèm CSP chặt (`default-src 'none'`), `nosniff`, `no-referrer`, `no-store`. HTML body hiển thị qua sanitize + sandbox.
- Chữ ký SHA-256 là **dấu vân tay toàn vẹn dữ liệu** (tái lập/kiểm chứng), không phải chữ ký số khóa bí mật.

Xem hướng dẫn chi tiết: `HUONG_DAN_SETUP_PYTHON.md`. Kế hoạch & trạng thái: `KE_HOACH_NANG_CAP_DIEU_TRA.md`.

## Chế độ forensic offline (bắt buộc)
- Không gọi API/MxToolbox/VirusTotal/SIEM; không DNS live/PTR live; không AI cloud; không ML đổi verdict.
- SPF/DKIM/DMARC và DNS lịch sử đọc từ `Authentication-Results` trong header, có thể tính lại bằng snapshot local (`pyspf`, `dkimpy`, `dnspython` chế độ `dns.zone`).
- Mọi thay đổi chứng cứ đều re-sign SHA-256 theo phiên người dùng; export có `case_id + msg_index`.
- Chi tiết tiêu chuẩn build/test: `TIEN_DO_BUILD.md`.


## Trạng thái cuối (đã build 2026-11-26)
- Forensic offline 100%: không API/MxToolbox/VirusTotal, không SIEM, không DNS live, không AI/ML đổi verdict.
- `analysis/rules/` + `app/urls.py`, `app/threatscan.py`: rule-driven, có `tests/test_rules.py`.
- `app/pipeline.py`: điều phối nạp dataset/xuất báo cáo.
- `app/dns_local.py` + `tools/dns_snapshot.py` + `tools/auth_dns_export.py`: SPF/DKIM/DMARC/DNS từ snapshot/header AR.
- `tools/verify_dataset.py`: đối chiếu SHA-256 với dataset gốc (exit 0/1).
- `app/relations.py` + `app/graph.py` + UI Graph: quan hệ message↔message có evidence, hop/GeoIP, filter, xuất CSV/PNG.
- Schema/API pháp chứng + re-sign SHA-256 theo `uid + session_fp + signed_at`.
- Báo cáo HTML/PDF: TOC, timeline, 3 nhóm quan sát/suy luận/chưa đủ cơ sở, ứng phó, phụ lục export, seal SHA-256.
- `tools/autopsy_handoff.py` + `tools/build_submission.py`: gói bàn giao Autopsy và ZIP nộp bài.
- Chi tiết tiêu chuẩn/test: `TIEN_DO_BUILD.md`, `BAO_CAO_HOAN_THANH_DIGITAL_FORENSICS.md`.
