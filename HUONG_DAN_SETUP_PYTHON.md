# Hướng dẫn cài đặt & vận hành — MailSleuth Python

Tài liệu này mô tả cách triển khai, cấu hình, sử dụng và hiểu kiến trúc/luồng dữ liệu của bản **FastAPI** trong `mailsleuth_python/` (song song với bản Node gốc, dữ liệu tách biệt qua `DATA_DIR`).

---

## 1. Yêu cầu & cài đặt

### 1.1 Yêu cầu
- **Python** 3.10+ (khuyến nghị 3.12). `pip` ≥ 23.
- **Node.js** (tùy chọn, chỉ để kiểm tra cú pháp frontend `node --check public/app.js`).
- **GeoLite2** (`.mmdb`) trong `GEOIP_DIR` để tra vị trí IP nội bộ (không gọi dịch vụ ngoài).
- **Trình duyệt** hiện đại (Chromium/Edge/Firefox). Chức năng chọn vị trí lưu/mở thư mục dùng File System Access API khi có; nếu không sẽ fallback tải xuống/chọn tệp.

> `PST/OST` không được server phân tích trực tiếp. Hãy trích xuất sang `.eml/.mbox/Maildir` bằng `readpst` (libpst), Outlook hoặc công cụ tương đương, sau đó nạp kết quả vào hệ thống.

### 1.2 Cài đặt
```powershell
cd "D:\Digital Forensics\mailsleuth_python"
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```
(Linux/macOS: `python3 -m venv .venv && source .venv/bin/activate`, `cp .env.example .env`.)

Sửa `.env` nếu cần (xem mục 3). Tạo thư mục dữ liệu sẽ được tự khởi tạo khi chạy lần đầu (`DATA_DIR`: `uploads/`, `evidence/`, `messages/`, `tmp/`, `reports/`, `app.db`).

### 1.3 Khởi tạo tài khoản quản trị (khuyến nghị)

Quản trị viên dùng cơ chế **khóa/verifier offline**: dẫn xuất bằng **PBKDF2-HMAC-SHA256 (600.000 vòng)** từ `password + SHA-256("mailsleuth-admin-v1|<username>|<CCCD số>")`. Chỉ lưu `salt` (băm từ CCCD), số vòng lặp và `verifier` của khóa dẫn xuất — **không lưu CCCD, không lưu mật khẩu**. Khóa khôi phục (`MSK1-...`) chỉ hiển thị/ghi ra file một lần.

```powershell
# Lần đầu / enroll (yêu cầu CCCD)
python tools/admin_keygen.py --user admin --cccd 001203004567 --write-db --key-out .\admin.key

# Đổi mật khẩu (dùng salt đã lưu, không cần nhập lại CCCD)
python tools/admin_keygen.py --user admin --password --write-db --key-out .\admin.key
```
- Chạy trên máy chủ, không chạy trên máy chia sẻ; bảo quản `admin.key` ngoại tuyến rồi xóa bản tạm.
- Đăng nhập admin bằng **mật khẩu**; khóa `MSK1-...` dùng như bí mật khôi phục/xác thực thay thế theo cơ chế đã lập.
- `ADMIN_PASS` trong `.env` chỉ là **bootstrap legacy/dev** khi chưa có admin; sau khi enroll bằng keygen nên gỡ/không dùng ở môi trường thật.

### 1.4 Chạy server
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Mở `http://127.0.0.1:8000`. (Chạy song song bản Node ở cổng khác nếu cần; `DATA_DIR` phải tách biệt.)

### 1.5 Python 3.14 & ghi chú Linux

**Python 3.14:** `requirements.txt` đã có nhánh `python_version >= "3.13"` (FastAPI ≥0.120 dùng `lifespan`, Pydantic ≥2.12, Pillow ≥11.3, bcrypt ≥5). Mã nguồn không dùng module bị loại bỏ ở 3.13/3.14 (`imghdr`, `cgi`, `distutils`, `telnetlib`, `on_event`). Tuy nhiên **chưa chạy smoke thực tế trên 3.14** — khuyến nghị tạo venv riêng và chạy lại 8 bộ test trước khi đưa vào production:

```bash
python3.14 -m venv .venv314
. .venv314/bin/activate
pip install -r requirements.txt
python -m pip check
python tests/test_rules.py && python tests/test_forensic_api.py && python tests/test_report_forensic.py
```

Lưu ý: `maxminddb` (dependency của `geoip2`) có phần mở rộng C. Nếu wheel cho 3.14 chưa có, pip sẽ build từ source → cần `build-essential`/`python3.14-dev`. Nếu gặp lỗi, dùng Python 3.12/3.13 (đã test) thay vì ép 3.14.

**Linux:**
- Cài font Unicode cho PDF/m bản đồ: `sudo apt-get install -y fonts-dejavu-core` (hoặc `dejavu-sans-fonts` trên RHEL). `report.py` tìm `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf` và `DejaVuSans-Bold.ttf`; nếu thiếu, PDF rơi về Helvetica (mất dấu tiếng Việt). Có thể copy font vào `app/assets/DejaVuSans.ttf` làm fallback.
- Đặt locale UTF-8: `export LANG=C.UTF-8 LC_ALL=C.UTF-8` để tránh lỗi khi đọc/ghi tên file và báo cáo tiếng Việt.
- Trong `.env` dùng **đường dẫn tuyệt đối**: `DATA_DIR=/var/lib/mailsleuth/data`, `GEOIP_DIR=/opt/mailsleuth/geoip` (file `GeoLite2-*.mmdb` phải có). Tạo thư mục và cấp quyền ghi cho user chạy service; `evidence/*.bin` được chmod 0444, `quarantine/` chỉ đọc.
- Chạy bằng user chuyên dụng, **không chạy bằng root**; bind `127.0.0.1`, đặt nginx/Apachereverse proxy nếu cần truy cập từ xa.
- Khi chạy HTTPS: `COOKIE_SECURE=1`, `TRUST_PROXY=1`; nếu cookie Secure mà vẫn dùng HTTP thì không đăng nhập được.
- PST/OST: `tools/pst_extract.py` trên Linux cần `pypff`/`libpff` cài riêng (không nằm trong requirements). Nếu không có, dùng `python tools/autopsy_handoff.py <case_id> <dir>` để giao cho Autopsy/FTK Imager.
- Kiểm tra sau cài đặt: `node --check public/app.js` (tùy chọn), `python -m py_compile` toàn bộ `app/ analysis/ tools/ tests/`, rồi chạy 8 bộ test như mục 8.


---

## 2. Sơ đồ kiến trúc hệ thống

```mermaid
flowchart TB
  subgraph Client["Trình duyệt - SPA (public/)"]
    UI[index.html + app.js + app.css + fx.js]
    UI --> T1[Analysis: chọn tệp/thư mục, nền tảng Win/Linux\nstream 3 dòng + biên độ + %\nPause/Stop/Cancel]
    UI --> T2[Results: Overview/Messages/URLs/Graph\nheader/body, export/import, verify]
    UI --> T4[Administration / Logs (chỉ ADMIN)]
  end

  subgraph Server["FastAPI - app/main.py"]
    MW[Middleware: session cookie, CSRF, rate-limit, headers]
    API1[Auth/Profile: register/login/recover/rename\nRBAC + ownership theo cases.uid]
    API2[Analyze: /api/analyze/stream NDJSON\n/api/analyze batch]
    API3[Case/Report: cases, message, urls, graph, map\nreport html/pdf/csv/json, verify]
  end

  subgraph Modules["Mô-đun xử lý (app/)"]
    P[parsers.py, bodies.py\nEML/MSG/MBOX/Maildir/TXT\nnhận diện client & platform]
    F[headers.py, authcheck.py, routing.py\nurls.py, attachments.py, ioc.py]
    U[urlintel.py\nparse CSV/JSON/XML/TXT\nrule local, merge, CSV-safe]
    G[graph.py\nthực thể/cạnh từ chứng cứ]
    M[mapgen.py\nbản đồ lược đồ nội bộ]
    R[report.py\nHTML/PDF/CSV 20 mục, seal + case_signature SHA-256]\n    PIPE[pipeline.py\nđiều phối nạp dataset/xuất]\n    REL[relations.py + graph.py\ncạnh message↔message có evidence]
  end

  subgraph Data["DATA_DIR"]
    DB[(app.db SQLite WAL)\nusers, cases, audit, kv\nsessions, session_signatures, url_imports]
    EV[evidence/<case>.bin (read-only)]
    MS[messages/<case>/*.hdr|txt|html|json]
    Q[quarantine/]
    UP[uploads/tmp/reports]
  end

  subgraph Local["Tài nguyên cục bộ (tùy chọn)"]
    GEO[(GeoLite2 *.mmdb)]
    SNAP[(DNS snapshot local\nzone/JSON do user cấp)]
  end

  Client <-->|cookie sid + x-csrf| Server
  API2 --> P --> F --> E
  F --> U --> R
  E --> G --> R
  E --> M
  Server <--> Modules
  Modules <--> DB
  Modules <--> EV
  Modules <--> MS
  Modules <--> Q
  E --> GEO
  E --> SNAP
```


---

## 3. Luồng xử lý & luồng dữ liệu

### 3.1 Luồng phân tích (streaming)

```mermaid
sequenceDiagram
  autonumber
  participant U as Người dùng (UI)
  participant S as /api/analyze/stream
  participant P as Parsers/Bodies
  participant A as Forensic modules
  participant X as Graph/Map/Report-sign
  participant D as DB + FS (DATA_DIR)

  U->>S: POST 1 tệp (sequential) + platform/lang
  S-->>U: NDJSON stage receive/parse/analyze (tiến độ thực)
  S->>P: đọc & nhận diện định dạng/client/platform
  P->>A: header, body, URL, IP, attachment, hash
  A->>A: headers/auth/routing/urls/attachments/ioc + score/verdict
  A->>X: geo local, entity graph, url stats, schematic map
  X->>D: lưu evidence.bin, messages/<case>/, case JSON
  X->>D: case_signature SHA-256 (gắn seal) theo uid sở hữu
  S-->>U: NDJSON result (hoặc error đúng tệp)
  U->>U: chuyển tab Results, hiển thị Overview/Messages/URLs/Graph
```

- **Pause**: dừng sau tệp hiện tại; **Stop**: hủy phần còn lại nhưng giữ kết quả đã hoàn tất; **Cancel**: hủy và bỏ kết quả của lượt chạy.
- Mỗi tệp một request streaming → lỗi dừng đúng tệp và báo rõ, có thể xử lý rồi chạy tiếp tệp sau.

### 3.2 Luồng dữ liệu vụ việc (case → messages → entities → links)

```mermaid
flowchart TB
  Inv[Case/Vụ việc\nid, uid sở hữu bất biến, sig SHA-256, platform, lang] --> Msg[Messages\nindex, client/format, from/to/subject/date\nheaders, body ref, originIPs, auth, verdict]
  Msg --> Ent[Entities (trích từ chứng cứ)\nactor/address, domain, ip, url, attachment/hash]
  Ent --> Lnk[Links/Relations\nCONTAINS, SENT, TO/CC/BCC\nUSES_DOMAIN, ORIGIN_IP\nCONTAINS_URL, HAS_ATTACHMENT]
  Lnk --> Graph[Đồ thị /api/case/{id}/graph(.svg)\ncạnh từ chứng cứ; TIME_NEAR dán nhãn suy luận]
  Msg --> Rel[app/relations.py\nTHREAD_REPLY / SHARES_* có evidence]
  Rel --> TL[timeline_events + báo cáo mục Timeline]
  Msg --> Store1[(cases.result JSON trong DB)]
  Msg --> Store2[(messages/<case>/idx.hdr|txt|html|json)]
  Inv --> Store3[(evidence/<case>.bin, read-only)]
```

- **Sở hữu** gắn với `users.uid` (hex32, bất biến). Đổi tên tài khoản không ghi đè `cases.user` và không làm mất quyền truy cập/lịch sử/chữ ký của vụ việc đã ký.

### 3.3 Luồng URL import & tái phân tích

```mermaid
flowchart LR
  A[Export URL CSV theo case] --> B[Phân tích ngoài (tùy chọn)]
  B --> C[Import CSV/JSON/XML/TXT]
  C --> D[Parse & chuẩn hóa entry]
  D --> E[Re-analyze bằng rule/mẫu local\n(offline, một lần)]
  E --> F[Merge theo URL: verdict/risk/reasons/source/target]
  F --> G[Cập nhật case + urlImports + tái ký SHA-256]
  G --> H[Verify/Report phản ánh kết quả mới]
```

### 3.4 Luồng báo cáo & xác minh chữ ký

```mermaid
flowchart LR
  R[case row + result JSON + uid + SHA-256(sid) + signed_at] --> S[case_signature: SHA-256 canonical facts]
  S --> H[HTML: seal SVG góc dưới phải + CSP chặt]
  S --> P[PDF: vẽ seal]
  S --> C[CSV/JSON theo ngôn ngữ]
  S --> V[/api/report/{id}/verify\nrecompute & compare]
```

Chữ ký là **fingerprint toàn vẹn** (deterministic) để kiểm tra dữ liệu vụ việc không bị thay đổi; không phải chữ ký số bằng khóa bí mật/PKI.

---

## 4. Cấu hình (.env)

| Biến | Mặc định | Mô tả |
|---|---:|---|
| `PORT` | 8000 | Cổng lắng nghe |
| `DATA_DIR` | ./data | Dữ liệu runtime (DB, evidence, messages, quarantine, uploads/tmp/reports) |
| `GEOIP_DIR` | ../mailsleuth/geoip | GeoLite2 (`GeoLite2-*.mmdb`) |
| `DNS_SNAPSHOT` | data/dns_snapshot.json | Snapshot DNS local (zone/JSON). Không có → SPF/DKIM/DMARC `not_run` |
| `GEO_IPS` | 20 | Giới hạn IP tra GeoIP |
| `COOKIE_SECURE` | 0 | `1` khi chạy HTTPS (Secure cookie) |
| `TRUST_PROXY` | (rỗng) | `1` khi đứng sau reverse proxy tin cậy |
| `THREATSCAN_ENABLED` | 1 | Bật quét nội dung độc hại offline (heuristic + engine local nếu có) |
| `THREATSCAN_TIMEOUT` | 15 | Timeout (giây) cho engine/tool quét |
| `THREATSCAN_MAX_BYTES` | 26214400 | Giới hạn byte quét mỗi tệp đính kèm |
| `SANDBOX_URL` | (rỗng) | Adapter sandbox cục bộ (chỉ localhost/private) |
| `BODY_MAX_BYTES` | 524288 | Giới hạn body mỗi thư (byte) |
| `BODY_TOTAL_BYTES` | 33554432 | Ngân sách body mỗi vụ việc |
| `AVATAR_RATE_MAX` | 20 | Giới hạn đổi avatar/IP/phút |


---

## 5. Hướng dẫn sử dụng giao diện

1. **Đăng nhập/Đăng ký**: nhập username, SĐT hoặc user ID. User thường đăng ký có SĐT (tùy chọn), nhận **Key ID khôi phục (một lần)** — cần lưu lại để đặt lại mật khẩu. Có thể khôi phục bằng Key ID và đăng nhập bằng username/SĐT.
2. **Dashboard & nền tảng**: chọn thẻ **Windows** hoặc **Linux** để đặt ngữ cảnh; Auto-detect vẫn nhận từ tệp. Dashboard hiển thị thống kê vụ việc/thư/mức rủi ro.
3. **Phân tích (Analysis)**: kéo-thả hoặc chọn tệp/thư mục (`.eml/.msg/.mbox/.emlx/.mht/.mhtml/.txt`, Maildir). Preflight loại tệp không hợp lệ. Nhấn **Analyze** để chạy streaming: 3 dòng (tệp/giai đoạn/chi tiết) + thanh biên độ + %. **Pause** dừng sau tệp hiện tại, **Stop** giữ kết quả đã xong, **Cancel** hủy lượt chạy. Khi xong tự chuyển sang **Results**.
4. **Kết quả (Results)**: dải nhận diện client/nền tảng; sub-tab **Overview/Messages/URLs/Graph** (Graph có bộ lọc quan hệ). Tab **Case file** xem meta/bảng kê/bàn giao/timeline/đánh giá/kiến nghị/ảnh/phân công. Mở từng thư để xem header/body (HTML đã khử nguy hiểm, sandbox). Xuất **Report HTML/PDF/CSV** (theo ngôn ngữ), **Verify signature**, export bundle/URL CSV; **Import URL** (CSV/JSON/XML/TXT, tệp hoặc thư mục) để tái phân tích local và gộp vào vụ việc.
5. **History/DNS/IP-Geo**: mở lại vụ việc; tra cứu DNS và IP/Geo (local), xem bản đồ lược đồ nội bộ.
7. **Guide**: hướng dẫn, ghi chú, lưu ý vận hành.
8. **Administration/Logs (ADMIN)**: thống kê, tạo tài khoản (analyst/admin; admin cần enroll/verifier theo quy trình), cấp token đổi tên một lần, bật/tắt/quyền (có chặn tự khóa/tự hạ quyền), xem audit & phiên ký.

**Cảnh báo viền phát sáng:** đỏ = nguy hiểm, vàng = đáng nghi, xanh = chưa chắc chắn; trạng thái bình thường không phát sáng.

---

## 6. API tham chiếu (chính)

| Nhóm | Endpoint | Ghi chú |
|---|---|---|
| Auth | `POST /api/register`, `/api/login`, `/api/logout`, `/api/recover`, `/api/password` | CSRF cho request ghi; session cookie `sid` |
| Hồ sơ | `GET /api/me`, `GET/POST /api/profile*`, `POST /api/profile/rename` | Đổi tên cần token một lần do admin cấp |
| Phân tích | `POST /api/analyze/stream`, `POST /api/analyze` | Stream NDJSON từng tệp; batch nhiều tệp |
| Vụ việc | `GET /api/cases`, `GET /api/case/{id}/message/{idx}` | Theo quyền sở hữu uid (admin xem tất cả) |
| URL | `GET /api/case/{id}/urls(.csv)`, `POST /api/urls/import`, `GET /api/urlintel/{id}(.csv)` | Import parse + local re-analysis + merge + re-sign |
| Báo cáo | `GET /api/report/{id}` `(.pdf`, `.csv)`, `/api/report/{id}/verify` | `lang=en|vi`; ký SHA-256 + seal; CSP/no-store |
| Tra cứu | `POST /api/dns`, `POST /api/ip`, `GET /api/map` | DNS/Geo local; map lược đồ nội bộ |
| Quản trị | `GET/POST /api/admin/*` | users/stats/logs/sessions, tạo user, cấp rename token, role/disable/reset (chỉ admin) |

Mã lỗi API trả về dạng `{"error":"<code>"}` (ví dụ `auth`, `csrf`, `forbidden`, `rate`, `too_large`, `file_too_large`, `local_only`).

---

## 7. Lưu trữ & vệ sinh dữ liệu

- `evidence/<case>.bin`: bản gốc chỉ đọc (phục vụ tái dựng body/báo cáo).
- `messages/<case>/`: header/body đã trích (text + HTML đã khử nguy hiểm) theo chỉ số thư.
- `quarantine/`: bản sao cách ly của tệp đính kèm nguy hiểm (read-only).
- `uploads/tmp/reports`: vùng tạm/báo cáo; nên dọn định kỳ theo chính sách lưu trữ.

Công cụ hỗ trợ: `tools/purge.py` (xem/áp dụng xóa theo thời gian hoặc theo case, có log purge). Sao lưu `app.db` kèm `evidence/` và `messages/` nếu cần di chuyển.

---

## 8. Kiểm thử & xác minh

```powershell
# biên dịch/kiểm tra cú pháp
node --check public\app.js

# bộ kiểm thử/audit trong repo
python tests\audit.py            # (tùy kịch bản/môi trường)
```

Khuyến nghị kiểm thử thủ công trên UI: streaming + Pause/Stop/Cancel, tự chuyển Results, xem header/body, export (chọn vị trí), import URL, xác minh chữ ký, phân quyền admin/analyst, dark mode và i18n.

---

## 9. Bảo mật & lưu ý vận hành

- **Bí mật**: không lưu/không in CCCD; không echo key API; khóa admin/verifier tạo offline (`tools/admin_keygen.py`).
- **Phân quyền & chống leo thang**: RBAC (admin/analyst), sở hữu case theo `uid` bất biến, kiểm tra CSRF cho thao tác ghi, chặn tự hạ quyền/tự vô hiệu hóa.
- **Toàn vẹn & hiển thị an toàn**: chữ ký SHA-256 + con dấu; CSP `default-src 'none'`, `nosniff`, `no-referrer`, `no-store` cho báo cáo; HTML body được sanitize và render trong sandbox; CSV xuất được trung hòa công thức.
- **Bản đồ**: lược đồ nội bộ từ tọa độ GeoIP — mang tính hỗ trợ định vị tương đối, không phải bản đồ đường phố/tọa độ chính xác tuyệt đối.

---

## 10. Xử lý sự cố nhanh

| Hiện tượng | Hướng xử lý |
|---|---|
| Không đăng nhập admin được | Enroll lại bằng `tools/admin_keygen.py --write-db`; kiểm tra `users.admin_kdf`; `ADMIN_PASS` chỉ là bootstrap dev |
| Bản đồ trống / `no_location` | IP không có tọa độ trong GeoLite2 hoặc là IP private; kiểm tra `GEOIP_DIR` |
| Kết quả SPF/DKIM/DMARC là `not_run` | Không có snapshot DNS hoặc không có `Authentication-Results` trong EML. Tạo snapshot bằng `python tools/dns_snapshot.py`; không truy DNS live |
| Body/HTML không hiển thị | Kiểm tra `messages/<case>/` và `evidence/<case>.bin` còn tồn tại; giới hạn `BODY_MAX_BYTES/BODY_TOTAL_BYTES` |
| Cổng bận | Đổi `--port` hoặc dừng tiến trình uvicorn cũ |

---


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
