# Kế hoạch & trạng thái nâng cấp điều tra — MailSleuth Python


---

## 1. Phạm vi & nguyên tắc

- Chỉ tác động `mailsleuth_python/` (bản Node gốc giữ nguyên, dữ liệu tách biệt qua `DATA_DIR`).
- **Offline-safe mặc định**: không bản đồ/AI ngoài; DNS thật tùy chọn (`LIVE_DNS`).
- **Không lưu bí mật nhạy cảm**: CCCD không lưu, khóa/verifier admin tạo offline; key dịch vụ per-user trong `kv`, không echo/log.
- Mọi thay đổi quan trọng đi kèm cơ chế kiểm chứng (chữ ký báo cáo, CSRF/RBAC, test/smoke khi phù hợp).

---

## 2. Kiến trúc hiện tại (tổng quan)

```mermaid
flowchart TB
  subgraph UI[Frontend SPA]
    A[Analysis - streaming 3 dòng + biên độ + %\nPause/Stop/Cancel]
    B[Results - Overview/Messages/URLs/Graph\nReport/Verify/Export-Import]
  end
  subgraph API[FastAPI app/main.py]
    S[Session + CSRF + RBAC\nownership: cases.uid]
    E[/analyze/stream (NDJSON)\n/analyze]
    R[report/verify, case, urls, graph, map]
  end
  subgraph Core[app/* modules]
    P[parsers,bodies] --> F[headers,authcheck,routing,urls,attachments,ioc]
    F --> U[urlintel local] --> REP[report: SHA-256 + seal]
    F --> G[graph/mapgen]
  end
  subgraph Data[DATA_DIR]
    D[(SQLite: users,cases,audit,kv,sessions,url_imports,...)]
    FS[evidence, messages, quarantine, uploads/tmp]
  end
  UI <--> API <--> Core <--> Data
  L -. optional .-> Core
```

### Thành phần chính
| Nhóm | Mô-đun/tệp | Vai trò |
|---|---|---|
| API & điều phối | `app/main.py` | Endpoint, streaming, authz/CSRF, hợp nhất kết quả, lưu case |
| Lưu trữ | `app/db.py` | SQLite WAL, migration (uid/phone/admin_kdf/sig/platform/url_imports...) |
| Tài khoản | `app/auth.py`, `tools/admin_keygen.py` | bcrypt user, recovery key, uid/SĐT, PBKDF2 admin verifier, rename token |
| Phân tích | `app/parsers.py`, `bodies.py`, `headers.py`, `authcheck.py`, `routing.py`, `urls.py`, `attachments.py`, `ioc.py` | Parse/nhận diện, header/auth/routing, URL/đính kèm/IOC, lưu body an toàn |
| Báo cáo | `app/report.py` | HTML/PDF/CSV/JSON, `case_signature` SHA-256, seal góc dưới phải, verify, CSP |
| Giao diện | `public/index.html`, `app.js`, `app.css` | 9 tab, streaming UI, dark/i18n, export/import, admin |

---

## 3. Luồng nghiệp vụ & dữ liệu

### 3.1 Luồng phân tích
```mermaid
sequenceDiagram
  participant UI
  participant API as /api/analyze/stream
  participant Pipe as Parse+Forensic+Enrich
  participant Store as DB/FS
  UI->>API: upload tuần tự (1 tệp/request)
  API-->>UI: stage receive/parse/analyze/result (NDJSON)
  API->>Pipe: detect client/platform, trích chứng cứ, chấm điểm
  Pipe->>Store: evidence, messages, case(result)+sig(uid)
  API-->>UI: result (hoặc error đúng tệp)
```

### 3.2 Luồng dữ liệu logic: vụ việc → thư → thực thể → liên kết
```mermaid
flowchart LR
  C[Case/Vụ việc\n(uid sở hữu, sig, platform, verdict/score)] --> M[Messages\n(header/body, client, auth, IP/URL/att refs)]
  M --> E[Entities\nactor, domain, ip, url, attachment/hash]
  E --> L[Links\nSENT, USES_DOMAIN, ORIGIN_IP,\nCONTAINS_URL, HAS_ATTACHMENT]
  L --> V[Graph SVG/JSON\nchỉ từ chứng cứ]
```
- Case gắn `uid` bất biến; `result.graph`/endpoint graph biểu diễn entities/links suy ra từ chứng cứ (không suy diễn danh tính).

### 3.3 Báo cáo, URL import, bản đồ, AI
- **Báo cáo:** `case_signature(row,result)` → SHA-256; seal hiển thị góc dưới phải; `GET /api/report/{id}/verify` tái tính đối chiếu. Ngôn ngữ `en/vi` cho HTML/PDF/CSV.
- **URL intel:** export theo target/nguồn; import CSV/JSON/XML/TXT → parse + rule local → merge verdict/risk/reasons → lưu `urlImports` → cập nhật case & **re-sign**.
- **Bản đồ:** `mapgen.py` vẽ schematic nội bộ từ tọa độ GeoIP (không tile/không dịch vụ ngoài).

---

## 4. Trạng thái hạng mục đã triển khai

| Hạng mục | Trạng thái | Ghi chú triển khai |
|---|---:|---|
| Phân tích EML/MSG/MBOX/Maildir/TXT, nhận diện client/nền tảng | Hoàn thành | `parsers.py`, `main.py`; `PST/OST` trích xuất ngoài rồi nạp |
| Streaming NDJSON, tiến độ thực, Pause/Stop/Cancel, dừng đúng lỗi | Hoàn thành | `/api/analyze/stream`, UI 3 dòng + biên độ + % |
| Header/Auth(SPF/DKIM/DMARC)/Routing/URL/Attachment/IOC | Hoàn thành | `headers.py`, `authcheck.py`, `routing.py`, `urls.py`, `attachments.py`, `ioc.py` |
| Báo cáo HTML/PDF/CSV/JSON đa ngôn ngữ + mộc/chữ ký SHA-256 + verify | Hoàn thành | `report.py`, endpoint report/verify, CSP/no-store |
| Thống kê IP/DNS/SPF/DMARC/routing/URL theo target, trích chứng cứ | Hoàn thành | Tổng hợp trong `result` và report/tabs |
| Đồ thị thực thể/liên kết từ chứng cứ | Hoàn thành | `graph.py`, `/api/case/{id}/graph(.svg)` |
| Bản đồ lược đồ nội bộ (thay map ngoài) | Hoàn thành | `mapgen.py`, `/api/map` local |
| URL export/import & tái phân tích local, merge, re-sign | Hoàn thành | `urlintel.py`, `/api/urls/import`, `/api/case/{id}/urls(.csv)` |
| Tài khoản: uid hex32, SĐT, Key ID khôi phục, đổi tên token một lần | Hoàn thành | `auth.py`, `db.py`, profile/rename APIs |
| Admin: PBKDF2-HMAC-SHA256 (password+CCCD salt), keygen offline, không lưu CCCD | Hoàn thành | `tools/admin_keygen.py`, `admin_kdf`/verifier |
| Phân quyền & chống leo thang ngang/dọc, CSRF, tab Admin chỉ admin | Hoàn thành | RBAC, `cases.uid` ownership, guard self-demote/disable |
| UI: 9 tab, Results/Messages/URLs/Graph, Guide, dark, cảnh báo viền, Win/Linux, export/import picker | Hoàn thành | `public/index.html`, `app.js`, `app.css` |
| An toàn bổ sung | Hoàn thành | CSV formula-safe, CSP/nosniff/no-referrer/no-store, body sanitize+sandbox |

---

## 5. Kiến trúc dữ liệu lưu trữ (SQLite & FS)

- **Bảng chính:** `users` (uid, phone, role, recovery hash, admin_kdf, rename_token...), `cases` (id, uid, sig, platform, lang, result JSON), `audit`, `kv`, `sessions`, `session_signatures`, `url_imports`.
- **Tệp:** `evidence/<case>.bin` (gốc, read-only), `messages/<case>/` (header/body trích), `quarantine/` (mẫu nguy hiểm cô lập), `uploads/tmp/reports`.

---

## 6. Hạng mục còn mở/đề xuất tiếp theo

- **Kiểm thử UI tự động E2E** ổn định hơn cho streaming/picker/graph trên môi trường CI/headless.
- **Đối chiếu “mẫu báo cáo chuẩn” cụ thể** của đơn vị (nếu có template bắt buộc) để tinh chỉnh bố cục/trường.
- **Rà soát phụ thuộc định kỳ** (pip-audit/pinning) và hardening triển khai (HTTPS, reverse proxy, sao lưu/vệ sinh).

---

## 7. Ghi chú thay thế so với kế hoạch cũ (M1–M7)

- Mô-đun forensic cốt lõi (header/auth/routing/URL/attachment/IOC) vẫn là nền tảng nhưng đã được tích hợp sâu vào luồng streaming, báo cáo có chữ ký, URL intel và đồ thị.
- `PST/OST` không parse nội bộ; **map ngoài (MapGlot/OSM tiles)** đã thay bằng **map lược đồ nội bộ**; AI chỉ **local**.
- Quản trị/tài khoản chuyển sang mô hình uid bất biến + PBKDF2 verifier (offline keygen, không lưu CCCD), tăng cường phân quyền/chống leo thang và tab Administration.

*Tài liệu đồng bộ với mã nguồn tại thời điểm cập nhật; xem thêm `README.md` và `HUONG_DAN_SETUP_PYTHON.md`.*


## Cập nhật cuối: kế hoạch đã hoàn thành
G0 → P10 đã build xong. Xem `TIEN_DO_BUILD.md` (tick trạng thái) và
`BAO_CAO_HOAN_THANH_DIGITAL_FORENSICS.md` (đối chiếu yêu cầu + kết quả test).
