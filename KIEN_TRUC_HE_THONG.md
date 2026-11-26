# KIẾN TRÚC HỆ THỐNG — MailSleuth Python (Forensic Offline 100%)

Tài liệu này giải thích **cấu trúc, luồng dữ liệu và lý do thiết kế** của codebase sau khi hoàn thành kế hoạch `TIEN_DO_BUILD.md`. Mọi sơ đồ dùng Mermaid, đọc được trên GitHub/VS Code. Không có thành phần nào gọi mạng.

---

## 1. Nguyên tắc kiến trúc

1. **Offline tuyệt đối**: không `requests`, không API/reputation, không MxToolbox/VirusTotal, không SIEM, không DNS resolver live, không AI/ML đổi verdict.
2. **Chứng cứ là gốc**: mọi finding, cạnh quan hệ, timeline event đều có field nguồn + `evidence`.
3. **Rule driven**: indicator nằm trong `analysis/rules/indicators.json`, có unit test; không chấm điểm cảm tính/theo brand.
4. **Điều phối mỏng**: `app/pipeline.py` chỉ nạp file → gọi core → xuất; logic nằm ở module chuyên biệt.
5. **Toàn vẹn theo phiên**: `case_signature = SHA-256(canonical facts + uid + SHA-256(sid) + signed_at)`; không lộ raw session id.
6. **Sở hữu bất biến**: `cases.uid` không đổi khi rename; mọi ghi kiểm tra RBAC/CSRF.

---

## 2. Sơ đồ thành phần tổng thể

```mermaid
flowchart TB
  subgraph CLIENT["Trình duyệt - SPA (public/)"]
    UI["index.html + app.js + app.css + fx.js"]
    TAB1["Analysis: upload/stream 3 dòng, Pause/Stop/Cancel"]
    TAB2["Results: Overview/Messages/URLs/Graph tương tác"]
    TAB3["Case file: meta/inventory/custody/timeline/assessment/response/screenshot/team"]
    TAB4["History/DNS/IP-Geo/Admin/Logs"]
    UI --> TAB1 & TAB2 & TAB3 & TAB4
  end

  subgraph API["FastAPI - app/main.py"]
    MW["Middleware: cookie sid, CSRF, rate-limit, security headers"]
    AUTH["Auth/Profile/Admin: register, login, recover, rename, RBAC theo uid"]
    AN["/api/analyze, /api/analyze/stream"]
    CASE["/api/case/*, /api/report/*, /api/ioc/*, /api/urls/*, /api/map"]
    FOR["/api/case/{id}/forensic/{kind} - 8 bảng pháp chứng"]
  end

  subgraph CORE["Lõi phân tích - offline"]
    PIPE["pipeline.py - điều phối"]
    PARSE["parsers.py + bodies.py - EML/MSG/MBOX/Maildir/TXT, client/platform"]
    HDR["headers.py + authcheck.py + routing.py - header/SPF/DKIM/DMARC/hops"]
    RULES["analysis/rules/indicators.json + urls.py + threatscan.py - rule/fact"]
    ATT["attachments.py - hash/magic/entropy/archive/macro/PE/image"]
    DNSL["dns_local.py - snapshot DNS, không resolver"]
    GEO["enrichment.py + mapgen.py - GeoLite2 mmdb + map lược đồ"]
    REL["relations.py + graph.py - message↔message, evidence graph, PNG"]
    REP["report.py - 20 mục HTML/PDF/CSV + seal + case_signature"]
    IOC["ioc.py - CSV/STIX có case_id + msg_index"]
  end

  subgraph STORE["DATA_DIR - lưu trữ local"]
    DB[("app.db SQLite WAL<br/>users, cases, audit, kv, sessions,<br/>case_meta, evidence_inventory, custody_events,<br/>timeline_events, assessments, responses,<br/>screenshots, team_assignment, url_imports")]
    EV["evidence/&lt;case&gt;.bin read-only"]
    MSG["messages/&lt;case&gt;/ - header/body đã sanitize"]
    Q["quarantine/ - attachment nguy hiểm"]
    SNAP["dns_snapshot.json - snapshot do user cấp"]
    GEODB["GeoLite2 *.mmdb - local"]
  end

  subgraph EXPORT["Gói nộp bài / bàn giao"]
    SUB["build_submission.py → ZIP: PDF/HTML/CSV/STIX/relations/graph/slide/manifest"]
    AUT["autopsy_handoff.py → PST/OST/OLE/carving cho Autopsy/FTK"]
    ADNS["auth_dns_export.py → SPF/DKIM/DMARC/DNS cho tool local"]
    VER["verify_dataset.py → SHA-256 đối chiếu dataset gốc"]
  end

  CLIENT <-->|"cookie sid + x-csrf"| API
  AN --> PIPE --> PARSE --> HDR
  HDR --> RULES --> ATT
  HDR --> DNSL
  DNSL --> SNAP
  GEO --> GEODB
  PARSE --> REL
  REL --> REP
  REL --> IOC
  API <--> CORE
  CORE <--> STORE
  CORE --> EXPORT
```

**Giải thích lớp**
- **Client**: chỉ là giao diện; không tự quyết verdict, không gọi API ngoài (kể cả local AI đã gỡ).
- **API**: xác thực/CSRF/RBAC, điều phối request, trả dữ liệu; ownership luôn theo `uid`.
- **Core**: module Python chuyên biệt. `pipeline.py` không chứa rule; `analysis/rules/` là nguồn indicator duy nhất.
- **Store**: SQLite + file; evidence gốc read-only, mọi thay đổi dẫn tới re-sign.
- **Export**: đóng gói cho điều tra viên/tool khác, vẫn offline, kèm `manifest.sha256`.

---

## 3. Luồng phân tích một lô email (sequence)

```mermaid
sequenceDiagram
  autonumber
  participant U as Analyst
  participant UI as SPA
  participant API as FastAPI
  participant P as pipeline.py
  participant C as Core libs
  participant DB as SQLite + FS

  U->>UI: Chọn tệp/thư mục, khai mục tiêu/phạm vi (tab Case file)
  UI->>API: POST /api/case/{id}/forensic/meta (CSRF)
  UI->>API: POST /api/analyze/stream (mỗi file 1 request)
  API->>P: _analyze_one(name, bytes, user, uid)
  P->>C: parse → header → auth → URL → attachment → GeoIP → IOC
  C-->>P: findings[] có source_field + evidence
  P->>C: relations.build() → timeline events
  P->>DB: lưu evidence read-only, messages/, case JSON
  P->>DB: case_signature (uid + SHA-256(sid) + signed_at)
  API-->>UI: NDJSON stage/result (dừng đúng file nếu lỗi)
  UI->>UI: tự chuyển Results; vẽ Graph + danh sách quan hệ
  U->>UI: Xem/điền custody, assessment, response, screenshot, team
  UI->>API: POST /api/case/{id}/forensic/{kind}
  API->>DB: insert + _resign_case() (re-sign SHA-256)
  U->>API: GET /api/report/{id}.pdf|html|csv, /verify
```

**Điểm chú ý**
- Streaming giữ nguyên hành vi cũ: `stage` → `result`; Pause/Stop/Cancel không thay đổi.
- Mỗi lần ghi vào 8 bảng pháp chứng đều gọi `_resign_case()` → chữ ký luôn phản ánh dữ liệu mới nhất.
- Lỗi ở một file không làm mất kết quả các file đã xong.

---

## 4. Mô hình dữ liệu (#)

```mermaid
erDiagram
  USERS ||--o{ CASES : "uid sở hữu"
  CASES ||--o| CASE_META : "objective/scope/source"
  CASES ||--o{ EVIDENCE_INVENTORY : "msg_index + sha256"
  CASES ||--o{ CUSTODY_EVENTS : "actor/transfer/hash"
  CASES ||--o{ TIMELINE_EVENTS : "ts + confidence"
  CASES ||--o{ ASSESSMENTS : "observed/inference/unverified"
  CASES ||--o{ RESPONSE_ACTIONS : "action/rationale"
  CASES ||--o{ SCREENSHOTS : "tool/step/caption"
  CASES ||--o{ TEAM_ASSIGNMENT : "member/role/tasks"
  CASES ||--o{ URL_IMPORTS : "re-analysis local"
  CASES {
    text id PK
    text uid FK
    text sha256
    text sig
    text session_fingerprint
    text signed_at
    text result JSON
  }
  EVIDENCE_INVENTORY {
    int id PK
    int msg_index
    text role
    text name
    text sha256
    text source_field
  }
  TIMELINE_EVENTS {
    int id PK
    text ts
    int msg_index
    text source_field
    text confidence
  }
  ASSESSMENTS {
    int id PK
    text kind
    text claim
    text evidence_refs
    text limitation
  }
```

**Quy tắc**
- Không xóa `cases.user` khi đổi tên (lịch sử/chữ ký giữ nguyên).
- `uid` là khóa sở hữu; admin xem tất cả nhưng vẫn ghi audit.
- Export có `case_id + msg_index`, sort `(msg_index, type, value)` → không trộn giữa các thư.

---

## 5. Quan hệ chứng cứ & graph giao diện

```mermaid
flowchart LR
  S["Actor gửi"] -->|SENT| M["Message #i"]
  M -->|TO/CC/BCC| R["Actor nhận"]
  S -->|USES_DOMAIN| D["Domain"]
  R -->|USES_DOMAIN| D
  M -->|ORIGIN_IP| IP["IP Received"]
  IP -->|LOCATED_IN - GeoLite2| G["Geo"]
  H["Received hop"] -->|RECEIVED_VIA| IP
  M -->|CONTAINS_URL| U["URL"]
  M -->|HAS_ATTACHMENT| A["Attachment/hash"]
  M -->|OCCURRED_AT| TL["Timeline event"]
  M1["Mail #1"] -->|THREAD_REPLY / SHARES_*| M2["Mail #2"]
```

- Cạnh liền = **quan sát** được từ field; cạnh đứt = **suy luận** (`TIME_NEAR`) — UI ghi rõ `confidence`.
- Graph có layout deterministic (cùng input → cùng ảnh), `graph.to_png()` để nhúng PDF; HTML dùng SVG.
- UI lọc theo loại cạnh, click vào cạnh hiện `evidence`; link tải `relations.csv`.

---

## 6. SPF/DKIM/DMARC & DNS lịch sử

```mermaid
flowchart TD
  A["EML dataset"] --> B{"Có Authentication-Results?"}
  B -->|Có| C["source = header-captured<br/>chứng cứ chính"]
  B -->|Không| D{"Có snapshot DNS?"}
  D -->|Có| E["pyspf + dkimpy + dns.zone.from_file<br/>dnsfunc local → recomputed-from-snapshot"]
  D -->|Không| F["not_run / chưa đủ cơ sở<br/>KHÔNG query live"]
  C --> G["Bảng đánh giá: hỗ trợ / không đủ cơ sở"]
  E --> G
  F --> G
```

Thư viện: `spf` (pyspf), `dkim` (dkimpy), `dns` (dnspython, **chỉ** `dns.zone`), `idna`, `email` (stdlib), `ipaddress`, `urllib.parse`. `tools/auth_dns_export.py` đóng gói raw record + snapshot + `manifest.sha256` cho tool local khác.

---

## 7. Báo cáo & chữ ký

```mermaid
flowchart LR
  F["Canonical case facts + findings + IOC"] --> S["SHA-256"]
  U["uid"] --> S
  SID["SHA-256(sid)"] --> S
  T["signed_at UTC"] --> S
  S --> SEAL["Seal SVG góc dưới phải"]
  S --> V["/api/report/{id}/verify - tính lại"]
  S --> RPT["report.html/pdf: 20 mục<br/>TOC → ... → Timeline → Phân loại → Kiến nghị → Phụ lục → Ký"]
```

Chữ ký là **fingerprint toàn vẹn có tính tái lập**, không phải chữ ký PKI; verify endpoint cho phép đối chiếu. `session_fingerprint` là hash của sid → không lộ session token trong file báo cáo.

---

## 8. Ranh giới & bàn giao ngoài

```mermaid
flowchart LR
  subgraph IN["Python/local (có trong repo)"]
    EML[EML/MSG/MBOX/Maildir/TXT]
    LIB[email, bs4, oletools, pefile, zipfile,<br/>pyspf, dkimpy, dnspython-snapshot,<br/>Pillow, fpdf2]
    OUT[PDF/HTML/CSV/STIX/JSON/CSV]
  end
  subgraph OUTSIDE["Tool điều tra viên mở thủ công"]
    AUT[Autopsy / FTK Imager - PST/OST, carving, OLE sâu]
    TOOL[spfquery / opendkim-testkey / dig@127.0.0.1]
  end
  EML --> LIB --> OUT
  OUT -->|"auth_dns_export / autopsy_handoff + manifest"| AUT
  OUT -->|"dns_snapshot + auth_summary"| TOOL
  IN -. "không gọi ra mạng" .- OUTSIDE
```

---

## 9. Bản đồ tập tin quan trọng

| Tập tin | Vai trò |
|---|---|
| `app/main.py` | API, auth/CSRF/RBAC, streaming, endpoints forensic/report |
| `app/pipeline.py` | Điều phối nạp dataset → lõi → xuất báo cáo |
| `app/parsers.py`, `app/bodies.py` | Đọc định dạng, client/platform, sanitize body |
| `app/headers.py`, `authcheck.py`, `routing.py` | Header, SPF/DKIM/DMARC, Received hops |
| `analysis/rules/indicators.json`, `app/urls.py`, `app/threatscan.py` | Rule/fact, URL & attachment an toàn |
| `app/attachments.py` | Hash/magic/entropy/archive/macro/PE/image |
| `app/dns_local.py` | DNS snapshot, không live |
| `app/enrichment.py`, `mapgen.py` | GeoLite2 + bản đồ lược đồ |
| `app/relations.py`, `graph.py` | Quan hệ mail↔mail, graph SVG/PNG |
| `app/report.py`, `ioc.py` | Báo cáo 20 mục, seal, IOC CSV/STIX có index |
| `app/db.py` | Schema + migration, ownership `uid` |
| `tools/verify_dataset.py` | Kiểm SHA-256 dataset gốc |
| `tools/dns_snapshot.py`, `auth_dns_export.py` | Snapshot DNS + gói bàn giao xác thực |
| `tools/autopsy_handoff.py`, `build_submission.py` | Gói Autopsy + ZIP nộp bài |
| `public/index.html`, `app.js` | 9 tab + tab Case file, dashboard Findings/Relations |
| `TIEN_DO_BUILD.md` | Tiêu chuẩn build/test + trạng thái phase |
| `BAO_CAO_HOAN_THANH_DIGITAL_FORENSICS.md` | Đối chiếu yêu cầu + 31 test + giới hạn |

---

## 10. Giới hạn phải ghi khi báo cáo
- GeoLite2 cho vị trí gần đúng; không phản ánh quá khứ nếu dùng DB hiện tại.
- Thiếu Received/Authentication-Results → ghi `not_run`, không suy đoán IP/danh tính.
- DKIM có thể không verify nếu body/MIME thay đổi sau khi nhận.
- Autopsy/FTK là bước ngoài; hệ thống chỉ đóng gói + hướng dẫn.
- `TIME_NEAR` và map mũi tên là lớp suy luận/phụ, không dùng để kết luận.

> Mọi thay đổi kiến trúc phải cập nhật đồng thời tài liệu này, `HUONG_DAN_SETUP_PYTHON.md` và `TIEN_DO_BUILD.md`.

## 11. Global Relations (bổ sung)
`app/global_graph.py` + `/api/graph/global` + tab **Relations** thay cho DNS/IP-Geo: index toàn bộ case → cạnh `SENT/TO/ORIGIN_IP/...` có evidence → UI lọc/index/SVG/CSV. Xem `BAO_CAO_HOAN_THANH_DIGITAL_FORENSICS.md` mục 13.

---

## 12. Kiến trúc hoàn chỉnh sau fix cuối (tham chiếu chính)

### 12.1 Sơ đồ tổng thể (cập nhật)

```mermaid
flowchart TB
  subgraph UI["SPA - public/index.html + app.js + app.css + fx.js"]
    TABS["8 tab: Analysis / Results / Guide / History / Relations / Case file / Admin / Logs"]
    DASH["Dashboard: Cases / Messages / Malicious / Suspicious / Clean / Findings / Relations"]
    RES["Results: Overview / Messages / URLs / Graph / Timeline + Total analysed"]
    REL["Relations: index 30.000 thư + Message-ID/From/To + filter + SVG + CSV"]
    CASE["Case file: 8 sections + form Assessment/Response"]
  end

  subgraph API["FastAPI app/main.py"]
    SEC["Auth / CSRF / RBAC(uid) / rate limit stream 6000 + pace 60ms"]
    ANA["/api/analyze/stream + /api/analyze"]
    CASEAPI["/api/cases(limit 30000) + /api/cases/count + /api/case/* + /api/forensic/*"]
    REPORT["/api/report/{id} HTML/PDF/CSV + /verify"]
    GAPI["/api/graph/global + /api/graph/index"]
  end

  subgraph CORE["Lõi offline - analysis/ + app/"]
    PARSE["parsers/bodies: EML/MSG/MBOX/Maildir/TXT + client/platform"]
    RULES["analysis/rules/indicators.json + urls/threatscan: rule/fact có source_field"]
    AUTH["authcheck + dns_local(snapshot): SPF/DKIM/DMARC từ AR/snapshot"]
    EXT["attachments + oletools/pefile/bs4/zipfile: hash/magic/macro/archive"]
    RELMOD["relations + global_graph + graph + mapgen + timeline + ioc"]
    SIGN["report.py: 20 mục + seal SHA-256 + phụ lục hash thật"]
  end

  subgraph STORE["DATA_DIR"]
    DB[("SQLite: cases + 8 bảng pháp chứng + url_imports + sessions")]
    FS["evidence/ read-only, messages/, quarantine/, uploads/, reports/"]
    SNAP["dns_snapshot.json + GeoLite2 mmdb(local)"]
  end

  subgraph OUT["Xuất/bàn giao"]
    ZIP["build_submission.py → ZIP: report + ioc/STIX + relations + graph + slide + manifest"]
    HAND["auth_dns_export.py + autopsy_handoff.py + verify_dataset.py"]
  end

  UI <--> API
  API --> CORE
  CORE <--> STORE
  CORE --> OUT
  OUT --> UI
```

### 12.2 Các fix cuối đã áp dụng (đồng bộlocal + VM)
1. **Phụ lục export thật**: `build_submission` xuất file phụ trước → tính `sha256/size` → nhét `result.exports` → mới render report → phụ lục có hash thật.
2. **Chữ ký phủ đủ**: `case_signature` thêm `extra = timeline_events/assessments/responses/screenshots/team/exports`; mọi ghi pháp chứng qua API đều re-sign; verify khớp.
3. **Map snapshot**: `_report_parts` dùng `result.ipInfo[].geo` lưu lúc phân tích, không gọi `geo_lookup()` lại lúc xuất.
4. **Form pháp chứng**: tab Case file có 2 form thêm đánh giá (observed/inference/unverified) và kiến nghị ứng phó; lưu qua POST + re-sign.
5. **Stat đúng**: `relStat` dùng `actors_total` (3026), không phải top 60; History limit 30000, text đúng; favicon SVG local hết 404.
6. **Graph 30.000 case**: index qua SQLite JSON1 (nhanh ~6–10s), nhóm đủ Thư/Actor/Domain/IP/URL/Hash.

### 12.3 Trạng thái nghiệm thu
- HEAD `d2c5dd3` = `origin/main` trên local **và** VM; working tree sạch.
- 13/13 unit test PASS; `py_compile` + `node --check` OK; console browser 0 lỗi.
- `/api/health` 200 (`offline:true`); mọi endpoint báo cáo/xuất/graph 200.
- Dữ liệu: 15.029 case; Relations index 30.000; phân loại bad 48 / suspicious 14.971 / clean 10.

> File này là nguồn tham chiếu kiến trúc. Mọi thay đổi sau này phải cập nhật đồng thời `HUONG_DAN_SETUP_PYTHON.md`, `TIEN_DO_BUILD.md` và `BAO_CAO_HOAN_THANH_DIGITAL_FORENSICS.md`.
