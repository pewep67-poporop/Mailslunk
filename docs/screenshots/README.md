# Ảnh chụp màn hình chứng cứ (đính kèm báo cáo)

Chụp trực tiếp từ hệ thống đang chạy tại `http://192.168.65.131:8000/` sau khi
tắt/pip install/restart dịch vụ trên VM ngày 27/11/2026.

| File | Nội dung |
|---|---|
| `pip_install.png` | `pip install -r requirements.txt` trong venv VM — tất cả "Requirement already satisfied" |
| `restart_ok.png` | Lệnh khởi động uvicorn bằng `venv/bin/python` sau restart |
| `s1_dashboard.jpg` | Dashboard: 15.029 vụ việc / 15.029 thư, 48 độc hại, 14.971 đáng ngờ, 10 sạch, 25.854 findings |
| `s2_results_overview.jpg` | Results/Overview của 1 case: findings, URL/IOC, chữ ký SHA-256 |
| `s3_timeline.jpg` | Timeline từ `Date`/`Received` (mốc quá khứ, confidence=observed) |
| `s4_graph.jpg` | Sơ đồ liên kết thực thể (node/edge có evidence) |
| `s5_relations.jpg` | Tab Relations: 30.000 thư, bảng Message-ID/From/To, phân loại actor/domain/IP/URL/hash, SVG |
| `s6_casefile.jpg` | Tab Case file: 8 mục + form thêm đánh giá/kiến nghị |
| `s7_tests_banner.png` | Kết quả test trên VM: `RESULT: 13 PASS / 0 FAIL`, HEAD `039a2fa` |

Tất cả ảnh là chứng cứ trực quan; không chỉnh sửa nội dung ngoài việc đổi tên file.
