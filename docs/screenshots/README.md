# Ảnh chứng cứ báo cáo (chụp lại toàn màn hình, có chọn lọc)

Chụp từ `http://192.168.65.131:8000/` sau khi tắt service, `pip install -r requirements.txt`
(đều đã satisfied) và restart bằng `venv/bin/python`. Ảnh được phóng cửa sổ Edge/terminal
để không bị cắt như bản chụp trước.

| File | Vị trí chụp / nội dung chứng cứ |
|---|---|
| `s1_dashboard_full.jpg` | Dashboard sau restart: 15.030 vụ việc / 15.030 thư, 48 độc hại, 14.971 đáng ngờ, 10 sạch, 25.857 findings |
| `s2_results_overview_full.jpg` | Tab Kết quả → Tổng quan của 1 case: findings, URL, IOC, chữ ký SHA-256, "Total analysed" |
| `s3_timeline_chain_full.jpg` | Tab Kết quả → Timeline: **chuỗi mốc UTC** `03:00:00 → 03:00:00 → 03:02:00`, 3 mốc, tổng 120s, cột `seq/delta_s/elapsed_s/source_field/geo/confidence` (dùng email mẫu có 2 hop Received để chứng minh cơ chế) |
| `s4_graph_full.jpg` | Tab Kết quả → Sơ đồ liên kết thực thể, node/edge có chứng cứ |
| `s5_relations_overview_full.jpg` | Tab Quan hệ chứng cứ: tiêu đề, hint, bộ lọc, dòng nhóm `Thư 30000 · Actor 3028 · Domain 519 · IP 6 · URL 623 · Hash 2066`, 253 cạnh |
| `s6_relations_table_full.jpg` | Bảng danh sách thư trong tab Quan hệ: `STT | Message-ID | Từ (From) | Đến (To) | Tiêu đề | Ngày | Kết luận | Điểm | Case`, đang hiện 1–50 / 30000 |
| `s7_casefile_full.jpg` | Tab Case file: 8 mục + 2 form thêm đánh giá / kiến nghị ứng phó |
| `s8_tests_full.png` | Terminal VM: `bash tests/run_unit.sh` → `RESULT: 13 PASS / 0 FAIL`, HEAD `4425ad7` |

Ghi chú:
- Các case cũ được sinh ra trước khi có cơ chế chuỗi thời gian giờ vẫn tự tính lại `seq/delta_s/elapsed_s` khi đọc dữ liệu.
- Ảnh timeline dùng email mẫu do chính giao diện nạp (`timeline_demo.eml`) để có đủ 3 mốc thời gian thực; không sửa dữ liệu dataset.
