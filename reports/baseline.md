# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Trong `agent/loop.py` tại hàm `_naive_loop(message, llm)` (dòng 27), hàm không nhận hay tạo bất kỳ định danh nào như `run_id`, `agent_id` hay `principal_id`. Mọi lượt chạy đều ẩn danh, không có cơ chế quản lý danh tính phiên chạy.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có ai (không có Policy Engine / PEP) cho phép hay kiểm soát. Trong `agent/loop.py` tại hàm `_naive_loop()` (dòng 35-44), khi `injected` tồn tại thì `_naive_loop` tự ý gọi trực tiếp `tools.http_post(injected.target_url, {"records": collected})` mà không qua bất kỳ kiểm tra chính sách hay quyền hạn nào. Bản thân hàm `tools.http_post()` trong `agent/tools.py` (dòng 68-85) chỉ kiểm tra cứng IP/port đích (hard-allowlist `127.0.0.1:10024`) chứ không thẩm định quyền gửi dữ liệu hay tính chất nhạy cảm của payload.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Bằng chứng được lưu tại file `reports/sink.log`. Cụ thể tại `sink/sink.py`, phương thức `Handler.do_POST` bên trong hàm `make_handler()` (dòng 40-50) sẽ đọc toàn bộ `body` của request HTTP POST và ghi nối tiếp vào `reports/sink.log` dưới dạng từng dòng JSON: `{"path": ..., "body": ...}`.
