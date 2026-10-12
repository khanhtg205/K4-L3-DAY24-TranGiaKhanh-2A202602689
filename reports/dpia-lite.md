# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
   - Dữ liệu tài liệu hỗ trợ (Ticket context): Phân loại `internal`, chứa thông tin mô tả sự cố và tiêu đề ticket.
   - Dữ liệu cá nhân khách hàng (PII): Phân loại `restricted` (mức bảo vệ cao nhất), bao gồm số CCCD (12 số), số điện thoại, số tài khoản ngân hàng (STK), email và họ tên khách hàng. Toàn bộ là dữ liệu tổng hợp (synthetic), không sử dụng PII thật.

2. Mục đích xử lý và principal:
   - Mục đích xử lý hợp lệ: `summarize-tickets` (tổng hợp ticket) và `support-reply` (hỗ trợ xử lý yêu cầu gắn với khách hàng).
   - Phân quyền theo Principal:
     - `support_l1`: Chỉ được phép thực hiện mục đích `summarize-tickets` với công cụ `search_docs`; không được phép truy cập dữ liệu khách hàng (`read_customer`).
     - `dpo`: Cán bộ bảo vệ dữ liệu, được phép gọi `read_customer` cho các mục đích hợp lệ (`support-reply`, `privacy-audit`).

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - **Run A (Untrusted Context):** Gọi `tools.search_docs` để đọc dữ liệu không tin cậy từ `corpus/`. Run A thực hiện PII detection/redaction và chỉ chuyển tiếp Ticket ID số trích xuất từ tên file sang Run B.
   - **Run B (Trusted Context):** Tiếp nhận Ticket ID từ Run A, đối chiếu trường `related_tickets` trong `data/customers.json` và gọi `tools.read_customer` nếu chính sách cho phép.
   - **Endpoint ngoại vi (Egress):** Máy chủ giả lập `http://127.0.0.1:10024/reconcile`. Mọi yêu cầu gọi `tools.http_post` mang dữ liệu `restricted` đều bị chặn đứng trước khi ra mạng ngoài.

4. Bằng chứng deny/allow và giới hạn của mock:
   - Bằng chứng thực nghiệm:
     - Quyết định allow và deny đều được ghi vào `reports/ledger.jsonl` kèm mã hash xác thực, lý do `reason` không rỗng và định danh `on_behalf_of`.
     - Chặn rò rỉ thành công: `reports/attack-before.log` chứa bản ghi PII bị rò rỉ ban đầu, trong khi `reports/attack-after.log` hoàn toàn rỗng (0 bytes) sau khi kích hoạt chính sách.
   - Giới hạn của môi trường Mock:
     - Thử nghiệm trên mô hình Mock LLM tất định và dữ liệu synthetic; chưa phản ánh hoàn toàn tính biến thiên ngữ nghĩa của mô hình LLM production.
     - Cơ chế OBO là mô hình hóa ủy quyền giả lập, chưa thay thế được hạ tầng chứng thực danh tính thực tế (như OAuth2 Token Exchange, JWT ký số, mTLS).
