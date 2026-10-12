# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks phiên bản v8.30.1.
- Commit chứa token giả: `1bdd849922156c868a5ee9293d68f5b72e242d2c` (commit `1bdd849`).
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt` (dòng 1).
  - Rule ID: `lab24-synthetic-token` (định nghĩa trong `.gitleaks.toml`).
  - Kết quả: Lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .` phát hiện 1 finding vi phạm rule `lab24-synthetic-token` tại commit `1bdd849` (`leaks found: 1`).
- Kết quả quét file hiện tại:
  - Lệnh `gitleaks dir --config .gitleaks.toml --verbose .` quét sạch hoàn toàn, báo cáo `no leaks found`.
- Nếu đây là credential thật, cần xử lý thế nào:
  - Bắt buộc phải lập tức **thu hồi (revoke)** và **cấp đổi mới (rotate)** credential trên hệ thống cung cấp dịch vụ để vô hiệu hoá mã bí mật đã lộ.
  - Rà soát toàn bộ access logs/audit logs kể từ thời điểm commit `1bdd849` để xác định phạm vi bị khai thác trái phép.
  - Làm sạch lịch sử Git (sử dụng `git-filter-repo` hoặc BFG Repo-Cleaner) nếu cần loại bỏ hoàn toàn dấu vết khỏi repo.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xóa file ở commit sau chỉ xóa khỏi cây thư mục làm việc hiện tại (HEAD), nhưng commit `1bdd849` và blob dữ liệu của nó **vẫn nằm nguyên vẹn trong lịch sử Git**. Bất kỳ ai clone repo đều có thể checkout commit cũ hoặc dùng `git show 1bdd849` để lấy secret.
  - Pin dependency và pre-commit hook chỉ giúp chống thay đổi mã nguồn trong tương lai hoặc bảo vệ chuỗi cung ứng, chứ **không thể vô hiệu hóa** một credential đã từng bị lộ ra ngoài. Vì vậy, bước rotate/thu hồi trực tiếp từ nhà cung cấp là bắt buộc và không có công cụ Git nào thay thế được.
