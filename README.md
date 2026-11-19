#### 🔐 Quy trình truyền nhận và hoạt động cụ thể:

1. **Khởi tạo và Phân phối Khóa (Bởi Người Nhận):**
   - **Người nhận** khởi tạo cặp khóa **RSA-2048**.
   - **Người nhận** giấu **Public Key** của mình vào một file âm thanh bằng kỹ thuật LSB và gửi file âm thanh này đi cho người gửi.

2. **Chuẩn bị và Mã hóa Dữ liệu (Bởi Người Gửi):**
   - **Người gửi** nhận file âm thanh, trích xuất **Public Key** của người nhận từ file đó.
   - **Người gửi** mã hóa dữ liệu gốc (văn bản `.txt` hoặc hình ảnh `.jpg`) bằng thuật toán **AES-GCM (128-bit)** để tạo ra `ciphertext`, `key`, `nonce`, và `tag`.
   - **Người gửi** bảo vệ thông tin giải mã AES (`key` + `nonce` + `tag` = 48 bytes) bằng cách mã hóa nó bằng **RSA Public Key** vừa trích xuất được.

3. **Nhúng dữ liệu mật vào file WAV (Bởi Người Gửi):**
   - **Khóa RSA đã mã hóa** (2048 bits) được giấu vào các byte đầu tiên của file âm thanh.
   - **Header kích thước dữ liệu (Data Size)** (32 bits) được giấu tiếp theo.
   - **Dữ liệu mã hóa (Ciphertext)** được giấu vào phần còn lại của file âm thanh và gửi file âm thanh mật này lại cho người nhận.

4. **Giải mã và Khôi phục tin (Bởi Người Nhận):**
   - **Người nhận** nhận file âm thanh chứa tin mật.
   - Trích xuất khóa RSA bị mã hóa, sử dụng **Private Key** (giữ bí mật ở phía mình) để giải mã lấy lại `key`, `nonce`, và `tag` của AES.
   - Trích xuất và giải mã dữ liệu `ciphertext` bằng khóa AES vừa khôi phục để thu về file gốc ban đầu.