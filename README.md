# Audio Steganography — Hybrid RSA-2048 + AES-GCM + LSB

Ứng dụng Demo giấu tin mật đa tầng trong tệp âm thanh **WAV PCM 16-bit**, kết hợp mật mã lai (**RSA-2048 OAEP** + **AES-128 GCM**) và kỹ thuật thay thế bit ít quan trọng nhất (**LSB**).

* **Môn học:** Bảo mật Thông tin (502049) — Trường Đại học Tôn Đức Thắng
* **Nhóm thực hiện:** Nhóm 12 (Châu Huỳnh Thông · Vũ Bảo Khánh)

---

## 1. Kiến trúc hệ thống & Cấu trúc thư mục

Dự án được tổ chức theo mô hình tách biệt giữa **Lõi thuật toán xử lý (`stego_core.py`)** và **Giao diện người dùng (`app.py`)**:

```text
BMTT_FINAL/
├── reports                      # Thư mục chứa file báo cáo dự án
├── src
|   ├── .venv/                   # Môi trường ảo Python (không đẩy lên Git)
|   ├── outputs/                 # Thư mục lưu tệp âm thanh Stego và tệp khôi phục
|   ├── RSA_keys/                # Thư mục lưu khóa bí mật cục bộ (private_key.pem)
|   ├── temp_ui/                 # Tệp tạm phục vụ đối chiếu trên giao diện
|   ├── main.py                  # Module lõi: Xác thực WAV, Mã hóa lai, Nhúng/Trích LSB, Đo SNR/CER
|   ├── app.py                   # Giao diện Web tương tác cục bộ bằng Streamlit
|   └── requirements.txt         # Danh sách thư viện phụ thuộc
└── README.md                    # Tài liệu hướng dẫn cài đặt và vận hành
```

---

## 2. Nguyên lý hoạt động & Giao thức dữ liệu

### 2.1. Quy tắc nhúng LSB trên WAV PCM 16-bit
* Hệ thống chỉ chấp nhận tệp **RIFF/WAVE** chuẩn **Linear PCM 16-bit little-endian** (`sampwidth = 2`, không nén).
* Mỗi mẫu âm thanh (sample) gồm 2 byte: `[Byte thấp (LSB)]` và `[Byte cao (MSB)]`.
* Thuật toán chỉ thao tác trên **byte thấp** của từng mẫu (bước nhảy `step = 2`, tức các chỉ số `0, 2, 4, ...` trong vùng `data chunk`) để đảm bảo sai lệch biên độ tối đa `|Δsample| ≤ 1`, không gây rè hay biến dạng âm thanh nghe được.
* **Phép toán ghi bit:** `byte_mới = (byte_gốc & 254) | bit`
* **Phép toán đọc bit:** `bit = byte_stego & 1`

### 2.2. Cấu trúc gói tin nhúng (Stego Payload Layout)
Hệ thống vận hành theo quy trình trao đổi khóa bất đối xứng 2 pha:

1. **Pha 1 — Tạo khóa & Nhúng Public Key (`generate_and_hide_public_key`):**
   * Người nhận sinh cặp khóa **RSA-2048**, lưu `private_key.pem` cục bộ.
   * Xuất Public Key dạng DER và nhúng vào tệp âm thanh vật chứa theo cấu trúc:
     `[Độ dài Public Key (32 bit)]` $\rightarrow$ `[Public Key DER (~2352 bit)]`

2. **Pha 2 — Mã hóa lai & Giấu tin mật (`encoding_secure`):**
   * Người gửi trích xuất Public Key từ tệp WAV vật chứa.
   * Sinh khóa phiên ngẫu nhiên **AES-128** (`16 bytes`), mã hóa dữ liệu gốc bằng chế độ **AES-GCM** để thu về `ciphertext`, `nonce` (`16 bytes`) và `tag` xác thực toàn vẹn (`16 bytes`).
   * Gộp `aes_key + nonce + tag` (`48 bytes`) và mã hóa bằng **RSA-OAEP** tạo thành khối khóa mã hóa cố định `256 bytes` (`2048 bits`).
   * Nhúng toàn bộ gói tin vào tệp WAV theo cấu trúc:
     `[RSA Encrypted Keys (2048 bit)]` $\rightarrow$ `[Độ dài Ciphertext (32 bit)]` $\rightarrow$ `[AES-GCM Ciphertext (biến thiên)]`

3. **Pha 3 — Trích xuất & Giải mã xác thực (`decoding_secure`):**
   * Đọc 2048 bit đầu để giải mã RSA bằng `private_key.pem`, khôi phục `aes_key`, `nonce`, `tag`.
   * Đọc 32 bit tiếp theo để xác định độ dài `ciphertext`, kiểm tra chống tràn bộ nhớ.
   * Trích xuất `ciphertext` và giải mã xác thực qua `decrypt_and_verify()`. Nếu sai khóa hoặc tệp âm thanh bị chỉnh sửa dù chỉ 1 bit, hệ thống sẽ từ chối và báo lỗi ngay lập tức.

---

## 3. Hướng dẫn cài đặt môi trường

### Bước 1: Tạo và kích hoạt môi trường ảo (`.venv`)
Mở Terminal tại thư mục gốc của dự án và chạy lệnh:

* **Trên Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  ```
* **Trên Windows (Command Prompt):**
  ```cmd
  python -m venv .venv
  .venv\Scripts\activate
  ```
* **Trên macOS / Linux:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

### Bước 2: Cài đặt thư viện
Khi đầu dòng lệnh xuất hiện `(.venv)`, tiến hành cài đặt các gói phụ thuộc:

```bash
pip install -r requirements.txt
```
*(Hoặc cài trực tiếp: `pip install pycryptodome streamlit numpy pytest`)*

---

## 4. Hướng dẫn vận hành Demo (`app.py`)

Khởi chạy ứng dụng giao diện Web cục bộ bằng lệnh:

```bash
streamlit run app.py
```

Trình duyệt sẽ tự động mở tại địa chỉ `http://localhost:8501` với 4 phân khu chức năng:

1. **Bước 1: Tạo Khóa (Người Nhận)**
   * Tải lên một tệp `.wav` (PCM 16-bit) làm vật chứa.
   * Bấm **Sinh Khóa & Nhúng Public Key** để tạo `RSA_keys/private_key.pem` và tải về tệp `public_key_carrier.wav`.
2. **Bước 2: Mã Hóa & Giấu Tin (Người Gửi)**
   * Tải lên tệp `public_key_carrier.wav` ở Bước 1.
   * Nhập thông điệp văn bản UTF-8 hoặc tải lên tệp tin bất kỳ (`.txt`, `.jpg`, `.pdf`...).
   * Bấm **Mã Hóa & Giấu Tin**. Hệ thống tự động kiểm tra sức chứa, xuất tệp `encrypted_sound.wav`, hiển thị chỉ số **SNR (dB)**, **thời gian thực thi** và trình phát nhạc đối chiếu trực tiếp.
3. **Bước 3: Trích Xuất & Giải Mã (Người Nhận)**
   * Tải lên tệp `encrypted_sound.wav` và chọn `private_key.pem`.
   * Nhập phần mở rộng tệp đầu ra (mặc định `txt`) và bấm **Trích Xuất & Giải Mã**.
4. **Bước 4: Đối Chiếu & Nghiệm Thu (SRS)**
   * Tự động so sánh từng byte giữa dữ liệu gốc ở Bước 2 và dữ liệu khôi phục ở Bước 3 để tính tỷ lệ lỗi **CER (%)** và xác nhận trạng thái **PASS/FAIL**.

---

## 5. Tiêu chí nghiệm thu & Giới hạn kỹ thuật

### Ngưỡng đạt chuẩn (Acceptance Criteria)
* **Toàn vẹn dữ liệu (`AC-01`):** `CER = 0.00%`, dữ liệu sau giải mã trùng khớp 100% từng byte với dữ liệu gốc.
* **Chất lượng âm học (`AC-02`):** Chỉ số tín hiệu trên nhiễu `SNR > 60 dB`, không có tiếng rè hoặc méo tiếng khi nghe đối chiếu.
* **Tính tương thích (`AC-03`):** Tệp Stego WAV mở và phát bình thường trên VLC, Windows Media Player, Audacity và Sonic Visualiser.
* **Hiệu năng (`AC-04`):** Thời gian Encode/Decode `< 2.0 giây` đối với tệp âm thanh 3 phút và văn bản dưới 5.000 từ.

### Giới hạn phạm vi
* **Định dạng đầu vào:** Chỉ hỗ trợ WAV không nén (Linear PCM 16-bit). Hệ thống sẽ từ chối các tệp WAV 8-bit, 24-bit hoặc tệp nén suy hao (MP3, AAC).
* **Tính bền vững:** Dữ liệu nhúng LSB nhạy cảm với các phép biến đổi tín hiệu (nén lại sang MP3, thay đổi âm lượng, cắt ghép hoặc chuyển đổi tần số lấy mẫu).
