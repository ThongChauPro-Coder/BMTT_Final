import streamlit as st
import time
import os
from main import (
    generate_and_hide_public_key,
    encoding_secure,
    decoding_secure,
    calculate_snr,
    calculate_cer
)

st.set_page_config(page_title="Audio Steganography Demo", page_icon="🔊", layout="wide")

st.title("🔊 Hệ Thống Giấu Tin Trong Âm Thanh (Hybrid RSA + AES-GCM + LSB)")
st.markdown("**Đồ án môn Bảo mật Thông tin** | Hỗ trợ định dạng: `WAV PCM 16-bit`")

# Tạo thư mục tạm cho phiên làm việc UI
os.makedirs("temp_ui", exist_ok=True)

tab1, tab2, tab3, tab4 = st.tabs([
    "🔑 Bước 1: Tạo Khóa (Người Nhận)",
    "🔒 Bước 2: Mã Hóa & Giấu Tin (Người Gửi)",
    "🔓 Bước 3: Trích Xuất & Giải Mã (Người Nhận)",
    "📊 Bước 4: Đối Chiếu & Nghiệm Thu (SRS)"
])

# ================= TAB 1: TẠO KHÓA =================
with tab1:
    st.header("1. Sinh cặp khóa RSA-2048 & Nhúng Public Key")
    st.info("Người nhận chọn một file âm thanh WAV gốc để giấu Public Key vào đó, đồng thời giữ lại Private Key.")
    
    cover_wav = st.file_uploader("Chọn file WAV làm vật chứa khóa (.wav)", type=["wav"], key="tab1_wav")
    
    if st.button("🚀 Sinh Khóa & Nhúng Public Key", type="primary"):
        if cover_wav is None:
            st.warning("Vui lòng tải lên một file WAV trước!")
        else:
            try:
                in_path = "temp_ui/cover_for_key.wav"
                out_path = "outputs/public_key_carrier.wav"
                with open(in_path, "wb") as f:
                    f.write(cover_wav.getbuffer())
                
                t0 = time.perf_counter()
                generate_and_hide_public_key(in_path, out_path)
                elapsed = time.perf_counter() - t0
                
                st.success(f"✅ Hoàn tất trong **{elapsed:.3f}s**! Private Key đã lưu tại `RSA_keys/private_key.pem`.")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Âm thanh gốc:**")
                    st.audio(in_path)
                with col2:
                    st.write("**Âm thanh đã nhúng Public Key:**")
                    st.audio(out_path)
                    with open(out_path, "rb") as f:
                        st.download_button("⬇️ Tải file WAV mang Public Key", f, file_name="public_key_carrier.wav")
            except Exception as e:
                st.error(f"❌ Lỗi: {e}")

# ================= TAB 2: GIẤU TIN =================
with tab2:
    st.header("2. Mã hóa dữ liệu bằng AES-GCM & Nhúng LSB")
    
    col_left, col_right = st.columns(2)
    with col_left:
        carrier_wav = st.file_uploader("1. Tải lên file WAV mang Public Key", type=["wav"], key="tab2_wav")
    with col_right:
        input_mode = st.radio("2. Chọn loại dữ liệu mật cần giấu:", ["Nhập văn bản trực tiếp", "Tải lên tệp tin (TXT, Ảnh, PDF...)"])
        
        plain_bytes = None
        if input_mode == "Nhập văn bản trực tiếp":
            secret_text = st.text_area("Nhập thông điệp bí mật (Hỗ trợ tiếng Việt UTF-8):", height=100)
            if secret_text:
                plain_bytes = secret_text.encode("utf-8")
        else:
            secret_file = st.file_uploader("Chọn tệp tin bí mật", key="tab2_file")
            if secret_file:
                plain_bytes = secret_file.read()

    if st.button("🔐 Mã Hóa & Giấu Tin Vào Âm Thanh", type="primary"):
        if carrier_wav is None or not plain_bytes:
            st.warning("Vui lòng cung cấp đủ file WAV và dữ liệu bí mật!")
        else:
            try:
                carrier_path = "temp_ui/carrier_in.wav"
                stego_path = "outputs/encrypted_sound.wav"
                with open(carrier_path, "wb") as f:
                    f.write(carrier_wav.getbuffer())
                
                # Lưu lại bản gốc để đối chiếu CER ở Tab 4
                with open("temp_ui/original_secret.bin", "wb") as f:
                    f.write(plain_bytes)

                t0 = time.perf_counter()
                _, used_bits, max_bits = encoding_secure(carrier_path, plain_bytes, stego_path)
                elapsed = time.perf_counter() - t0
                snr_val = calculate_snr(carrier_path, stego_path)

                st.success("✅ Đã mã hóa và nhúng tin thành công!")
                
                # Hiển thị các chỉ số nghiệm thu theo SRS (AC-02, AC-04)
                m1, m2, m3 = st.columns(3)
                m1.metric("Thời gian xử lý (Mục tiêu < 2.0s)", f"{elapsed:.4f} s", delta="Đạt" if elapsed < 2.0 else "Chậm")
                m2.metric("Chỉ số SNR (Mục tiêu > 60 dB)", f"{snr_val:.2f} dB", delta="Đạt" if snr_val > 60 else "Thấp")
                m3.metric("Dung lượng đã dùng", f"{(used_bits/max_bits)*100:.2f}%", f"{used_bits}/{max_bits} bits")

                st.divider()
                c1, c2 = st.columns(2)
                with c1:
                    st.write("**Nghe thử Cover WAV (Trước khi giấu):**")
                    st.audio(carrier_path)
                with c2:
                    st.write("**Nghe thử Stego WAV (Sau khi giấu):**")
                    st.audio(stego_path)
                    with open(stego_path, "rb") as f:
                        st.download_button("⬇️ Tải file Stego WAV kết quả", f, file_name="encrypted_sound.wav")

            except Exception as e:
                st.error(f"❌ Thất bại: {e}")

# ================= TAB 3: GIẢI MÃ =================
with tab3:
    st.header("3. Trích xuất LSB & Giải mã xác thực")
    
    c1, c2 = st.columns(2)
    with c1:
        stego_in = st.file_uploader("1. Chọn file Stego WAV cần giải mã", type=["wav"], key="tab3_wav")
    with c2:
        key_source = st.radio("2. Nguồn Private Key:", ["Dùng khóa mặc định (RSA_keys/private_key.pem)", "Tải lên file Private Key khác"])
        priv_key_bytes = None
        if key_source == "Dùng khóa mặc định (RSA_keys/private_key.pem)":
            if os.path.exists("RSA_keys/private_key.pem"):
                with open("RSA_keys/private_key.pem", "rb") as f:
                    priv_key_bytes = f.read()
                st.caption("✔️ Đã tìm thấy Private Key cục bộ.")
            else:
                st.warning("⚠️ Chưa có Private Key cục bộ. Hãy chạy Bước 1 hoặc tải khóa lên.")
        else:
            uploaded_key = st.file_uploader("Tải lên file Private Key (.pem)", key="tab3_key")
            if uploaded_key:
                priv_key_bytes = uploaded_key.read()

    out_ext = st.text_input("Đuôi file muốn lưu sau khi giải mã (ví dụ: txt, jpg, pdf, png):", value="txt")

    if st.button("🔓 Trích Xuất & Giải Mã", type="primary"):
        if stego_in is None or priv_key_bytes is None:
            st.warning("Vui lòng chọn file Stego WAV và cung cấp Private Key!")
        else:
            try:
                stego_in_path = "temp_ui/stego_to_decode.wav"
                with open(stego_in_path, "wb") as f:
                    f.write(stego_in.getbuffer())

                t0 = time.perf_counter()
                recovered_bytes = decoding_secure(stego_in_path, priv_key_bytes)
                elapsed = time.perf_counter() - t0

                out_file = f"outputs/retrieved_file.{out_ext.strip('.')}"
                with open(out_file, "wb") as f:
                    f.write(recovered_bytes)
                with open("temp_ui/recovered_secret.bin", "wb") as f:
                    f.write(recovered_bytes)

                st.success(f"✅ Giải mã & Xác thực toàn vẹn AES-GCM thành công trong **{elapsed:.4f}s**!")
                
                # Nếu là văn bản UTF-8 thì hiển thị trực tiếp lên màn hình
                try:
                    decoded_text = recovered_bytes.decode("utf-8")
                    st.text_area("Nội dung văn bản khôi phục được:", value=decoded_text, height=120)
                except UnicodeDecodeError:
                    st.info("Dữ liệu khôi phục là tệp nhị phân (ảnh/tài liệu). Hãy bấm nút bên dưới để tải về.")

                with open(out_file, "rb") as f:
                    st.download_button(f"⬇️ Tải xuống file khôi phục ({out_file})", f, file_name=f"retrieved_file.{out_ext.strip('.')}")

            except Exception as e:
                st.error(f"❌ Giải mã thất bại (Sai Private Key hoặc file âm thanh đã bị sửa đổi): {e}")

# ================= TAB 4: BÁO CÁO NGHIỆM THU =================
with tab4:
    st.header("4. Kiểm chứng tiêu chí nghiệm thu (Acceptance Criteria)")
    st.write("Đối chiếu tự động dữ liệu gốc ở **Bước 2** và dữ liệu khôi phục ở **Bước 3** theo Mục 8.1 của SRS.")

    if os.path.exists("temp_ui/original_secret.bin") and os.path.exists("temp_ui/recovered_secret.bin"):
        with open("temp_ui/original_secret.bin", "rb") as f1, open("temp_ui/recovered_secret.bin", "rb") as f2:
            b_orig = f1.read()
            b_rec = f2.read()
        
        cer = calculate_cer(b_orig, b_rec)
        is_exact = (b_orig == b_rec)

        col1, col2, col3 = st.columns(3)
        col1.metric("Kích thước gốc", f"{len(b_orig)} bytes")
        col2.metric("Kích thước khôi phục", f"{len(b_rec)} bytes")
        col3.metric("Tỷ lệ lỗi CER (Mục tiêu 0%)", f"{cer:.2f}%", delta="PASS (Toàn vẹn 100%)" if is_exact else "FAIL")
    else:
        st.info("Hãy thực hiện xong **Bước 2 (Giấu tin)** và **Bước 3 (Giải mã)** để xem bảng đối chiếu tự động tại đây.")
