from __future__ import annotations

import hashlib
import io
import os
import re
import tempfile
from pathlib import Path

import matplotlib.pyplot as plt
import streamlit as st

from main import (
    calculate_cer,
    calculate_snr,
    decoding_secure,
    encoding_secure,
    generate_rsa_key_pair,
    plot_audio_comparison,
)

st.set_page_config(
    page_title="Audio Steganography | Secure Demo",
    page_icon="🔊",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
    <style>
    .stApp { background: #0b1020; color: #e8edf7; }
    [data-testid="stHeader"] { background: rgba(11,16,32,0.85); }
    .block-container { max-width: 1450px; padding-top: 1.7rem; padding-bottom: 3rem; }
    [data-testid="stSidebar"] { background: #10182b; border-right: 1px solid #26334d; }
    [data-testid="stMetric"] {
        background: #121d32; border: 1px solid #263650;
        border-radius: 14px; padding: 14px 16px;
    }
    [data-testid="stMetricLabel"] { color: #a9b8d0; }
    [data-testid="stMetricValue"] { color: #f3f6fc; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        background: #121d32; border: 1px solid #263650;
        border-radius: 10px 10px 0 0; padding: 10px 16px;
    }
    .stTabs [aria-selected="true"] { background: #20385d; }
    div[data-testid="stFileUploader"] section {
        background: #111b2e; border: 1px dashed #49617f; border-radius: 12px;
    }
    div.stButton > button, div.stDownloadButton > button {
        border-radius: 10px; min-height: 2.7rem; font-weight: 650;
    }
    .hero {
        padding: 1.35rem 1.5rem; border-radius: 18px;
        background: linear-gradient(115deg, #172944 0%, #17213a 55%, #241d3d 100%);
        border: 1px solid #344866; margin-bottom: 1rem;
    }
    .hero-kicker { color: #9db7dc; font-size: .82rem; letter-spacing: .08em; text-transform: uppercase; }
    .hero-title { color: #f7f9ff; font-size: 1.8rem; font-weight: 800; margin: .25rem 0; }
    .hero-sub { color: #c2cde0; margin: 0; }
    .small-note { color: #9eacc2; font-size: .88rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


SESSION_DEFAULTS = {
    "public_key_pem": None,
    "private_key_pem": None,
    "original_secret": None,
    "original_secret_name": "secret.bin",
    "carrier_audio": None,
    "stego_audio": None,
    "plot_png": None,
    "encode_metrics": None,
    "recovered_secret": None,
    "recovered_name": "retrieved_file.bin",
    "decode_seconds": None,
}
for key, value in SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value

with st.sidebar:
    st.markdown("## 🔊 Audio Steganography")
    st.caption("Đồ án môn Bảo mật Thông tin")
    st.divider()
    st.markdown("**Công nghệ sử dụng**")
    st.markdown("- RSA-2048 / OAEP-SHA256\n- AES-256-GCM\n- LSB trên WAV PCM 16-bit\n- Streamlit, NumPy, Matplotlib")
    st.divider()
    st.markdown("**Luồng xử lý**")
    st.markdown("1. Tạo cặp khóa RSA\n2. Mã hóa và nhúng tin\n3. Trích xuất và giải mã\n4. Đối chiếu nghiệm thu")
    st.caption("Khuyến nghị chạy local cho demo học thuật. Không triển khai công khai nếu chưa có xác thực người dùng và bảo vệ hạ tầng.")

st.markdown(
    """
    <div class="hero">
      <div class="hero-kicker">Information Security · Final Demo</div>
      <div class="hero-title">🔊 Hệ thống giấu tin trong âm thanh</div>
      <p class="hero-sub">Hybrid Encryption: RSA-2048 + AES-256-GCM · Audio Steganography: LSB</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    "<p class='small-note'>Định dạng đầu vào: WAV RIFF · PCM 16-bit · Public Key và Private Key được quản lý tách biệt với file âm thanh.</p>",
    unsafe_allow_html=True,
)

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "🔑 01 · Khởi tạo khóa",
        "🔒 02 · Mã hóa & giấu tin",
        "🔓 03 · Trích xuất & giải mã",
        "📊 04 · Kiểm thử & nghiệm thu",
    ]
)

with tab1:
    st.header("Khởi tạo cặp khóa RSA-2048")
    st.write(
        "Người nhận tạo cặp khóa. Public Key được chia sẻ cho người gửi; "
        "Private Key phải được giữ bí mật và chỉ người nhận sử dụng."
    )

    left, right = st.columns([1.05, 0.95], gap="large")
    with left:
        with st.container(border=True):
            st.subheader("Thiết lập bảo vệ Private Key")
            key_password = st.text_input(
                "Mật khẩu mã hóa Private Key",
                type="password",
                key="new_key_password",
                help="Tối thiểu 12 ký tự. Mật khẩu này dùng để bảo vệ file Private Key PEM khi lưu trữ.",
            )
            key_password_confirm = st.text_input(
                "Xác nhận mật khẩu",
                type="password",
                key="new_key_password_confirm",
            )
            create_keys = st.button("✨ Tạo cặp khóa RSA", type="primary", use_container_width=True)
            if create_keys:
                if len(key_password) < 12:
                    st.error("Mật khẩu cần có ít nhất 12 ký tự.")
                elif key_password != key_password_confirm:
                    st.error("Hai mật khẩu không trùng khớp.")
                else:
                    try:
                        public_pem, private_pem = generate_rsa_key_pair(key_password)
                        st.session_state.public_key_pem = public_pem
                        st.session_state.private_key_pem = private_pem
                        st.session_state.original_secret = None
                        st.session_state.carrier_audio = None
                        st.session_state.stego_audio = None
                        st.session_state.plot_png = None
                        st.session_state.encode_metrics = None
                        st.session_state.recovered_secret = None
                        st.session_state.decode_seconds = None
                        st.success("Đã tạo cặp khóa RSA-2048 thành công.")
                    except Exception as exc:
                        st.error(f"Không thể tạo khóa: {exc}")

    with right:
        with st.container(border=True):
            st.subheader("Nguyên tắc quản lý khóa")
            st.markdown(
                "**Public Key**\n\n"
                "- Có thể gửi cho người gửi.\n"
                "- Dùng để mã hóa khóa phiên AES.\n\n"
                "**Private Key**\n\n"
                "- Không chia sẻ cho người gửi.\n"
                "- Được mã hóa bằng mật khẩu trước khi tải xuống.\n"
                "- Cần sao lưu an toàn để giải mã về sau."
            )

    if st.session_state.public_key_pem and st.session_state.private_key_pem:
        fingerprint = hashlib.sha256(st.session_state.public_key_pem).hexdigest().upper()
        st.divider()
        st.subheader("Cặp khóa hiện tại")
        st.success("Cặp khóa đã sẵn sàng trong phiên làm việc này.")
        st.code("SHA-256 fingerprint: " + ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)))
        key_col1, key_col2 = st.columns(2)
        with key_col1:
            st.download_button(
                "⬇️ Tải Public Key (.pem)",
                data=st.session_state.public_key_pem,
                file_name="public_key.pem",
                mime="application/x-pem-file",
                use_container_width=True,
                key="download_public_key",
            )
        with key_col2:
            st.download_button(
                "⬇️ Tải Private Key đã mã hóa (.pem)",
                data=st.session_state.private_key_pem,
                file_name="private_key_encrypted.pem",
                mime="application/x-pem-file",
                use_container_width=True,
                key="download_private_key",
            )
        st.warning("Hãy lưu Private Key và mật khẩu ở nơi an toàn. Nếu mất một trong hai, bạn có thể không giải mã được dữ liệu.")
    else:
        st.info("Chưa có cặp khóa trong phiên làm việc. Hãy tạo khóa ở khung bên trái.")

with tab2:
    st.header("Mã hóa dữ liệu và nhúng vào WAV")
    st.caption("Bạn có thể dùng WAV PCM 16-bit thông thường. File WAV không cần chứa Public Key.")

    col_audio, col_key = st.columns(2, gap="large")
    with col_audio:
        with st.container(border=True):
            st.subheader("1. File âm thanh vật mang tin")
            carrier_upload = st.file_uploader(
                "Tải WAV PCM 16-bit",
                type=["wav"],
                key="carrier_upload",
                help="Đây là âm thanh gốc (Cover WAV), không cần nhúng Public Key từ trước.",
            )
    with col_key:
        with st.container(border=True):
            st.subheader("2. Public Key của người nhận")
            key_options = ["Tải Public Key .pem lên"]
            if st.session_state.public_key_pem:
                key_options.insert(0, "Dùng Public Key tạo ở Bước 1")
            public_key_source = st.radio(
                "Nguồn Public Key",
                key_options,
                key="public_key_source",
            )
            public_key_data = None
            if public_key_source == "Dùng Public Key tạo ở Bước 1":
                public_key_data = st.session_state.public_key_pem
                st.success("Đang sử dụng Public Key của phiên hiện tại.")
            else:
                public_upload = st.file_uploader(
                    "Chọn Public Key (.pem)",
                    type=["pem", "pub", "key"],
                    key="public_key_upload",
                )
                if public_upload is not None:
                    public_key_data = public_upload.getvalue()
                    st.success("Đã nhận Public Key.")

    st.divider()
    st.subheader("3. Dữ liệu bí mật cần giấu")
    input_mode = st.radio(
        "Chọn loại dữ liệu",
        ["Văn bản UTF-8", "Tệp tin bất kỳ"],
        horizontal=True,
        key="secret_input_mode",
    )
    plain_bytes = None
    secret_name = "secret.txt"
    if input_mode == "Văn bản UTF-8":
        secret_text = st.text_area(
            "Nhập thông điệp bí mật",
            height=130,
            placeholder="Nhập nội dung cần mã hóa và giấu trong âm thanh...",
            key="secret_text_input",
        )
        if secret_text:
            plain_bytes = secret_text.encode("utf-8")
    else:
        secret_upload = st.file_uploader(
            "Tải tệp cần giấu (TXT, PDF, PNG, JPG, DOCX, ...)",
            key="secret_file_upload",
        )
        if secret_upload is not None:
            plain_bytes = secret_upload.getvalue()
            secret_name = Path(secret_upload.name).name
            st.caption(f"Tệp đã chọn: {secret_name} · {len(plain_bytes):,} bytes")

    if st.button("🔐 Mã hóa và giấu tin", type="primary", use_container_width=True, key="run_encode"):
      
        st.session_state.encode_metrics = None
        st.session_state.stego_audio = None
        st.session_state.plot_png = None
        st.session_state.recovered_secret = None
        if carrier_upload is None:
            st.error("Vui lòng tải lên file WAV vật mang tin.")
        elif public_key_data is None:
            st.error("Vui lòng cung cấp Public Key của người nhận.")
        elif plain_bytes is None or len(plain_bytes) == 0:
            st.error("Vui lòng nhập văn bản hoặc chọn tệp có dữ liệu.")
        else:
            try:
                carrier_bytes = carrier_upload.getvalue()
                with tempfile.TemporaryDirectory() as temp_dir:
                    carrier_path = os.path.join(temp_dir, "cover.wav")
                    stego_path = os.path.join(temp_dir, "stego.wav")
                    with open(carrier_path, "wb") as file_obj:
                        file_obj.write(carrier_bytes)

                    start_time = __import__("time").perf_counter()
                    _, used_bits, capacity_bits = encoding_secure(
                        carrier_path,
                        plain_bytes,
                        public_key_data,
                        stego_path,
                    )
                    elapsed = __import__("time").perf_counter() - start_time
                    snr_value = calculate_snr(carrier_path, stego_path)
                    with open(stego_path, "rb") as file_obj:
                        stego_bytes = file_obj.read()

                    fig = plot_audio_comparison(carrier_path, stego_path, zoom_samples=250)
                    image_buffer = io.BytesIO()
                    fig.savefig(image_buffer, format="png", dpi=150, bbox_inches="tight")
                    plt.close(fig)
                    plot_png = image_buffer.getvalue()

                st.session_state.original_secret = bytes(plain_bytes)
                st.session_state.original_secret_name = secret_name
                st.session_state.carrier_audio = carrier_bytes
                st.session_state.stego_audio = stego_bytes
                st.session_state.plot_png = plot_png
                st.session_state.recovered_secret = None
                st.session_state.encode_metrics = {
                    "seconds": elapsed,
                    "snr": snr_value,
                    "used_bits": used_bits,
                    "capacity_bits": capacity_bits,
                }
                st.success("Mã hóa và nhúng LSB hoàn tất.")
            except Exception as exc:
                st.error(f"Không thể mã hóa/nhúng dữ liệu: {exc}")

    if st.session_state.encode_metrics and st.session_state.stego_audio:
        metrics = st.session_state.encode_metrics
        st.divider()
        st.subheader("Kết quả mã hóa")
        m1, m2, m3 = st.columns(3)
        m1.metric(
            "Thời gian Encode",
            f"{metrics['seconds']:.4f} s",
            "Đạt" if metrics["seconds"] < 2.0 else "Vượt ngưỡng 2 giây",
        )
        snr_display = "∞" if metrics["snr"] == float("inf") else f"{metrics['snr']:.2f} dB"
        m2.metric(
            "SNR",
            snr_display,
            "Đạt" if metrics["snr"] > 60 else "Dưới 60 dB",
        )
        usage = metrics["used_bits"] / metrics["capacity_bits"] * 100 if metrics["capacity_bits"] else 0
        m3.metric("Dung lượng đã sử dụng", f"{usage:.2f}%", f"{metrics['used_bits']:,}/{metrics['capacity_bits']:,} bit")

        audio_col1, audio_col2 = st.columns(2)
        with audio_col1:
            st.markdown("**Cover WAV · Trước khi nhúng**")
            st.audio(st.session_state.carrier_audio, format="audio/wav")
        with audio_col2:
            st.markdown("**Stego WAV · Sau khi nhúng**")
            st.audio(st.session_state.stego_audio, format="audio/wav")
            st.download_button(
                "⬇️ Tải file Stego WAV",
                data=st.session_state.stego_audio,
                file_name="stego_audio.wav",
                mime="audio/wav",
                use_container_width=True,
                key="download_stego_audio",
            )
        with st.expander("📈 Xem biểu đồ so sánh tín hiệu"):
            st.image(st.session_state.plot_png, use_container_width=True)

with tab3:
    st.header("Trích xuất LSB và giải mã")
    st.write("Chọn file Stego WAV cùng Private Key tương ứng với Public Key đã dùng khi mã hóa.")

    decode_left, decode_right = st.columns(2, gap="large")
    with decode_left:
        with st.container(border=True):
            st.subheader("1. File Stego WAV")
            stego_upload = st.file_uploader(
                "Tải file âm thanh đã giấu tin",
                type=["wav"],
                key="stego_upload_decode",
            )
    with decode_right:
        with st.container(border=True):
            st.subheader("2. Private Key của người nhận")
            private_options = ["Tải Private Key .pem lên"]
            if st.session_state.private_key_pem:
                private_options.insert(0, "Dùng Private Key tạo ở Bước 1")
            private_source = st.radio(
                "Nguồn Private Key",
                private_options,
                key="private_key_source",
            )
            private_key_data = None
            if private_source == "Dùng Private Key tạo ở Bước 1":
                private_key_data = st.session_state.private_key_pem
                st.success("Đang sử dụng Private Key đã tạo trong phiên này.")
            else:
                private_upload = st.file_uploader(
                    "Chọn Private Key (.pem)",
                    type=["pem", "key"],
                    key="private_key_upload",
                )
                if private_upload is not None:
                    private_key_data = private_upload.getvalue()
                    st.success("Đã nhận Private Key.")

    private_password = st.text_input(
        "Mật khẩu mở khóa Private Key (nếu file được mã hóa)",
        type="password",
        key="private_key_password_decode",
    )
    output_filename = st.text_input(
        "Tên file sau khi khôi phục",
        value="retrieved_file.bin",
        key="decoded_output_filename",
        help="Chỉ dùng tên file, không nhập đường dẫn thư mục.",
    )

    if st.button("🔓 Trích xuất và giải mã", type="primary", use_container_width=True, key="run_decode"):
        st.session_state.recovered_secret = None
        st.session_state.decode_seconds = None
        if stego_upload is None:
            st.error("Vui lòng tải lên file Stego WAV.")
        elif private_key_data is None:
            st.error("Vui lòng cung cấp Private Key.")
        else:
            safe_name = Path(output_filename).name
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", safe_name).strip("._")
            if not safe_name:
                safe_name = "retrieved_file.bin"
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    stego_path = os.path.join(temp_dir, "input_stego.wav")
                    with open(stego_path, "wb") as file_obj:
                        file_obj.write(stego_upload.getvalue())
                    start_time = __import__("time").perf_counter()
                    recovered = decoding_secure(
                        stego_path,
                        private_key_data,
                        passphrase=private_password or None,
                    )
                    decode_seconds = __import__("time").perf_counter() - start_time

                st.session_state.recovered_secret = recovered
                st.session_state.recovered_name = safe_name
                st.session_state.decode_seconds = decode_seconds
                st.success("Giải mã RSA và xác thực AES-GCM thành công.")
            except Exception as exc:
                st.error(f"Giải mã thất bại: {exc}")

    if st.session_state.recovered_secret is not None:
        st.divider()
        st.subheader("Dữ liệu đã khôi phục")
        d1, d2 = st.columns(2)
        d1.metric("Dung lượng khôi phục", f"{len(st.session_state.recovered_secret):,} bytes")
        d2.metric("Thời gian Decode", f"{st.session_state.decode_seconds:.4f} s")
        st.download_button(
            "⬇️ Tải dữ liệu đã khôi phục",
            data=st.session_state.recovered_secret,
            file_name=st.session_state.recovered_name,
            mime="application/octet-stream",
            use_container_width=True,
            key="download_recovered_file",
        )
        try:
            recovered_text = st.session_state.recovered_secret.decode("utf-8")
            if all(char.isprintable() or char in "\r\n\t" for char in recovered_text):
                st.text_area("Nội dung văn bản khôi phục", value=recovered_text, height=150, disabled=True)
            else:
                st.info("Dữ liệu khôi phục là tệp nhị phân. Hãy tải tệp xuống để mở bằng ứng dụng phù hợp.")
        except UnicodeDecodeError:
            st.info("Dữ liệu khôi phục là tệp nhị phân. Hãy tải tệp xuống để mở bằng ứng dụng phù hợp.")

with tab4:
    st.header("Kiểm thử và nghiệm thu")
    st.write("Đối chiếu dữ liệu trước khi mã hóa với dữ liệu sau khi giải mã.")

    original_for_compare = st.session_state.original_secret
    recovered_for_compare = st.session_state.recovered_secret

    if original_for_compare is not None and recovered_for_compare is not None:
        st.caption("Đang đối chiếu dữ liệu được tạo và khôi phục trong cùng phiên làm việc.")
    else:
        st.info("Nếu bạn giải mã ở một phiên khác, hãy tải lên bản gốc và bản đã khôi phục để thực hiện đối chiếu.")
        compare_col1, compare_col2 = st.columns(2)
        with compare_col1:
            original_upload = st.file_uploader("Tải dữ liệu gốc", key="compare_original_upload")
        with compare_col2:
            recovered_upload = st.file_uploader("Tải dữ liệu đã khôi phục", key="compare_recovered_upload")
        if original_upload is not None and recovered_upload is not None:
            original_for_compare = original_upload.getvalue()
            recovered_for_compare = recovered_upload.getvalue()

    if original_for_compare is not None and recovered_for_compare is not None:
        is_exact = original_for_compare == recovered_for_compare
        error_rate = calculate_cer(original_for_compare, recovered_for_compare)
        c1, c2, c3 = st.columns(3)
        c1.metric("Dung lượng dữ liệu gốc", f"{len(original_for_compare):,} bytes")
        c2.metric("Dung lượng khôi phục", f"{len(recovered_for_compare):,} bytes")
        c3.metric("Tỷ lệ sai lệch", f"{error_rate:.4f}%", "PASS" if is_exact else "FAIL")

        if is_exact:
            st.success("PASS · Dữ liệu khôi phục trùng khớp 100% với dữ liệu gốc.")
        else:
            st.error("FAIL · Dữ liệu khôi phục có sai lệch so với dữ liệu gốc.")

        st.dataframe(
            [
                {"Tiêu chí": "Khôi phục chính xác", "Kết quả": "PASS" if is_exact else "FAIL", "Ngưỡng": "100% trùng khớp"},
                {"Tiêu chí": "Tỷ lệ sai lệch", "Kết quả": f"{error_rate:.4f}%", "Ngưỡng": "0%"},
                {
                    "Tiêu chí": "SNR của quá trình nhúng",
                    "Kết quả": (
                        f"{st.session_state.encode_metrics['snr']:.2f} dB"
                        if st.session_state.encode_metrics and st.session_state.encode_metrics["snr"] != float("inf")
                        else ("∞" if st.session_state.encode_metrics else "Chưa có dữ liệu")
                    ),
                    "Ngưỡng": "> 60 dB",
                },
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("Cần có cả dữ liệu gốc và dữ liệu khôi phục để chạy kiểm thử toàn vẹn.")

    st.divider()
    st.markdown("**Lưu ý về chỉ số:** Hàm `calculate_cer` trong demo tính tỷ lệ sai lệch theo vị trí ký tự UTF-8 (hoặc byte đối với tệp nhị phân), phù hợp với công thức đơn giản trong SRS. Đây không phải CER theo khoảng cách chỉnh sửa Levenshtein.")
