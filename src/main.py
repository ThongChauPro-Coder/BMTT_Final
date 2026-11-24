from __future__ import annotations

import os
import struct
import wave
from pathlib import Path
from typing import Union

import matplotlib.pyplot as plt
import numpy as np
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

PathLike = Union[str, os.PathLike]

MAGIC = b"ASTG"
FORMAT_VERSION = 1
HEADER = struct.Struct(">4sBHQ")  
HEADER_BITS = HEADER.size * 8
AES_KEY_LEN = 32               
GCM_NONCE_LEN = 12               
GCM_TAG_LEN = 16
MIN_RSA_BITS = 2048


def generate_rsa_key_pair(passphrase: str) -> tuple[bytes, bytes]:
  
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValueError("Mật khẩu Private Key phải có ít nhất 12 ký tự.")

    key = RSA.generate(2048)
    public_key_pem = key.publickey().export_key(format="PEM")
    private_key_pem = key.export_key(
        format="PEM",
        passphrase=passphrase,
        pkcs=8,
        protection="scryptAndAES128-CBC",
    )
    return public_key_pem, private_key_pem


def _read_wav(wav_path: PathLike):
    
    try:
        with wave.open(str(wav_path), "rb") as wav_file:
            params = wav_file.getparams()
            if params.comptype != "NONE":
                raise ValueError("Chỉ hỗ trợ WAV PCM không nén.")
            if params.sampwidth != 2:
                raise ValueError(
                    f"Chỉ hỗ trợ PCM 16-bit; file hiện tại là {params.sampwidth * 8}-bit."
                )
            if params.nchannels < 1 or params.framerate <= 0 or params.nframes <= 0:
                raise ValueError("Thông số WAV không hợp lệ hoặc file không có dữ liệu âm thanh.")
            audio_data = bytearray(wav_file.readframes(params.nframes))
    except (wave.Error, EOFError) as exc:
        raise ValueError("Tệp tải lên không phải WAV RIFF hợp lệ hoặc đã bị hỏng.") from exc

    expected_length = params.nframes * params.nchannels * params.sampwidth
    if len(audio_data) != expected_length:
        raise ValueError("Dữ liệu audio không khớp với Header WAV.")
    return params, audio_data


def validate_wav(wav_path: PathLike):

    params, _ = _read_wav(wav_path)
    return params


def _write_wav(output_path: PathLike, params, audio_data: bytearray) -> str:
    output_path = str(output_path)
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with wave.open(output_path, "wb") as output_wav:
        output_wav.setparams(params)
        output_wav.writeframes(audio_data)
    return output_path


def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Độ dài chuỗi bit phải chia hết cho 8.")
    if any(bit not in "01" for bit in bits):
        raise ValueError("Chuỗi chứa ký tự không phải bit 0 hoặc 1.")
    return bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits), 8))


def _embed_bits(audio_data: bytearray, bits: str) -> None:
   
    capacity = len(audio_data) // 2
    if len(bits) > capacity:
        raise OverflowError(
            f"Không đủ sức chứa: cần {len(bits):,} bit, WAV chỉ chứa {capacity:,} bit."
        )

    for sample_index, bit in enumerate(bits):
        byte_index = sample_index * 2
        audio_data[byte_index] = (audio_data[byte_index] & 0xFE) | int(bit)


def _extract_bits(audio_data: bytearray, bit_count: int) -> str:
    capacity = len(audio_data) // 2
    if bit_count < 0 or bit_count > capacity:
        raise ValueError("Độ dài dữ liệu cần trích xuất vượt quá sức chứa của WAV.")
    return "".join(str(audio_data[index * 2] & 1) for index in range(bit_count))


def _import_public_key(public_key_data: bytes):
    try:
        public_key = RSA.import_key(public_key_data)
    except (ValueError, IndexError, TypeError) as exc:
        raise ValueError("Public Key không hợp lệ. Hãy chọn đúng tệp public_key.pem.") from exc

    if public_key.has_private():
        raise ValueError("Bước mã hóa chỉ nhận Public Key, không tải Private Key lên đây.")
    if public_key.size_in_bits() < MIN_RSA_BITS:
        raise ValueError("RSA phải có độ dài tối thiểu 2048 bit.")
    return public_key


def _import_private_key(private_key_data: bytes, passphrase: str | None):
    try:
        private_key = RSA.import_key(private_key_data, passphrase=passphrase or None)
    except (ValueError, IndexError, TypeError) as exc:
        raise ValueError(
            "Không đọc được Private Key. Hãy kiểm tra tệp PEM và mật khẩu mở khóa."
        ) from exc

    if not private_key.has_private():
        raise ValueError("Tệp được chọn không chứa Private Key.")
    if private_key.size_in_bits() < MIN_RSA_BITS:
        raise ValueError("RSA phải có độ dài tối thiểu 2048 bit.")
    return private_key


def encoding_secure(
    carrier_wav_path: PathLike,
    plain_bytes: bytes,
    public_key_data: bytes,
    output_wav_path: PathLike = "outputs/encrypted_sound.wav",
):
   
    if not isinstance(plain_bytes, (bytes, bytearray)):
        raise TypeError("Thông điệp cần mã hóa phải ở dạng bytes.")

    params, audio_data = _read_wav(carrier_wav_path)
    public_key = _import_public_key(public_key_data)
    rsa_cipher_length = public_key.size_in_bytes()

    header = HEADER.pack(MAGIC, FORMAT_VERSION, rsa_cipher_length, len(plain_bytes))

    aes_key = get_random_bytes(AES_KEY_LEN)
    nonce = get_random_bytes(GCM_NONCE_LEN)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LEN)
    aes_cipher.update(header)  
    ciphertext, tag = aes_cipher.encrypt_and_digest(bytes(plain_bytes))

    session_bundle = aes_key + nonce + tag
    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_bundle = rsa_cipher.encrypt(session_bundle)

    if len(encrypted_bundle) != rsa_cipher_length:
        raise ValueError("Kích thước dữ liệu RSA không đúng với khóa công khai.")

    payload = header + encrypted_bundle + ciphertext
    payload_bits = bytes_to_bits(payload)
    capacity_bits = len(audio_data) // 2

    if len(payload_bits) > capacity_bits:
        raise OverflowError(
            f"Vượt quá sức chứa! Cần {len(payload_bits):,} bit nhưng WAV chỉ chứa tối đa "
            f"{capacity_bits:,} bit. Hãy dùng file WAV dài hơn hoặc thông điệp nhỏ hơn."
        )

    _embed_bits(audio_data, payload_bits)
    output_path = _write_wav(output_wav_path, params, audio_data)
    return output_path, len(payload_bits), capacity_bits


def decoding_secure(
    stego_wav_path: PathLike,
    private_key_data: bytes,
    passphrase: str | None = None,
) -> bytes:
    
    params, audio_data = _read_wav(stego_wav_path)
    capacity_bits = len(audio_data) // 2
    if capacity_bits < HEADER_BITS:
        raise ValueError("File WAV quá ngắn, không chứa Header của dữ liệu giấu.")

    header_bytes = bits_to_bytes(_extract_bits(audio_data, HEADER_BITS))
    try:
        magic, version, rsa_length, ciphertext_length = HEADER.unpack(header_bytes)
    except struct.error as exc:
        raise ValueError("Không đọc được Header dữ liệu giấu.") from exc

    if magic != MAGIC:
        raise ValueError("Không tìm thấy dữ liệu của hệ thống Audio Steganography trong WAV.")
    if version != FORMAT_VERSION:
        raise ValueError(f"Phiên bản dữ liệu không được hỗ trợ: {version}.")
    if rsa_length <= 0 or rsa_length > 1024:
        raise ValueError("Độ dài khối RSA trong Header không hợp lệ.")

    total_payload_bytes = HEADER.size + rsa_length + ciphertext_length
    total_payload_bits = total_payload_bytes * 8
    if total_payload_bits > capacity_bits:
        raise ValueError("Header khai báo dữ liệu vượt quá sức chứa hoặc file WAV đã bị sửa.")
    if ciphertext_length == 0:
        raise ValueError("Thông điệp mã hóa rỗng hoặc Header không hợp lệ.")

    private_key = _import_private_key(private_key_data, passphrase)
    if rsa_length != private_key.size_in_bytes():
        raise ValueError("Private Key không khớp với độ dài khóa RSA đã dùng khi mã hóa.")

    payload = bits_to_bytes(_extract_bits(audio_data, total_payload_bits))
    header = payload[:HEADER.size]
    rsa_start = HEADER.size
    rsa_end = rsa_start + rsa_length
    encrypted_bundle = payload[rsa_start:rsa_end]
    ciphertext = payload[rsa_end:]

    try:
        rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        session_bundle = rsa_cipher.decrypt(encrypted_bundle)
    except (ValueError, TypeError) as exc:
        raise ValueError("Giải mã RSA thất bại: Private Key không đúng hoặc dữ liệu đã bị thay đổi.") from exc

    expected_bundle_len = AES_KEY_LEN + GCM_NONCE_LEN + GCM_TAG_LEN
    if len(session_bundle) != expected_bundle_len:
        raise ValueError("Gói khóa phiên AES không hợp lệ.")

    aes_key = session_bundle[:AES_KEY_LEN]
    nonce_start = AES_KEY_LEN
    nonce_end = nonce_start + GCM_NONCE_LEN
    nonce = session_bundle[nonce_start:nonce_end]
    tag = session_bundle[nonce_end:]

    try:
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LEN)
        aes_cipher.update(header)
        return aes_cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError(
            "Xác thực AES-GCM thất bại: file WAV có thể đã bị chỉnh sửa, hỏng hoặc không đúng dữ liệu."
        ) from exc


def calculate_snr(cover_path: PathLike, stego_path: PathLike) -> float:
  
    params1, data1 = _read_wav(cover_path)
    params2, data2 = _read_wav(stego_path)
    if params1 != params2 or len(data1) != len(data2):
        raise ValueError("Hai file WAV không cùng thông số hoặc độ dài để tính SNR.")

    original = np.frombuffer(data1, dtype="<i2").astype(np.float64)
    modified = np.frombuffer(data2, dtype="<i2").astype(np.float64)
    noise_power = float(np.sum((original - modified) ** 2))
    signal_power = float(np.sum(original ** 2))

    if noise_power == 0:
        return float("inf")
    if signal_power == 0:
        return float("-inf")
    return float(10.0 * np.log10(signal_power / noise_power))


def calculate_cer(original_bytes: bytes, recovered_bytes: bytes) -> float:

    try:
        original = original_bytes.decode("utf-8")
        recovered = recovered_bytes.decode("utf-8")
    except UnicodeDecodeError:
        original = original_bytes
        recovered = recovered_bytes

    denominator = max(len(original), 1)
    mismatches = sum(a != b for a, b in zip(original, recovered))
    mismatches += abs(len(original) - len(recovered))
    return (mismatches / denominator) * 100.0



def plot_audio_comparison(
    cover_path: PathLike,
    stego_path: PathLike,
    zoom_samples: int = 200,
):
    _, cover_data = _read_wav(cover_path)
    _, stego_data = _read_wav(stego_path)

    cover = np.frombuffer(cover_data, dtype="<i2").astype(np.int32)
    stego = np.frombuffer(stego_data, dtype="<i2").astype(np.int32)

    if len(cover) != len(stego):
        raise ValueError("Hai tín hiệu không cùng số lượng mẫu.")

    if len(cover) == 0:
        raise ValueError("Tín hiệu âm thanh không có mẫu.")

    total_samples = len(cover)
    count = max(1, min(int(zoom_samples), total_samples))

    x_values = np.arange(count)
    difference = stego[:count] - cover[:count]
    full_difference = stego - cover

    changed_indices_all = np.flatnonzero(full_difference)
    changed_samples = len(changed_indices_all)
    max_difference = int(np.max(np.abs(full_difference)))
    mse = float(np.mean(full_difference.astype(np.float64) ** 2))

    embed_end_idx = int(changed_indices_all[-1]) if changed_samples > 0 else 0

    overview_step = max(1, total_samples // 5000)
    overview_x = np.arange(0, total_samples, overview_step)

    fig, axes = plt.subplots(4, 1, figsize=(14, 13), facecolor="white")

    axes[0].plot(
        x_values, cover[:count],
        label="Cover WAV (Gốc)", color="#1f77b4", linewidth=1.5
    )
    axes[0].plot(
        x_values, stego[:count],
        label="Stego WAV (Đã nhúng)", color="#ff7f0e", linestyle="--", linewidth=1.2
    )
    axes[0].set_title(f"1. So sánh dạng sóng trước và sau khi nhúng ({count} mẫu đầu)", fontweight="bold")
    axes[0].set_ylabel("Biên độ mẫu")
    axes[0].set_xlim(0, count - 1)
    axes[0].legend(loc="upper right")
    axes[0].grid(True, alpha=0.3)

    axes[1].step(
        x_values, difference, where="mid",
        label="Sai khác (Stego - Cover)", color="#2ca02c", linewidth=1.2
    )
    axes[1].axhline(0, color="black", linewidth=0.8)
    axes[1].set_ylim(-1.5, 1.5)
    axes[1].set_yticks([-1, 0, 1])
    axes[1].set_xlim(0, count - 1)
    axes[1].set_title("2. Sai khác biên độ giữa hai tín hiệu (Phóng đại mức ±1 LSB)", fontweight="bold")
    axes[1].set_ylabel("Chênh lệch")
    axes[1].legend(loc="upper right")
    axes[1].grid(True, alpha=0.3)

    changed_indices_zoom = np.flatnonzero(difference)
    if len(changed_indices_zoom) > 0:
        axes[2].stem(
            changed_indices_zoom,
            difference[changed_indices_zoom],
            linefmt="C1-",
            markerfmt="C1o",
            basefmt="k-"
        )
    else:
        axes[2].axhline(0, color="black", linewidth=0.8)

    axes[2].set_title("3. Vị trí chính xác các mẫu bị tác động bit LSB", fontweight="bold")
    axes[2].set_ylabel("Chênh lệch")
    axes[2].set_ylim(-1.5, 1.5)
    axes[2].set_yticks([-1, 0, 1])
    axes[2].set_xlim(0, count - 1)
    axes[2].grid(True, alpha=0.3)

    axes[3].plot(
        overview_x, cover[overview_x],
        label="Cover WAV", color="#1f77b4", linewidth=0.7
    )
    axes[3].plot(
        overview_x, stego[overview_x],
        label="Stego WAV", color="#ff7f0e", linewidth=0.7, alpha=0.7
    )
    if embed_end_idx > 0:
        axes[3].axvspan(
            0, embed_end_idx, color="red", alpha=0.15,
            label=f"Vùng chứa dữ liệu nhúng (Mẫu 0 → {embed_end_idx:,})"
        )
    axes[3].set_title("4. Tổng quan tín hiệu trên toàn bộ file và phạm vi nhúng tin", fontweight="bold")
    axes[3].set_xlabel("Chỉ số mẫu (Sample Index)")
    axes[3].set_ylabel("Biên độ mẫu")
    axes[3].set_xlim(0, total_samples)
    axes[3].legend(loc="upper right")
    axes[3].grid(True, alpha=0.3)

    fig.suptitle(
        f"ĐÁNH GIÁ TRỰC QUAN AUDIO STEGANOGRAPHY (LSB)\n"
        f"Số mẫu thay đổi: {changed_samples:,} / {total_samples:,} ({changed_samples/total_samples*100:.2f}%)  |  "
        f"Sai khác tối đa: {max_difference}  |  MSE: {mse:.6f}",
        fontsize=12,
        fontweight="bold",
        color="#111111"
    )

    fig.tight_layout(rect=[0, 0, 1, 0.94])
    return fig
