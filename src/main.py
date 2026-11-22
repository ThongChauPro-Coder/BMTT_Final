import wave as w
import os
import numpy as np
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

os.makedirs('outputs', exist_ok=True)
os.makedirs('RSA_keys', exist_ok=True)

def bytes_to_bits(data_bytes):
    return ''.join(format(b, '08b') for b in data_bytes)

def bits_to_bytes(bits_str):
    return bytes(int(bits_str[i:i+8], 2) for i in range(0, len(bits_str), 8))

def validate_wav(sound_ref):
 
    try:
        with w.open(sound_ref, 'rb') as sound:
            params = sound.getparams()
            if params.comptype != 'NONE' or params.sampwidth != 2:
                raise ValueError(f"Định dạng không hỗ trợ: Yêu cầu WAV PCM 16-bit (File hiện tại: {params.sampwidth*8}-bit, nén: {params.comptype}).")
            return params
    except w.Error:
        raise ValueError("Tệp tải lên không phải định dạng RIFF/WAVE hợp lệ.")

def calculate_snr(cover_path, stego_path):
   
    with w.open(cover_path, 'rb') as f1, w.open(stego_path, 'rb') as f2:
        s1 = np.frombuffer(f1.readframes(f1.getnframes()), dtype=np.int16).astype(np.float64)
        s2 = np.frombuffer(f2.readframes(f2.getnframes()), dtype=np.int16).astype(np.float64)
    
    noise = s1 - s2
    noise_power = np.sum(noise ** 2)
    if noise_power == 0:
        return float('inf')
    signal_power = np.sum(s1 ** 2)
    return 10 * np.log10(signal_power / noise_power)

def calculate_cer(orig_bytes, rec_bytes):

    if orig_bytes == rec_bytes:
        return 0.0
    max_len = max(len(orig_bytes), len(rec_bytes))
    if max_len == 0:
        return 0.0
    diffs = sum(a != b for a, b in zip(orig_bytes, rec_bytes)) + abs(len(orig_bytes) - len(rec_bytes))
    return (diffs / max_len) * 100.0

# --- 1. Sinh Khóa RSA & Nhúng Public Key ---
def generate_and_hide_public_key(sound_ref, out_sound_ref='outputs/public_key_carrier.wav'):
    params = validate_wav(sound_ref)
    
    key = RSA.generate(2048)
    private_key = key.export_key(format='DER')
    public_key = key.publickey().export_key(format='DER')
    
    with open('RSA_keys/private_key.pem', 'wb') as f:
        f.write(private_key)

    with w.open(sound_ref, 'rb') as sound:
        sound_data = bytearray(sound.readframes(sound.getnframes()))

    pub_bits = bytes_to_bits(public_key)
    pub_len = len(pub_bits)
    
    if (32 + pub_len) > len(sound_data) // 2:
        raise ValueError("File âm thanh quá ngắn để chứa Public Key RSA-2048!")

    len_bits = format(pub_len, '032b')
    idx = 0
    for bit in len_bits:
        sound_data[idx] = (sound_data[idx] & 254) | int(bit)
        idx += 2

    for bit in pub_bits:
        sound_data[idx] = (sound_data[idx] & 254) | int(bit)
        idx += 2

    with w.open(out_sound_ref, 'wb') as out_sound:
        out_sound.setparams(params)
        out_sound.writeframes(sound_data)
    return out_sound_ref

# --- 2. Trích xuất Public Key ---
def extract_public_key(sound_ref):
    validate_wav(sound_ref)
    with w.open(sound_ref, 'rb') as sound:
        sound_data = bytearray(sound.readframes(sound.getnframes()))

    len_bits = ''.join(str(sound_data[i] & 1) for i in range(0, 64, 2))
    pub_len = int(len_bits, 2)
    
    if pub_len <= 0 or (64 + pub_len * 2) > len(sound_data):
        raise ValueError("Không tìm thấy Public Key hợp lệ trong file âm thanh này.")

    pub_bits = ''.join(str(sound_data[i] & 1) for i in range(64, 64 + pub_len * 2, 2))
    return bits_to_bytes(pub_bits)

# --- 3. Mã hóa & Giấu Tin Mật ---
def encoding_secure(carrier_key_sound, plain_bytes, output_sound_ref='outputs/encrypted_sound.wav'):
    params = validate_wav(carrier_key_sound)
    public_key_der = extract_public_key(carrier_key_sound)
    public_key = RSA.importKey(public_key_der)

    # Mã hóa AES-GCM
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plain_bytes)
    nonce = cipher_aes.nonce

    # Mã hóa RSA cho khóa phiên
    combined_keys = aes_key + nonce + tag
    cipher_rsa = PKCS1_OAEP.new(public_key)
    rsa_encrypted_bytes = cipher_rsa.encrypt(combined_keys)

    rsa_encrypted_bits = bytes_to_bits(rsa_encrypted_bytes)
    ciphertext_bits = bytes_to_bits(ciphertext)
    size_bits = format(len(ciphertext_bits), '032b')

    with w.open(carrier_key_sound, 'rb') as sound:
        sound_data = bytearray(sound.readframes(sound.getnframes()))

    total_bits_needed = len(rsa_encrypted_bits) + len(size_bits) + len(ciphertext_bits)
    max_capacity_bits = len(sound_data) // 2

    # Kiểm tra sức chứa TRƯỚC khi ghi (FR-10, FR-11)
    if total_bits_needed > max_capacity_bits:
        raise OverflowError(f"Vượt quá sức chứa! Cần {total_bits_needed} bits nhưng file WAV chỉ chứa tối đa {max_capacity_bits} bits.")

    full_bits = rsa_encrypted_bits + size_bits + ciphertext_bits
    idx = 0
    for bit in full_bits:
        sound_data[idx] = (sound_data[idx] & 254) | int(bit)
        idx += 2

    with w.open(output_sound_ref, 'wb') as out_sound:
        out_sound.setparams(params)
        out_sound.writeframes(sound_data)
    return output_sound_ref, total_bits_needed, max_capacity_bits

# --- 4. Giải Mã & Khôi Phục ---
def decoding_secure(encrypted_sound_ref, private_key_der):
    validate_wav(encrypted_sound_ref)
    private_key = RSA.importKey(private_key_der)

    with w.open(encrypted_sound_ref, 'rb') as sound:
        sound_data = bytearray(sound.readframes(sound.getnframes()))

    if len(sound_data) < 4160:
        raise ValueError("File âm thanh quá ngắn, không chứa dữ liệu mã hóa.")

    # 1. Trích xuất RSA Encrypted Keys (2048 bits)
    rsa_bits = ''.join(str(sound_data[i] & 1) for i in range(0, 4096, 2))
    rsa_encrypted_bytes = bits_to_bytes(rsa_bits)

    cipher_rsa = PKCS1_OAEP.new(private_key)
    combined_keys = cipher_rsa.decrypt(rsa_encrypted_bytes)
    
    aes_key = combined_keys[0:16]
    nonce = combined_keys[16:32]
    tag = combined_keys[32:48]

    # 2. Trích xuất độ dài Ciphertext (32 bits)
    size_bits = ''.join(str(sound_data[i] & 1) for i in range(4096, 4160, 2))
    ciphertext_len = int(size_bits, 2)

    if ciphertext_len <= 0 or (4160 + ciphertext_len * 2) > len(sound_data) or ciphertext_len % 8 != 0:
        raise ValueError("Header độ dài dữ liệu không hợp lệ hoặc file đã bị hỏng.")

    # 3. Trích xuất và giải mã Ciphertext
    ciphertext_bits = ''.join(str(sound_data[i] & 1) for i in range(4160, 4160 + ciphertext_len * 2, 2))
    ciphertext = bits_to_bytes(ciphertext_bits)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_bytes
