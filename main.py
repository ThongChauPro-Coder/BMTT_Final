import wave as w
import os

# Đọc file hình ảnh và chuyển thành chuỗi bits
def img_to_bits(path):
    with open(path, 'rb') as img_file:
        img_data = img_file.read()
        return ''.join(format(data, '08b') for data in img_data)

# Chuyển từ chuỗi bits thành file hình ảnh
def bits_to_img(bits):
    with open('outputs/retrive_img.jpg', 'wb') as img_file:
        img_file.write(bits)
    print("Đã tạo file 'retrive_img.jpg' thành công")

# Đọc file txt và chuyển thành chuỗi bits
def text_to_bytes(path):
    with open(path, "r", encoding="utf-8") as text_file:
        content = text_file.read()

    byte = content.encode('utf-8')    # Chuyển từ plain text sang dạng số theo bảng mã utf-8

    return byte    # Chuyển từ dãy số sang dạng dãy số nhị phân với 8 bits

# Chuyển từ chuỗi bits thành file txt
def bits_to_text(bits):
    with open('outputs/retrive_text.txt', 'wb') as text_file:
        text_file.write(bits)
    print("Đã tạo file 'retrive_text.txt' ở folder 'outputs' thành công.")

def AES_encode(byte, KEY=16):
  key = get_random_bytes(KEY)

  cipher = AES.new(key, AES.MODE_GCM)

  ciphertext, tag = cipher.encrypt_and_digest(byte)
  nonce = cipher.nonce

  return ''.join(format(byte, '08b') for byte in ciphertext), key, nonce, tag


#----------------------Encoding Phase----------------------

def encoding(sound_ref, data_ref, public_key, type='text', SIZE=32, AES_KEY=16, TAG=16, NONCE=16, RSA_KEY=2048):
  sound = w.open(sound_ref, 'rb')

  sound_data = bytearray(sound.readframes(sound.getnframes()))

  if type == 'image':
    plain_data = img_to_bits(data_ref)

  elif type == 'text':
    plain_data = text_to_bits(data_ref)

  cipherbit, key, nonce, tag = AES_encode(plain_data, AES_KEY)
  combined = key + nonce + tag

  key_encrypted = RSA_encrypt(combined, public_key)

  # Giấu key
  sound_index = 0
  for bit in key_encrypted:
    replace = (sound_data[sound_index] & 254) | int(bit)
    sound_data[sound_index] = replace
    sound_index += 2

  # Header Size
  size = str(format(len(cipherbit), f'0{SIZE}b'))
  sound_index = RSA_KEY*2
  for bit in size:
    replace = (sound_data[sound_index] & 254) | int(bit)
    sound_data[sound_index] = replace
    sound_index += 2


  # Stenography
  capacity = (len(sound_data) - SIZE*2 - RSA_KEY*2) // 2
  if len(cipherbit) < capacity:
    sound_index = SIZE*2 + RSA_KEY*2
    for bit in cipherbit:
      replace = (sound_data[sound_index] & 254) | int(bit)
      sound_data[sound_index] = replace
      sound_index += 2
  else:
    print(f'Độ dài của {type} vượt quá {capacity}bytes sức chứa của file .wav')

  # Tạo folder 'outputs' nếu chưa có
  os.makedirs('outputs', exist_ok=True)

  new_sound = w.open('outputs/encrypted_sound.wav', 'wb')
  new_sound.setparams(sound.getparams())
  new_sound.writeframes(sound_data)

  print("Đã tạo file 'encrypted_sound.wav' ở folder 'outputs' thành công.")

  sound.close()
  new_sound.close()



#----------------------Decoding Phase----------------------

def decoding(sound_ref, type, private_key, SIZE=32, AES_KEY=16, TAG=16, NONCE=16):
  encrypted_sound = w.open(sound_ref, 'rb')

  sound_data = bytearray(encrypted_sound.readframes(encrypted_sound.getnframes()))

  # Get Data Size
  size = [str(sound_data[i] & 1) for i in range(0, SIZE*2, 2)]
  size = int(''.join(size), 2)

  # Retrive Data
  data = [str(sound_data[i] & 1) for i in range(SIZE*2, SIZE*2 + size*2, 2)]
  data = ''.join(data)

  bits_data = bytes(int(data[i:i + 8], 2) for i in range(0, len(data), 8))

  # Tạo folder 'outputs' nếu chưa có
  os.makedirs('outputs', exist_ok=True)

  if type == 'image':
    bits_to_img(bits_data)

  elif type == 'text':
    return bits_to_text(bits_data)

  encrypted_sound.close()

encoding('sound.wav', 'text.txt', type='text')

decoding('outputs/encrypted_sound.wav', type='text')

!pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# độ dài header quy định độ dài data: 4 bytes = 32 bits
# độ dài key: 16 bytes = 128 bits
# độ dài nonce: 16 bytes = 128 bits
# độ dài tag: 16 bytes = 128 bits

# tổng: 416 bits

# RSA key: 2048 bits

text = 'thông diep bi mat looooooooooooooooooooooooo'

key = get_random_bytes(16)

cipher = AES.new(key, AES.MODE_GCM)

ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
nonce = cipher.nonce

print(f'key: {key}')
print(f'nonce: {nonce}')
print(f'ciphertext: {ciphertext}')
print(f'tag: {tag}')

print(''.join(format(byte, '08b') for byte in key))

decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

plaintext = decipher.decrypt(ciphertext)
print(type(ciphertext))

print(plaintext.decode('utf-8'))

def text_to_bits(path, KEY):
  with open(path, "r", encoding="utf-8") as text_file:
    content = text_file.read()

  encode = content.encode('utf-8')

  key = get_random_bytes(KEY)

  cipher = AES.new(key, AES.MODE_GCM)

  ciphertext, tag = cipher.encrypt_and_digest(encode)
  nonce = cipher.nonce

  return ''.join(format(word, '08b') for word in encode)

content = text_to_bits('text.txt')

def create_RSA_keys():
  key = RSA.generate(2048)

  private_key = key.export_key(format='DER')
  public_key = key.publickey().export_key(format='DER')

  # Tạo thư mục RSA_keys nếu chưa tồn tại
  os.makedirs('RSA_keys', exist_ok=True)

  # Tạo 2 file keys lưu vào RSA_keys
  with open('RSA_keys/private_key.pem', 'wb') as private_key_file:
    private_key_file.write(private_key)

  with open('RSA_keys/public_key.pem', 'wb') as public_key_file:
    public_key_file.write(public_key)

with open('text.txt', 'r') as f:
  text = f.read()

# Đọc public key từ file .pem
with open('RSA_keys/public_key.pem', 'rb') as f:
  public_key = f.read()

def RSA_encrypt(plaintext, public_key):
  # Chuyển key chuỗi bytes thành key sử dụng được
  public_key = RSA.importKey(public_key)

  cipher_encrypt = PKCS1_OAEP.new(public_key)

  ciphertext = cipher_encrypt.encrypt(plaintext)
 
  return ''.join(format(byte, '08b') for byte in ciphertext)

byte = bytes(int(bit[i:i + 8], 2) for i in range(0, len(bit), 8))

with open('RSA_keys/private_key.pem', 'rb') as f:
  private_key = f.read()

def RSA_decrypt(ciphertext, private_key):
  private_key = RSA.importKey(private_key)

  cipher_decrypt = PKCS1_OAEP.new(private_key)

  plaintext = cipher_decrypt.decrypt(ciphertext)