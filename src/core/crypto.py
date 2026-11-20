from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class HybridCrypto:
    def __init__(self):
        self.aes_key = None
        self.nonce = None
        self.tag = None
        self.ciphertext = None

    def encrypt(self, plaintext):
        # Generate a random AES key
        self.aes_key = get_random_bytes(16)  # 128 bits

        # Create AES cipher in GCM mode
        cipher = AES.new(self.aes_key, AES.MODE_GCM)

        # Encrypt the plaintext and get the ciphertext and tag
        self.ciphertext, self.tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        self.nonce = cipher.nonce

    def decrypt(self):
        # Create AES cipher with the same key and nonce
        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=self.nonce)

        # Decrypt the ciphertext and verify the tag
        plaintext = cipher.decrypt_and_verify(self.ciphertext, self.tag)
        return plaintext.decode('utf-8')

    def get_aes_key(self):
        return self.aes_key

    def get_nonce(self):
        return self.nonce

    def get_tag(self):
        return self.tag

    def get_ciphertext(self):
        return self.ciphertext
    
    @staticmethod
    def encrypt_payload(raw_data: bytes, public_key_bytes: bytes) -> bytes:
        # Load the public key
        public_key = RSA.import_key(public_key_bytes)

        # Generate a random AES key
        aes_key = get_random_bytes(16)  # 128 bits

        # Create AES cipher in GCM mode
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)

        # Encrypt the raw data and get the ciphertext and tag
        ciphertext, tag = cipher_aes.encrypt_and_digest(raw_data)
        nonce = cipher_aes.nonce

        # Encrypt the AES key using RSA
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Return the concatenated result: encrypted AES key + nonce + tag + ciphertext
        return encrypted_aes_key + nonce + tag + ciphertext
    
    
    @staticmethod
    def decrypt_payload(encrypted_payload: bytes, private_key_bytes: bytes) -> bytes:
        # Load the private key
        private_key = RSA.import_key(private_key_bytes)

        # Extract the encrypted AES key, nonce, tag, and ciphertext from the payload
        encrypted_aes_key = encrypted_payload[:private_key.size_in_bytes()]
        nonce = encrypted_payload[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
        tag = encrypted_payload[private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 32]
        ciphertext = encrypted_payload[private_key.size_in_bytes() + 32:]

        # Decrypt the AES key using RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Create AES cipher with the decrypted key and nonce
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

        # Decrypt the ciphertext and verify the tag
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return plaintext