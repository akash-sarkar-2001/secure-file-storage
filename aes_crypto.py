from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file_data(file_data: bytes):
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(12)   # GCM IV length
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return {
        "ciphertext": ciphertext,
        "key": key.hex(),
        "iv": iv.hex(),
        "tag": tag.hex()
    }

def decrypt_file_data(ciphertext: bytes, key_hex: str, iv_hex: str, tag_hex: str):
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    tag = bytes.fromhex(tag_hex)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)
