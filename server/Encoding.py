from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
import zlib

def get_crc_sum(data:bytes):
    """Calculate and return the CRC-32 checksum of the given data."""
    return zlib.crc32(data) & 0xffffffff

def rsa_encryption(public_key, aes_key):
    """Encrypt the AES key using RSA public key and return the encrypted result."""
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher.encrypt(aes_key)

def generate_aes_key():
    """Generate and return a random 16-byte AES key."""
    return get_random_bytes(16)

def aes_decryption(aes_key, data):
    """Decrypt the AES-encrypted data and return the result."""
    iv = bytearray([0] * AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def calculate_crc32(data):
    """Calculate and return the CRC-32 checksum of the given string data."""
    return get_crc_sum(data.encode())
