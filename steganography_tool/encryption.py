from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

from .logger import stego_logger

# AES block size is 16 bytes
AES_BLOCK_SIZE = AES.block_size

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a strong cryptographic key from a password and salt using PBKDF2.
    """
    # Use a high number of iterations for security
    iterations = 100000
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    return key

def encrypt_message(message: bytes, password: str) -> bytes:
    """
    Encrypts a message using AES-256 in CBC mode with a password-derived key.
    Returns the concatenated salt, IV, and ciphertext.
    """
    stego_logger.info("[*] Encrypting message...")
    # Generate a random salt
    salt = get_random_bytes(16)
    # Derive key from password and salt
    key = derive_key(password, salt)
    # Generate a random IV
    iv = get_random_bytes(AES_BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the message to be a multiple of AES_BLOCK_SIZE
    padded_message = pad(message, AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_message)

    stego_logger.info("[+] Message encrypted. Combining salt, IV, and ciphertext.")
    return salt + iv + ciphertext

def decrypt_message(encrypted_payload: bytes, password: str) -> bytes:
    """
    Decrypts an encrypted payload (salt + IV + ciphertext) using a password.
    Returns the original plaintext message.
    """
    stego_logger.info("[*] Decrypting message...")
    # Extract salt, IV, and ciphertext from the payload
    salt = encrypted_payload[:16]
    iv = encrypted_payload[16:32]
    ciphertext = encrypted_payload[32:]

    # Derive the key using the same password and extracted salt
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_padded_message = cipher.decrypt(ciphertext)
        original_message = unpad(decrypted_padded_message, AES_BLOCK_SIZE)
        stego_logger.info("[+] Message decrypted successfully.")
        return original_message
    except ValueError as e:
        stego_logger.error(f"[ERROR] Decryption failed. Incorrect password or corrupted data: {e}")
        raise ValueError("Decryption failed. Incorrect password or corrupted data.")
    except Exception as e:
        stego_logger.error(f"[ERROR] An unexpected error occurred during decryption: {e}")
        raise