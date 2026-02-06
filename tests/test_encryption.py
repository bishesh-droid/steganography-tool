import unittest
from unittest.mock import patch, MagicMock
from Crypto.Random import get_random_bytes

from steganography_tool.encryption import encrypt_message, decrypt_message, AES_BLOCK_SIZE

class TestEncryption(unittest.TestCase):

    def setUp(self):
        self.password = "mysecretpassword"
        self.message = b"This is a very secret message that needs to be hidden."
        # Mock the logger
        patch('steganography_tool.encryption.stego_logger').start()
        self.addCleanup(patch.stopall)

    def test_encrypt_decrypt_message(self):
        encrypted_payload = encrypt_message(self.message, self.password)
        decrypted_message = decrypt_message(encrypted_payload, self.password)
        self.assertEqual(decrypted_message, self.message)

    def test_decrypt_with_wrong_password(self):
        encrypted_payload = encrypt_message(self.message, self.password)
        with self.assertRaises(ValueError) as cm:
            decrypt_message(encrypted_payload, "wrongpassword")
        self.assertIn("Incorrect password or corrupted data", str(cm.exception))

    def test_decrypt_with_corrupted_payload(self):
        encrypted_payload = encrypt_message(self.message, self.password)
        # Corrupt the last byte of the ciphertext to reliably break PKCS7 padding
        corrupted_payload = bytearray(encrypted_payload)
        corrupted_payload[-1] ^= 0x01

        with self.assertRaises(ValueError) as cm:
            decrypt_message(bytes(corrupted_payload), self.password)
        self.assertIn("Incorrect password or corrupted data", str(cm.exception))

    def test_different_salts_for_same_message_password(self):
        encrypted_payload1 = encrypt_message(self.message, self.password)
        encrypted_payload2 = encrypt_message(self.message, self.password)

        # Salts should be different
        salt1 = encrypted_payload1[:16]
        salt2 = encrypted_payload2[:16]
        self.assertNotEqual(salt1, salt2)

        # Decrypted messages should be the same
        decrypted1 = decrypt_message(encrypted_payload1, self.password)
        decrypted2 = decrypt_message(encrypted_payload2, self.password)
        self.assertEqual(decrypted1, self.message)
        self.assertEqual(decrypted2, self.message)

    def test_empty_message(self):
        empty_message = b""
        encrypted_payload = encrypt_message(empty_message, self.password)
        decrypted_message = decrypt_message(encrypted_payload, self.password)
        self.assertEqual(decrypted_message, empty_message)

if __name__ == '__main__':
    unittest.main()