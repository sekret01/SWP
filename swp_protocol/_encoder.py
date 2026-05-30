import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from swp_protocol.exceptions import AesGcmKeyError


class AesGcmCrypto:
    NONCE_SIZE = 12

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise AesGcmKeyError(f"Длина ключа AESGCM должна быть равна 32, текущая длина: {len(key)}")
        self.aesgcm = AESGCM(key=key)


    def encode(self, payload: bytes) -> bytes:
        """ Шифровка данных """
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self.aesgcm.encrypt(nonce, payload, None)
        return nonce + ciphertext

    def decode(self, encrypted_payload: bytes) -> bytes:
        """ Расшифровка данных """
        if len(encrypted_payload) < self.NONCE_SIZE:
            raise ValueError("Invalid encrypted data")
        nonce = encrypted_payload[:self.NONCE_SIZE]
        ciphertext = encrypted_payload[self.NONCE_SIZE:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)
    