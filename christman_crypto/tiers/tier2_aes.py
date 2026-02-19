"""
Tier 2 — SYMMETRIC: AES-256-GCM
================================
AES-256 in Galois/Counter Mode.

GCM provides authenticated encryption — it not only encrypts the data
but produces a 128-bit authentication tag. Any tampering with the
ciphertext or the associated data is detected on decryption.

Key size: 256 bits (32 bytes) — maximum AES key length.
Nonce:    96 bits (12 bytes) — randomly generated per message.
Tag:      128 bits (16 bytes) — authentication.

Bundle format: nonce(12) || ciphertext || tag(16)

Dependencies: cryptography >= 41.0
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESCipher:
    """AES-256-GCM authenticated encryption."""

    KEY_SIZE   = 32   # 256-bit key
    NONCE_SIZE = 12   # 96-bit nonce (GCM standard)

    def __init__(self, key: bytes = None):
        """
        Pass a 32-byte key, or omit to auto-generate one.
        Store the key securely — loss means permanent data loss.
        """
        if key is None:
            key = os.urandom(self.KEY_SIZE)
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-256 key must be {self.KEY_SIZE} bytes.")
        self._key  = key
        self._aesgcm = AESGCM(key)

    @property
    def key(self) -> bytes:
        return self._key

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)

    def encrypt(self, plaintext: bytes, aad: bytes = None) -> bytes:
        """
        Encrypt and authenticate.
        aad = Additional Authenticated Data (encrypted in tag, not in body).
        Returns: nonce || ciphertext+tag
        """
        nonce = os.urandom(self.NONCE_SIZE)
        ct    = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct

    def decrypt(self, bundle: bytes, aad: bytes = None) -> bytes:
        """
        Decrypt and verify authentication tag.
        Raises cryptography.exceptions.InvalidTag if tampered.
        """
        if len(bundle) < self.NONCE_SIZE + 16:
            raise ValueError("Bundle too short.")
        nonce = bundle[:self.NONCE_SIZE]
        ct    = bundle[self.NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ct, aad)
