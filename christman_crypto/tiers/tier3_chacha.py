"""
Tier 3 — STREAM: ChaCha20-Poly1305
====================================
ChaCha20 stream cipher + Poly1305 authentication tag.

Designed by Daniel J. Bernstein as a faster, safer alternative to AES
on hardware without AES-NI acceleration. Used by TLS 1.3, SSH, WireGuard.

Key:   256-bit (32 bytes)
Nonce:  96-bit (12 bytes) — randomly generated per message
Tag:   128-bit (16 bytes) — Poly1305 authentication

Bundle format: nonce(12) || ciphertext || tag(16)

Note: For even larger nonce safety margins, see the PQ layer's
XChaCha20 (192-bit nonce). ChaCha20-Poly1305 here uses the standard
IETF 96-bit nonce variant from RFC 8439.

Dependencies: cryptography >= 41.0
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class ChaChaCipher:
    """ChaCha20-Poly1305 authenticated stream encryption."""

    KEY_SIZE   = 32
    NONCE_SIZE = 12

    def __init__(self, key: bytes = None):
        if key is None:
            key = os.urandom(self.KEY_SIZE)
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"ChaCha20 key must be {self.KEY_SIZE} bytes.")
        self._key    = key
        self._cipher = ChaCha20Poly1305(key)

    @property
    def key(self) -> bytes:
        return self._key

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)

    def encrypt(self, plaintext: bytes, aad: bytes = None) -> bytes:
        """
        Encrypt and authenticate plaintext.
        Returns: nonce(12) || ciphertext || tag(16)
        """
        nonce = os.urandom(self.NONCE_SIZE)
        ct    = self._cipher.encrypt(nonce, plaintext, aad)
        return nonce + ct

    def decrypt(self, bundle: bytes, aad: bytes = None) -> bytes:
        """
        Decrypt and verify. Raises InvalidTag on tamper.
        """
        if len(bundle) < self.NONCE_SIZE + 16:
            raise ValueError("Bundle too short.")
        nonce = bundle[:self.NONCE_SIZE]
        ct    = bundle[self.NONCE_SIZE:]
        return self._cipher.decrypt(nonce, ct, aad)
