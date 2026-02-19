"""
Tier 4 — ASYMMETRIC: RSA-4096 + OAEP
======================================
RSA public-key encryption with OAEP padding.

RSA-4096 with OAEP (Optimal Asymmetric Encryption Padding) using
SHA-256 as the hash function. The 4096-bit key provides a strong
classical security margin (~140-bit equivalent).

WARNING: RSA is vulnerable to quantum computers running Shor's algorithm.
For long-term confidentiality, wrap RSA with the PQ layer (ML-KEM).
RSA remains appropriate for short-lived sessions and systems where
quantum threat is not yet a concern.

Use cases:
  - Encrypting small payloads (session keys, tokens)
  - Identity: verify who you're talking to
  - Step toward Tier 5 (Hybrid) and Tier 6 (Signatures)

Dependencies: cryptography >= 41.0
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from typing import Tuple


class RSACipher:
    """RSA-4096 OAEP encryption / decryption."""

    KEY_SIZE = 4096

    def __init__(self, private_key=None, public_key=None):
        """
        Pass existing keys, or call generate_keypair() to create new ones.
        """
        self._private_key = private_key
        self._public_key  = public_key

    @classmethod
    def generate_keypair(cls) -> "RSACipher":
        """Generate a fresh RSA-4096 keypair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=cls.KEY_SIZE,
        )
        return cls(private_key=private_key, public_key=private_key.public_key())

    @classmethod
    def from_pem(cls, private_pem: bytes = None,
                 public_pem: bytes = None) -> "RSACipher":
        """Load keys from PEM bytes."""
        priv = (serialization.load_pem_private_key(private_pem, password=None)
                if private_pem else None)
        pub  = (serialization.load_pem_public_key(public_pem)
                if public_pem else None)
        if priv and not pub:
            pub = priv.public_key()
        return cls(private_key=priv, public_key=pub)

    def export_public_pem(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def export_private_pem(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

    def _oaep(self):
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with recipient's public key. Max ~446 bytes for 4096-bit."""
        if self._public_key is None:
            raise RuntimeError("No public key loaded.")
        return self._public_key.encrypt(plaintext, self._oaep())

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt with private key."""
        if self._private_key is None:
            raise RuntimeError("No private key loaded.")
        return self._private_key.decrypt(ciphertext, self._oaep())
