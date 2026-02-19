"""
Tier 5 — HYBRID: RSA + AES-256-GCM (Envelope Encryption)
===========================================================
The best of both worlds: RSA for key exchange, AES for data.

The hybrid pattern solves RSA's biggest limitation — it can only encrypt
~446 bytes directly with a 4096-bit key. The solution: encrypt the DATA
with a random AES-256 key, then encrypt THAT key with RSA. The recipient
decrypts the AES key with their RSA private key, then decrypts the data.

This is exactly how TLS, PGP, and S/MIME work under the hood.

Bundle format:
    [4-byte AES key length][RSA-encrypted AES key][AES-GCM encrypted data]

For quantum resistance, use the PQ layer (Tier PQ) instead of this tier,
which replaces RSA with ML-KEM for the key exchange step.

Dependencies: cryptography >= 41.0
"""

import os
import struct
from .tier4_rsa import RSACipher
from .tier2_aes import AESCipher


class HybridCipher:
    """RSA-4096 + AES-256-GCM envelope encryption."""

    def __init__(self, rsa_cipher: RSACipher = None):
        """Pass an RSACipher with loaded keys, or auto-generate."""
        if rsa_cipher is None:
            rsa_cipher = RSACipher.generate_keypair()
        self._rsa = rsa_cipher

    @classmethod
    def generate(cls) -> "HybridCipher":
        return cls(RSACipher.generate_keypair())

    def export_public_pem(self) -> bytes:
        return self._rsa.export_public_pem()

    def export_private_pem(self) -> bytes:
        return self._rsa.export_private_pem()

    def encrypt(self, plaintext: bytes, aad: bytes = None) -> bytes:
        """
        Encrypt arbitrary-length plaintext.
        Only the recipient's RSA private key can decrypt.
        Returns self-contained bundle.
        """
        # 1. Generate a fresh AES-256 session key
        aes_key = AESCipher.generate_key()
        aes     = AESCipher(aes_key)

        # 2. Encrypt the data with AES-256-GCM
        encrypted_data = aes.encrypt(plaintext, aad)

        # 3. Encrypt the AES key with RSA-4096-OAEP
        encrypted_key = self._rsa.encrypt(aes_key)

        # 4. Bundle: [4-byte key_len][encrypted_key][encrypted_data]
        return struct.pack('>I', len(encrypted_key)) + encrypted_key + encrypted_data

    def decrypt(self, bundle: bytes, aad: bytes = None) -> bytes:
        """
        Decrypt a bundle produced by encrypt().
        Requires RSA private key.
        """
        if len(bundle) < 4:
            raise ValueError("Bundle too short.")
        key_len      = struct.unpack('>I', bundle[:4])[0]
        encrypted_key = bundle[4:4 + key_len]
        encrypted_data = bundle[4 + key_len:]

        # 1. Recover AES key with RSA private key
        aes_key = self._rsa.decrypt(encrypted_key)

        # 2. Decrypt data with AES-256-GCM
        aes = AESCipher(aes_key)
        return aes.decrypt(encrypted_data, aad)
