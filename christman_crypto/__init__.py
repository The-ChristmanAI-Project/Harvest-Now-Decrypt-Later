"""
christman_crypto — The Christman AI Project
============================================
Seven-tier hybrid cryptographic stack.
From Vigenère (1553) to NIST FIPS 203 post-quantum ML-KEM (2024).

Tiers:
    1  LEGACY       — Vigenère Polyalphabetic (George-loop enhanced)
    2  SYMMETRIC    — AES-256-GCM (authenticated encryption)
    3  STREAM       — ChaCha20-Poly1305 (high-speed authenticated stream)
    4  ASYMMETRIC   — RSA-4096 + OAEP (public-key encryption)
    5  HYBRID       — RSA + AES-256-GCM (envelope encryption)
    6  SIGNATURES   — RSA-PSS + optional PQ hybrid (HybridSigner)
    7  STEGANOGRAPHY — LSB Text-in-Image hiding
    PQ POST-QUANTUM — ML-KEM (CRYSTALS-Kyber FIPS 203) + XChaCha20-Poly1305

Author : Everett Christman  |  The Christman AI Project
License: Apache 2.0
"""

from __future__ import annotations

__version__ = "1.0.1"
__author__ = "Everett Christman"
__project__ = "The Christman AI Project"

from typing import Optional, Tuple

from .tiers.tier1_vigenere import VigenereCipher
from .tiers.tier2_aes import AESCipher
from .tiers.tier3_chacha import ChaChaCipher
from .tiers.tier4_rsa import RSACipher
from .tiers.tier5_hybrid import HybridCipher
from .tiers.tier6_signatures import (
    DigitalSigner,
    HybridSigner,
    OQS_AVAILABLE,
    PQSigner,
    bundle_hybrid,
    unbundle_hybrid,
)
from .tiers.tier7_steg import LSBSteganography
from .postquantum import XChaCha20Cipher, MLKEM, HybridPQCipher
from .kyber import KyberHandshake

# ── Convenience payload protectors (process-local HNDL hybrid) ───────────────
# encrypt_payload / decrypt_payload use a process-scoped ML-KEM-768 keypair.
# For multi-party or long-term key storage, use HybridPQCipher directly with
# explicit ek/dk. Rule 13: this is process-local, not a key-management service.

_process_pq: Optional[HybridPQCipher] = None
_process_ek: Optional[bytes] = None
_process_dk: Optional[bytes] = None


def _ensure_process_pq() -> Tuple[HybridPQCipher, bytes, bytes]:
    global _process_pq, _process_ek, _process_dk
    if _process_pq is None or _process_ek is None or _process_dk is None:
        _process_pq = HybridPQCipher(768)
        _process_ek, _process_dk = _process_pq.keygen()
    return _process_pq, _process_ek, _process_dk


def encrypt_payload(data: bytes) -> bytes:
    """
    Encrypt bytes with process-local ML-KEM-768 + XChaCha20-Poly1305.

    Returns a self-contained hybrid ciphertext bundle. Decrypt only works
    in the same process (or after keys were re-seeded via the same runtime).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    pq, ek, _dk = _ensure_process_pq()
    return pq.encrypt(ek, bytes(data))


def decrypt_payload(bundle: bytes) -> bytes:
    """Decrypt a bundle produced by encrypt_payload() in this process."""
    if not isinstance(bundle, (bytes, bytearray)):
        raise TypeError("bundle must be bytes")
    pq, _ek, dk = _ensure_process_pq()
    return pq.decrypt(dk, bytes(bundle))


__all__ = [
    "VigenereCipher",
    "AESCipher",
    "ChaChaCipher",
    "RSACipher",
    "HybridCipher",
    "DigitalSigner",
    "HybridSigner",
    "PQSigner",
    "OQS_AVAILABLE",
    "bundle_hybrid",
    "unbundle_hybrid",
    "LSBSteganography",
    "XChaCha20Cipher",
    "MLKEM",
    "HybridPQCipher",
    "KyberHandshake",
    "encrypt_payload",
    "decrypt_payload",
]
