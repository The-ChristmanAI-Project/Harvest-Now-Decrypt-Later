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
    6  SIGNATURES   — RSA-PSS Digital Signatures (non-repudiation)
    7  STEGANOGRAPHY — LSB Text-in-Image hiding
    PQ POST-QUANTUM — ML-KEM (CRYSTALS-Kyber FIPS 203) + XChaCha20-Poly1305

Author : Everett Christman  |  The Christman AI Project
License: Apache 2.0
"""

__version__  = "1.0.0"
__author__   = "Everett Christman"
__project__  = "The Christman AI Project"

from .tiers.tier1_vigenere    import VigenereCipher
from .tiers.tier2_aes         import AESCipher
from .tiers.tier3_chacha      import ChaChaCipher
from .tiers.tier4_rsa         import RSACipher
from .tiers.tier5_hybrid      import HybridCipher
from .tiers.tier6_signatures  import DigitalSigner
from .tiers.tier7_steg        import LSBSteganography
from .postquantum             import XChaCha20Cipher, MLKEM, HybridPQCipher
from .kyber                   import KyberHandshake

__all__ = [
    "VigenereCipher",
    "AESCipher",
    "ChaChaCipher",
    "RSACipher",
    "HybridCipher",
    "DigitalSigner",
    "LSBSteganography",
    "XChaCha20Cipher",
    "MLKEM",
    "HybridPQCipher",
    "KyberHandshake",
]
