"""
Tier 1 — LEGACY: Vigenère Polyalphabetic Cipher
================================================
Enhanced with George-loop key scheduling: the key is re-derived
at each cycle using a positional hash of the previous state,
making the period effectively unbounded against Kasiski analysis.

Historical note: Blaise de Vigenère, 1553. Called "le chiffre
indéchiffrable" for 300 years. Not modern-secure, but the foundation
of every polyalphabetic cipher that followed — including stream ciphers.

Role in the stack: Legacy layer. Historical anchor. Educational baseline.
"""

import hashlib


class VigenereCipher:
    """
    Vigenère cipher with George-loop key extension.

    The George-loop prevents standard Kasiski/Friedman attacks by
    extending the key via SHA-256 hashing at each period boundary,
    so the effective key period equals the message length.
    """

    ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def __init__(self, key: str):
        if not key or not key.isalpha():
            raise ValueError("Vigenère key must be alphabetic.")
        self._base_key = key.upper()

    def _build_keystream(self, length: int) -> list:
        """
        Build a keystream of `length` integers (0-25) using
        the George-loop: re-hash the key every period to extend it.
        """
        stream = []
        current_key = self._base_key
        idx = 0
        cycle = 0
        while len(stream) < length:
            stream.append(self.ALPHA.index(current_key[idx]))
            idx += 1
            if idx >= len(current_key):
                # George-loop: derive next key segment from hash
                seed = f"{current_key}{cycle}".encode()
                digest = hashlib.sha256(seed).hexdigest().upper()
                current_key = "".join(c for c in digest if c.isalpha()) or current_key
                idx = 0
                cycle += 1
        return stream[:length]

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string. Non-alpha characters pass through."""
        text = plaintext.upper()
        alpha_only = [c for c in text if c.isalpha()]
        keystream = self._build_keystream(len(alpha_only))
        result = []
        k_idx = 0
        for ch in text:
            if ch.isalpha():
                enc = (self.ALPHA.index(ch) + keystream[k_idx]) % 26
                result.append(self.ALPHA[enc])
                k_idx += 1
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext string."""
        text = ciphertext.upper()
        alpha_only = [c for c in text if c.isalpha()]
        keystream = self._build_keystream(len(alpha_only))
        result = []
        k_idx = 0
        for ch in text:
            if ch.isalpha():
                dec = (self.ALPHA.index(ch) - keystream[k_idx]) % 26
                result.append(self.ALPHA[dec])
                k_idx += 1
            else:
                result.append(ch)
        return "".join(result)
