"""
Tier 6 — SIGNATURES: RSA-PSS Digital Signatures
=================================================
Non-repudiation: prove who sent something and that it wasn't changed.

RSA-PSS (Probabilistic Signature Scheme) with SHA-256 hashing.
PSS is the modern, provably secure RSA signature scheme (superior to
the older PKCS#1 v1.5). Used in TLS certificates, code signing, email.

What signatures give you:
  • Authenticity  — message came from the holder of the private key
  • Integrity     — any modification to the message invalidates the signature
  • Non-repudiation — signer cannot later deny signing it

What they do NOT give you:
  • Confidentiality — the message is still readable; combine with encryption

For forensic work: a signed document is a COMMITMENT. The signature
is evidence that cannot be forged without the private key.

Dependencies: cryptography >= 41.0
"""

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class DigitalSigner:
    """RSA-PSS-4096 digital signatures."""

    KEY_SIZE = 4096

    def __init__(self, private_key=None, public_key=None):
        self._private_key = private_key
        self._public_key  = public_key

    @classmethod
    def generate_keypair(cls) -> "DigitalSigner":
        """Generate a fresh signing keypair."""
        priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=cls.KEY_SIZE,
        )
        return cls(private_key=priv, public_key=priv.public_key())

    @classmethod
    def from_pem(cls, private_pem: bytes = None,
                 public_pem: bytes = None) -> "DigitalSigner":
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

    def _pss(self):
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )

    def sign(self, message: bytes) -> bytes:
        """Sign message with private key. Returns signature bytes."""
        if self._private_key is None:
            raise RuntimeError("No private key loaded.")
        return self._private_key.sign(message, self._pss(), hashes.SHA256())

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify signature against message using public key.
        Returns True if valid, False if invalid (never raises).
        """
        if self._public_key is None:
            raise RuntimeError("No public key loaded.")
        try:
            self._public_key.verify(signature, message, self._pss(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False
