"""
Tier 6 — SIGNATURES: RSA-PSS + optional Post-Quantum Hybrid
=============================================================
Non-repudiation: prove who sent something and that it wasn't changed.

Classical baseline: RSA-PSS-4096 with SHA-256 (cryptography library).
Optional PQ: ML-DSA / Falcon via liboqs (`oqs` package) when installed.

Hybrid mode signs with BOTH classical and PQ, and verifies BOTH.
This is the authenticity clock (Shor forges RSA). Confidentiality against
Harvest Now, Decrypt Later is the ML-KEM seal in postquantum.py, not this file.

Dependencies:
  cryptography >= 41.0   (required — RSA-PSS)
  oqs                    (optional — Dilithium / Falcon)

Rule 13: If oqs is missing, HybridSigner degrades to classical RSA-PSS
with an explicit `pq_available=False` flag — never pretends PQ is active.
"""

from __future__ import annotations

import logging
import struct
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger(__name__)

try:
    import oqs  # type: ignore

    OQS_AVAILABLE = True
except ImportError:
    oqs = None  # type: ignore
    OQS_AVAILABLE = False
    logger.info(
        "Tier 6: oqs not installed — PQ signatures unavailable. "
        "Classical RSA-PSS remains fully functional. "
        "Install with: pip install oqs  (or christman-crypto[pq-sig])"
    )


# ────────────────────────────────────────────────
# Classical baseline: RSA-PSS-4096
# ────────────────────────────────────────────────

class DigitalSigner:
    """RSA-PSS-4096 digital signatures with SHA-256 hashing."""

    KEY_SIZE = 4096

    def __init__(self, private_key=None, public_key=None):
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate_keypair(cls) -> "DigitalSigner":
        """Generate a fresh signing keypair."""
        priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=cls.KEY_SIZE,
        )
        return cls(private_key=priv, public_key=priv.public_key())

    @classmethod
    def from_pem(
        cls,
        private_pem: bytes = None,
        public_pem: bytes = None,
    ) -> "DigitalSigner":
        priv = (
            serialization.load_pem_private_key(private_pem, password=None)
            if private_pem
            else None
        )
        pub = (
            serialization.load_pem_public_key(public_pem)
            if public_pem
            else None
        )
        if priv and not pub:
            pub = priv.public_key()
        return cls(private_key=priv, public_key=pub)

    def export_public_pem(self) -> bytes:
        if self._public_key is None:
            raise RuntimeError("No public key loaded.")
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_pem(self) -> bytes:
        if self._private_key is None:
            raise RuntimeError("No private key loaded.")
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def _pss(self):
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,  # explicit for FIPS / consistency
        )

    def sign(self, message: bytes) -> bytes:
        if self._private_key is None:
            raise RuntimeError("No private key loaded.")
        return self._private_key.sign(message, self._pss(), hashes.SHA256())

    def verify(self, message: bytes, signature: bytes) -> bool:
        if self._public_key is None:
            raise RuntimeError("No public key loaded.")
        try:
            self._public_key.verify(
                signature, message, self._pss(), hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


# ────────────────────────────────────────────────
# Post-quantum signer (optional — requires oqs)
# ────────────────────────────────────────────────

# Friendly aliases → liboqs mechanism names (ML-DSA = Dilithium NIST names)
_PQ_ALIASES = {
    "Dilithium5": "ML-DSA-87",
    "Dilithium3": "ML-DSA-65",
    "Dilithium2": "ML-DSA-44",
    "ML-DSA-87": "ML-DSA-87",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-44": "ML-DSA-44",
    "Falcon-1024": "Falcon-1024",
    "Falcon-512": "Falcon-512",
}


class PQSigner:
    """
    Pure post-quantum signer: ML-DSA (Dilithium) or Falcon (FN-DSA).

    Requires the `oqs` package (liboqs Python bindings).
    Raises RuntimeError if oqs is not installed.
    """

    def __init__(self, algo: str = "Dilithium5"):
        if not OQS_AVAILABLE:
            raise RuntimeError(
                "PQ signatures require the 'oqs' package. "
                "Install with: pip install oqs"
            )
        supported = list(oqs.get_enabled_sig_mechanisms())
        self.algo = _PQ_ALIASES.get(algo, algo)
        if self.algo not in supported:
            # Fallback: try legacy Dilithium names if ML-DSA not present
            legacy = {
                "ML-DSA-87": "Dilithium5",
                "ML-DSA-65": "Dilithium3",
                "ML-DSA-44": "Dilithium2",
            }.get(self.algo)
            if legacy and legacy in supported:
                self.algo = legacy
            else:
                raise ValueError(
                    f"Algorithm {self.algo!r} not available. "
                    f"Enabled: {supported}"
                )
        self._sig = oqs.Signature(self.algo)
        self.public_key: Optional[bytes] = None
        self.secret_key: Optional[bytes] = None

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate and store a keypair. Returns (public_key, secret_key)."""
        self.public_key = self._sig.generate_keypair()
        self.secret_key = self._sig.export_secret_key()
        return self.public_key, self.secret_key

    def sign(self, message: bytes, secret_key: Optional[bytes] = None) -> bytes:
        sk = secret_key if secret_key is not None else self.secret_key
        if sk is None:
            raise RuntimeError("No PQ secret key — call keygen() first.")
        signer = oqs.Signature(self.algo, sk)
        return signer.sign(message)

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: Optional[bytes] = None,
    ) -> bool:
        pk = public_key if public_key is not None else self.public_key
        if pk is None:
            raise RuntimeError("No PQ public key provided.")
        verifier = oqs.Signature(self.algo)
        return bool(verifier.verify(message, signature, pk))


# ────────────────────────────────────────────────
# Hybrid bundle format
# ────────────────────────────────────────────────

# magic | classic_len(u32) | classic_sig | pq_len(u32) | pq_sig
_HYBRID_MAGIC = b"HNDL6\x00"


def bundle_hybrid(classic_sig: bytes, pq_sig: bytes) -> bytes:
    """Length-prefixed hybrid: magic | classic | pq."""
    return (
        _HYBRID_MAGIC
        + struct.pack(">I", len(classic_sig))
        + classic_sig
        + struct.pack(">I", len(pq_sig))
        + pq_sig
    )


def unbundle_hybrid(hybrid: bytes) -> Tuple[bytes, bytes]:
    """Unpack hybrid signature. Raises ValueError if malformed."""
    if not hybrid.startswith(_HYBRID_MAGIC):
        raise ValueError("Not a hybrid HNDL Tier-6 signature.")
    off = len(_HYBRID_MAGIC)
    if len(hybrid) < off + 4:
        raise ValueError("Hybrid signature truncated.")
    classic_len = struct.unpack(">I", hybrid[off : off + 4])[0]
    off += 4
    classic = hybrid[off : off + classic_len]
    off += classic_len
    if len(hybrid) < off + 4:
        raise ValueError("Hybrid signature truncated (pq length).")
    pq_len = struct.unpack(">I", hybrid[off : off + 4])[0]
    off += 4
    pq = hybrid[off : off + pq_len]
    if len(pq) != pq_len:
        raise ValueError("Hybrid signature truncated (pq body).")
    return classic, pq


def is_hybrid_signature(signature: bytes) -> bool:
    return signature.startswith(_HYBRID_MAGIC)


# ────────────────────────────────────────────────
# Hybrid Signer (Classical + optional PQ)
# ────────────────────────────────────────────────

class HybridSigner:
    """
    Tier 6 hybrid: RSA-PSS + optional post-quantum signature.

    Parameters
    ----------
    use_pq : bool
        Request PQ layer. If True but oqs is missing, degrades to classical
        with pq_available=False (Rule 13 — honest).
    pq_algo : str
        PQ algorithm alias (default Dilithium5 / ML-DSA-87).
    classic : DigitalSigner, optional
        Existing classical keypair; otherwise generated.
    """

    def __init__(
        self,
        use_pq: bool = True,
        pq_algo: str = "Dilithium5",
        classic: Optional[DigitalSigner] = None,
    ):
        self.classic = classic or DigitalSigner.generate_keypair()
        self.pq_requested = use_pq
        self.pq_available = bool(use_pq and OQS_AVAILABLE)
        self.pq: Optional[PQSigner] = None
        self._pq_pk: Optional[bytes] = None
        self._pq_sk: Optional[bytes] = None

        if use_pq and not OQS_AVAILABLE:
            logger.warning(
                "HybridSigner: PQ requested but oqs not installed — "
                "operating classical-only (pq_available=False)."
            )
        elif self.pq_available:
            self.pq = PQSigner(pq_algo)
            self._pq_pk, self._pq_sk = self.pq.keygen()

    @property
    def mode(self) -> str:
        return "hybrid_rsa_pss_pq" if self.pq_available else "classical_rsa_pss"

    def keygen(self) -> dict:
        """
        Export the keys currently on this instance.

        Does not mint a new pair. Construct a new HybridSigner to rotate.
        """
        return {
            "mode": self.mode,
            "classic_public_pem": self.classic.export_public_pem(),
            "classic_private_pem": self.classic.export_private_pem(),
            "pq_public": self._pq_pk,
            "pq_secret": self._pq_sk,
            "pq_available": self.pq_available,
        }

    def sign(self, message: bytes) -> bytes:
        """
        Sign message. Hybrid when PQ available; classical otherwise.

        Keys are fixed at construction / keygen — never rotated per sign.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        classic_sig = self.classic.sign(bytes(message))
        if self.pq_available and self.pq is not None and self._pq_sk is not None:
            pq_sig = self.pq.sign(bytes(message), self._pq_sk)
            return bundle_hybrid(classic_sig, pq_sig)
        return classic_sig

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify signature. Hybrid requires BOTH classical and PQ to pass.
        Classical-only signatures verify against RSA-PSS alone.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("signature must be bytes")
        message = bytes(message)
        signature = bytes(signature)

        if is_hybrid_signature(signature):
            if not self.pq_available or self.pq is None or self._pq_pk is None:
                logger.warning(
                    "Hybrid signature presented but verifier has no PQ keys."
                )
                return False
            try:
                classic_sig, pq_sig = unbundle_hybrid(signature)
            except ValueError:
                return False
            classic_ok = self.classic.verify(message, classic_sig)
            pq_ok = self.pq.verify(message, pq_sig, self._pq_pk)
            return classic_ok and pq_ok

        return self.classic.verify(message, signature)

    def export_public_pem(self) -> bytes:
        return self.classic.export_public_pem()

    def export_private_pem(self) -> bytes:
        return self.classic.export_private_pem()


# ────────────────────────────────────────────────
# Self-test
# ────────────────────────────────────────────────

if __name__ == "__main__":
    print("Tier 6 Signature Test — Christman AI Project")
    print(f"oqs available: {OQS_AVAILABLE}")

    msg = b"Test message for signature - Harvest Now, Decrypt Later."

    signer_classic = HybridSigner(use_pq=False)
    sig_c = signer_classic.sign(msg)
    print("Classical mode:", signer_classic.mode)
    print("Classical sig len:", len(sig_c))
    print("Verify classic:", signer_classic.verify(msg, sig_c))
    print("Tamper rejected:", not signer_classic.verify(b"tampered", sig_c))

    signer_h = HybridSigner(use_pq=True)
    print("Hybrid mode:", signer_h.mode, "pq_available=", signer_h.pq_available)
    sig_h = signer_h.sign(msg)
    print("Hybrid/classic sig len:", len(sig_h))
    print("Verify:", signer_h.verify(msg, sig_h))
    print("Tamper rejected:", not signer_h.verify(b"tampered", sig_h))
