"""Family crypto integration — The Christman AI Project — Apache 2.0.

Optional bridge to the family cryptographic stack
(`christman_crypto <https://github.com/The-ChristmanAI-Project/Harvest-Now-Decrypt-Later>`_):

* Continuity-packet sealing upgrades from the skeleton-grade SHA-256
  keystream XOR to **AES-256-GCM** (Tier 2, ``AESCipher``) — authenticated
  encryption with tamper-evident tags, nonce||ciphertext||tag bundles.
* Capability-descriptor signing upgrades from skeleton-grade HMAC-SHA256 to
  **RSA-PSS-4096** (Tier 6, ``DigitalSigner``) — asymmetric, non-repudiable
  adapter signatures verifiable from a public PEM alone.

Both integrations are OPTIONAL. When ``christman_crypto`` is not importable
(for any reason — package absent, a transitive dependency missing, etc.)
every entry point falls back to the inspectable stdlib implementations and
the packet/descriptor SCHEMAS do not change: sealed blobs carry a magic
prefix so ``open()`` can route them, and signatures carry an algorithm
prefix (``"rsa-pss-sha256:"`` / ``"hmac-sha256:"``) so verification can
dispatch without forking the document format.

The governance bus is untouched: it stays on ed25519 per GLV-SPEC Appendix A.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Optional

# Magic prefix identifying family-sealed continuity-packet blobs (§7.1).
AESGCM_SEAL_MAGIC = b"GLVSEAL1:AESGCM:"

# AAD bound into every family-sealed packet: domain separation for §7.1.
PACKET_SEAL_AAD = b"glove-continuity-packet/GLV-SPEC-1.0.0"

# Signature algorithm prefixes carried in document signature fields.
RSA_PSS_PREFIX = "rsa-pss-sha256:"
HMAC_PREFIX = "hmac-sha256:"


def _load_family() -> Optional[Any]:
    """Import the family stack, returning the module or None.

    Any failure (ImportError, a missing transitive dep such as liboqs
    bindings, a broken install) downgrades to the stdlib fallback path —
    the Glove core must never fail to boot because optional crypto is absent.
    """
    try:
        import christman_crypto  # noqa: F401

        return christman_crypto
    except Exception:
        return None


def family_available() -> bool:
    """True when the family crypto stack is importable in this environment."""
    return _load_family() is not None


def family_status() -> str:
    """Human-readable provider status for diagnostics / demos."""
    cc = _load_family()
    if cc is None:
        return "christman_crypto unavailable — stdlib fallback crypto active"
    return f"christman_crypto {getattr(cc, '__version__', '?')} active (AES-256-GCM + RSA-PSS)"


# ---------------------------------------------------------------------------
# Continuity-packet sealing (REQ-ST-02 / REQ-GV-10)
# ---------------------------------------------------------------------------


class AesGcmSealer:
    """Family-backed seal/open provider: AES-256-GCM (Tier 2 ``AESCipher``).

    Bundle format: ``GLVSEAL1:AESGCM:`` || nonce(12) || ciphertext || tag(16).
    The magic prefix lets ``ContinuityPacket.open`` route blobs without any
    schema change; the AAD binds the bundle to the packet domain.
    """

    name = "aes-256-gcm (christman_crypto Tier 2)"

    def __init__(self, aes_cipher_cls: Any):
        self._cipher_cls = aes_cipher_cls

    @staticmethod
    def _normalize_key(client_key: bytes) -> bytes:
        """AES-256 needs exactly 32 bytes; a client-held passphrase of any
        length is normalized deterministically with SHA-256. Key custody is
        unchanged — the key never leaves the client (REQ-GV-10)."""
        if len(client_key) == 32:
            return bytes(client_key)
        return hashlib.sha256(bytes(client_key)).digest()

    def seal(self, data: bytes, client_key: bytes) -> bytes:
        cipher = self._cipher_cls(self._normalize_key(client_key))
        return AESGCM_SEAL_MAGIC + cipher.encrypt(data, aad=PACKET_SEAL_AAD)

    def open(self, blob: bytes, client_key: bytes) -> bytes:
        if not blob.startswith(AESGCM_SEAL_MAGIC):
            raise ValueError("not a family-sealed continuity packet blob")
        cipher = self._cipher_cls(self._normalize_key(client_key))
        # Raises cryptography.exceptions.InvalidTag on any tampering.
        return cipher.decrypt(blob[len(AESGCM_SEAL_MAGIC):], aad=PACKET_SEAL_AAD)


def get_aesgcm_sealer() -> Optional[AesGcmSealer]:
    """Return the family seal provider, or None when unavailable."""
    cc = _load_family()
    if cc is None:
        return None
    return AesGcmSealer(cc.AESCipher)


# ---------------------------------------------------------------------------
# Capability-descriptor signing (REQ-CV-03)
# ---------------------------------------------------------------------------


class FamilyDescriptorSigner:
    """Adapter signing identity backed by Tier 6 ``DigitalSigner``
    (RSA-PSS-4096, SHA-256, 32-byte salt).

    Holds a private key for signing, or a public key only for verification —
    the being side never needs adapter private key material.
    """

    def __init__(self, digital_signer: Any):
        self._signer = digital_signer

    @classmethod
    def generate(cls) -> "FamilyDescriptorSigner":
        """Generate a fresh RSA-4096 adapter signing keypair."""
        cc = _load_family()
        if cc is None:
            raise RuntimeError(
                "christman_crypto is not importable; cannot generate a "
                "family signing identity"
            )
        return cls(cc.DigitalSigner.generate_keypair())

    @classmethod
    def from_pem(
        cls, private_pem: bytes | None = None, public_pem: bytes | None = None
    ) -> "FamilyDescriptorSigner":
        cc = _load_family()
        if cc is None:
            raise RuntimeError(
                "christman_crypto is not importable; cannot load a "
                "family signing identity"
            )
        return cls(cc.DigitalSigner.from_pem(private_pem=private_pem, public_pem=public_pem))

    def public_pem(self) -> bytes:
        return self._signer.export_public_pem()

    def private_pem(self) -> bytes:
        return self._signer.export_private_pem()

    def sign_raw(self, message: bytes) -> bytes:
        return self._signer.sign(message)

    def verify_raw(self, message: bytes, signature: bytes) -> bool:
        return bool(self._signer.verify(message, signature))


def _as_family_signer(key: Any) -> Optional[Any]:
    """Adapt a family-capable signing key to a uniform raw interface.

    Accepts ``FamilyDescriptorSigner`` or a raw ``christman_crypto``
    ``DigitalSigner`` (duck-typed so we never hard-depend on the import).
    Returns None for anything else (e.g. symmetric bytes keys)."""
    if isinstance(key, FamilyDescriptorSigner):
        return key
    if (
        key is not None
        and not isinstance(key, (bytes, bytearray, str))
        and callable(getattr(key, "sign", None))
        and callable(getattr(key, "verify", None))
        and callable(getattr(key, "export_public_pem", None))
    ):
        class _RawAdapter:
            def __init__(self, s: Any):
                self._s = s

            def sign_raw(self, message: bytes) -> bytes:
                return self._s.sign(message)

            def verify_raw(self, message: bytes, signature: bytes) -> bool:
                return bool(self._s.verify(message, signature))

        return _RawAdapter(key)
    return None


def sign_descriptor_body(body: bytes, adapter_key: Any) -> str:
    """Sign a canonical descriptor body.

    * Family signing identity (``FamilyDescriptorSigner`` / ``DigitalSigner``)
      -> ``"rsa-pss-sha256:<hex>"`` (Tier 6 RSA-PSS-4096).
    * ``bytes`` -> ``"hmac-sha256:<hex>"`` (skeleton-grade stdlib fallback).

    The returned string slots into ``CapabilityDescriptor.signature``; the
    schema is unchanged either way.
    """
    signer = _as_family_signer(adapter_key)
    if signer is not None:
        return RSA_PSS_PREFIX + signer.sign_raw(body).hex()
    if isinstance(adapter_key, (bytes, bytearray)):
        tag = hmac.new(bytes(adapter_key), body, hashlib.sha256).hexdigest()
        return HMAC_PREFIX + tag
    raise TypeError(
        "adapter_key must be bytes (HMAC fallback) or a family signing "
        "identity (FamilyDescriptorSigner / DigitalSigner)"
    )


def verify_descriptor_body(body: bytes, signature: str, adapter_key: Any) -> bool:
    """Verify a descriptor signature produced by :func:`sign_descriptor_body`.

    Dispatches on the algorithm prefix so both family and fallback documents
    verify through the same code path. A key of the wrong kind for the
    signature's algorithm yields False, never an exception.
    """
    if signature.startswith(RSA_PSS_PREFIX):
        signer = _as_family_signer(adapter_key)
        if signer is None:
            return False
        try:
            sig_bytes = bytes.fromhex(signature[len(RSA_PSS_PREFIX):])
        except ValueError:
            return False
        try:
            return signer.verify_raw(body, sig_bytes)
        except Exception:
            return False
    if signature.startswith(HMAC_PREFIX):
        if not isinstance(adapter_key, (bytes, bytearray)):
            return False
        expected = HMAC_PREFIX + hmac.new(
            bytes(adapter_key), body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected)
    return False
