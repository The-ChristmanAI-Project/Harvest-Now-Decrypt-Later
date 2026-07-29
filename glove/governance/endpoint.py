"""Governance ENDPOINT tooling — GLV-SPEC-1.0.0 §5 / Appendix A.

This module runs at governance endpoints (consensus participants, caregiver
consoles, Pulse Tether sources, Ring 4) — NEVER inside the Glove. It is the
only place ed25519 SIGNING keys exist in this package. The Glove-side bus
(`glove.governance.bus`) holds verification-only public keys and contains
no signing code path, so the Glove is structurally incapable of forging or
originating governance envelopes (INV-1/INV-4, REQ-GV-02/07).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from ..contract.envelope import monotonic_ns
from .bus import AUTH_TAG_SCHEME, GovClass, GovEnvelope, _framing_bytes


def generate_signing_key() -> bytes:
    """Generate a fresh ed25519 signing key; returns the 32-byte seed."""
    return Ed25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )


def public_key_from_signing_key(signing_key: bytes) -> bytes:
    """Derive the 32-byte verification public key an endpoint registers
    with the bus out-of-band (REQ-GV-02)."""
    if len(signing_key) != 32:
        raise ValueError("ed25519 signing keys are 32-byte seeds")
    private = Ed25519PrivateKey.from_private_bytes(bytes(signing_key))
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def compute_auth_tag(
    signing_key: bytes, gov_class: str, sender: str, sender_seq: int,
    expires_ns: int, payload: bytes,
) -> str:
    """Sender ed25519 signature over framing + payload (REQ-GV-02).
    Endpoint-side only; the bus verifies with the registered public key."""
    private = Ed25519PrivateKey.from_private_bytes(bytes(signing_key))
    signature = private.sign(_framing_bytes(gov_class, sender, sender_seq, expires_ns) + bytes(payload))
    return AUTH_TAG_SCHEME + ":" + signature.hex()


def create_envelope(
    signing_key: bytes, gov_class: GovClass, sender: str, sender_seq: int,
    ttl_ns: int, payload: bytes, *, now_ns: int | None = None,
) -> GovEnvelope:
    """Endpoint-side envelope constructor (runs at governance endpoints,
    never inside the Glove)."""
    now = monotonic_ns() if now_ns is None else now_ns
    expires = now + ttl_ns
    tag = compute_auth_tag(signing_key, str(gov_class), sender, sender_seq, expires, payload)
    return GovEnvelope(gov_class=GovClass(gov_class), sender=sender, sender_seq=sender_seq,
                       expires_ns=expires, auth_tag=tag, payload=bytes(payload))
