"""Family crypto integration tests — The Christman AI Project — Apache 2.0.

Covers the upgrade paths wired through :mod:`glove.family_crypto`:

* continuity-packet seal/open via AES-256-GCM (Tier 2 ``AESCipher``) with
  tamper detection (REQ-ST-02, REQ-GV-10),
* capability-descriptor sign/verify via RSA-PSS-4096 (Tier 6
  ``DigitalSigner``) (REQ-CV-03),
* automatic fallback to the stdlib providers when ``christman_crypto`` is
  not importable — simulated by masking the import — with no schema fork.

The family-backed tests skip cleanly when the optional stack is absent.
"""

from __future__ import annotations

import sys
from dataclasses import replace

import pytest

import glove.family_crypto as fc
from glove.contract.capabilities import CapabilityDescriptor
from glove.continuity.packet import (
    ContinuityPacket,
    get_seal_provider,
    set_seal_provider,
)

BEING = "11111111-2222-3333-4444-555555555555"
BEING_KEY = b"being-root-key"
CLIENT_KEY = b"client-held-key"  # REQ-GV-10: client-held keys only

family_required = pytest.mark.skipif(
    not fc.family_available(), reason="christman_crypto not importable"
)


@pytest.fixture()
def packet() -> ContinuityPacket:
    return ContinuityPacket.genesis(
        being_id=BEING,
        being_key=BEING_KEY,
        identity_assertion="x",
        governance_snapshot=b"gov",
    )


@pytest.fixture()
def descriptor() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        descriptor_version="1.0.0",
        body_class="mock.test_body",
        body_serial="T-001",
        simulated=True,
        contract_versions=("1.0.0",),
        action_types=("ACT_LOCOMOTION",),
    )


@pytest.fixture(autouse=True)
def _restore_provider():
    yield
    set_seal_provider(None)


# ---------------------------------------------------------------------------
# Packet sealing via the family stack (Tier 2 AES-256-GCM)
# ---------------------------------------------------------------------------


@family_required
def test_family_seal_open_roundtrip(packet: ContinuityPacket):
    blob = packet.seal(CLIENT_KEY)
    assert blob.startswith(fc.AESGCM_SEAL_MAGIC)  # family provider active
    assert get_seal_provider().name.startswith("aes-256-gcm")
    opened = ContinuityPacket.open(blob, CLIENT_KEY)
    assert opened.being_id == BEING
    assert opened.governance_snapshot == b"gov"
    assert opened.verify_integrity(BEING_KEY)


@family_required
def test_family_seal_tamper_detected(packet: ContinuityPacket):
    blob = bytearray(packet.seal(CLIENT_KEY))
    blob[-1] ^= 0xFF  # flip a ciphertext/tag bit
    with pytest.raises(Exception):  # AES-GCM InvalidTag
        ContinuityPacket.open(bytes(blob), CLIENT_KEY)


@family_required
def test_family_seal_wrong_key_rejected(packet: ContinuityPacket):
    blob = packet.seal(CLIENT_KEY)
    with pytest.raises(Exception):
        ContinuityPacket.open(blob, b"not-the-client-key")


@family_required
def test_family_seal_key_normalization(packet: ContinuityPacket):
    # 32-byte keys pass through; other lengths are SHA-256 normalized and
    # must NOT interoperate with the raw key.
    blob = packet.seal(CLIENT_KEY)
    raw32 = CLIENT_KEY.ljust(32, b"\0")
    with pytest.raises(Exception):
        ContinuityPacket.open(blob, raw32)


@family_required
def test_family_seal_is_randomized(packet: ContinuityPacket):
    # AES-GCM uses a fresh nonce per seal — unlike the deterministic
    # skeleton keystream, equal plaintexts must not yield equal blobs.
    assert packet.seal(CLIENT_KEY) != packet.seal(CLIENT_KEY)


# ---------------------------------------------------------------------------
# Descriptor signing via the family stack (Tier 6 RSA-PSS-4096)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def signer() -> "fc.FamilyDescriptorSigner":
    if not fc.family_available():
        pytest.skip("christman_crypto not importable")
    return fc.FamilyDescriptorSigner.generate()  # RSA-4096 keygen (slow, module-scoped)


@family_required
def test_family_descriptor_sign_verify(descriptor: CapabilityDescriptor, signer):
    signed = descriptor.sign(signer)
    assert signed.signature.startswith(fc.RSA_PSS_PREFIX)
    assert signed.verify_signature(signer)
    # Public-key-only identity verifies — non-repudiation without private key.
    verifier = fc.FamilyDescriptorSigner.from_pem(public_pem=signer.public_pem())
    assert signed.verify_signature(verifier)


@family_required
def test_family_descriptor_tamper_detected(descriptor: CapabilityDescriptor, signer):
    signed = descriptor.sign(signer)
    forged = replace(signed, body_serial="T-EVIL")
    assert not forged.verify_signature(signer)


@family_required
def test_family_descriptor_wrong_signer_rejected(descriptor: CapabilityDescriptor, signer):
    signed = descriptor.sign(signer)
    other = fc.FamilyDescriptorSigner.generate()
    assert not signed.verify_signature(other)
    # A symmetric fallback key can never verify an asymmetric signature.
    assert not signed.verify_signature(b"adapter-shared-key")


@family_required
def test_family_descriptor_pem_roundtrip(descriptor: CapabilityDescriptor, signer):
    reloaded = fc.FamilyDescriptorSigner.from_pem(private_pem=signer.private_pem())
    signed = descriptor.sign(reloaded)
    verifier = fc.FamilyDescriptorSigner.from_pem(public_pem=signer.public_pem())
    assert signed.verify_signature(verifier)


# ---------------------------------------------------------------------------
# Fallback paths (christman_crypto absent) — schema unchanged
# ---------------------------------------------------------------------------


@pytest.fixture()
def no_family(monkeypatch):
    """Simulate a deployment without the family crypto stack."""
    monkeypatch.setitem(sys.modules, "christman_crypto", None)  # import fails
    monkeypatch.delitem(sys.modules, "glove.family_crypto", raising=False)
    yield
    # sys.modules restoration handled by monkeypatch


def test_fallback_seal_open_roundtrip(no_family, packet: ContinuityPacket):
    assert not fc.family_available()
    assert get_seal_provider().name.startswith("stdlib-")
    blob = packet.seal(CLIENT_KEY)
    assert not blob.startswith(fc.AESGCM_SEAL_MAGIC)
    opened = ContinuityPacket.open(blob, CLIENT_KEY)
    assert opened.being_id == BEING and opened.governance_snapshot == b"gov"


def test_fallback_hmac_descriptor_still_works(no_family, descriptor: CapabilityDescriptor):
    signed = descriptor.sign(b"adapter-shared-key")
    assert signed.signature.startswith(fc.HMAC_PREFIX)
    assert signed.verify_signature(b"adapter-shared-key")
    assert not signed.verify_signature(b"wrong-key")


@family_required
def test_family_blob_survives_cross_provider(packet: ContinuityPacket, monkeypatch):
    # Seal with family crypto, then confirm opening without the stack gives a
    # clear error rather than silent corruption.
    blob = packet.seal(CLIENT_KEY)
    assert blob.startswith(fc.AESGCM_SEAL_MAGIC)
    monkeypatch.setattr(fc, "get_aesgcm_sealer", lambda: None)
    with pytest.raises(RuntimeError, match="christman_crypto"):
        ContinuityPacket.open(blob, CLIENT_KEY)


@family_required
def test_mixed_algorithms_dispatch_by_prefix(descriptor: CapabilityDescriptor, signer):
    # HMAC-signed and RSA-signed descriptors coexist; verification dispatches
    # on the signature prefix without any schema fork.
    hmac_signed = descriptor.sign(b"adapter-shared-key")
    rsa_signed = descriptor.sign(signer)
    assert hmac_signed.verify_signature(b"adapter-shared-key")
    assert rsa_signed.verify_signature(signer)
    # Cross-checks fail closed.
    assert not hmac_signed.verify_signature(signer)
    assert not rsa_signed.verify_signature(b"adapter-shared-key")
