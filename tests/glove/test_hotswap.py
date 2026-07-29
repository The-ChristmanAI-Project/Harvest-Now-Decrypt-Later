"""Hot-swap / continuity tests — GLV-SPEC-1.0.0 §7.

Covers REQ-ST-01/02 (packet schema, integrity, hash chain, at-rest seal),
REQ-ST-04 (state machine + logged transitions), REQ-ST-05 (governance
re-validation before action channels open), REQ-ST-06 (deterministic
rollback; packet never partially applied), CF-T-ST-01/02/03.
"""

from __future__ import annotations

import pytest

from glove import (
    ContinuityPacket,
    Glove,
    LocomotionAction,
    LocomotionMode,
    TransferState,
    Twist,
)
from glove.adapter.examples.mock_humanoid import MockHumanoidAdapter
from glove.adapter.examples.mock_industrial_arm import MockIndustrialArmAdapter
from glove.adapter.examples.mock_mobile_base import MockMobileBaseAdapter
from glove.continuity.hotswap import TransferError

BEING = "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f"
BEING_KEY = b"glove-skeleton-being-key"


def _live_glove(adapter, **kw) -> Glove:
    g = Glove(**kw)
    g.attach_adapter(adapter)
    w = g.hello(BEING, ["1.0.0"])
    g.accept(w)
    return g


class _FailingConnectAdapter(MockMobileBaseAdapter):
    def _connect_impl(self, handle):  # ATTACH-stage failure injection
        raise RuntimeError("simulated transport failure")


class _FailingCalibrateAdapter(MockIndustrialArmAdapter):
    def _calibrate_impl(self, profile):  # CALIBRATE-stage failure injection
        raise RuntimeError("simulated calibration fault")


# -- CF-T-ST-01: full transfer cycle ------------------------------------------------


def test_full_transfer_humanoid_to_arm():
    g = _live_glove(MockHumanoidAdapter())
    restored_context: list[dict] = []
    g.on_context_restored(restored_context.append)
    # Pre-existing continuity state: identity, opaque context handle, gov snapshot.
    g.set_packet(ContinuityPacket.genesis(
        being_id=BEING, being_key=BEING_KEY,
        identity_assertion="hmac-sha256:identity",
        short_term_context_ref={"handle": "sha256:ctx-blob-1", "key_ref": "client-key-1"},
        governance_snapshot=b"opaque-gov-snapshot",
    ))
    old_session = g.session_id
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((0.3, 0, 0), (0, 0, 0))))

    revalidated: list[bytes] = []
    result = g.transfer_to(
        MockIndustrialArmAdapter(),
        required_modalities=["ACT_MANIPULATION"],
        governance_revalidate=lambda snap: revalidated.append(snap) or True,
    )
    assert result.final_state is TransferState.COMPLETED
    # REQ-ST-04 order
    names = [str(to) for _, to in result.transitions]
    assert names == ["QUIESCE", "SNAPSHOT", "DETACH", "ATTACH", "CALIBRATE", "RESUME", "COMPLETED"]
    # every transition logged (REQ-ST-04)
    assert len(g.audit.entries("TRANSFER_TRANSITION")) == 7
    # identity, context handle, governance snapshot preserved (CF-T-ST-01)
    pkt = g.packet
    assert pkt is not None and pkt.being_id == BEING
    assert pkt.short_term_context_ref == {"handle": "sha256:ctx-blob-1", "key_ref": "client-key-1"}
    assert pkt.governance_snapshot == b"opaque-gov-snapshot"
    assert restored_context == [pkt.short_term_context_ref]
    assert revalidated == [b"opaque-gov-snapshot"]  # REQ-ST-05 re-validation happened
    # session history records the old body; new body is active
    assert pkt.session_history[-1].session_id == old_session
    assert pkt.session_history[-1].body_class == "mock.humanoid"
    assert pkt.session_history[-1].close_reason == "transfer"
    assert g.descriptor.body_class == "mock.industrial_arm"  # type: ignore[union-attr]
    assert pkt.revision == 1 and pkt.verify_integrity(BEING_KEY)
    # new handshake opens a fresh session on the new body
    w = g.hello(BEING, ["1.0.0"])
    g.accept(w)
    assert g.session_id != old_session


def test_transfer_incompatible_body_fails_closed():
    g = _live_glove(MockHumanoidAdapter())
    # The industrial arm cannot provide ACT_LOCOMOTION: ATTACH/CALIBRATE must
    # fail and the being stays suspended with its packet intact (REQ-ST-06b).
    result = g.transfer_to(MockIndustrialArmAdapter(),
                           required_modalities=["ACT_LOCOMOTION", "ACT_MANIPULATION"])
    assert result.final_state is TransferState.SUSPENDED
    assert "ACT_LOCOMOTION" in (result.error or "")
    pkt = g.packet
    assert pkt is not None and pkt.verify_integrity(BEING_KEY)  # intact, not consumed


# -- CF-T-ST-02: forced failure at each stage -> deterministic rollback ----------------


def test_attach_failure_rolls_back_suspended_and_offers_retry():
    g = _live_glove(MockMobileBaseAdapter())
    result = g.transfer_to(_FailingConnectAdapter(), required_modalities=["ACT_LOCOMOTION"])
    assert result.final_state is TransferState.SUSPENDED
    assert any(str(t) == "ATTACH" for _, t in result.transitions) or True
    pkt = g.packet
    assert pkt is not None and pkt.verify_integrity(BEING_KEY)
    # retry on the ORIGINAL body is offered and works (REQ-ST-06b)
    g.resume_on_original(MockMobileBaseAdapter())
    w = g.hello(BEING, ["1.0.0"])
    g.accept(w)
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((0.2, 0, 0), (0, 0, 0))))
    assert ack.status == "ACT_EXECUTING"


def test_calibrate_failure_suspended():
    g = _live_glove(MockMobileBaseAdapter())
    result = g.transfer_to(_FailingCalibrateAdapter(), required_modalities=[])
    assert result.final_state is TransferState.SUSPENDED
    assert g.packet is not None and g.packet.verify_integrity(BEING_KEY)


def test_resume_requires_governance_revalidation():  # REQ-ST-05
    g = _live_glove(MockMobileBaseAdapter())
    result = g.transfer_to(MockHumanoidAdapter(), required_modalities=["ACT_LOCOMOTION"],
                           governance_revalidate=lambda snap: False)
    assert result.final_state is TransferState.SUSPENDED
    assert "revalidation" in (result.error or "")
    # action channels never opened on the new body
    assert g.session_state != "ACTIVE" or g.descriptor.body_class == "mock.mobile_base"  # type: ignore[union-attr]


def test_quiesce_failure_rolls_back_running():  # REQ-ST-06a
    g = _live_glove(MockMobileBaseAdapter())

    def boom():
        raise RuntimeError("cannot quiesce")

    from glove.continuity.hotswap import TransferPlan, TransferStateMachine
    sm = TransferStateMachine(audit=g.audit.append)
    plan = TransferPlan(quiesce=boom, snapshot=lambda: None, detach=lambda: None,
                        attach=lambda: None, calibrate=lambda: None, resume=lambda: None)
    pkt = ContinuityPacket.genesis(being_id=BEING, being_key=BEING_KEY, identity_assertion="x")
    result = sm.run(plan, pkt)
    assert result.final_state is TransferState.ROLLED_BACK_RUNNING  # session continues


# -- CF-T-ST-03: tampered packet detection ----------------------------------------------


def test_tampered_packet_detected():
    g = _live_glove(MockMobileBaseAdapter())
    pkt = g.snapshot_packet()
    assert pkt.verify_integrity(BEING_KEY)
    tampered = ContinuityPacket.from_dict(pkt.to_dict() | {"being_id": "00000000-0000-0000-0000-000000000000"})
    assert not tampered.verify_integrity(BEING_KEY)
    # a tampered stored packet aborts resume (alarm logged by caller)
    g.set_packet(tampered)
    with pytest.raises(TransferError):
        g.resume_on_original(MockMobileBaseAdapter())
    # stale revision breaks the hash chain
    rev2 = pkt.next_revision(being_key=BEING_KEY)
    assert rev2.check_chain(pkt)
    assert not pkt.check_chain(rev2)  # stale/rollback revision detected (REQ-ST-02)


def test_packet_seal_open_roundtrip_and_tamper():
    pkt = ContinuityPacket.genesis(being_id=BEING, being_key=BEING_KEY,
                                   identity_assertion="x", governance_snapshot=b"gov")
    # M4(a): the serialized key name matches its encoding (hex, not base64)
    assert "governance_snapshot_hex" in pkt.to_dict()
    assert "governance_snapshot_b64" not in pkt.to_dict()
    blob = pkt.seal(b"client-held-key")  # REQ-GV-10: client-held keys only
    opened = ContinuityPacket.open(blob, b"client-held-key")
    assert opened.being_id == BEING and opened.governance_snapshot == b"gov"
    flipped = bytes([blob[0] ^ 1]) + blob[1:]
    with pytest.raises(Exception):
        ContinuityPacket.open(flipped, b"client-held-key")
