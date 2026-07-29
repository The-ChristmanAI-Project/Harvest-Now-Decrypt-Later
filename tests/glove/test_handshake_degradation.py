"""Handshake + graceful degradation tests — GLV-SPEC-1.0.0 §3.3.

Covers REQ-CV-01 (version compat), REQ-CV-02 (HELLO/WELCOME/ACCEPT, no
traffic before ACCEPT), REQ-CV-03 (signed descriptor), REQ-CV-06 (graceful
degradation, CAPABILITY_ABSENT, no synthetic emulation), REQ-CV-07
(SIMULATED declaration visible).
"""

from __future__ import annotations

import pytest

from glove import (
    CapabilityDescriptor,
    Decline,
    Glove,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    AttentionAction,
    AttentionMode,
    ControlMode,
    RejectReason,
    Twist,
    Welcome,
)
from glove.adapter.examples.mock_humanoid import MockHumanoidAdapter
from glove.adapter.examples.mock_industrial_arm import MockIndustrialArmAdapter
from glove.adapter.examples.mock_mobile_base import MockMobileBaseAdapter

BEING = "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f"


def _glove_with(adapter) -> Glove:
    g = Glove()
    g.attach_adapter(adapter)
    return g


def _accepted(g: Glove) -> Welcome:
    w = g.hello(BEING, ["1.0.0"])
    assert isinstance(w, Welcome)
    g.accept(w)
    return w


# -- REQ-CV-02 handshake ordering --------------------------------------------


def test_handshake_full_cycle():
    g = _glove_with(MockMobileBaseAdapter())
    w = _accepted(g)
    assert w.selected_version == "1.0.0"
    assert w.session_id
    assert w.capability_descriptor.body_class == "mock.mobile_base"
    assert g.session_state == "ACTIVE"


def test_no_traffic_before_accept():  # REQ-CV-02
    g = _glove_with(MockMobileBaseAdapter())
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((0.1, 0, 0), (0, 0, 0))))
    assert ack.status == "ACT_REJECTED"
    assert ack.reason == str(RejectReason.SESSION_INACTIVE)
    g.hello(BEING, ["1.0.0"])  # WELCOME sent but not yet ACCEPTed
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((0.1, 0, 0), (0, 0, 0))))
    assert ack.status == "ACT_REJECTED"


def test_version_mismatch_clean_decline():  # CF-T-CON-02, REQ-CV-01
    g = _glove_with(MockMobileBaseAdapter())
    result = g.hello(BEING, ["2.0.0", "3.1.0"])
    assert isinstance(result, Decline)
    assert g.session_state != "ACTIVE"
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((0.1, 0, 0), (0, 0, 0))))
    assert ack.status == "ACT_REJECTED"


def test_highest_shared_major_selected():
    g = _glove_with(MockMobileBaseAdapter())
    w = g.hello(BEING, ["0.9.0", "1.0.0"])
    assert isinstance(w, Welcome) and w.selected_version == "1.0.0"


# -- REQ-CV-03 signed descriptor ----------------------------------------------


def test_descriptor_signed_and_verifiable():
    g = _glove_with(MockMobileBaseAdapter())
    d = g.descriptor
    assert d is not None and d.signature.startswith("hmac-sha256:")
    assert d.verify_signature(g.adapter.adapter_key)  # type: ignore[union-attr]
    assert not d.verify_signature(b"wrong-key")
    assert d.hash() == d.hash()  # deterministic


def test_descriptor_enumerates_required_content():  # REQ-CV-03
    d = _accepted(_glove_with(MockHumanoidAdapter())).capability_descriptor
    assert d.action_types and d.joint_groups and d.effectors and d.sensors
    assert d.static_transforms and d.qos_rates
    assert d.envelope_params.max_linear_mps > 0
    assert "raw_control" in d.optional_modalities
    assert d.detector_artifacts  # REQ-SC-06 frozen, hashed detector artifacts


# -- REQ-CV-06 graceful degradation --------------------------------------------


def test_absent_modalities_reject_capability_absent():
    # Mobile base: no manipulation, no attention.
    g = _glove_with(MockMobileBaseAdapter())
    _accepted(g)
    from glove import Grip
    ack = g.submit_action(ManipulationAction(effector="arm.left",
                                             control_mode=ControlMode.GRIP, grip=Grip(0.5)))
    assert ack.status == "ACT_REJECTED" and ack.reason == str(RejectReason.CAPABILITY_ABSENT)
    ack = g.submit_action(AttentionAction(mode=AttentionMode.FIXATE, point=(1, 0, 1)))
    assert ack.reason == str(RejectReason.CAPABILITY_ABSENT)
    # Industrial arm: no locomotion, no attention.
    g2 = _glove_with(MockIndustrialArmAdapter())
    _accepted(g2)
    ack = g2.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                            twist=Twist((0.1, 0, 0), (0, 0, 0))))
    assert ack.reason == str(RejectReason.CAPABILITY_ABSENT)


def test_being_operates_on_remaining_modalities_without_error():
    # Degradation is graceful: remaining modalities keep working (REQ-CV-06).
    g = _glove_with(MockMobileBaseAdapter())
    _accepted(g)
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((0.3, 0, 0), (0, 0, 0.1))))
    assert ack.status == "ACT_EXECUTING"


def test_no_synthetic_emulation_of_absent_modalities():
    # The base has no cameras: no SN_VISION may ever appear (REQ-CV-06).
    g = _glove_with(MockMobileBaseAdapter())
    received = []
    g.on_sensory(lambda mt, p: received.append(str(mt)))
    _accepted(g)
    adapter = g.adapter
    adapter.emit_tick(); adapter.emit_internal()  # type: ignore[attr-defined]
    assert "SN_VISION" not in received
    assert "SN_PROPRIO" in received


# -- REQ-CV-07 SIMULATED declaration -------------------------------------------


@pytest.mark.parametrize("adapter_cls", [MockMobileBaseAdapter, MockIndustrialArmAdapter, MockHumanoidAdapter])
def test_simulated_declaration_visible(adapter_cls):
    g = _glove_with(adapter_cls())
    w = _accepted(g)
    assert w.capability_descriptor.simulated is True
    attached = g.audit.entries("ADAPTER_ATTACHED")
    assert attached and attached[0]["record"]["simulated"] is True


def test_unknown_effector_and_tool_rejected():
    g = _glove_with(MockIndustrialArmAdapter())
    _accepted(g)
    from glove import Grip, ToolAction, ToolOperation
    ack = g.submit_action(ManipulationAction(effector="arm.nonexistent",
                                             control_mode=ControlMode.GRIP, grip=Grip(0.5)))
    assert ack.reason == str(RejectReason.UNKNOWN_EFFECTOR)
    ack = g.submit_action(ToolAction(tool_id="tool.nope", operation=ToolOperation.ACTIVATE))
    assert ack.reason == str(RejectReason.UNKNOWN_TOOL)
