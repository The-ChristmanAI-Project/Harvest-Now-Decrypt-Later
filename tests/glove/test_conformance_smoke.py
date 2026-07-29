"""Conformance smoke test — the zero-being-modification proof (CR-5).

ONE being-side stub drives all three mock adapters UNCHANGED. The stub
derives its command set purely from the negotiated capability descriptor
(REQ-CV-02/03/06): it never special-cases a body class. If the same code
runs against every body, the Glove — not the being — absorbed the hardware
difference.
"""

from __future__ import annotations

import pytest

from glove import (
    AttentionAction,
    AttentionMode,
    ControlMode,
    ExpressionAction,
    ExpressionChannel,
    Glove,
    Grip,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    MsgType,
    Pose,
    Twist,
    Utterance,
    Waypoint,
)
from glove.adapter.examples.mock_humanoid import MockHumanoidAdapter
from glove.adapter.examples.mock_industrial_arm import MockIndustrialArmAdapter
from glove.adapter.examples.mock_mobile_base import MockMobileBaseAdapter

BEING = "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f"


def being_stub(glove: Glove) -> dict[str, list]:
    """The being side. Identical for every body (zero-being-modification).

    Speaks only the Neural Contract; derives everything from the descriptor.
    """
    log: dict[str, list] = {"acks": [], "sensory": []}
    glove.on_ack(log["acks"].append)
    glove.on_sensory(lambda mt, p: log["sensory"].append(str(mt)))

    # REQ-CV-02 handshake — identical on every body.
    welcome = glove.hello(BEING, ["1.0.0"])
    glove.accept(welcome)
    d = welcome.capability_descriptor

    # Drive every modality the descriptor declares; skip what is absent
    # (REQ-CV-06 graceful degradation — no error paths needed).
    if d.supports_action(MsgType.ACT_LOCOMOTION) and d.supports_locomotion_mode("VELOCITY"):
        glove.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                             twist=Twist((0.2, 0.0, 0.0), (0.0, 0.0, 0.1))))
    if d.supports_action(MsgType.ACT_MANIPULATION) and d.effectors:
        eff = d.effectors[0]
        if "GRIP" in eff.control_modes:
            glove.submit_action(ManipulationAction(effector=eff.name,
                                                   control_mode=ControlMode.GRIP,
                                                   grip=Grip(aperture=0.5, max_force=eff.max_force_n)))
        if "POSE_TRAJ" in eff.control_modes:
            glove.submit_action(ManipulationAction(
                effector=eff.name, control_mode=ControlMode.POSE_TRAJ,
                waypoints=(Waypoint(t_from_start_s=0.0,
                                    pose=Pose((0.4, 0.1, 0.8), (1.0, 0, 0, 0))),)))
    if d.supports_action(MsgType.ACT_EXPRESSION) and d.supports_expression_channel("SPEECH"):
        glove.submit_action(ExpressionAction(channel=ExpressionChannel.SPEECH,
                                             utterance=Utterance(text="I am online.", locale="en-US")))
    if d.supports_action(MsgType.ACT_ATTENTION):
        glove.submit_action(AttentionAction(mode=AttentionMode.FIXATE, point=(1.2, -0.3, 1.1)))

    # Pump one sensory sweep if the adapter simulates one.
    adapter = glove.adapter
    if hasattr(adapter, "emit_tick"):
        adapter.emit_tick()  # type: ignore[attr-defined]
    if hasattr(adapter, "emit_internal"):
        adapter.emit_internal()  # type: ignore[attr-defined]
    return log


@pytest.mark.parametrize("adapter_cls,expected_actions", [
    (MockMobileBaseAdapter, {"ACT_LOCOMOTION", "ACT_EXPRESSION"}),
    (MockIndustrialArmAdapter, {"ACT_MANIPULATION", "ACT_TOOL", "ACT_EXPRESSION"}),
    (MockHumanoidAdapter, {"ACT_LOCOMOTION", "ACT_MANIPULATION", "ACT_EXPRESSION",
                           "ACT_ATTENTION", "ACT_TOOL", "ACT_RAW"}),
])
def test_same_being_drives_all_bodies_unchanged(adapter_cls, expected_actions):
    glove = Glove()
    glove.attach_adapter(adapter_cls())
    log = being_stub(glove)

    # Negotiated descriptor matches the body's declared subset.
    assert set(glove.descriptor.action_types) == expected_actions  # type: ignore[union-attr]
    # Every submitted action got an acknowledgement; none schema-rejected.
    assert log["acks"]
    assert all(a.status in ("ACT_EXECUTING", "ACT_COMPLETED", "ACT_CLIPPED") for a in log["acks"])
    # Sensory flowed through the contract in normalized form.
    assert MsgType.SN_PROPRIO.value in log["sensory"]
    assert MsgType.SN_INTERNAL.value in log["sensory"]
    # Audit trail complete and hash-chain intact (REQ-CF-09).
    assert glove.audit.verify_chain()
    assert glove.audit.entries("ACTION_VALIDATED")
    assert glove.audit.entries("ADAPTER_ATTACHED")[0]["record"]["simulated"] is True


def test_being_sees_only_declared_modalities():
    # The base has no manipulation/attention: the stub simply never submits
    # them — degradation is data-driven, not error-driven (REQ-CV-06).
    glove = Glove()
    glove.attach_adapter(MockMobileBaseAdapter())
    log = being_stub(glove)
    manip_acks = [a for a in log["acks"]]
    assert len(manip_acks) == 2  # locomotion + speech only
