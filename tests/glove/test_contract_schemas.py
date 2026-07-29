"""Contract schema tests — GLV-SPEC-1.0.0 §3.0/3.1/3.2.

Covers CF-T-CON-01-style rejection of malformed/out-of-range messages at the
schema level (REQ-AC-01), REQ-SC-01 units/REQ-SC-02 frames, REQ-SC-04
mapping constants, and REQ-CV-01/05 versioning rules.
"""

from __future__ import annotations

import pytest

from glove.contract.envelope import (
    ContractError,
    MsgType,
    QoSClass,
    SequenceTracker,
    check_unit_quat,
    make_envelope,
    parse_semver,
    versions_compatible,
)
from glove.contract.actions import (
    AttentionAction,
    AttentionMode,
    ControlMode,
    ExpressionAction,
    ExpressionChannel,
    Grip,
    LedPattern,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    Pose,
    RawAction,
    RawEncoding,
    ToolAction,
    ToolOperation,
    Twist,
    Utterance,
    Waypoint,
    MAX_WAYPOINTS,
)
from glove.contract.sensory import (
    denormalize_joint,
    normalize_joint,
    FrameDescriptor,
    FrameEncoding,
    mark_stale,
)

BEING = "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f"
SESSION = "0192b4a0-7c1e-7f3a-9a1b-2c3d4e5f6071"


# -- §3.0 envelope ------------------------------------------------------------


def test_envelope_roundtrip():
    env = make_envelope(MsgType.ACT_LOCOMOTION, {"mode": "VELOCITY"}, session_id=SESSION,
                        being_id=BEING, seq=1042, qos_class=QoSClass.RT)
    d = env.to_dict()
    assert d["msg_type"] == "ACT_LOCOMOTION" and d["seq"] == 1042
    env2 = type(env).from_dict(d)
    assert env2.msg_id == env.msg_id and env2.qos_class is QoSClass.RT


def test_envelope_rejects_bad_fields():
    with pytest.raises(ContractError):
        make_envelope(MsgType.ACT_LOCOMOTION, {}, session_id="not-a-uuid",
                      being_id=BEING, seq=0, qos_class=QoSClass.RT)
    with pytest.raises(ContractError):
        make_envelope(MsgType.ACT_LOCOMOTION, {}, session_id=SESSION,
                      being_id=BEING, seq=-1, qos_class=QoSClass.RT)
    with pytest.raises(ContractError):
        make_envelope(MsgType.ACT_LOCOMOTION, {}, session_id=SESSION, being_id=BEING,
                      seq=0, qos_class=QoSClass.RT, contract_version="1.0")


def test_extension_keys_must_be_namespaced():  # REQ-CV-05
    with pytest.raises(ContractError):
        make_envelope(MsgType.ACT_LOCOMOTION, {}, session_id=SESSION, being_id=BEING,
                      seq=0, qos_class=QoSClass.RT, extensions={"bare": 1})


def test_semver_and_major_compat():  # REQ-CV-01
    assert parse_semver("1.2.3") == (1, 2, 3)
    assert versions_compatible("1.0.0", "1.4.2")
    assert not versions_compatible("1.0.0", "2.0.0")
    with pytest.raises(ContractError):
        parse_semver("v1.0.0")


def test_seq_gap_detection():  # REQ-SC-03: gaps visible, never concealed
    assert SequenceTracker.gaps([10, 11, 14, 15]) == [12, 13]


# -- §3.2.1 frames / quaternions -------------------------------------------------


def test_quaternion_norm_enforced():  # reject ||q|| off 1 by > 1e-3
    check_unit_quat((1.0, 0.0, 0.0, 0.0), "q")
    check_unit_quat((0.9239, 0.0, 0.3827, 0.0), "q")
    with pytest.raises(ContractError):
        check_unit_quat((1.1, 0.0, 0.0, 0.0), "q")


# -- §3.1.1 locomotion --------------------------------------------------------------


def test_locomotion_velocity_requires_twist_and_range():
    LocomotionAction(mode=LocomotionMode.VELOCITY,
                     twist=Twist((0.4, 0.0, 0.0), (0.0, 0.0, 0.15))).validate()
    with pytest.raises(ContractError):
        LocomotionAction(mode=LocomotionMode.VELOCITY).validate()
    with pytest.raises(ContractError):
        LocomotionAction(mode=LocomotionMode.VELOCITY,
                         twist=Twist((0.4, 0.0, 0.0), (0.0, 0.0, 0.15)),
                         duration_s=31.0).validate()  # duration (0, 30]
    with pytest.raises(ContractError):
        LocomotionAction(mode=LocomotionMode.POSE_GOAL).validate()


def test_locomotion_qos_class_per_spec():
    v = LocomotionAction(mode=LocomotionMode.VELOCITY,
                         twist=Twist((0.1, 0, 0), (0, 0, 0))).validate()
    assert v.qos is QoSClass.RT
    p = LocomotionAction(mode=LocomotionMode.POSE_GOAL,
                         goal_pose=Pose((1.0, 0.0, 0.0), (1.0, 0, 0, 0))).validate()
    assert p.qos is QoSClass.EVENT


# -- §3.1.2 manipulation -----------------------------------------------------------


def test_manipulation_waypoint_caps_and_monotonic_time():
    wps = tuple(Waypoint(t_from_start_s=float(i), pose=Pose((0.1, 0, 0.5), (1, 0, 0, 0)))
                for i in range(MAX_WAYPOINTS + 1))
    with pytest.raises(ContractError):
        ManipulationAction(effector="arm.left", control_mode=ControlMode.POSE_TRAJ,
                           waypoints=wps).validate()
    with pytest.raises(ContractError):
        ManipulationAction(effector="arm.left", control_mode=ControlMode.POSE_TRAJ,
                           waypoints=(Waypoint(t_from_start_s=2.0, pose=Pose((0, 0, 0), (1, 0, 0, 0))),
                                      Waypoint(t_from_start_s=1.0, pose=Pose((0, 0, 0), (1, 0, 0, 0))))
                           ).validate()


def test_joint_traj_normalized_range():
    with pytest.raises(ContractError):
        ManipulationAction(effector="arm.left", control_mode=ControlMode.JOINT_TRAJ,
                           waypoints=(Waypoint(t_from_start_s=0.0, joints=(0.0, 1.5)),)).validate()


def test_grip_aperture_range():
    with pytest.raises(ContractError):
        ManipulationAction(effector="gripper.main", control_mode=ControlMode.GRIP,
                           grip=Grip(aperture=1.2)).validate()
    ManipulationAction(effector="gripper.main", control_mode=ControlMode.GRIP,
                       grip=Grip(aperture=0.5, max_force=40.0)).validate()


def test_wrench_qos_is_rt():
    a = ManipulationAction(effector="arm.left", control_mode=ControlMode.WRENCH,
                           wrench=Twist((1, 0, 0), (0, 0, 0))).validate()
    assert a.qos is QoSClass.RT


# -- §3.1.3 expression ---------------------------------------------------------------


def test_utterance_length_cap_and_prosody_ranges():
    with pytest.raises(ContractError):
        ExpressionAction(channel=ExpressionChannel.SPEECH,
                         utterance=Utterance(text="x" * 4097)).validate()
    with pytest.raises(ContractError):
        ExpressionAction(channel=ExpressionChannel.SPEECH,
                         utterance=Utterance(text="hi", prosody={"rate": 3.0})).validate()
    ExpressionAction(channel=ExpressionChannel.LED,
                     led=LedPattern(color_rgb=(1.0, 0.2, 0.0), duty=0.5, period_s=1.0)).validate()


# -- §3.1.4 attention -----------------------------------------------------------------


def test_attention_exactly_one_target():
    with pytest.raises(ContractError):
        AttentionAction(mode=AttentionMode.FIXATE).validate()
    with pytest.raises(ContractError):
        AttentionAction(mode=AttentionMode.FIXATE, point=(1, 0, 1),
                        direction=(1, 0, 0)).validate()
    with pytest.raises(ContractError):
        AttentionAction(mode=AttentionMode.FIXATE, direction=(2, 0, 0)).validate()  # not unit
    with pytest.raises(ContractError):
        AttentionAction(mode=AttentionMode.FIXATE, point=(1, 0, 1), settle_s=6.0).validate()
    AttentionAction(mode=AttentionMode.SMOOTH_PURSUIT, track_id="trk-0042").validate()


# -- §3.1.5/6 tool + raw ----------------------------------------------------------------


def test_tool_and_raw_validation():
    ToolAction(tool_id="tool.screwdriver.01", operation=ToolOperation.ACTIVATE).validate()
    with pytest.raises(ContractError):
        RawAction(channel="c", encoding=RawEncoding.JOINT_VEL, payload=(), expires_ns=0).validate()
    with pytest.raises(ContractError):
        RawAction(channel="c", encoding=RawEncoding.OPAQUE, payload=(1.0,), expires_ns=0).validate()
    with pytest.raises(ContractError):
        RawAction(channel="c", encoding=RawEncoding.JOINT_VEL, payload=(0.1,),
                  expires_ns=1_000_000_000).validate(now_ns=0)  # > 250 ms from emit


# -- §3.2 sensory helpers -----------------------------------------------------------------


def test_joint_normalization_roundtrip():  # REQ-SC-04: linear, published constants
    lo, hi = -2.9, 2.9
    for v in (-2.9, -1.0, 0.0, 1.3, 2.9):
        n = normalize_joint(v, lo, hi)
        assert -1.0 <= n <= 1.0
        assert denormalize_joint(n, lo, hi) == pytest.approx(v)
    assert normalize_joint(lo, lo, hi) == -1.0
    assert normalize_joint(hi, lo, hi) == 1.0


def test_frame_descriptor_rejects_network_url():  # REQ-SC-07: local refs only
    with pytest.raises(ContractError):
        FrameDescriptor(camera="head.rgb", encoding=FrameEncoding.RGB8, width=640, height=480,
                        data_ref="https://evil.example/frames/1",
                        intrinsics={"fx": 1, "fy": 1, "cx": 1, "cy": 1}).validate()


def test_stale_marking():  # REQ-AD-09
    assert mark_stale({"a": 1})["stale"] is True


# -- REQ-AC-01: OUT_OF_RANGE vs SCHEMA_INVALID ack reasons (M4b) ----------------


def test_out_of_range_vs_schema_invalid_ack_distinction():
    """Range/bounds violations reject with OUT_OF_RANGE; structural/schema
    errors reject with SCHEMA_INVALID."""
    from glove import Glove, RejectReason
    from glove.adapter.examples.mock_mobile_base import MockMobileBaseAdapter

    g = Glove()
    g.attach_adapter(MockMobileBaseAdapter())
    w = g.hello(BEING, ["1.0.0"])
    g.accept(w)

    # range violation: duration_s must be in (0, 30]
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((0.1, 0, 0), (0, 0, 0)),
                                           duration_s=0.0))
    assert ack.status == "ACT_REJECTED" and ack.reason == str(RejectReason.OUT_OF_RANGE)

    # range violation: grip aperture outside [0, 1] (industrial arm gripper)
    from glove.adapter.examples.mock_industrial_arm import MockIndustrialArmAdapter

    g2 = Glove()
    g2.attach_adapter(MockIndustrialArmAdapter())
    w2 = g2.hello(BEING, ["1.0.0"])
    g2.accept(w2)
    ack = g2.submit_action(ManipulationAction(effector="gripper.main",
                                              control_mode=ControlMode.GRIP,
                                              grip=Grip(aperture=1.5)))
    assert ack.status == "ACT_REJECTED" and ack.reason == str(RejectReason.OUT_OF_RANGE)

    # structural/schema error: VELOCITY mode without a twist
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY))
    assert ack.status == "ACT_REJECTED" and ack.reason == str(RejectReason.SCHEMA_INVALID)
