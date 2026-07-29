"""Safety envelope tests — GLV-SPEC-1.0.0 §6.

Covers REQ-SE-01 (evaluate every action), REQ-SE-02 (clip or refuse, never
originate), REQ-SE-03 (composition + hash-stamp, policy only tightens),
REQ-SE-04 (dead-man), REQ-SE-05 (watchdog / e-stop / impact), REQ-SE-06
(degraded modes), REQ-SE-08 (audit of every decision), and CF-T-ACT-01/02.
"""

from __future__ import annotations

import pytest

from glove import (
    AbortCause,
    DegradedMode,
    Glove,
    Grip,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    ControlMode,
    Pose,
    RawAction,
    RawEncoding,
    RejectReason,
    Twist,
    Waypoint,
)
from glove.adapter.base import DeactivateMode
from glove.adapter.examples.mock_humanoid import MockHumanoidAdapter
from glove.adapter.examples.mock_industrial_arm import MockIndustrialArmAdapter
from glove.adapter.examples.mock_mobile_base import MockMobileBaseAdapter

BEING = "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f"


class FakeClock:
    def __init__(self) -> None:
        self.t = 1_000_000_000_000

    def __call__(self) -> int:
        return self.t

    def advance_s(self, s: float) -> None:
        self.t += int(s * 1e9)


def _live_glove(adapter, clock=None) -> Glove:
    g = Glove(clock=clock) if clock else Glove()
    g.attach_adapter(adapter)
    w = g.hello(BEING, ["1.0.0"])
    g.accept(w)
    return g


# -- REQ-SE-01/02 + REQ-AC-04: clip -------------------------------------------


def test_velocity_clipped_to_envelope_with_delta():  # CF-T-ACT-02 style
    g = _live_glove(MockMobileBaseAdapter())  # max 1.5 m/s, 1.8 rad/s
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((2.0, 0.0, 0.0), (0.0, 0.0, 0.15))))
    # velocity is RT: ack is EXECUTING; clip evidence is in the audit log
    clips = g.audit.entries("ENVELOPE_CLIP")
    assert clips and clips[0]["record"]["clip_delta"]["linear_excess_mps"] == pytest.approx(0.5)
    # dispatched twist was actually clipped to the composed limit
    twist_cmds = [e for e in g.audit.entries("ACTION_DISPATCHED")]
    assert twist_cmds
    assert g.adapter._last_twist[0] == pytest.approx(1.5)  # type: ignore[attr-defined]


def test_wrench_clipped_and_ack_carries_delta():  # REQ-AC-04
    g = _live_glove(MockIndustrialArmAdapter())  # arm.main: 200 N, 40 N·m
    # wrench is RT -> EXECUTING ack; verify the clip delta via a non-RT path audit
    g.submit_action(ManipulationAction(effector="arm.main", control_mode=ControlMode.WRENCH,
                                       wrench=Twist((500.0, 0, 0), (0, 0, 100.0))))
    clips = g.audit.entries("ENVELOPE_CLIP")
    assert clips
    delta = clips[0]["record"]["clip_delta"]
    assert delta["force_excess_n"] == pytest.approx(300.0)
    assert delta["torque_excess_nm"] == pytest.approx(60.0)


def test_grip_max_force_clipped():
    g = _live_glove(MockIndustrialArmAdapter())  # gripper.main: 80 N
    ack = g.submit_action(ManipulationAction(effector="gripper.main",
                                             control_mode=ControlMode.GRIP,
                                             grip=Grip(aperture=0.5, max_force=120.0)))
    assert ack.status == "ACT_CLIPPED"
    assert ack.clip_delta["grip.max_force"] == [120.0, 80.0]


def test_pose_goal_in_forbidden_zone_refused():  # REQ-SE-02(b)
    g = _live_glove(MockIndustrialArmAdapter())
    ack = g.submit_action(ManipulationAction(
        effector="arm.main", control_mode=ControlMode.POSE_TRAJ,
        waypoints=(Waypoint(t_from_start_s=0.0,
                            pose=Pose((0.0, 0.0, 0.5), (1, 0, 0, 0))),),  # inside pedestal column
    ))
    assert ack.status == "ACT_REJECTED" and ack.reason == str(RejectReason.ENVELOPE_VIOLATION)
    # nothing was dispatched (REQ-AC-01: never partially executed)
    assert not any(e["record"]["kind"] == "pose_traj" for e in g.audit.entries("ACTION_DISPATCHED"))


def test_pose_traj_clipped_to_workspace():
    g = _live_glove(MockIndustrialArmAdapter())  # workspace z <= 1.6
    ack = g.submit_action(ManipulationAction(
        effector="arm.main", control_mode=ControlMode.POSE_TRAJ,
        waypoints=(Waypoint(t_from_start_s=0.0, pose=Pose((0.5, 0.0, 5.0), (1, 0, 0, 0))),),
    ))
    assert ack.status == "ACT_CLIPPED"
    assert ack.clip_delta["waypoints[0].pose.position"][1][2] == pytest.approx(1.6)


# -- REQ-SE-03 composition ------------------------------------------------------


def test_policy_may_only_tighten():
    adapter = MockMobileBaseAdapter()
    g = Glove(policy_tighten={"max_linear_mps": 0.5})  # tighter than 1.5
    g.attach_adapter(adapter)
    w = g.hello(BEING, ["1.0.0"]); g.accept(w)
    assert g.envelope.params.max_linear_mps == 0.5  # type: ignore[union-attr]
    g2 = Glove(policy_tighten={"max_linear_mps": 99.0})  # loosening attempt
    g2.attach_adapter(MockMobileBaseAdapter())
    assert g2.envelope.params.max_linear_mps == 1.5  # type: ignore[union-attr]  # never loosened (REQ-SE-03)


def test_composed_params_hash_stamped_at_session_start():
    g = _live_glove(MockMobileBaseAdapter())
    composed = g.audit.entries("ENVELOPE_COMPOSED")
    assert composed and composed[0]["record"]["params_hash"] == g.envelope.params_hash()  # type: ignore[union-attr]


# -- REQ-SE-04 dead-man (CF-T-ACT-01) -------------------------------------------


def test_deadman_expiry_commands_controlled_stop():
    clock = FakeClock()
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter, clock)
    acks = []
    g.on_ack(acks.append)
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                     twist=Twist((0.5, 0, 0), (0, 0, 0))))
    assert adapter._last_twist[0] == pytest.approx(0.5)
    clock.advance_s(0.6)  # default dead-man 0.5 s lapses
    g.tick()
    assert adapter._last_twist == (0.0, 0.0)  # controlled stop (REQ-AC-03)
    assert adapter.halts >= 1
    assert any(a.status == "ACT_ABORTED" and a.cause == str(AbortCause.DEADMAN) for a in acks)


def test_deadman_refresh_prevents_stop():
    clock = FakeClock()
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter, clock)
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((0.5, 0, 0), (0, 0, 0))))
    clock.advance_s(0.3)
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((0.6, 0, 0), (0, 0, 0))))
    clock.advance_s(0.3)
    g.tick()
    assert adapter._last_twist[0] == pytest.approx(0.6)  # still alive


def test_deadman_uses_per_message_duration_s():
    """W1 / §3.1.1: the locomotion dead-man timeout is the MESSAGE's
    duration_s, not the fixed envelope default (REQ-SE-04)."""
    clock = FakeClock()
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter, clock)
    acks = []
    g.on_ack(acks.append)
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                     twist=Twist((0.5, 0, 0), (0, 0, 0)), duration_s=5.0))
    clock.advance_s(0.6)  # past the 0.5 s default, within the message's 5.0 s
    g.tick()
    assert adapter._last_twist[0] == pytest.approx(0.5)  # MUST NOT stop yet
    assert not any(a.status == "ACT_ABORTED" for a in acks)
    clock.advance_s(4.5)  # now past the message's own 5.0 s deadline
    g.tick()
    assert adapter._last_twist == (0.0, 0.0)
    assert any(a.status == "ACT_ABORTED" and a.cause == str(AbortCause.DEADMAN) for a in acks)


def test_deadman_short_per_message_duration_stops_earlier():
    """W1: a message carrying duration_s=0.2 must stop by 0.3 s."""
    clock = FakeClock()
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter, clock)
    acks = []
    g.on_ack(acks.append)
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                     twist=Twist((0.5, 0, 0), (0, 0, 0)), duration_s=0.2))
    clock.advance_s(0.3)  # past the message's own 0.2 s deadline
    g.tick()
    assert adapter._last_twist == (0.0, 0.0)
    assert any(a.status == "ACT_ABORTED" and a.cause == str(AbortCause.DEADMAN) for a in acks)


def test_raw_deadman_uses_per_message_expires_ns():
    """M1 / §3.1.6: the raw channel dead-man deadline is the message's
    absolute expires_ns, not the fixed wrench timeout."""
    clock = FakeClock()
    adapter = MockHumanoidAdapter()
    g = _live_glove(adapter, clock)
    g.grant_raw_control(True)
    acks = []
    g.on_ack(acks.append)
    ack = g.submit_action(RawAction(channel="base.joint_vel_direct",
                                    encoding=RawEncoding.JOINT_VEL, payload=(0.1, 0.1),
                                    expires_ns=clock() + int(0.1e9)))
    assert ack.status == "ACT_EXECUTING"
    # past expires_ns (0.1 s) but still inside the fixed 0.25 s wrench default
    clock.advance_s(0.15)
    g.tick()
    assert any(a.status == "ACT_ABORTED" and a.cause == str(AbortCause.DEADMAN) for a in acks)


def test_raw_deadman_within_expiry_survives():
    """M1: before expires_ns lapses the raw channel stays alive."""
    clock = FakeClock()
    adapter = MockHumanoidAdapter()
    g = _live_glove(adapter, clock)
    g.grant_raw_control(True)
    acks = []
    g.on_ack(acks.append)
    g.submit_action(RawAction(channel="base.joint_vel_direct",
                              encoding=RawEncoding.JOINT_VEL, payload=(0.1, 0.1),
                              expires_ns=clock() + int(0.2e9)))
    clock.advance_s(0.15)  # within the message's 0.2 s expiry
    g.tick()
    assert not any(a.status == "ACT_ABORTED" for a in acks)
    clock.advance_s(0.1)  # total 0.25 s > 0.2 s expiry
    g.tick()
    assert any(a.status == "ACT_ABORTED" and a.cause == str(AbortCause.DEADMAN) for a in acks)


# -- W2: RT dispatch faults must not be masked as ACT_EXECUTING -----------------


def test_rt_dispatch_fault_not_masked_as_executing():
    """W2: when the adapter is externally deactivated (session ACTIVE,
    envelope not tripped), an RT submit must surface the dispatch fault —
    never ACT_EXECUTING."""
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter)
    adapter.deactivate(DeactivateMode.IMMEDIATE)  # external deactivation
    assert g.session_state == "ACTIVE"
    assert not g.envelope.halted and g.envelope.degraded is None  # type: ignore[union-attr]
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((0.5, 0, 0), (0, 0, 0))))
    assert ack.status != "ACT_EXECUTING"
    assert ack.status == "ACT_ABORTED" and ack.cause == str(AbortCause.ENVELOPE_FAULT)


# -- REQ-SE-01: JOINT_TRAJ per-joint velocity limits (M3) ------------------------


def test_joint_traj_per_joint_velocity_clipped():
    """M3 / REQ-SE-01: implied per-joint velocities between JOINT_TRAJ
    waypoints clip to the descriptor-published JointLimit.max_velocity."""
    adapter = MockHumanoidAdapter()  # arm.left joints: ±2.9 rad, max 2.5 rad/s
    g = _live_glove(adapter)
    ack = g.submit_action(ManipulationAction(
        effector="arm.left", control_mode=ControlMode.JOINT_TRAJ,
        waypoints=(
            Waypoint(t_from_start_s=0.0, joints=(0.0,) * 6),
            Waypoint(t_from_start_s=0.1, joints=(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)),
        ),
    ))
    # implied velocity: 1.0 norm * 2.9 rad / 0.1 s = 29 rad/s >> 2.5 rad/s
    assert ack.status == "ACT_CLIPPED"
    old, new = ack.clip_delta["waypoints[1].joints[0]"]
    assert old == 1.0
    assert new == pytest.approx(2.5 * 0.1 * 2 / 5.8)  # allowed SI delta renormalized
    # the dispatched SI position respects the velocity limit exactly
    assert adapter._arm_si["arm.left"][0] == pytest.approx(0.25)  # 2.5 rad/s * 0.1 s


def test_joint_traj_within_velocity_limits_passes():
    adapter = MockHumanoidAdapter()
    g = _live_glove(adapter)
    ack = g.submit_action(ManipulationAction(
        effector="arm.left", control_mode=ControlMode.JOINT_TRAJ,
        waypoints=(
            Waypoint(t_from_start_s=0.0, joints=(0.0,) * 6),
            Waypoint(t_from_start_s=1.0, joints=(0.5, 0.0, 0.0, 0.0, 0.0, 0.0)),
        ),
    ))
    # implied velocity: 0.5 norm * 2.9 rad / 1.0 s = 1.45 rad/s < 2.5 rad/s
    assert ack.status == "ACT_COMPLETED"
    assert not g.audit.entries("ENVELOPE_CLIP")


# -- REQ-SE-05 watchdog / impact / e-stop ----------------------------------------


def test_impact_above_ceiling_trips_halt():  # REQ-SC-05 + REQ-SE-05
    adapter = MockMobileBaseAdapter()  # ceiling 30 N
    g = _live_glove(adapter)
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((0.5, 0, 0), (0, 0, 0))))
    adapter.emit_bump("base.bump.front", 45.0)
    assert g.envelope.halted  # type: ignore[union-attr]
    assert adapter.halts >= 1
    assert any(e["kind"] == "ENVELOPE_HALT" for e in g.audit.entries())


def test_watchdog_trip_halts():
    clock = FakeClock()
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter, clock)
    clock.advance_s(10.0)  # adapter heartbeat watchdog (0.5 s) starves: no tick pets... tick pets when ACTIVE
    g.envelope.check_watchdogs()  # type: ignore[union-attr]
    assert g.envelope.halted  # type: ignore[union-attr]


def test_halt_blocks_further_actions_until_governance_clears():
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter)
    adapter.emit_bump("base.bump.front", 100.0)
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((0.5, 0, 0), (0, 0, 0))))
    assert ack.status == "ACT_REJECTED"
    assert not g.envelope.clear_halt(governance_clearance=False)  # type: ignore[union-attr]
    assert g.envelope.clear_halt(governance_clearance=True)  # type: ignore[union-attr]


# -- REQ-SE-06 degraded mode -----------------------------------------------------


def test_degraded_mode_entry_and_clearance():
    g = _live_glove(MockMobileBaseAdapter())
    mode = g.envelope.enter_degraded(None, "PULSE_TETHER_LOSS")  # type: ignore[union-attr]
    assert mode is DegradedMode.HOLD  # adapter-declared default
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((0.5, 0, 0), (0, 0, 0))))
    assert ack.status == "ACT_REJECTED"  # remains degraded
    assert not g.envelope.exit_degraded(governance_clearance=False)  # type: ignore[union-attr]
    assert g.envelope.exit_degraded(governance_clearance=True)  # type: ignore[union-attr]


def test_critical_fault_triggers_degraded():  # REQ-SC-08 + REQ-SE-06
    from glove.contract.sensory import Fault, FaultSeverity
    adapter = MockMobileBaseAdapter()
    g = _live_glove(adapter)
    adapter.report_fault(Fault(code="mockbase.motor.overtemp", severity=FaultSeverity.CRITICAL))
    assert g.envelope.degraded is not None  # type: ignore[union-attr]


# -- REQ-SE-02 non-origination + REQ-SE-08 audit -----------------------------------


def test_envelope_never_originates_actions():
    # No dispatch may occur without a being action message (§1.3, REQ-SE-02).
    g = _live_glove(MockMobileBaseAdapter())
    g.envelope.enter_degraded(DegradedMode.HOLD, "test")  # type: ignore[union-attr]
    g.tick()
    dispatched = g.audit.entries("ACTION_DISPATCHED")
    assert dispatched == []  # halts/stops are protective terminations, not actuation


def test_every_envelope_decision_audited_with_params_hash():  # REQ-SE-08
    g = _live_glove(MockMobileBaseAdapter())
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY, twist=Twist((9.0, 0, 0), (0, 0, 0))))
    clips = g.audit.entries("ENVELOPE_CLIP")
    assert clips and clips[0]["record"]["params_hash"] == g.envelope.params_hash()  # type: ignore[union-attr]
    assert g.audit.verify_chain()  # REQ-CF-09 hash chain intact
