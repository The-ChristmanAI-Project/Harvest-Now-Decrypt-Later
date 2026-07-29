"""MockIndustrialArmAdapter — §4 boundary example.

Simulated 6-DOF industrial arm on a fixed pedestal with a parallel gripper
and one declared tool. NO locomotion, NO attention/gaze, NO speech — the
capability subset demonstrates negotiation + graceful degradation on the
manipulation side (REQ-CV-06). Declared SIMULATED per REQ-CV-07.
"""

from __future__ import annotations

from typing import Any, Iterable

from ...contract.capabilities import (
    CapabilityDescriptor,
    EffectorDecl,
    EnvelopeParams,
    FrameTransform,
    JointGroup,
    JointLimit,
    SensorDecl,
    ToolDecl,
)
from ...contract.envelope import MsgType
from ...contract.sensory import normalize_joint
from ...mapping.engine import DEFAULT_TABLE
from ..base import (
    AdapterFaultError,
    DeactivateMode,
    DispatchOutcome,
    DispatchResult,
    LifecycleFault,
    MappedCommand,
    RobotAdapter,
)

_JOINT_LIMITS = tuple((-2.96, 2.96) for _ in range(6))  # rad, manufacturer spec


class MockIndustrialArmAdapter(RobotAdapter):
    """6-DOF pedestal arm + gripper + screwdriver tool (SIMULATED)."""

    def __init__(self, serial: str = "MOCKARM-0001") -> None:
        super().__init__()
        self._serial = serial
        self._connected = False
        self._joints_si = [0.0] * 6
        self._grip_stroke = 0.085
        self._tool_active = False
        self._halts = 0
        self.executed: list[MappedCommand] = []

    # -- lifecycle ------------------------------------------------------------

    def _discover_impl(self) -> Iterable[Any]:
        return [{"serial": self._serial, "transport": "sim://local"}]

    def _connect_impl(self, handle: Any) -> None:
        self._connected = True

    def _calibrate_impl(self, profile: dict[str, Any] | None) -> CapabilityDescriptor:
        descriptor = CapabilityDescriptor(
            descriptor_version="1.0.0",
            body_class="mock.industrial_arm",
            body_serial=self._serial,
            simulated=True,
            contract_versions=("1.0.0",),
            action_types=(str(MsgType.ACT_MANIPULATION), str(MsgType.ACT_TOOL),
                          str(MsgType.ACT_EXPRESSION)),
            expression_channels=("LED",),  # no speech/face on a pedestal arm
            joint_groups=(
                JointGroup(name="arm.main", joints=tuple(
                    JointLimit(f"arm.main.j{i+1}", lo, hi, max_velocity=2.0, max_effort=150.0)
                    for i, (lo, hi) in enumerate(_JOINT_LIMITS)
                )),
            ),
            effectors=(
                EffectorDecl("arm.main", ("POSE_TRAJ", "JOINT_TRAJ", "WRENCH"),
                             max_force_n=200.0, max_torque_nm=40.0),
                EffectorDecl("gripper.main", ("GRIP",), max_force_n=80.0, max_torque_nm=0.0),
            ),
            tools=(
                ToolDecl("tool.screwdriver.01",
                         ("ATTACH", "DETACH", "ACTIVATE", "DEACTIVATE", "SET_PARAM"),
                         manifest={"speed_rpm": [0, 800], "torque_limit_nm": [0.0, 2.5]}),
            ),
            sensors=(
                SensorDecl("arm.encoders", str(MsgType.SN_PROPRIO), 500.0, frame="GLOVE-TOOL"),
                SensorDecl("arm.ft", str(MsgType.SN_CONTACT), 500.0, frame="GLOVE-TOOL"),
                SensorDecl("arm.controller", str(MsgType.SN_INTERNAL), 2.0),
            ),
            static_transforms=(
                FrameTransform("GLOVE-WORLD", "GLOVE-BASE", (0.0, 0.0, 0.0), (1.0, 0.0, 0.0, 0.0)),
                FrameTransform("GLOVE-BASE", "GLOVE-TOOL", (0.0, 0.0, 0.92), (1.0, 0.0, 0.0, 0.0)),
            ),
            envelope_params=self.physical_limits(),
            qos_rates={str(MsgType.SN_PROPRIO): 500.0, str(MsgType.SN_CONTACT): 500.0,
                       str(MsgType.SN_INTERNAL): 2.0},
            extensions={"mock.mapping_table_hash": DEFAULT_TABLE.hash()},
        )
        return descriptor.sign(self.adapter_key)

    def _activate_impl(self) -> None:
        if not self._connected:
            raise AdapterFaultError(LifecycleFault.ACTIVATION_FAULT, "not connected")

    def _deactivate_impl(self, mode: DeactivateMode) -> None:
        self._tool_active = False

    def _disconnect_impl(self) -> None:
        self._connected = False

    # -- dispatch (REQ-AD-04: no re-interpretation of intent) ------------------

    def _dispatch_impl(self, cmd: MappedCommand) -> DispatchResult:
        self.executed.append(cmd)
        if cmd.kind == "joint_traj":
            self._joints_si = list(cmd.body["waypoints"][-1]["joints_si"])
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "pose_traj":
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "wrench":
            return DispatchResult(cmd.command_handle, DispatchOutcome.EXECUTING)
        if cmd.kind == "grip":
            self._grip_stroke = cmd.body["stroke_m"]
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "tool":
            if cmd.body["operation"] == "ACTIVATE":
                if cmd.body.get("safety_interlock") and not self._tool_interlock_ok():
                    return DispatchResult(cmd.command_handle, DispatchOutcome.FAULT, "interlock")
                self._tool_active = True
            elif cmd.body["operation"] == "DEACTIVATE":
                self._tool_active = False
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "led":
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        return DispatchResult(cmd.command_handle, DispatchOutcome.FAULT, f"unsupported kind {cmd.kind}")

    def _tool_interlock_ok(self) -> bool:
        return True  # simulated hardware interlock confirmation

    def halt(self) -> None:
        """REQ-AD-06: controller protective stop (brakes engaged)."""
        self._tool_active = False
        self._halts += 1

    # -- safety configuration (REQ-AD-10) -------------------------------------

    def physical_limits(self) -> EnvelopeParams:
        return EnvelopeParams(
            max_linear_mps=0.0,          # fixed pedestal: no base motion
            max_angular_radps=0.0,
            workspace_min=(-1.2, -1.2, 0.0),
            workspace_max=(1.2, 1.2, 1.6),
            forbidden_zones=(
                # self-collision volume around the pedestal column
                {"name": "pedestal_column", "min": (-0.15, -0.15, 0.0), "max": (0.15, 0.15, 0.9)},
            ),
            impact_force_ceiling_n=120.0,
            estop={"type": "protective_stop", "latency_ms_max": 8},
            deadman_wrench_s=0.25,
            degraded_mode="PARK",
        )

    # -- simulated sensory ingestion -------------------------------------------

    @property
    def halts(self) -> int:
        return self._halts

    @property
    def tool_active(self) -> bool:
        return self._tool_active

    def emit_tick(self) -> None:
        norms = [normalize_joint(v, *_JOINT_LIMITS[i]) for i, v in enumerate(self._joints_si)]
        self._emit_sensory(str(MsgType.SN_PROPRIO), {
            "groups": [{
                "name": "arm.main",
                "joints": norms,
                "joints_si": list(self._joints_si),
                "velocities": [0.0] * 6,
                "efforts": [0.0] * 6,
            }],
        })

    def emit_internal(self) -> None:
        self._emit_sensory(str(MsgType.SN_INTERNAL), {
            "battery": {"soc": 1.0, "voltage": 48.0, "current": 1.1},
            "thermal": [{"zone": "arm.main.actuator.3", "temp": 46.5}],
            "faults": [{"code": f.code, "severity": str(f.severity), "message": f.message}
                       for f in self.faults],
            "joint_limit_proximity": [{"group": "arm.main", "margin": 0.62}],
            "compute": {"load": 0.44, "mem_used": 0.51},
        })
