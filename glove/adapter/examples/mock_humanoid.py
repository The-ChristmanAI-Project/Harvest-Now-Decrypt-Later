"""MockHumanoidAdapter — §4 boundary example.

Simulated humanoid: two 6-DOF arms with grippers, 2-DOF neck, mobile base,
head RGB camera, microphone array, TTS, face, LEDs. Declares the broadest
capability subset of the three mocks — including ACT_ATTENTION and a
governance-gated raw channel — to demonstrate full-modality negotiation.
Declared SIMULATED per REQ-CV-07.
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

_ARM_LIMITS = tuple((-2.9, 2.9) for _ in range(6))
_NECK_LIMITS = ((-1.57, 1.57), (-0.8, 0.8))  # pan, tilt


class MockHumanoidAdapter(RobotAdapter):
    """Full-modality simulated humanoid (SIMULATED, REQ-CV-07)."""

    def __init__(self, serial: str = "MOCKHUM-0001") -> None:
        super().__init__()
        self._serial = serial
        self._connected = False
        self._last_twist = (0.0, 0.0)
        self._arm_si = {"arm.left": [0.0] * 6, "arm.right": [0.0] * 6}
        self._neck = [0.0, 0.0]
        self._halts = 0
        self._speech_log: list[str] = []
        self._gaze = (0.0, 0.0)
        self.executed: list[MappedCommand] = []

    # -- lifecycle ------------------------------------------------------------

    def _discover_impl(self) -> Iterable[Any]:
        return [{"serial": self._serial, "transport": "sim://local"}]

    def _connect_impl(self, handle: Any) -> None:
        self._connected = True

    def _calibrate_impl(self, profile: dict[str, Any] | None) -> CapabilityDescriptor:
        arm_joints = tuple(
            JointLimit(f"j{i+1}", lo, hi, max_velocity=2.5, max_effort=60.0)
            for i, (lo, hi) in enumerate(_ARM_LIMITS)
        )
        descriptor = CapabilityDescriptor(
            descriptor_version="1.0.0",
            body_class="mock.humanoid",
            body_serial=self._serial,
            simulated=True,
            contract_versions=("1.0.0",),
            action_types=(
                str(MsgType.ACT_LOCOMOTION), str(MsgType.ACT_MANIPULATION),
                str(MsgType.ACT_EXPRESSION), str(MsgType.ACT_ATTENTION),
                str(MsgType.ACT_TOOL), str(MsgType.ACT_RAW),
            ),
            locomotion_modes=("VELOCITY", "POSE_GOAL"),
            expression_channels=("SPEECH", "FACE", "POSTURE", "LED"),
            face_expressions=("neutral", "smile", "concern", "attentive"),
            joint_groups=(
                JointGroup(name="arm.left", joints=arm_joints),
                JointGroup(name="arm.right", joints=arm_joints),
                JointGroup(name="head.neck", joints=tuple(
                    JointLimit(name, lo, hi, max_velocity=3.0, max_effort=5.0)
                    for name, (lo, hi) in zip(("head.pan", "head.tilt"), _NECK_LIMITS)
                )),
            ),
            effectors=(
                EffectorDecl("arm.left", ("POSE_TRAJ", "JOINT_TRAJ", "WRENCH", "GRIP"),
                             max_force_n=100.0, max_torque_nm=20.0),
                EffectorDecl("arm.right", ("POSE_TRAJ", "JOINT_TRAJ", "WRENCH", "GRIP"),
                             max_force_n=100.0, max_torque_nm=20.0),
                EffectorDecl("gripper.left", ("GRIP",), max_force_n=60.0, max_torque_nm=0.0),
                EffectorDecl("gripper.right", ("GRIP",), max_force_n=60.0, max_torque_nm=0.0),
            ),
            tools=(
                ToolDecl("tool.flashlight.01", ("ATTACH", "DETACH", "ACTIVATE", "DEACTIVATE"),
                         manifest={"intensity": [0.0, 1.0]}),
            ),
            sensors=(
                SensorDecl("body.encoders", str(MsgType.SN_PROPRIO), 200.0, frame="GLOVE-BASE"),
                SensorDecl("hand.left.palm", str(MsgType.SN_CONTACT), 100.0, frame="GLOVE-TOOL"),
                SensorDecl("head.rgb", str(MsgType.SN_VISION), 30.0, frame="GLOVE-CAMERA.head.rgb"),
                SensorDecl("head.mic", str(MsgType.SN_AUDIO), 0.0, frame="GLOVE-HEAD"),
                SensorDecl("body.controller", str(MsgType.SN_INTERNAL), 5.0),
            ),
            static_transforms=(
                FrameTransform("GLOVE-WORLD", "GLOVE-BASE", (0.0, 0.0, 0.0), (1.0, 0.0, 0.0, 0.0)),
                FrameTransform("GLOVE-BASE", "GLOVE-HEAD", (0.0, 0.0, 1.55), (1.0, 0.0, 0.0, 0.0)),
                FrameTransform("GLOVE-HEAD", "GLOVE-CAMERA.head.rgb", (0.06, 0.0, 0.04),
                               (0.5, -0.5, 0.5, -0.5)),
            ),
            envelope_params=self.physical_limits(),
            raw_channels=("base.joint_vel_direct",),  # optional modality raw_control
            optional_modalities=("raw_control", "audio_stream"),
            qos_rates={str(MsgType.SN_PROPRIO): 200.0, str(MsgType.SN_VISION): 30.0,
                       str(MsgType.SN_CONTACT): 100.0, str(MsgType.SN_INTERNAL): 5.0},
            detector_artifacts={"vision.motion": "sha256:frozen-motion-detector-v1"},  # REQ-SC-06
            extensions={"mock.mapping_table_hash": DEFAULT_TABLE.hash()},
        )
        return descriptor.sign(self.adapter_key)

    def _activate_impl(self) -> None:
        if not self._connected:
            raise AdapterFaultError(LifecycleFault.ACTIVATION_FAULT, "not connected")

    def _deactivate_impl(self, mode: DeactivateMode) -> None:
        self._last_twist = (0.0, 0.0)

    def _disconnect_impl(self) -> None:
        self._connected = False

    # -- dispatch (REQ-AD-04/05) ------------------------------------------------

    def _dispatch_impl(self, cmd: MappedCommand) -> DispatchResult:
        self.executed.append(cmd)
        if cmd.kind == "twist":
            self._last_twist = (cmd.body["linear"][0], cmd.body["angular"][2])
            return DispatchResult(cmd.command_handle, DispatchOutcome.EXECUTING)
        if cmd.kind == "pose_goal":
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "joint_traj":
            self._arm_si[cmd.body["effector"]] = list(cmd.body["waypoints"][-1]["joints_si"])
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "pose_traj":
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "wrench":
            return DispatchResult(cmd.command_handle, DispatchOutcome.EXECUTING)
        if cmd.kind == "grip":
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "speech":
            self._speech_log.append(cmd.body["text"])  # verbatim (§3.1.3)
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind in ("face", "posture", "led"):
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "attention":
            self._neck = [cmd.body.get("pan_rad", 0.0), cmd.body.get("tilt_rad", 0.0)]
            self._gaze = (self._neck[0], self._neck[1])
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "tool":
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "raw":
            return DispatchResult(cmd.command_handle, DispatchOutcome.EXECUTING)
        return DispatchResult(cmd.command_handle, DispatchOutcome.FAULT, f"unsupported kind {cmd.kind}")

    def halt(self) -> None:
        """REQ-AD-06: controlled stop; damped-brake safest state."""
        self._last_twist = (0.0, 0.0)
        self._halts += 1

    # -- safety configuration (REQ-AD-10) ----------------------------------------

    def physical_limits(self) -> EnvelopeParams:
        return EnvelopeParams(
            max_linear_mps=0.8,
            max_angular_radps=1.2,
            workspace_min=(-1.0, -1.0, 0.0),
            workspace_max=(1.0, 1.0, 2.0),
            forbidden_zones=(
                {"name": "torso_self_collision", "min": (-0.2, -0.2, 0.6), "max": (0.2, 0.2, 1.4)},
            ),
            impact_force_ceiling_n=50.0,
            estop={"type": "controlled_stop", "latency_ms_max": 10},
            deadman_locomotion_s=0.5,
            deadman_wrench_s=0.25,
            degraded_mode="HOLD",
        )

    # -- simulated sensory ingestion (deterministic, REQ-AD-08) -------------------

    @property
    def halts(self) -> int:
        return self._halts

    @property
    def speech_log(self) -> list[str]:
        return list(self._speech_log)

    @property
    def gaze(self) -> tuple[float, float]:
        return self._gaze

    def emit_tick(self) -> None:
        v, w = self._last_twist
        groups = []
        for name, si in self._arm_si.items():
            groups.append({
                "name": name,
                "joints": [normalize_joint(x, *_ARM_LIMITS[i]) for i, x in enumerate(si)],
                "joints_si": list(si),
                "velocities": [0.0] * 6,
            })
        groups.append({
            "name": "head.neck",
            "joints": [normalize_joint(self._neck[i], *_NECK_LIMITS[i]) for i in range(2)],
            "joints_si": list(self._neck),
        })
        self._emit_sensory(str(MsgType.SN_PROPRIO), {
            "groups": groups,
            "imu": {"linear_accel": [0.0, 0.0, 9.81], "angular_vel": [0.0, 0.0, w],
                    "orientation": [1.0, 0.0, 0.0, 0.0]},
            "odom": {"twist": {"linear": [v, 0.0, 0.0], "angular": [0.0, 0.0, w]}},
        })

    def emit_vision(self) -> None:
        """Normalized vision summary only; raw imagery NEVER crosses the
        contract (REQ-SC-07). Detection runs on a frozen, declared artifact
        (REQ-SC-06)."""
        self._emit_sensory(str(MsgType.SN_VISION), {
            "frames": [{
                "camera": "head.rgb", "encoding": "RGB8", "width": 640, "height": 480,
                "data_ref": "shm://glove-local/frames/mock-0001",
                "intrinsics": {"fx": 525.0, "fy": 525.0, "cx": 320.0, "cy": 240.0},
            }],
            "events": [{
                "kind": "OBJECT_TRACK", "track_id": "trk-0001",
                "bbox": [0.41, 0.30, 0.12, 0.22], "position": [1.20, -0.35, 1.10],
                "frame": "GLOVE-WORLD", "confidence": 0.87,
            }],
        })

    def emit_audio(self, label: str = "glass_break") -> None:
        self._emit_sensory(str(MsgType.SN_AUDIO), {
            "events": [{"kind": "SOUND_EVENT", "label": label, "direction": [0.78, 0.12],
                        "level_db": 71.5, "confidence": 0.93}],
        })

    def emit_internal(self) -> None:
        self._emit_sensory(str(MsgType.SN_INTERNAL), {
            "battery": {"soc": 0.83, "voltage": 25.9, "current": 2.1},
            "faults": [{"code": f.code, "severity": str(f.severity), "message": f.message}
                       for f in self.faults],
            "compute": {"load": 0.37, "mem_used": 0.42},
        })
