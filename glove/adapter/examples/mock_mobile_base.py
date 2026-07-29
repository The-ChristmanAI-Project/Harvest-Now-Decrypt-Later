"""MockMobileBaseAdapter — §4 boundary example (cf. spec Appendix B).

Simulated differential-drive base: 2 wheel encoders, IMU, bump sensors,
battery. NO real hardware dependencies; the "native driver" is a
deterministic in-process simulation. Declares NO manipulation, attention, or
vision — a deliberately small capability subset to demonstrate negotiation
and graceful degradation (REQ-CV-06). Declared SIMULATED per REQ-CV-07.
"""

from __future__ import annotations

import math
from typing import Any, Iterable

from ...contract.capabilities import (
    CapabilityDescriptor,
    EnvelopeParams,
    FrameTransform,
    JointGroup,
    JointLimit,
    SensorDecl,
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

WHEEL_RADIUS_M = 0.10
TRACK_WIDTH_M = 0.40
WHEEL_LIMIT = (-12.0, 12.0)  # rad/s equivalent position limits are wide; use velocity


class MockMobileBaseAdapter(RobotAdapter):
    """Differential-drive mobile base (SIMULATED, REQ-CV-07)."""

    def __init__(self, serial: str = "MOCKBASE-0001") -> None:
        super().__init__()
        self._serial = serial
        self._connected = False
        self._last_twist = (0.0, 0.0)  # (v m/s, w rad/s) robot-space
        self._odom = (0.0, 0.0, 0.0)   # x, y, theta — deterministic sim state
        self._tick = 0
        self._halts = 0
        self._speech_log: list[str] = []

    # -- lifecycle hooks (REQ-AD-01/02) --------------------------------------

    def _discover_impl(self) -> Iterable[Any]:
        return [{"serial": self._serial, "transport": "sim://local"}]

    def _connect_impl(self, handle: Any) -> None:
        if handle is not None and handle.get("serial") not in (None, self._serial):
            raise AdapterFaultError(LifecycleFault.CONNECT_FAULT, "serial mismatch")
        self._connected = True  # motion stays inhibited until activate()

    def _calibrate_impl(self, profile: dict[str, Any] | None) -> CapabilityDescriptor:
        # Calibration artifacts: frame transforms + mapping constants. A
        # continuity-packet profile for this body class is accepted verbatim
        # (§7.2 CALIBRATE); values are identical because the sim is static.
        descriptor = CapabilityDescriptor(
            descriptor_version="1.0.0",
            body_class="mock.mobile_base",
            body_serial=self._serial,
            simulated=True,  # REQ-CV-07
            contract_versions=("1.0.0",),
            action_types=(str(MsgType.ACT_LOCOMOTION), str(MsgType.ACT_EXPRESSION)),
            locomotion_modes=("VELOCITY", "POSE_GOAL"),
            expression_channels=("SPEECH", "LED"),
            joint_groups=(
                JointGroup(name="base.wheels", joints=(
                    JointLimit("wheel.left", -1e6, 1e6, max_velocity=15.0, max_effort=40.0),
                    JointLimit("wheel.right", -1e6, 1e6, max_velocity=15.0, max_effort=40.0),
                )),
            ),
            sensors=(
                SensorDecl("base.encoders", str(MsgType.SN_PROPRIO), 200.0, frame="GLOVE-BASE"),
                SensorDecl("base.imu", str(MsgType.SN_PROPRIO), 100.0, frame="GLOVE-HEAD"),
                SensorDecl("base.bump", str(MsgType.SN_CONTACT), 100.0),
                SensorDecl("base.battery", str(MsgType.SN_INTERNAL), 1.0),
            ),
            static_transforms=(
                FrameTransform("GLOVE-WORLD", "GLOVE-BASE", (0.0, 0.0, 0.0), (1.0, 0.0, 0.0, 0.0)),
                FrameTransform("GLOVE-BASE", "GLOVE-HEAD", (0.0, 0.0, 0.25), (1.0, 0.0, 0.0, 0.0)),
            ),
            envelope_params=self.physical_limits(),
            qos_rates={str(MsgType.SN_PROPRIO): 200.0, str(MsgType.SN_CONTACT): 100.0,
                       str(MsgType.SN_INTERNAL): 1.0},
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

    # -- dispatch (REQ-AD-04/05): already validated + clipped robot-space ----

    def _dispatch_impl(self, cmd: MappedCommand) -> DispatchResult:
        if cmd.kind == "twist":
            v = cmd.body["linear"][0]
            w = cmd.body["angular"][2]
            # Robot-native conversion: twist -> (v_left, v_right) wheel speeds.
            v_left = (v - w * TRACK_WIDTH_M / 2.0) / WHEEL_RADIUS_M
            v_right = (v + w * TRACK_WIDTH_M / 2.0) / WHEEL_RADIUS_M
            self._last_twist = (v, w)
            self._wheel_speeds = (v_left, v_right)
            return DispatchResult(cmd.command_handle, DispatchOutcome.EXECUTING)
        if cmd.kind == "pose_goal":
            self._odom = (cmd.body["position"][0], cmd.body["position"][1], self._odom[2])
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "speech":
            # §3.1.3: utterance passed to the TTS stage VERBATIM.
            self._speech_log.append(cmd.body["text"])
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        if cmd.kind == "led":
            return DispatchResult(cmd.command_handle, DispatchOutcome.COMPLETED)
        return DispatchResult(cmd.command_handle, DispatchOutcome.FAULT, f"unsupported kind {cmd.kind}")

    def halt(self) -> None:
        """REQ-AD-06: safest native stop (controlled stop -> torque-off)."""
        self._last_twist = (0.0, 0.0)
        self._halts += 1

    # -- safety configuration (REQ-AD-10) -------------------------------------

    def physical_limits(self) -> EnvelopeParams:
        return EnvelopeParams(
            max_linear_mps=1.5,
            max_angular_radps=1.8,
            impact_force_ceiling_n=30.0,
            estop={"type": "torque_off", "latency_ms_max": 5},
            deadman_locomotion_s=0.5,
            degraded_mode="HOLD",
        )

    # -- simulated sensory ingestion (REQ-AD-07/08: deterministic) ------------

    @property
    def halts(self) -> int:
        return self._halts

    @property
    def speech_log(self) -> list[str]:
        return list(self._speech_log)

    def emit_tick(self) -> None:
        """Simulate one native sensor sweep and push NORMALIZED packets.
        Identical ticks on identical sim state produce identical outputs
        (REQ-AD-08)."""
        self._tick += 1
        v, w = self._last_twist
        x, y, th = self._odom
        dt = 0.005  # 200 Hz sim step
        x += v * math.cos(th) * dt
        y += v * math.sin(th) * dt
        th += w * dt
        self._odom = (x, y, th)
        v_l, v_r = getattr(self, "_wheel_speeds", (0.0, 0.0))
        self._emit_sensory(str(MsgType.SN_PROPRIO), {
            "groups": [{
                "name": "base.wheels",
                "joints": [normalize_joint(v_l, *WHEEL_LIMIT), normalize_joint(v_r, *WHEEL_LIMIT)],
                "joints_si": [v_l, v_r],
                "velocities": [v_l, v_r],
            }],
            "imu": {"linear_accel": [0.0, 0.0, 9.81], "angular_vel": [0.0, 0.0, w],
                    "orientation": [math.cos(th / 2), 0.0, 0.0, math.sin(th / 2)]},
            "odom": {
                "pose": {"frame": "GLOVE-WORLD", "position": [x, y, 0.0],
                         "orientation": [math.cos(th / 2), 0.0, 0.0, math.sin(th / 2)]},
                "twist": {"linear": [v, 0.0, 0.0], "angular": [0.0, 0.0, w]},
            },
        })

    def emit_bump(self, zone: str, force_n: float) -> None:
        """Simulated bump sensor; IMPACT also reaches the envelope (REQ-SC-05)."""
        self._emit_sensory(str(MsgType.SN_CONTACT), {
            "contacts": [{"sensor": zone, "normal_force": force_n, "active": True}],
            "events": [{"kind": "IMPACT", "sensor": zone, "peak_force_n": force_n,
                        "confidence": 1.0}],
        })

    def emit_internal(self) -> None:
        self._emit_sensory(str(MsgType.SN_INTERNAL), {
            "battery": {"soc": 0.62, "voltage": 24.1, "current": 3.2, "time_remaining_s": 4170},
            "faults": [{"code": f.code, "severity": str(f.severity), "message": f.message}
                       for f in self.faults],
        })
