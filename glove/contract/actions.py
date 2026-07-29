"""Action schema dataclasses — GLV-SPEC-1.0.0 §3.1.

Actions flow being -> Glove. All spatial quantities MUST use SI units
(REQ-SC-01) and the canonical frame convention of §3.2.1 (REQ-SC-02).
REQ-AC-01: any action failing schema validation, referencing a non-negotiated
capability, or using out-of-range values MUST be rejected with ACT_REJECTED
carrying a machine-readable reason code; it MUST NOT be partially executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from .envelope import (
    ContractError,
    OutOfRangeError,
    QoSClass,
    MsgType,
    check_range,
    check_unit_quat,
    check_unit_vec3,
    check_vec3,
)

Vec3 = tuple[float, float, float]
Quat = tuple[float, float, float, float]

# ---------------------------------------------------------------------------
# Reason codes (machine-readable, REQ-AC-01) and abort causes (§3.1.7)
# ---------------------------------------------------------------------------


class RejectReason(StrEnum):
    SCHEMA_INVALID = "SCHEMA_INVALID"            # failed §3.1 field validation
    CAPABILITY_ABSENT = "CAPABILITY_ABSENT"      # modality absent (REQ-CV-06)
    OUT_OF_RANGE = "OUT_OF_RANGE"                # value outside declared range
    ENVELOPE_VIOLATION = "ENVELOPE_VIOLATION"    # safety-envelope refusal (REQ-SE-02)
    RAW_NOT_GRANTED = "RAW_NOT_GRANTED"          # missing raw_control grant (REQ-AC-05)
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"      # version/capability descriptor mismatch
    UNKNOWN_EFFECTOR = "UNKNOWN_EFFECTOR"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    UNKNOWN_CHANNEL = "UNKNOWN_CHANNEL"
    SESSION_INACTIVE = "SESSION_INACTIVE"        # no ACCEPT yet / session closed


class AbortCause(StrEnum):
    GOV_OVERRIDE = "GOV_OVERRIDE"   # caregiver override preemption (REQ-GV-04)
    ESTOP = "ESTOP"                 # watchdog / e-stop (REQ-SE-05)
    ENVELOPE_FAULT = "ENVELOPE_FAULT"
    DEADMAN = "DEADMAN"             # dead-man expiry stop (REQ-SE-04)
    DEACTIVATE = "DEACTIVATE"       # orderly stop (§4.1)


# ---------------------------------------------------------------------------
# Shared geometry
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class Pose:
    position: Vec3
    orientation: Quat
    frame: str = "GLOVE-WORLD"

    def validate(self, name: str = "pose") -> "Pose":
        check_vec3(self.position, f"{name}.position")
        check_unit_quat(self.orientation, f"{name}.orientation")
        return self


@dataclass(slots=True, frozen=True)
class Twist:
    linear: Vec3
    angular: Vec3

    def validate(self, name: str = "twist") -> "Twist":
        check_vec3(self.linear, f"{name}.linear")
        check_vec3(self.angular, f"{name}.angular")
        return self


# ---------------------------------------------------------------------------
# §3.1.1 Locomotion — ACT_LOCOMOTION
# ---------------------------------------------------------------------------


class LocomotionMode(StrEnum):
    VELOCITY = "VELOCITY"    # QoS RT, 50-200 Hz, dead-man (REQ-AC-03)
    POSE_GOAL = "POSE_GOAL"  # QoS EVENT


class Priority(StrEnum):
    NORMAL = "NORMAL"
    YIELD = "YIELD"
    URGENT = "URGENT"  # scheduling hint; still subordinate to envelope + governance


DEFAULT_LOCO_DEADMAN_S = 0.5  # §3.1.1 default duration_s / REQ-SE-04


@dataclass(slots=True, frozen=True)
class LocomotionAction:
    mode: LocomotionMode
    twist: Twist | None = None          # GLOVE-BASE frame, m/s + rad/s (VELOCITY)
    goal_pose: Pose | None = None       # GLOVE-WORLD frame (POSE_GOAL)
    duration_s: float = DEFAULT_LOCO_DEADMAN_S  # dead-man expiry, (0, 30]
    priority: Priority = Priority.NORMAL

    qos: QoSClass = field(init=False, default=QoSClass.RT)

    def validate(self) -> "LocomotionAction":
        if not isinstance(self.mode, LocomotionMode):
            raise ContractError(f"locomotion mode must be one of {list(LocomotionMode)}")
        if self.mode is LocomotionMode.VELOCITY:
            if self.twist is None:
                raise ContractError("VELOCITY mode requires twist")
            self.twist.validate()
        if self.mode is LocomotionMode.POSE_GOAL:
            if self.goal_pose is None:
                raise ContractError("POSE_GOAL mode requires goal_pose")
            self.goal_pose.validate("goal_pose")
        check_range(self.duration_s, "duration_s", 0.0, 30.0, open_lo=True)
        if not isinstance(self.priority, Priority):
            raise ContractError(f"priority must be one of {list(Priority)}")
        object.__setattr__(
            self, "qos", QoSClass.RT if self.mode is LocomotionMode.VELOCITY else QoSClass.EVENT
        )
        return self

    def to_payload(self) -> dict[str, Any]:
        d: dict[str, Any] = {"mode": str(self.mode), "duration_s": self.duration_s,
                             "priority": str(self.priority)}
        if self.twist is not None:
            d["twist"] = {"linear": list(self.twist.linear), "angular": list(self.twist.angular)}
        if self.goal_pose is not None:
            d["goal_pose"] = {
                "frame": self.goal_pose.frame,
                "position": list(self.goal_pose.position),
                "orientation": list(self.goal_pose.orientation),
            }
        return d


# ---------------------------------------------------------------------------
# §3.1.2 Manipulation — ACT_MANIPULATION
# ---------------------------------------------------------------------------


class ControlMode(StrEnum):
    POSE_TRAJ = "POSE_TRAJ"
    JOINT_TRAJ = "JOINT_TRAJ"
    WRENCH = "WRENCH"
    GRIP = "GRIP"


MAX_WAYPOINTS = 64  # §3.1.2
DEFAULT_WRENCH_DEADMAN_S = 0.25  # §3.1.2 / REQ-SE-04


@dataclass(slots=True, frozen=True)
class Waypoint:
    t_from_start_s: float
    pose: Pose | None = None            # GLOVE-TOOL frame (POSE_TRAJ)
    joints: tuple[float, ...] | None = None  # normalized [-1, 1] (JOINT_TRAJ)

    def validate(self, mode: ControlMode) -> "Waypoint":
        check_range(self.t_from_start_s, "waypoints[].t_from_start_s", 0.0, float("inf"))
        if mode is ControlMode.POSE_TRAJ:
            if self.pose is None:
                raise ContractError("POSE_TRAJ waypoint requires pose")
            self.pose.validate("waypoints[].pose")
        if mode is ControlMode.JOINT_TRAJ:
            if self.joints is None:
                raise ContractError("JOINT_TRAJ waypoint requires joints (normalized)")
            for i, j in enumerate(self.joints):
                check_range(j, f"waypoints[].joints[{i}]", -1.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class Grip:
    aperture: float                # [0,1]: 0 = closed, 1 = open
    max_force: float | None = None  # N, envelope-clipped

    def validate(self) -> "Grip":
        check_range(self.aperture, "grip.aperture", 0.0, 1.0)
        if self.max_force is not None:
            check_range(self.max_force, "grip.max_force", 0.0, float("inf"), open_lo=True)
        return self


@dataclass(slots=True, frozen=True)
class ManipulationAction:
    effector: str                     # logical name from capability descriptor
    control_mode: ControlMode
    waypoints: tuple[Waypoint, ...] = ()
    wrench: Twist | None = None       # force (N) in .linear, torque (N·m) in .angular, GLOVE-TOOL
    grip: Grip | None = None
    impedance: dict[str, Any] | None = None  # optional stiffness/damping overrides

    def validate(self) -> "ManipulationAction":
        if not self.effector or not isinstance(self.effector, str):
            raise ContractError("effector must be a non-empty logical effector name")
        if not isinstance(self.control_mode, ControlMode):
            raise ContractError(f"control_mode must be one of {list(ControlMode)}")
        if self.control_mode in (ControlMode.POSE_TRAJ, ControlMode.JOINT_TRAJ):
            if not self.waypoints:
                raise ContractError(f"{self.control_mode} requires waypoints")
            if len(self.waypoints) > MAX_WAYPOINTS:
                raise ContractError(f"waypoints exceed {MAX_WAYPOINTS} points")
            last_t = -1.0
            for wp in self.waypoints:
                wp.validate(self.control_mode)
                if wp.t_from_start_s < last_t:
                    raise ContractError("waypoints[].t_from_start_s must be monotonic")
                last_t = wp.t_from_start_s
        if self.control_mode is ControlMode.WRENCH:
            if self.wrench is None:
                raise ContractError("WRENCH mode requires wrench (force N, torque N·m)")
            self.wrench.validate("wrench")
        if self.control_mode is ControlMode.GRIP:
            if self.grip is None:
                raise ContractError("GRIP mode requires grip")
            self.grip.validate()
        return self

    @property
    def qos(self) -> QoSClass:
        # §3.1.2: trajectories EVENT for submission; WRENCH is RT 100-500 Hz dead-man.
        return QoSClass.RT if self.control_mode is ControlMode.WRENCH else QoSClass.EVENT


# ---------------------------------------------------------------------------
# §3.1.3 Speech / Gesture — ACT_EXPRESSION
# ---------------------------------------------------------------------------


class ExpressionChannel(StrEnum):
    SPEECH = "SPEECH"
    FACE = "FACE"
    POSTURE = "POSTURE"
    LED = "LED"


MAX_UTTERANCE_CHARS = 4096  # §3.1.3


@dataclass(slots=True, frozen=True)
class Utterance:
    text: str
    locale: str | None = None      # BCP-47 hint
    prosody: dict[str, float] | None = None  # rate [0.5,2], pitch [0.5,2], gain [0,1]

    def validate(self) -> "Utterance":
        if not isinstance(self.text, str) or len(self.text) > MAX_UTTERANCE_CHARS:
            raise ContractError(f"utterance.text must be <= {MAX_UTTERANCE_CHARS} chars")
        if self.prosody:
            if "rate" in self.prosody:
                check_range(self.prosody["rate"], "prosody.rate", 0.5, 2.0)
            if "pitch" in self.prosody:
                check_range(self.prosody["pitch"], "prosody.pitch", 0.5, 2.0)
            if "gain" in self.prosody:
                check_range(self.prosody["gain"], "prosody.gain", 0.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class LedPattern:
    color_rgb: Vec3     # [0,1]^3
    duty: float         # [0,1]
    period_s: float     # > 0

    def validate(self) -> "LedPattern":
        c = check_vec3(self.color_rgb, "led.color")
        for i, v in enumerate(c):
            check_range(v, f"led.color[{i}]", 0.0, 1.0)
        check_range(self.duty, "led.duty", 0.0, 1.0)
        check_range(self.period_s, "led.period_s", 0.0, float("inf"), open_lo=True)
        return self


@dataclass(slots=True, frozen=True)
class ExpressionAction:
    channel: ExpressionChannel
    utterance: Utterance | None = None     # SPEECH
    expression: str | None = None          # FACE: named expression from declared set
    posture: Pose | None = None            # POSTURE: manipulation semantics
    led: LedPattern | None = None          # LED

    def validate(self) -> "ExpressionAction":
        if not isinstance(self.channel, ExpressionChannel):
            raise ContractError(f"channel must be one of {list(ExpressionChannel)}")
        if self.channel is ExpressionChannel.SPEECH:
            if self.utterance is None:
                raise ContractError("SPEECH channel requires utterance")
            # REQ (§3.1.3): the Glove performs NO NLP on utterance.text; verbatim pass.
            self.utterance.validate()
        if self.channel is ExpressionChannel.FACE and not self.expression:
            raise ContractError("FACE channel requires expression name")
        if self.channel is ExpressionChannel.POSTURE:
            if self.posture is None:
                raise ContractError("POSTURE channel requires posture pose")
            self.posture.validate("posture.pose")
        if self.channel is ExpressionChannel.LED:
            if self.led is None:
                raise ContractError("LED channel requires led pattern")
            self.led.validate()
        return self

    qos: QoSClass = field(init=False, default=QoSClass.EVENT)


# ---------------------------------------------------------------------------
# §3.1.4 Attention / Gaze — ACT_ATTENTION
# ---------------------------------------------------------------------------


class AttentionMode(StrEnum):
    FIXATE = "FIXATE"
    SMOOTH_PURSUIT = "SMOOTH_PURSUIT"
    SACCADE = "SACCADE"
    RELEASE = "RELEASE"


@dataclass(slots=True, frozen=True)
class AttentionAction:
    mode: AttentionMode
    point: Vec3 | None = None       # fixation point, GLOVE-WORLD
    direction: Vec3 | None = None   # unit gaze direction, GLOVE-HEAD
    track_id: str | None = None     # from SN_VISION events
    frame: str = "GLOVE-WORLD"
    settle_s: float = 0.0           # [0, 5]

    def validate(self) -> "AttentionAction":
        if not isinstance(self.mode, AttentionMode):
            raise ContractError(f"mode must be one of {list(AttentionMode)}")
        specified = sum(x is not None for x in (self.point, self.direction, self.track_id))
        if specified != 1:
            raise ContractError("exactly one of target.point / target.direction / target.track_id required")
        if self.point is not None:
            check_vec3(self.point, "target.point")
        if self.direction is not None:
            check_unit_vec3(self.direction, "target.direction")
        check_range(self.settle_s, "settle_s", 0.0, 5.0)
        return self

    qos: QoSClass = field(init=False, default=QoSClass.EVENT)


# ---------------------------------------------------------------------------
# §3.1.5 Tool Use — ACT_TOOL
# ---------------------------------------------------------------------------


class ToolOperation(StrEnum):
    ATTACH = "ATTACH"
    DETACH = "DETACH"
    ACTIVATE = "ACTIVATE"
    DEACTIVATE = "DEACTIVATE"
    SET_PARAM = "SET_PARAM"


@dataclass(slots=True, frozen=True)
class ToolAction:
    tool_id: str                              # from capability descriptor
    operation: ToolOperation
    params: dict[str, Any] | None = None      # validated against tool manifest
    safety_interlock: bool = False

    def validate(self) -> "ToolAction":
        if not self.tool_id or not isinstance(self.tool_id, str):
            raise ContractError("tool_id must be a non-empty string")
        if not isinstance(self.operation, ToolOperation):
            raise ContractError(f"operation must be one of {list(ToolOperation)}")
        return self

    qos: QoSClass = field(init=False, default=QoSClass.EVENT)


# ---------------------------------------------------------------------------
# §3.1.6 Raw Low-Level Control — ACT_RAW (governance-gated escape hatch)
# ---------------------------------------------------------------------------


class RawEncoding(StrEnum):
    JOINT_VEL = "JOINT_VEL"
    JOINT_POS = "JOINT_POS"
    MOTOR_CURRENT = "MOTOR_CURRENT"
    OPAQUE = "OPAQUE"


RAW_MAX_EXPIRY_NS = 250_000_000  # expires_ns <= 250 ms from emit (§3.1.6)


@dataclass(slots=True, frozen=True)
class RawAction:
    channel: str                    # adapter-declared raw channel
    encoding: RawEncoding
    payload: tuple[float, ...] | bytes
    expires_ns: int                 # mandatory dead-man expiry (monotonic ns)

    def validate(self, *, now_ns: int | None = None) -> "RawAction":
        if not self.channel or not isinstance(self.channel, str):
            raise ContractError("channel must be a non-empty string")
        if not isinstance(self.encoding, RawEncoding):
            raise ContractError(f"encoding must be one of {list(RawEncoding)}")
        if self.encoding is RawEncoding.OPAQUE:
            if not isinstance(self.payload, (bytes, bytearray)):
                raise ContractError("OPAQUE encoding requires bytes payload")
        else:
            if not isinstance(self.payload, (list, tuple)) or not self.payload:
                raise ContractError(f"{self.encoding} encoding requires non-empty float[] payload")
            for i, v in enumerate(self.payload):
                check_range(v, f"payload[{i}]", -float("inf"), float("inf"))
        if now_ns is not None and self.expires_ns - now_ns > RAW_MAX_EXPIRY_NS:
            raise OutOfRangeError("expires_ns exceeds 250 ms from emit (§3.1.6)")
        return self

    qos: QoSClass = field(init=False, default=QoSClass.RT)


# ---------------------------------------------------------------------------
# §3.1.7 Action acknowledgement events
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class ActionAck:
    """Terminal ack payload (§3.1.7). Exactly one terminal event per action,
    EVENT QoS, referencing the original msg_id (REQ-AC-06)."""

    ref_msg_id: str
    status: Literal[
        "ACT_ACCEPTED", "ACT_EXECUTING", "ACT_COMPLETED",
        "ACT_CLIPPED", "ACT_REJECTED", "ACT_ABORTED",
    ]
    reason: str | None = None        # RejectReason for ACT_REJECTED
    cause: str | None = None         # AbortCause for ACT_ABORTED
    clip_delta: dict[str, Any] | None = None  # REQ-AC-04: what the envelope modified

    def to_payload(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ref_msg_id": self.ref_msg_id, "status": self.status}
        if self.reason is not None:
            d["reason"] = self.reason
        if self.cause is not None:
            d["cause"] = self.cause
        if self.clip_delta is not None:
            d["clip_delta"] = self.clip_delta
        return d
