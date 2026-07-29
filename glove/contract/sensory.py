"""Sensory schema dataclasses — GLV-SPEC-1.0.0 §3.2.

Sensory messages flow Glove -> being. All use the §3.0 common envelope,
SI units (REQ-SC-01), and canonical frames (REQ-SC-02): right-handed,
Z-up, X-forward, Y-left; GLOVE-CAMERA.<name> is the documented Z-up
exception (Z = optical axis outward).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .envelope import ContractError, check_range, check_unit_quat, check_vec3

Vec3 = tuple[float, float, float]
Quat = tuple[float, float, float, float]

# ---------------------------------------------------------------------------
# Joint normalization (REQ-SC-04): normalized [-1,1] maps LINEARLY to declared
# joint limits; mapping constants are published in the capability descriptor.
# ---------------------------------------------------------------------------


def normalize_joint(si_value: float, limit_min: float, limit_max: float) -> float:
    """[limit_min, limit_max] -> [-1, 1], linear (REQ-SC-04)."""
    if limit_max <= limit_min:
        raise ContractError("joint limit_max must exceed limit_min")
    mid = 0.5 * (limit_max + limit_min)
    half = 0.5 * (limit_max - limit_min)
    return (si_value - mid) / half


def denormalize_joint(norm_value: float, limit_min: float, limit_max: float) -> float:
    """[-1, 1] -> [limit_min, limit_max], linear (REQ-SC-04)."""
    mid = 0.5 * (limit_max + limit_min)
    half = 0.5 * (limit_max - limit_min)
    return mid + norm_value * half


# ---------------------------------------------------------------------------
# §3.2.2 Proprioception — SN_PROPRIO (QoS FAST, 50-500 Hz)
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class JointGroupState:
    name: str                              # logical group, e.g. "arm.left"
    joints: tuple[float, ...]              # normalized [-1, 1] per REQ-SC-04
    joints_si: tuple[float, ...]           # rad (revolute) or m (prismatic)
    velocities: tuple[float, ...] | None = None  # rad/s or m/s
    efforts: tuple[float, ...] | None = None     # N·m or N

    def validate(self) -> "JointGroupState":
        if not self.name:
            raise ContractError("groups[].name required")
        if len(self.joints) != len(self.joints_si):
            raise ContractError("groups[].joints and joints_si length mismatch")
        for i, j in enumerate(self.joints):
            check_range(j, f"groups[].joints[{i}]", -1.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class ImuState:
    linear_accel: Vec3 | None = None   # m/s^2, GLOVE-HEAD or declared IMU frame
    angular_vel: Vec3 | None = None    # rad/s
    orientation: Quat | None = None    # fused orientation

    def validate(self) -> "ImuState":
        if self.linear_accel is not None:
            check_vec3(self.linear_accel, "imu.linear_accel")
        if self.angular_vel is not None:
            check_vec3(self.angular_vel, "imu.angular_vel")
        if self.orientation is not None:
            check_unit_quat(self.orientation, "imu.orientation")
        return self


@dataclass(slots=True, frozen=True)
class OdomState:
    pose: Any = None                      # actions.Pose (GLOVE-WORLD)
    twist: Any = None                     # actions.Twist (GLOVE-BASE)
    covariance: tuple[float, ...] | None = None  # row-major 6x6, mixed SI^2

    def validate(self) -> "OdomState":
        if self.covariance is not None and len(self.covariance) != 36:
            raise ContractError("odom.covariance must be float[36]")
        return self


@dataclass(slots=True, frozen=True)
class Proprioception:
    groups: tuple[JointGroupState, ...]
    imu: ImuState | None = None
    odom: OdomState | None = None

    def validate(self) -> "Proprioception":
        if not self.groups:
            raise ContractError("SN_PROPRIO requires at least one group")
        for g in self.groups:
            g.validate()
        if self.imu is not None:
            self.imu.validate()
        if self.odom is not None:
            self.odom.validate()
        return self


# ---------------------------------------------------------------------------
# §3.2.3 Contact / Force / Tactile — SN_CONTACT (QoS FAST/EVENT)
# ---------------------------------------------------------------------------


class ContactEventKind(StrEnum):
    IMPACT = "IMPACT"              # peak force N; latency <= 20 ms (REQ-SC-05)
    SLIP = "SLIP"                  # confidence [0,1]
    GRASP_STABLE = "GRASP_STABLE"
    GRASP_LOST = "GRASP_LOST"


@dataclass(slots=True, frozen=True)
class Contact:
    sensor: str                    # logical tactile sensor/patch name
    normal_force: float            # N
    active: bool
    position: Vec3 | None = None   # centroid in sensor's declared frame

    def validate(self) -> "Contact":
        if not self.sensor:
            raise ContractError("contacts[].sensor required")
        check_range(self.normal_force, "contacts[].normal_force", 0.0, float("inf"))
        if self.position is not None:
            check_vec3(self.position, "contacts[].position")
        return self


@dataclass(slots=True, frozen=True)
class ContactEvent:
    kind: ContactEventKind
    sensor: str | None = None
    peak_force_n: float | None = None   # IMPACT
    confidence: float | None = None     # [0,1]; SLIP/IMPACT

    def validate(self) -> "ContactEvent":
        if not isinstance(self.kind, ContactEventKind):
            raise ContractError(f"events[].kind must be one of {list(ContactEventKind)}")
        if self.kind is ContactEventKind.IMPACT:
            if self.peak_force_n is None:
                raise ContractError("IMPACT event requires peak_force_n")
            check_range(self.peak_force_n, "peak_force_n", 0.0, float("inf"))
        if self.confidence is not None:
            check_range(self.confidence, "events[].confidence", 0.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class EffectorWrench:
    effector: str
    force: Vec3    # N, GLOVE-TOOL
    torque: Vec3   # N·m, GLOVE-TOOL

    def validate(self) -> "EffectorWrench":
        check_vec3(self.force, "wrenches[].force")
        check_vec3(self.torque, "wrenches[].torque")
        return self


@dataclass(slots=True, frozen=True)
class ContactReport:
    contacts: tuple[Contact, ...] = ()
    wrenches: tuple[EffectorWrench, ...] = ()
    events: tuple[ContactEvent, ...] = ()

    def validate(self) -> "ContactReport":
        for c in self.contacts:
            c.validate()
        for w in self.wrenches:
            w.validate()
        for e in self.events:
            e.validate()
        return self


# ---------------------------------------------------------------------------
# §3.2.4 Vision Summary — SN_VISION (QoS FAST, 5-60 Hz)
# Raw video frames MUST NOT transit the Neural Contract (REQ-SC-07).
# ---------------------------------------------------------------------------


class FrameEncoding(StrEnum):
    MONO8 = "MONO8"
    RGB8 = "RGB8"
    DEPTH16 = "DEPTH16"  # mm
    IR16 = "IR16"


class VisionEventKind(StrEnum):
    MOTION = "MOTION"
    OBJECT_TRACK = "OBJECT_TRACK"
    FACE_DETECT = "FACE_DETECT"
    SCENE_CHANGE = "SCENE_CHANGE"
    OCCLUSION = "OCCLUSION"


@dataclass(slots=True, frozen=True)
class FrameDescriptor:
    camera: str
    encoding: FrameEncoding
    width: int
    height: int
    data_ref: str                      # local shared-buffer handle, never a network URL
    intrinsics: dict[str, float]       # pinhole: fx, fy, cx, cy

    def validate(self) -> "FrameDescriptor":
        if not self.camera:
            raise ContractError("frames[].camera required")
        if not isinstance(self.encoding, FrameEncoding):
            raise ContractError(f"frames[].encoding must be one of {list(FrameEncoding)}")
        if not (0 < self.width <= 65535 and 0 < self.height <= 65535):
            raise ContractError("frames[].width/height must be uint16 > 0")
        if self.data_ref.startswith(("http://", "https://")):
            raise ContractError("frames[].data_ref MUST be a local handle, never a network URL (REQ-SC-07)")
        for k in ("fx", "fy", "cx", "cy"):
            if k not in self.intrinsics:
                raise ContractError(f"frames[].intrinsics.{k} required")
        return self


@dataclass(slots=True, frozen=True)
class VisionEvent:
    kind: VisionEventKind
    confidence: float                       # [0,1], required
    track_id: str | None = None             # stable per-session (track kinds)
    bbox: tuple[float, float, float, float] | None = None  # normalized [0,1], (x,y,w,h)
    position: Vec3 | None = None            # GLOVE-HEAD or GLOVE-WORLD
    frame: str | None = None

    def validate(self) -> "VisionEvent":
        if not isinstance(self.kind, VisionEventKind):
            raise ContractError(f"events[].kind must be one of {list(VisionEventKind)}")
        check_range(self.confidence, "events[].confidence", 0.0, 1.0)
        if self.kind is VisionEventKind.OBJECT_TRACK and not self.track_id:
            raise ContractError("OBJECT_TRACK requires track_id")
        if self.bbox is not None:
            if len(self.bbox) != 4:
                raise ContractError("events[].bbox must be float[4] (x,y,w,h)")
            for i, v in enumerate(self.bbox):
                check_range(v, f"events[].bbox[{i}]", 0.0, 1.0)
        if self.position is not None:
            check_vec3(self.position, "events[].position")
        return self


@dataclass(slots=True, frozen=True)
class VisionSummary:
    frames: tuple[FrameDescriptor, ...] = ()
    events: tuple[VisionEvent, ...] = ()

    def validate(self) -> "VisionSummary":
        for f in self.frames:
            f.validate()
        for e in self.events:
            e.validate()
        return self


# ---------------------------------------------------------------------------
# §3.2.5 Audio Events — SN_AUDIO (QoS EVENT)
# ---------------------------------------------------------------------------


class AudioEventKind(StrEnum):
    SPEECH_SEGMENT = "SPEECH_SEGMENT"
    SOUND_EVENT = "SOUND_EVENT"
    LOUDNESS_ALARM = "LOUDNESS_ALARM"
    SILENCE = "SILENCE"


@dataclass(slots=True, frozen=True)
class AudioEvent:
    kind: AudioEventKind
    direction: tuple[float, float] | None = None  # azimuth/elevation rad, GLOVE-HEAD
    level_db: float | None = None                 # dB SPL
    label: str | None = None                      # adapter's frozen classifier label
    transcript_ref: str | None = None             # local ref if ASR enabled by policy
    confidence: float | None = None               # [0,1]

    def validate(self) -> "AudioEvent":
        if not isinstance(self.kind, AudioEventKind):
            raise ContractError(f"events[].kind must be one of {list(AudioEventKind)}")
        if self.confidence is not None:
            check_range(self.confidence, "events[].confidence", 0.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class AudioReport:
    events: tuple[AudioEvent, ...]

    def validate(self) -> "AudioReport":
        if not self.events:
            raise ContractError("SN_AUDIO requires events[]")
        for e in self.events:
            e.validate()
        return self


# ---------------------------------------------------------------------------
# §3.2.6 Internal Robot State — SN_INTERNAL (QoS FAST 1-10 Hz + EVENT on change)
# ---------------------------------------------------------------------------


class FaultSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"  # EVENT within 50 ms (REQ-SC-08); triggers degraded mode (REQ-SE-06)
    FATAL = "FATAL"        # EVENT within 50 ms + envelope degraded/e-stop (REQ-SC-08)


@dataclass(slots=True, frozen=True)
class Fault:
    code: str                 # adapter-namespaced fault code (REQ-AD-11)
    severity: FaultSeverity
    message: str | None = None

    def validate(self) -> "Fault":
        if not self.code or "." not in self.code:
            raise ContractError("faults[].code must be adapter-namespaced (e.g. 'mockbase.wheel.slip')")
        if not isinstance(self.severity, FaultSeverity):
            raise ContractError(f"faults[].severity must be one of {list(FaultSeverity)}")
        return self


@dataclass(slots=True, frozen=True)
class BatteryState:
    soc: float                              # [0,1], required
    voltage: float | None = None            # V
    current: float | None = None            # A (+ discharge)
    time_remaining_s: float | None = None   # s, adapter estimate

    def validate(self) -> "BatteryState":
        check_range(self.soc, "battery.soc", 0.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class ThermalZone:
    zone: str
    temp: float  # °C


@dataclass(slots=True, frozen=True)
class JointLimitProximity:
    group: str
    margin: float  # [0,1]: 0 = at limit, 1 = mid-range

    def validate(self) -> "JointLimitProximity":
        check_range(self.margin, "joint_limit_proximity[].margin", 0.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class ComputeHealth:
    load: float      # [0,1]
    mem_used: float  # [0,1]

    def validate(self) -> "ComputeHealth":
        check_range(self.load, "compute.load", 0.0, 1.0)
        check_range(self.mem_used, "compute.mem_used", 0.0, 1.0)
        return self


@dataclass(slots=True, frozen=True)
class InternalState:
    battery: BatteryState
    faults: tuple[Fault, ...] = ()  # required, may be empty
    thermal: tuple[ThermalZone, ...] = ()
    joint_limit_proximity: tuple[JointLimitProximity, ...] = ()
    compute: ComputeHealth | None = None

    def validate(self) -> "InternalState":
        self.battery.validate()
        for f in self.faults:
            f.validate()
        for p in self.joint_limit_proximity:
            p.validate()
        if self.compute is not None:
            self.compute.validate()
        return self


# ---------------------------------------------------------------------------
# REQ-AD-09: sensor dropout — surfaced explicitly, never concealed.
# Stale data MUST carry stale: true after the negotiated freshness interval.
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class SensorDropout:
    sensor: str
    duration_ms: float
    stale: bool = True

    def to_payload(self) -> dict[str, Any]:
        return {"sensor": self.sensor, "duration_ms": self.duration_ms, "stale": self.stale}


def mark_stale(payload: dict[str, Any]) -> dict[str, Any]:
    """REQ-AD-09: stale data MUST carry stale: true; last-value holding without
    the flag is prohibited."""
    out = dict(payload)
    out["stale"] = True
    return out
