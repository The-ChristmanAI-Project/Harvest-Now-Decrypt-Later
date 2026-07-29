"""Capability descriptor + negotiation handshake — GLV-SPEC-1.0.0 §3.3.

REQ-CV-01: semantic versioning; parties MUST share a MAJOR version.
REQ-CV-02: HELLO -> WELCOME -> ACCEPT/DECLINE; no traffic before ACCEPT.
REQ-CV-03: the descriptor is a signed, versioned document enumerating every
           capability, limit, frame, mapping constant, and QoS rate.
REQ-CV-06: graceful degradation — absent modalities are marked absent and the
           being MUST be able to operate without them; the Glove MUST NOT
           emulate them with synthetic data (no phantom sensors).
REQ-CV-07: simulated bodies MUST be declared SIMULATED, visibly to the being
           and to governance audit logs.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

from .envelope import CONTRACT_VERSION, MsgType, parse_semver, versions_compatible
from ..family_crypto import sign_descriptor_body, verify_descriptor_body

# ---------------------------------------------------------------------------
# Descriptor content model (REQ-CV-03)
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class JointLimit:
    """Per-joint physical limits (REQ-AD-10). Mapping constants for REQ-SC-04
    are exactly (limit_min, limit_max): normalized [-1,1] maps linearly."""

    name: str
    limit_min: float   # rad or m
    limit_max: float   # rad or m
    max_velocity: float    # rad/s or m/s
    max_effort: float      # N·m or N
    kind: str = "revolute"  # revolute | prismatic

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "limit_min": self.limit_min, "limit_max": self.limit_max,
            "max_velocity": self.max_velocity, "max_effort": self.max_effort, "kind": self.kind,
        }


@dataclass(slots=True, frozen=True)
class JointGroup:
    name: str                       # logical group, e.g. "arm.left"
    joints: tuple[JointLimit, ...]  # descriptor-defined ordering (§3.2.2)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "joints": [j.to_dict() for j in self.joints]}


@dataclass(slots=True, frozen=True)
class EffectorDecl:
    name: str                            # logical effector, e.g. "arm.left"
    control_modes: tuple[str, ...]       # subset of §3.1.2 ControlMode values
    max_force_n: float                   # per-effector envelope limit (REQ-AD-10)
    max_torque_nm: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "control_modes": list(self.control_modes),
            "max_force_n": self.max_force_n, "max_torque_nm": self.max_torque_nm,
        }


@dataclass(slots=True, frozen=True)
class ToolDecl:
    tool_id: str
    operations: tuple[str, ...]
    manifest: dict[str, Any] = field(default_factory=dict)  # params schema per tool

    def to_dict(self) -> dict[str, Any]:
        return {"tool_id": self.tool_id, "operations": list(self.operations), "manifest": self.manifest}


@dataclass(slots=True, frozen=True)
class SensorDecl:
    name: str
    msg_type: str            # SN_PROPRIO / SN_CONTACT / SN_VISION / SN_AUDIO / SN_INTERNAL
    rate_hz: float           # negotiated rate bound
    frame: str | None = None
    resolution: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "msg_type": self.msg_type, "rate_hz": self.rate_hz,
            "frame": self.frame, "resolution": self.resolution,
        }


@dataclass(slots=True, frozen=True)
class FrameTransform:
    """Static frame transform published at activation / calibration change (§3.2.1)."""

    parent: str
    child: str
    translation: tuple[float, float, float]       # m
    rotation: tuple[float, float, float, float]   # quat (w,x,y,z)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent": self.parent, "child": self.child,
            "translation": list(self.translation), "rotation": list(self.rotation),
        }


@dataclass(slots=True, frozen=True)
class EnvelopeParams:
    """Adapter-supplied physical limit set configuring the safety envelope
    (REQ-AD-10, REQ-SE-03). Session policy MAY only tighten, never loosen.

    Self-collision geometry (REQ-SE-01) is expressed as forbidden zones:
    each entry in `forbidden_zones` is an axis-aligned volume in GLOVE-WORLD
    that end-effector goals/waypoints must never enter — including volumes
    occupied by the robot's own body (see the mocks' `torso_self_collision`
    and `pedestal_column` zones). Jerk limits are adapter-declared
    constraints enforced inside the adapter's native trajectory
    time-parameterization; the envelope enforces per-joint velocity limits
    directly (REQ-SE-01, JOINT_TRAJ clipping)."""

    max_linear_mps: float = 0.0
    max_angular_radps: float = 0.0
    workspace_min: tuple[float, float, float] = (-1e9, -1e9, -1e9)  # m, GLOVE-WORLD
    workspace_max: tuple[float, float, float] = (1e9, 1e9, 1e9)
    forbidden_zones: tuple[dict[str, Any], ...] = ()   # declared geometry incl. self-collision volumes (§6)
    impact_force_ceiling_n: float = 50.0               # REQ-SE-05 impact trip
    estop: dict[str, Any] = field(default_factory=lambda: {"type": "controlled_stop", "latency_ms_max": 10})
    deadman_locomotion_s: float = 0.5                  # REQ-SE-04
    deadman_wrench_s: float = 0.25
    degraded_mode: str = "HOLD"                        # HOLD | RETREAT | PARK (REQ-SE-06)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_linear_mps": self.max_linear_mps,
            "max_angular_radps": self.max_angular_radps,
            "workspace_min": list(self.workspace_min),
            "workspace_max": list(self.workspace_max),
            "forbidden_zones": list(self.forbidden_zones),
            "impact_force_ceiling_n": self.impact_force_ceiling_n,
            "estop": dict(self.estop),
            "deadman_locomotion_s": self.deadman_locomotion_s,
            "deadman_wrench_s": self.deadman_wrench_s,
            "degraded_mode": self.degraded_mode,
        }


# ---------------------------------------------------------------------------
# Capability descriptor (REQ-CV-03)
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(slots=True, frozen=True)
class CapabilityDescriptor:
    """Signed, versioned capability document (REQ-CV-03).

    `signature` is an algorithm-prefixed string over the canonical descriptor
    body:

    * ``"rsa-pss-sha256:<hex>"`` when signed with a family signing identity
      (:class:`glove.family_crypto.FamilyDescriptorSigner` or a raw
      ``christman_crypto.DigitalSigner``) — Tier 6 RSA-PSS-4096, asymmetric
      and non-repudiable, verifiable from the adapter's public PEM alone.
    * ``"hmac-sha256:<hex>"`` when signed with symmetric ``bytes`` — the
      skeleton-grade stdlib fallback for zero-dependency deployments.

    The *structure* (signed, hashed, versioned, inspectable) is what the spec
    normatively requires; the schema is identical across both algorithms.
    """

    descriptor_version: str                       # semver of this descriptor document
    body_class: str                               # e.g. "mock.mobile_base"
    body_serial: str
    simulated: bool                               # REQ-CV-07 SIMULATED declaration
    contract_versions: tuple[str, ...]            # versions the body/Glove supports
    action_types: tuple[str, ...]                 # supported ACT_* msg types
    locomotion_modes: tuple[str, ...] = ()        # VELOCITY / POSE_GOAL (≥1 if ACT_LOCOMOTION)
    expression_channels: tuple[str, ...] = ()
    face_expressions: tuple[str, ...] = ()
    joint_groups: tuple[JointGroup, ...] = ()
    effectors: tuple[EffectorDecl, ...] = ()
    tools: tuple[ToolDecl, ...] = ()
    sensors: tuple[SensorDecl, ...] = ()
    static_transforms: tuple[FrameTransform, ...] = ()
    envelope_params: EnvelopeParams = field(default_factory=EnvelopeParams)
    raw_channels: tuple[str, ...] = ()            # optional modality raw_control
    optional_modalities: tuple[str, ...] = ()     # e.g. "audio_stream"
    qos_rates: dict[str, float] = field(default_factory=dict)  # msg_type -> max rate Hz
    detector_artifacts: dict[str, str] = field(default_factory=dict)  # frozen, hashed (REQ-SC-06)
    extensions: dict[str, Any] = field(default_factory=dict)   # namespaced (REQ-CV-05)
    signature: str = ""

    # -- canonical form / hashing / signing --------------------------------

    def body_dict(self) -> dict[str, Any]:
        return {
            "descriptor_version": self.descriptor_version,
            "body_class": self.body_class,
            "body_serial": self.body_serial,
            "simulated": self.simulated,
            "contract_versions": list(self.contract_versions),
            "action_types": sorted(self.action_types),
            "locomotion_modes": sorted(self.locomotion_modes),
            "expression_channels": sorted(self.expression_channels),
            "face_expressions": sorted(self.face_expressions),
            "joint_groups": [g.to_dict() for g in self.joint_groups],
            "effectors": [e.to_dict() for e in self.effectors],
            "tools": [t.to_dict() for t in self.tools],
            "sensors": [s.to_dict() for s in self.sensors],
            "static_transforms": [t.to_dict() for t in self.static_transforms],
            "envelope_params": self.envelope_params.to_dict(),
            "raw_channels": sorted(self.raw_channels),
            "optional_modalities": sorted(self.optional_modalities),
            "qos_rates": dict(sorted(self.qos_rates.items())),
            "detector_artifacts": dict(sorted(self.detector_artifacts.items())),
            "extensions": self.extensions,
        }

    def hash(self) -> str:
        """Descriptor hash — carried in continuity packets (REQ-ST-01)."""
        return hashlib.sha256(_canonical(self.body_dict())).hexdigest()

    def sign(self, adapter_key: Any) -> "CapabilityDescriptor":
        """Sign the canonical descriptor body. `adapter_key` is either
        symmetric ``bytes`` (HMAC fallback) or a family signing identity —
        ``FamilyDescriptorSigner`` / ``DigitalSigner`` (Tier 6 RSA-PSS)."""
        return replace(self, signature=sign_descriptor_body(_canonical(self.body_dict()), adapter_key))

    def verify_signature(self, adapter_key: Any) -> bool:
        """Verify the descriptor signature. Dispatches on the algorithm
        prefix; a key of the wrong kind for the signature's algorithm
        returns False (never raises)."""
        return verify_descriptor_body(_canonical(self.body_dict()), self.signature, adapter_key)

    # -- capability queries (graceful degradation, REQ-CV-06) ---------------

    def supports_action(self, msg_type: MsgType | str) -> bool:
        return str(msg_type) in self.action_types

    def supports_locomotion_mode(self, mode: str) -> bool:
        return mode in self.locomotion_modes

    def find_effector(self, name: str) -> EffectorDecl | None:
        return next((e for e in self.effectors if e.name == name), None)

    def find_tool(self, tool_id: str) -> ToolDecl | None:
        return next((t for t in self.tools if t.tool_id == tool_id), None)

    def find_joint_group(self, name: str) -> JointGroup | None:
        return next((g for g in self.joint_groups if g.name == name), None)

    def supports_expression_channel(self, channel: str) -> bool:
        return channel in self.expression_channels

    def declares_raw_channel(self, channel: str) -> bool:
        return channel in self.raw_channels

    def with_tools(self, tools: tuple[ToolDecl, ...], descriptor_version: str, adapter_key: Any) -> "CapabilityDescriptor":
        """REQ-CV-04: mid-session descriptor change (e.g., tool attached)
        produces a re-versioned, re-signed descriptor announced via
        CAPABILITY_UPDATE."""
        return replace(self, tools=tools, descriptor_version=descriptor_version).sign(adapter_key)


# ---------------------------------------------------------------------------
# Handshake (REQ-CV-02)
# ---------------------------------------------------------------------------


def _uuid7ish() -> str:
    fn = getattr(uuid, "uuid7", uuid.uuid4)
    return str(fn())


@dataclass(slots=True, frozen=True)
class Hello:
    """Step 1 of REQ-CV-02: being -> Glove."""

    being_id: str
    supported_versions: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class Welcome:
    """Step 2 of REQ-CV-02: Glove -> being."""

    selected_version: str
    session_id: str
    capability_descriptor: CapabilityDescriptor


@dataclass(slots=True, frozen=True)
class Accept:
    """Step 3 of REQ-CV-02: being -> Glove. Session opens only now."""

    session_id: str
    selected_version: str


@dataclass(slots=True, frozen=True)
class Decline:
    """Step 3 of REQ-CV-02 (rejection path). Clean decline; no traffic."""

    reason: str


class NegotiationError(Exception):
    """Version incompatibility or protocol violation during handshake."""


def negotiate(hello: Hello, glove_versions: tuple[str, ...], descriptor: CapabilityDescriptor) -> Welcome:
    """Select the contract version per REQ-CV-01 (shared MAJOR).

    Chooses the highest being-supported version whose MAJOR matches a
    Glove-supported version. Raises NegotiationError on mismatch (the being
    then DECLINEs; no traffic flows — CF-T-CON-02).
    """
    if not hello.supported_versions:
        raise NegotiationError("HELLO carried no supported contract versions")
    glove_majors: dict[int, str] = {}
    for v in glove_versions:
        glove_majors.setdefault(parse_semver(v)[0], v)
    best: tuple[int, int, int] | None = None
    selected: str | None = None
    for v in hello.supported_versions:
        parsed = parse_semver(v)
        if parsed[0] in glove_majors:
            if best is None or parsed > best:
                best, selected = parsed, v
    if selected is None:
        raise NegotiationError(
            f"no shared MAJOR version: being={hello.supported_versions} glove={glove_versions}"
        )
    return Welcome(
        selected_version=selected,
        session_id=_uuid7ish(),
        capability_descriptor=descriptor,
    )


def check_accept(welcome: Welcome, accept: Accept) -> None:
    """Session opens only when ACCEPT matches the WELCOME (REQ-CV-02)."""
    if accept.session_id != welcome.session_id:
        raise NegotiationError("ACCEPT session_id does not match WELCOME")
    if not versions_compatible(accept.selected_version, welcome.selected_version):
        raise NegotiationError("ACCEPT version incompatible with WELCOME (REQ-CV-01)")


# Default contract versions supported by this Glove core.
GLOVE_CONTRACT_VERSIONS: tuple[str, ...] = (CONTRACT_VERSION,)
