"""Common message envelope — GLV-SPEC-1.0.0 §3.0.

Every contract message (action or sensory) MUST be wrapped in this envelope.
All quantities use SI units (REQ-SC-01); canonical frames per §3.2.1
(REQ-SC-02): right-handed, Z-up, X-forward, Y-left.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# Constants per §3.0
# ---------------------------------------------------------------------------

CONTRACT_VERSION = "1.0.0"  # this implementation conforms to GLV-SPEC-1.0.0
PACKET_VERSION = "1.0.0"    # continuity packet schema version (§7.1)

_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class QoSClass(StrEnum):
    """Timing classes per §3.0."""

    RT = "RT"        # hard real-time control (100-500 Hz, newest-value-wins, dead-man)
    FAST = "FAST"    # streaming sensory (20-200 Hz, lossy-acceptable, gaps via seq)
    EVENT = "EVENT"  # discrete async events (reliable, at-least-once, dedup by msg_id)
    GOV = "GOV"      # governance envelopes (reliable, ordered, authenticated; §5)


class MsgType(StrEnum):
    """Message type discriminators (§3.1 actions, §3.2 sensory, §5 governance)."""

    # Actions (being -> Glove), §3.1
    ACT_LOCOMOTION = "ACT_LOCOMOTION"
    ACT_MANIPULATION = "ACT_MANIPULATION"
    ACT_EXPRESSION = "ACT_EXPRESSION"
    ACT_ATTENTION = "ACT_ATTENTION"
    ACT_TOOL = "ACT_TOOL"
    ACT_RAW = "ACT_RAW"
    # Action acknowledgement events (§3.1.7)
    ACT_ACCEPTED = "ACT_ACCEPTED"
    ACT_EXECUTING = "ACT_EXECUTING"
    ACT_COMPLETED = "ACT_COMPLETED"
    ACT_CLIPPED = "ACT_CLIPPED"
    ACT_REJECTED = "ACT_REJECTED"
    ACT_ABORTED = "ACT_ABORTED"
    # Sensory (Glove -> being), §3.2
    SN_PROPRIO = "SN_PROPRIO"
    SN_CONTACT = "SN_CONTACT"
    SN_VISION = "SN_VISION"
    SN_AUDIO = "SN_AUDIO"
    SN_INTERNAL = "SN_INTERNAL"
    SN_MANIP_STATUS = "SN_MANIP_STATUS"
    SENSOR_DROPOUT = "SENSOR_DROPOUT"  # REQ-AD-09
    # Negotiation & adapter (§3.3, §4)
    CAPABILITY_UPDATE = "CAPABILITY_UPDATE"  # REQ-CV-04
    ADAPTER_STATE = "ADAPTER_STATE"          # REQ-AD-01
    # Governance (§5)
    GOV_ENVELOPE = "GOV_ENVELOPE"
    GOV_UNDELIVERED = "GOV_UNDELIVERED"  # transport-level notice, REQ-GV-07


ACTION_TYPES: frozenset[MsgType] = frozenset(
    {
        MsgType.ACT_LOCOMOTION,
        MsgType.ACT_MANIPULATION,
        MsgType.ACT_EXPRESSION,
        MsgType.ACT_ATTENTION,
        MsgType.ACT_TOOL,
        MsgType.ACT_RAW,
    }
)

SENSORY_TYPES: frozenset[MsgType] = frozenset(
    {
        MsgType.SN_PROPRIO,
        MsgType.SN_CONTACT,
        MsgType.SN_VISION,
        MsgType.SN_AUDIO,
        MsgType.SN_INTERNAL,
        MsgType.SN_MANIP_STATUS,
        MsgType.SENSOR_DROPOUT,
    }
)

ACK_TYPES: frozenset[MsgType] = frozenset(
    {
        MsgType.ACT_ACCEPTED,
        MsgType.ACT_EXECUTING,
        MsgType.ACT_COMPLETED,
        MsgType.ACT_CLIPPED,
        MsgType.ACT_REJECTED,
        MsgType.ACT_ABORTED,
    }
)

# Canonical frames per §3.2.1 (REQ-SC-02)
FRAME_WORLD = "GLOVE-WORLD"
FRAME_BASE = "GLOVE-BASE"
FRAME_HEAD = "GLOVE-HEAD"
FRAME_TOOL = "GLOVE-TOOL"


def camera_frame(name: str) -> str:
    """Per-camera optical frame, Z = optical axis outward (documented Z-up exception)."""
    return f"GLOVE-CAMERA.{name}"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ContractError(ValueError):
    """Raised on contract/envelope validation failure (REQ-AC-01)."""


class OutOfRangeError(ContractError):
    """Raised when a field VALUE is outside its declared range/bounds
    (REQ-AC-01: rejected with RejectReason.OUT_OF_RANGE). Structural and
    schema errors raise plain ContractError (RejectReason.SCHEMA_INVALID)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_semver(v: str) -> tuple[int, int, int]:
    m = _SEMVER_RE.match(v)
    if not m:
        raise ContractError(f"invalid semver: {v!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def versions_compatible(a: str, b: str) -> bool:
    """REQ-CV-01: parties MUST share a MAJOR version to connect."""
    return parse_semver(a)[0] == parse_semver(b)[0]


def monotonic_ns() -> int:
    """Primary timestamp source: sender's monotonic clock (§3.0, TF-7)."""
    return time.monotonic_ns()


def wall_rfc3339() -> str:
    """RFC 3339 UTC wall-clock timestamp (audit use only, TF-7)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_msg_id() -> str:
    """Message identifier. Uses uuid7 when available (Python 3.14+); the uuid4
    fallback preserves uniqueness, which is what conformance requires."""
    fn = getattr(uuid, "uuid7", uuid.uuid4)
    return str(fn())


def check_uuid(value: str, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ContractError(f"{name} must be a UUID string, got {value!r}") from exc


def check_vec3(v: Any, name: str) -> tuple[float, float, float]:
    if not (isinstance(v, (list, tuple)) and len(v) == 3):
        raise ContractError(f"{name} must be a vec3, got {v!r}")
    out = tuple(float(x) for x in v)
    if not all(_finite(x) for x in out):
        raise ContractError(f"{name} must be finite, got {v!r}")
    return out  # type: ignore[return-value]


def _finite(x: float) -> bool:
    return x == x and abs(x) != float("inf")


def check_unit_quat(q: Any, name: str, tol: float = 1e-3) -> tuple[float, float, float, float]:
    """Quaternion (w, x, y, z) with ||q|| = 1; deviation > 1e-3 MUST be rejected (§3.2.1)."""
    if not (isinstance(q, (list, tuple)) and len(q) == 4):
        raise ContractError(f"{name} must be a quat (w,x,y,z), got {q!r}")
    vals = tuple(float(x) for x in q)
    if not all(_finite(x) for x in vals):
        raise ContractError(f"{name} must be finite, got {q!r}")
    norm = sum(x * x for x in vals) ** 0.5
    if abs(norm - 1.0) > tol:
        raise ContractError(f"{name} quaternion norm {norm:.6f} deviates from 1 by > 1e-3")
    return vals  # type: ignore[return-value]


def check_unit_vec3(v: Any, name: str, tol: float = 1e-3) -> tuple[float, float, float]:
    vals = check_vec3(v, name)
    norm = sum(x * x for x in vals) ** 0.5
    if abs(norm - 1.0) > tol:
        raise OutOfRangeError(f"{name} must be a unit vector, norm={norm:.6f}")
    return vals


def check_range(x: Any, name: str, lo: float, hi: float, *, open_lo: bool = False, open_hi: bool = False) -> float:
    try:
        v = float(x)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"{name} must be numeric, got {x!r}") from exc
    lo_ok = v > lo if open_lo else v >= lo
    hi_ok = v < hi if open_hi else v <= hi
    if not (_finite(v) and lo_ok and hi_ok):
        raise OutOfRangeError(f"{name}={v} out of range ({lo},{hi})")
    return v


# ---------------------------------------------------------------------------
# Envelope (§3.0)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Envelope:
    """Common message envelope per §3.0. `payload` is the per-msg_type body.

    `extensions` holds namespaced (`vendor.key`) non-normative fields; they
    MUST NOT change the semantics of required fields (REQ-CV-05) and unknown
    optional fields MUST be ignored by receivers.
    """

    contract_version: str
    session_id: str
    being_id: str
    msg_id: str
    msg_type: MsgType
    seq: int
    t_emit_ns: int
    qos_class: QoSClass
    payload: Any
    t_wall: str | None = None
    extensions: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> "Envelope":
        parse_semver(self.contract_version)
        check_uuid(self.session_id, "session_id")
        check_uuid(self.being_id, "being_id")
        check_uuid(self.msg_id, "msg_id")
        if not isinstance(self.msg_type, MsgType):
            raise ContractError(f"unknown msg_type {self.msg_type!r}")
        if not (isinstance(self.seq, int) and 0 <= self.seq < 2**64):
            raise ContractError(f"seq must be uint64, got {self.seq!r}")
        if not isinstance(self.t_emit_ns, int):
            raise ContractError("t_emit_ns must be int64 monotonic ns")
        if not isinstance(self.qos_class, QoSClass):
            raise ContractError(f"unknown qos_class {self.qos_class!r}")
        for key in self.extensions:
            if "." not in key:
                raise ContractError(f"extension key {key!r} is not namespaced (REQ-CV-05)")
        return self

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "contract_version": self.contract_version,
            "session_id": self.session_id,
            "being_id": self.being_id,
            "msg_id": self.msg_id,
            "msg_type": str(self.msg_type),
            "seq": self.seq,
            "t_emit_ns": self.t_emit_ns,
            "qos_class": str(self.qos_class),
            "payload": self.payload,
        }
        if self.t_wall is not None:
            d["t_wall"] = self.t_wall
        if self.extensions:
            d["extensions"] = dict(self.extensions)
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Envelope":
        try:
            env = cls(
                contract_version=str(d["contract_version"]),
                session_id=str(d["session_id"]),
                being_id=str(d["being_id"]),
                msg_id=str(d["msg_id"]),
                msg_type=MsgType(d["msg_type"]),
                seq=int(d["seq"]),
                t_emit_ns=int(d["t_emit_ns"]),
                qos_class=QoSClass(d["qos_class"]),
                payload=d["payload"],
                t_wall=d.get("t_wall"),
                extensions=dict(d.get("extensions", {})),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractError(f"malformed envelope: {exc}") from exc
        return env.validate()


class SequenceTracker:
    """Per-session sequence allocation and gap detection.

    REQ-SC-03: seq MUST be monotonically increasing per session; a gap signals
    loss and MUST NOT be concealed by renumbering.
    """

    def __init__(self) -> None:
        self._next = 0

    def next(self) -> int:
        n = self._next
        self._next += 1
        return n

    @staticmethod
    def gaps(observed: list[int]) -> list[int]:
        """Return the sequence numbers lost between observed arrivals."""
        lost: list[int] = []
        for a, b in zip(observed, observed[1:]):
            lost.extend(range(a + 1, b))
        return lost


def make_envelope(
    msg_type: MsgType,
    payload: Any,
    *,
    session_id: str,
    being_id: str,
    seq: int,
    qos_class: QoSClass,
    contract_version: str = CONTRACT_VERSION,
    t_emit_ns: int | None = None,
    with_wall: bool = False,
    extensions: dict[str, Any] | None = None,
) -> Envelope:
    """Construct and validate an envelope (§3.0)."""
    env = Envelope(
        contract_version=contract_version,
        session_id=session_id,
        being_id=being_id,
        msg_id=new_msg_id(),
        msg_type=msg_type,
        seq=seq,
        t_emit_ns=monotonic_ns() if t_emit_ns is None else t_emit_ns,
        qos_class=qos_class,
        payload=payload,
        t_wall=wall_rfc3339() if with_wall else None,
        extensions=extensions or {},
    )
    return env.validate()
