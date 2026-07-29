"""The Glove Layer — reference implementation skeleton (GLV-SPEC-1.0.0).

A thin, inspectable, replaceable interface sheet between autonomous beings
and robotic systems. The Glove is a liner, not a brain: it translates, it
enforces physical limits, it relays governance unchanged — it never decides.
"""

__version__ = "1.0.0"
SPEC_ID = "GLV-SPEC-1.0.0"

from .contract.envelope import (  # noqa: F401
    CONTRACT_VERSION,
    PACKET_VERSION,
    Envelope,
    MsgType,
    OutOfRangeError,
    QoSClass,
    ContractError,
)
from .contract.actions import (  # noqa: F401
    AbortCause,
    ActionAck,
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
    Priority,
    RawAction,
    RawEncoding,
    RejectReason,
    ToolAction,
    ToolOperation,
    Twist,
    Utterance,
    Waypoint,
)
from .contract.capabilities import (  # noqa: F401
    CapabilityDescriptor,
    Decline,
    Hello,
    NegotiationError,
    Welcome,
)
from .family_crypto import (  # noqa: F401
    FamilyDescriptorSigner,
    family_available,
    family_status,
)
from .adapter.base import AdapterState, RobotAdapter  # noqa: F401
from .core.glove import AuditLog, Glove  # noqa: F401
from .governance.bus import GovClass, GovEnvelope, GovernanceBus  # noqa: F401
from .safety.envelope import DegradedMode, EnvelopeDecision, SafetyEnvelope  # noqa: F401
from .continuity.packet import ContinuityPacket  # noqa: F401
from .continuity.hotswap import TransferResult, TransferState  # noqa: F401
from .mapping.engine import MappingEngine, MappingTable  # noqa: F401
