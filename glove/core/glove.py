"""The Glove core — GLV-SPEC-1.0.0 §2, §3, §6, §7.

Thin orchestration ONLY. This module wires contract <-> mapping <-> envelope
<-> adapter and relays governance unchanged. It contains NO decision-making,
NO planning, NO learning, and NO goal generation (§1.3 Non-Goals; §1.4 the
non-negotiable design constraint: the Glove is a liner, not a brain). Every
actuation it emits is traceable to exactly one being action message or to a
safety-envelope clamp of such a message (REQ-CF-09 audit replay).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Iterable

from ..adapter.base import (
    AdapterState,
    DeactivateMode,
    DispatchOutcome,
    MappedCommand,
    RobotAdapter,
)
from ..contract.actions import (
    AbortCause,
    ActionAck,
    AttentionAction,
    ControlMode,
    ExpressionAction,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    RawAction,
    RejectReason,
    ToolAction,
)
from ..contract.capabilities import (
    Accept,
    CapabilityDescriptor,
    Decline,
    GLOVE_CONTRACT_VERSIONS,
    Hello,
    NegotiationError,
    Welcome,
    check_accept,
    negotiate,
)
from ..contract.envelope import (
    ACTION_TYPES,
    CONTRACT_VERSION,
    MsgType,
    OutOfRangeError,
    QoSClass,
    SequenceTracker,
    monotonic_ns,
)
from ..continuity.hotswap import (
    TransferError,
    TransferPlan,
    TransferResult,
    TransferState,
    TransferStateMachine,
)
from ..continuity.packet import (
    CalibrationArtifact,
    ContinuityPacket,
    SessionRecord,
)
from ..governance.bus import GovernanceBus
from ..mapping.engine import MappingEngine
from ..safety.envelope import DegradedMode, EnvelopeDecision, SafetyEnvelope

Action = (
    LocomotionAction | ManipulationAction | ExpressionAction
    | AttentionAction | ToolAction | RawAction
)


class SessionState(StrEnum):
    IDLE = "IDLE"              # no HELLO yet
    WELCOMED = "WELCOMED"      # WELCOME sent, awaiting ACCEPT/DECLINE
    ACTIVE = "ACTIVE"          # ACCEPT received; contract traffic may flow
    CLOSED = "CLOSED"


# RT channels subject to dead-man enforcement (REQ-SE-04)
_RT_CHANNELS: dict[type, str] = {
    LocomotionAction: "locomotion",
}


class AuditLog:
    """Append-only, hash-chained local audit log (REQ-CF-09).

    Records: every action message and its validation result; every envelope
    decision (REQ-SE-08); every governance envelope's framing metadata (never
    payload); every transfer state transition; every capability negotiation.
    Sufficient to replay, deterministically, why every dispatched command
    occurred (CF-T-INS-01). Local-only: no telemetry channel exists in this
    core (REQ-GV-09).
    """

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._last_hash = "0" * 64

    def append(self, kind: str, record: dict[str, Any]) -> None:
        body = json.dumps(
            {"kind": kind, "record": record, "prev_hash": self._last_hash},
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")
        h = hashlib.sha256(body).hexdigest()
        self._entries.append({"kind": kind, "record": record, "prev_hash": self._last_hash, "hash": h})
        self._last_hash = h

    def entries(self, kind: str | None = None) -> list[dict[str, Any]]:
        if kind is None:
            return list(self._entries)
        return [e for e in self._entries if e["kind"] == kind]

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self._entries:
            body = json.dumps(
                {"kind": e["kind"], "record": e["record"], "prev_hash": prev},
                sort_keys=True, separators=(",", ":"), default=str,
            ).encode("utf-8")
            if hashlib.sha256(body).hexdigest() != e["hash"] or e["prev_hash"] != prev:
                return False
            prev = e["hash"]
        return True


@dataclass(slots=True)
class _InFlight:
    msg_id: str
    command_handle: int
    channel: str | None  # RT channel for dead-man tracking, else None


class Glove:
    """The Glove core. Identical for all bodies (REQ-AD-00).

    Being-facing surface (identical across every adapter — the zero-being-
    modification guarantee, CR-5):
        hello() / accept()           — REQ-CV-02 handshake
        submit_action(action)        — §3.1 actions in, §3.1.7 acks out
        on_sensory(cb) / on_ack(cb)  — §3.2 sensory + ack delivery
        governance_bus               — §5 opaque relay
        tick()                       — dead-man/watchdog/pulse pumping (REQ-SE-04/05, REQ-GV-05)
        transfer_to(...)             — §7.2 hot-swap
    """

    def __init__(
        self,
        *,
        being_key: bytes = b"glove-skeleton-being-key",
        clock: Callable[[], int] = monotonic_ns,
        policy_tighten: dict[str, Any] | None = None,
    ) -> None:
        self._clock = clock
        self._being_key = being_key
        self._policy_tighten = policy_tighten
        self.audit = AuditLog()
        self.bus = GovernanceBus(clock=clock, audit=self.audit.append)
        self.mapping = MappingEngine()
        self._adapter: RobotAdapter | None = None
        self._descriptor: CapabilityDescriptor | None = None
        self._envelope: SafetyEnvelope | None = None
        self._session_state = SessionState.IDLE
        self._session_id: str | None = None
        self._being_id: str | None = None
        self._welcome: Welcome | None = None
        self._seq = SequenceTracker()
        self._out_seq = SequenceTracker()
        self._sensory_cb: Callable[[MsgType, dict[str, Any]], None] = lambda mt, p: None
        self._ack_cb: Callable[[ActionAck], None] = lambda a: None
        self._context_cb: Callable[[dict[str, Any]], None] = lambda ref: None
        self._in_flight: dict[str, _InFlight] = {}
        self._rt_channel_msg: dict[str, str] = {}  # channel -> current msg_id (newest-value-wins)
        self._handles = iter(range(1, 2**31))
        self._packet: ContinuityPacket | None = None
        self._raw_control_granted = False
        # Governance wiring: the Glove RELAYS; thresholds arrive as policy
        # configuration (REQ-GV-08). Hooks are physical reactions only.
        self.bus.set_preempt_hook(self._on_gov_override)
        self.bus.set_pulse_loss_hook(self._on_pulse_loss)

    # ------------------------------------------------------------------
    # Attachment / lifecycle (§4.1 ordering enforced by RobotAdapter)
    # ------------------------------------------------------------------

    def attach_adapter(
        self,
        adapter: RobotAdapter,
        *,
        profile: dict[str, Any] | None = None,
        handle: Any | None = None,
    ) -> CapabilityDescriptor:
        """Run the §4.1 lifecycle to ACTIVE and compose the session envelope."""
        adapter.set_sensory_sink(self._ingest_sensory)
        adapter.set_state_sink(self._on_adapter_state)
        handles = adapter.discover()
        adapter.connect(handle if handle is not None else (handles[0] if handles else None))
        descriptor = adapter.calibrate(profile)
        adapter.activate()
        self._adapter = adapter
        self._descriptor = descriptor
        self._envelope = SafetyEnvelope(
            descriptor, policy_tighten=self._policy_tighten,
            audit=self.audit.append, clock=self._clock,
        )
        self._envelope.set_halt_hook(adapter.halt)
        self._envelope.register_watchdog("adapter_heartbeat", timeout_s=0.5)
        # REQ-CV-07: SIMULATED declaration is visible to the being and to audit.
        self.audit.append("ADAPTER_ATTACHED", {
            "body_class": descriptor.body_class, "body_serial": descriptor.body_serial,
            "simulated": descriptor.simulated, "descriptor_hash": descriptor.hash(),
        })
        return descriptor

    @property
    def adapter(self) -> RobotAdapter | None:
        return self._adapter

    @property
    def descriptor(self) -> CapabilityDescriptor | None:
        return self._descriptor

    @property
    def envelope(self) -> SafetyEnvelope | None:
        return self._envelope

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def session_state(self) -> SessionState:
        return self._session_state

    @property
    def packet(self) -> ContinuityPacket | None:
        return self._packet

    def set_packet(self, packet: ContinuityPacket) -> None:
        self._packet = packet

    # ------------------------------------------------------------------
    # Handshake (REQ-CV-02)
    # ------------------------------------------------------------------

    def hello(self, being_id: str, supported_versions: Iterable[str]) -> Welcome | Decline:
        """Step 1->2 of REQ-CV-02. No traffic may flow before ACCEPT."""
        if self._descriptor is None:
            raise NegotiationError("no adapter attached; nothing to negotiate")
        self.audit.append("NEGOTIATION_HELLO", {"being_id": being_id,
                                                "versions": list(supported_versions)})
        try:
            welcome = negotiate(Hello(being_id=being_id, supported_versions=tuple(supported_versions)),
                                GLOVE_CONTRACT_VERSIONS, self._descriptor)
        except NegotiationError as exc:
            self.audit.append("NEGOTIATION_DECLINED", {"reason": str(exc)})
            return Decline(reason=str(exc))
        self._welcome = welcome
        self._being_id = being_id
        self._session_state = SessionState.WELCOMED
        self.audit.append("NEGOTIATION_WELCOME", {
            "selected_version": welcome.selected_version, "session_id": welcome.session_id,
            "descriptor_hash": welcome.capability_descriptor.hash(),
        })
        return welcome

    def accept(self, welcome: Welcome) -> None:
        """Step 3 of REQ-CV-02: the being confirms; the session opens."""
        check_accept(welcome, Accept(session_id=welcome.session_id,
                                     selected_version=welcome.selected_version))
        self._session_id = welcome.session_id
        self._session_state = SessionState.ACTIVE
        self._seq = SequenceTracker()
        self._out_seq = SequenceTracker()
        self.audit.append("NEGOTIATION_ACCEPT", {"session_id": welcome.session_id})

    def decline(self, reason: str) -> None:
        self._session_state = SessionState.CLOSED
        self.audit.append("NEGOTIATION_DECLINED", {"reason": reason})

    # ------------------------------------------------------------------
    # Delivery registration (being side)
    # ------------------------------------------------------------------

    def on_sensory(self, cb: Callable[[MsgType, dict[str, Any]], None]) -> None:
        self._sensory_cb = cb

    def on_ack(self, cb: Callable[[ActionAck], None]) -> None:
        self._ack_cb = cb

    def on_context_restored(self, cb: Callable[[dict[str, Any]], None]) -> None:
        """RESUME restores the being's short-term context handle (REQ-ST-04)."""
        self._context_cb = cb

    def grant_raw_control(self, granted: bool) -> None:
        """REQ-AC-05: the raw channel requires an ACTIVE governance grant of
        scope raw_control. The grant decision is made by governance ABOVE the
        Glove (via RING4/POLICY envelopes); this method only records the
        endpoint's decision. The Glove never decides it."""
        self._raw_control_granted = granted
        self.audit.append("RAW_CONTROL_GRANT", {"granted": granted})

    # ------------------------------------------------------------------
    # Efferent path (§2.3): validate -> envelope -> map -> dispatch
    # ------------------------------------------------------------------

    def submit_action(self, action: Action, *, msg_id: str | None = None) -> ActionAck:
        """REQ-AC-01: validate against negotiated contract + capability
        descriptor before any mapping or dispatch. REQ-AC-06: exactly one
        terminal ack per action. The Glove translates; it never decides."""
        msg_id = msg_id or str(uuid.uuid4())
        try:
            uuid.UUID(msg_id)
        except ValueError:
            msg_id = str(uuid.uuid4())
        terminal = self._validate_action(action, msg_id)
        if terminal is not None:
            return self._emit_ack(terminal)

        # RT bookkeeping: newest-value-wins on dead-man channels (§3.0 QoS).
        channel = _RT_CHANNELS.get(type(action))
        if isinstance(action, ManipulationAction) and action.control_mode is ControlMode.WRENCH:
            channel = "wrench"
        if isinstance(action, RawAction):
            channel = "raw"
        if channel and channel in self._rt_channel_msg:
            prev = self._rt_channel_msg.pop(channel)
            self._complete_in_flight(prev)  # superseded command completes

        # Safety envelope: clip or refuse, never originate (REQ-SE-01/02).
        assert self._envelope is not None
        verdict = self._envelope.evaluate(action, msg_id)
        if verdict.decision is EnvelopeDecision.REFUSE:
            return self._emit_ack(ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                                            reason=verdict.reason or str(RejectReason.ENVELOPE_VIOLATION)))
        clipped = verdict.decision is EnvelopeDecision.CLIP
        mapped_action = verdict.action

        # Map being-space -> robot-space via static versioned tables (REQ-CF-08).
        assert self._descriptor is not None
        kind, body = self.mapping.to_robot(mapped_action, self._descriptor)
        handle = next(self._handles)
        cmd = MappedCommand(command_handle=handle, msg_id=msg_id, kind=kind, body=body)

        # Dispatch through the adapter boundary (REQ-AD-04/05).
        assert self._adapter is not None
        result = self._adapter.dispatch(cmd)
        self.audit.append("ACTION_DISPATCHED", {
            "msg_id": msg_id, "command_handle": handle, "kind": kind,
            "clipped": clipped, "outcome": str(result.outcome),
        })

        # A dispatch fault must surface for RT channels too — it must NOT be
        # masked by the RT executing-ack path below.
        if result.outcome is DispatchOutcome.FAULT:
            return self._emit_ack(ActionAck(ref_msg_id=msg_id, status="ACT_ABORTED",
                                            cause=str(AbortCause.ENVELOPE_FAULT)))

        if channel:
            # REQ-SE-04 per-message dead-man deadline: locomotion messages
            # carry duration_s (§3.1.1); raw messages carry an absolute
            # expires_ns (§3.1.6); wrench uses the composed default.
            timeout_s = mapped_action.duration_s if isinstance(mapped_action, LocomotionAction) else None
            expires_ns = mapped_action.expires_ns if isinstance(mapped_action, RawAction) else None
            self._envelope.note_rt_refresh(channel, timeout_s=timeout_s, expires_ns=expires_ns)
            self._rt_channel_msg[channel] = msg_id
            self._in_flight[msg_id] = _InFlight(msg_id=msg_id, command_handle=handle, channel=channel)
            # RT commands acknowledge execution start; terminal ack arrives at
            # completion/supersede/abort (§3.1.7).
            return self._emit_ack(ActionAck(ref_msg_id=msg_id, status="ACT_EXECUTING"))
        status = "ACT_CLIPPED" if clipped else "ACT_COMPLETED"
        return self._emit_ack(ActionAck(ref_msg_id=msg_id, status=status,  # type: ignore[arg-type]
                                        clip_delta=verdict.clip_delta if clipped else None))

    def _validate_action(self, action: Action, msg_id: str) -> ActionAck | None:
        """REQ-AC-01 + REQ-CV-06 capability checks. Returns a terminal
        ACT_REJECTED ack, or None if the action may proceed."""
        if self._session_state is not SessionState.ACTIVE:
            return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                             reason=str(RejectReason.SESSION_INACTIVE))
        assert self._descriptor is not None
        d = self._descriptor
        try:
            if isinstance(action, LocomotionAction):
                action.validate()
                if not d.supports_action(MsgType.ACT_LOCOMOTION):
                    return self._absent(msg_id, "ACT_LOCOMOTION")
                if not d.supports_locomotion_mode(str(action.mode)):
                    return self._absent(msg_id, f"locomotion mode {action.mode}")
            elif isinstance(action, ManipulationAction):
                action.validate()
                if not d.supports_action(MsgType.ACT_MANIPULATION):
                    return self._absent(msg_id, "ACT_MANIPULATION")
                eff = d.find_effector(action.effector)
                if eff is None:
                    return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                                     reason=str(RejectReason.UNKNOWN_EFFECTOR))
                if str(action.control_mode) not in eff.control_modes:
                    return self._absent(msg_id, f"control mode {action.control_mode} on {action.effector}")
            elif isinstance(action, ExpressionAction):
                action.validate()
                if not d.supports_action(MsgType.ACT_EXPRESSION):
                    return self._absent(msg_id, "ACT_EXPRESSION")
                if not d.supports_expression_channel(str(action.channel)):
                    return self._absent(msg_id, f"expression channel {action.channel}")
                if action.expression and action.expression not in d.face_expressions and "FACE" in d.expression_channels:
                    return self._absent(msg_id, f"face expression {action.expression}")
            elif isinstance(action, AttentionAction):
                action.validate()
                if not d.supports_action(MsgType.ACT_ATTENTION):
                    return self._absent(msg_id, "ACT_ATTENTION")
            elif isinstance(action, ToolAction):
                action.validate()
                if not d.supports_action(MsgType.ACT_TOOL):
                    return self._absent(msg_id, "ACT_TOOL")
                if d.find_tool(action.tool_id) is None:
                    return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                                     reason=str(RejectReason.UNKNOWN_TOOL))
            elif isinstance(action, RawAction):
                action.validate(now_ns=self._clock())
                # REQ-AC-05: descriptor channel + active governance grant.
                if not d.declares_raw_channel(action.channel):
                    return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                                     reason=str(RejectReason.UNKNOWN_CHANNEL))
                if not self._raw_control_granted:
                    return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                                     reason=str(RejectReason.RAW_NOT_GRANTED))
            else:
                return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                                 reason=str(RejectReason.SCHEMA_INVALID))
        except OutOfRangeError as exc:
            # REQ-AC-01: range/bounds violations are machine-distinguishable
            # from structural/schema errors.
            self.audit.append("ACTION_REJECTED", {"msg_id": msg_id, "reason": str(exc)})
            return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                             reason=str(RejectReason.OUT_OF_RANGE))
        except Exception as exc:
            self.audit.append("ACTION_REJECTED", {"msg_id": msg_id, "reason": str(exc)})
            return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                             reason=str(RejectReason.SCHEMA_INVALID))
        self.audit.append("ACTION_VALIDATED", {"msg_id": msg_id, "type": type(action).__name__})
        return None

    def _absent(self, msg_id: str, modality: str) -> ActionAck:
        """REQ-CV-06: absent modalities reject with CAPABILITY_ABSENT; the
        Glove MUST NOT emulate them with synthetic data."""
        self.audit.append("ACTION_REJECTED", {"msg_id": msg_id, "reason": "CAPABILITY_ABSENT",
                                              "modality": modality})
        return ActionAck(ref_msg_id=msg_id, status="ACT_REJECTED",
                         reason=str(RejectReason.CAPABILITY_ABSENT))

    def _emit_ack(self, ack: ActionAck) -> ActionAck:
        self._ack_cb(ack)
        return ack

    def _complete_in_flight(self, msg_id: str) -> None:
        if self._in_flight.pop(msg_id, None) is not None:
            self._emit_ack(ActionAck(ref_msg_id=msg_id, status="ACT_COMPLETED"))

    # ------------------------------------------------------------------
    # Afferent path (§2.3): normalize (adapter) -> stamp/order -> deliver
    # The core applies NO semantic interpretation beyond normalization and
    # loss policy; IMPACT events and faults also reach the envelope
    # (REQ-SC-05, REQ-SC-08).
    # ------------------------------------------------------------------

    def _ingest_sensory(self, msg_type: str, payload: dict[str, Any]) -> None:
        mt = MsgType(msg_type)
        self.audit.append("SENSORY_DELIVERED", {"msg_type": msg_type, "seq": self._out_seq.next()})
        if mt is MsgType.SN_CONTACT:
            for ev in payload.get("events", ()):
                if ev.get("kind") == "IMPACT" and self._envelope is not None:
                    self._envelope.on_impact(float(ev.get("peak_force_n", 0.0)))  # REQ-SC-05
        if mt is MsgType.SN_INTERNAL and self._envelope is not None:
            for f in payload.get("faults", ()):
                sev = f.get("severity")
                if sev == "FATAL":
                    self._envelope.trip(f"fatal:{f.get('code', '?')}")  # REQ-SC-08
                elif sev == "CRITICAL":
                    self._envelope.enter_degraded(None, f"critical:{f.get('code', '?')}")  # REQ-SE-06
        self._sensory_cb(mt, payload)

    def _on_adapter_state(self, state: AdapterState) -> None:
        self.audit.append("ADAPTER_STATE", {"state": str(state)})

    # ------------------------------------------------------------------
    # Governance reactions (physical only — REQ-GV-08)
    # ------------------------------------------------------------------

    def _on_gov_override(self) -> None:
        """REQ-GV-04: validated OVERRIDE preempts ALL in-flight and queued
        action traffic; default preempt behavior is a controlled stop (halt
        at envelope and adapter); preemption reported via ACT_ABORTED with
        cause GOV_OVERRIDE. In-process: immediate (<< 50 ms)."""
        if self._envelope is not None:
            self._envelope.trip("GOV_OVERRIDE")
        in_flight = list(self._in_flight.values())
        self._in_flight.clear()
        self._rt_channel_msg.clear()
        for inf in in_flight:
            self._emit_ack(ActionAck(ref_msg_id=inf.msg_id, status="ACT_ABORTED",
                                     cause=str(AbortCause.GOV_OVERRIDE)))
        self.audit.append("GOV_OVERRIDE_PREEMPTED", {"aborted": len(in_flight)})

    def _on_pulse_loss(self) -> None:
        """REQ-SE-06: Pulse Tether loss beyond threshold enters the
        policy-declared degraded mode and stays until governance clearance."""
        if self._envelope is not None:
            self._envelope.enter_degraded(None, "PULSE_TETHER_LOSS")

    # ------------------------------------------------------------------
    # Periodic pumping (REQ-SE-04 dead-man, REQ-SE-05 watchdog, REQ-GV-05)
    # ------------------------------------------------------------------

    def tick(self) -> None:
        """Drive local, autonomous safety machinery. MUST work with the being
        disconnected and the network absent (REQ-OF-05)."""
        if self._adapter is not None and self._adapter.state is AdapterState.ACTIVE:
            self._envelope and self._envelope.pet_watchdog("adapter_heartbeat")
        if self._envelope is not None:
            for channel in self._envelope.check_deadman():
                msg_id = self._rt_channel_msg.pop(channel, None)
                if msg_id is not None:
                    self._in_flight.pop(msg_id, None)
                    self._emit_ack(ActionAck(ref_msg_id=msg_id, status="ACT_ABORTED",
                                             cause=str(AbortCause.DEADMAN)))
            self._envelope.check_watchdogs()
        self.bus.check_pulse()

    # ------------------------------------------------------------------
    # Hot-swap orchestration (§7.2, REQ-ST-04..08)
    # ------------------------------------------------------------------

    def snapshot_packet(self, close_reason: str = "transfer") -> ContinuityPacket:
        """SNAPSHOT stage: write, sign, hash-chain, persist locally (REQ-ST-04)."""
        assert self._descriptor is not None and self._session_id is not None
        base = self._packet or ContinuityPacket.genesis(
            being_id=self._being_id or str(uuid.uuid4()),
            being_key=self._being_key,
            identity_assertion="hmac-sha256:" + hashlib.sha256(self._being_key).hexdigest(),
        )
        calib = CalibrationArtifact(
            body_class=self._descriptor.body_class,
            body_serial=self._descriptor.body_serial,
            artifacts={
                "static_transforms": [t.to_dict() for t in self._descriptor.static_transforms],
                "mapping_table_hash": self.mapping.table.hash(),
                "mapping_table": self.mapping.table.to_dict(),
            },
        )
        pkt = base.next_revision(
            being_key=self._being_key,
            session_record=SessionRecord(session_id=self._session_id,
                                         body_class=self._descriptor.body_class,
                                         close_reason=close_reason),
            calibration=calib,
            schema_versions={
                "contract_version": CONTRACT_VERSION,
                "capability_descriptor_hash": self._descriptor.hash(),
                "envelope_params_hash": self._envelope.params_hash() if self._envelope else "",
            },
        )
        if not pkt.verify_integrity(self._being_key):
            raise TransferError(TransferState.SNAPSHOT, "packet failed self-integrity check")
        self._packet = pkt
        return pkt

    def transfer_to(
        self,
        new_adapter: RobotAdapter,
        *,
        required_modalities: Iterable[str] = (),
        governance_revalidate: Callable[[bytes], bool] = lambda snapshot: True,
        profile: dict[str, Any] | None = None,
    ) -> TransferResult:
        """REQ-ST-04 state machine with REQ-ST-06 rollback.

        `governance_revalidate` is the GOVERNANCE LAYER's re-validation of
        the snapshot (REQ-ST-05); the Glove MUST NOT open action channels on
        the basis of the snapshot alone — if the callback returns False the
        RESUME stage fails and the being stays suspended.
        """
        if self._adapter is None or self._descriptor is None:
            raise TransferError(TransferState.RUNNING, "no active body to transfer from")
        old_adapter = self._adapter
        old_descriptor = self._descriptor
        sm = TransferStateMachine(audit=self.audit.append)
        packet_holder: dict[str, ContinuityPacket] = {}

        def quiesce() -> None:
            # All RT channels dead-man-stopped, queued actions drained/aborted,
            # envelope HOLD asserted (REQ-ST-04).
            assert self._envelope is not None
            self._envelope.enter_degraded(DegradedMode.HOLD, "TRANSFER_QUIESCE")
            for inf in list(self._in_flight.values()):
                self._emit_ack(ActionAck(ref_msg_id=inf.msg_id, status="ACT_ABORTED",
                                         cause=str(AbortCause.DEACTIVATE)))
            self._in_flight.clear()
            self._rt_channel_msg.clear()

        def snapshot() -> None:
            packet_holder["pkt"] = self.snapshot_packet("transfer")

        def detach() -> None:
            old_adapter.deactivate(DeactivateMode.IMMEDIATE)
            old_adapter.disconnect()

        def attach() -> None:
            new_adapter.set_sensory_sink(self._ingest_sensory)
            new_adapter.set_state_sink(self._on_adapter_state)
            handles = new_adapter.discover()
            new_adapter.connect(handles[0] if handles else None)

        def calibrate() -> None:
            nonlocal profile
            # Restore calibration artifacts from the packet when the body
            # class is known (REQ-ST-04 CALIBRATE).
            pkt = packet_holder["pkt"]
            for art in pkt.calibration_artifacts:
                if profile is None:
                    profile = {"body_class": art.body_class, "body_serial": art.body_serial,
                               "artifacts": art.artifacts}
            descriptor = new_adapter.calibrate(profile)
            missing = [m for m in required_modalities
                       if m not in descriptor.action_types]
            if missing:
                raise TransferError(TransferState.CALIBRATE,
                                    f"required modalities absent on new body: {missing}")
            new_adapter.activate()
            self._adapter = new_adapter
            self._descriptor = descriptor
            self._envelope = SafetyEnvelope(descriptor, policy_tighten=self._policy_tighten,
                                            audit=self.audit.append, clock=self._clock)
            self._envelope.set_halt_hook(new_adapter.halt)
            self._envelope.register_watchdog("adapter_heartbeat", timeout_s=0.5)

        def resume() -> None:
            pkt = packet_holder["pkt"]
            # REQ-ST-05: governance snapshot re-validated by the governance
            # layer BEFORE any action channel opens.
            if not pkt.verify_integrity(self._being_key):
                raise TransferError(TransferState.RESUME, "packet integrity check failed")
            if not governance_revalidate(pkt.governance_snapshot):
                raise TransferError(TransferState.RESUME, "governance snapshot revalidation failed")
            # Context handle restored to the being; new session_id; the being
            # re-runs the REQ-CV-02 handshake.
            self._context_cb(dict(pkt.short_term_context_ref))
            self._session_state = SessionState.IDLE
            self._session_id = None
            self._in_flight.clear()
            self._rt_channel_msg.clear()

        plan = TransferPlan(quiesce=quiesce, snapshot=snapshot, detach=detach,
                            attach=attach, calibrate=calibrate, resume=resume)
        current = self._packet or ContinuityPacket.genesis(
            being_id=self._being_id or str(uuid.uuid4()), being_key=self._being_key,
            identity_assertion="hmac-sha256:" + hashlib.sha256(self._being_key).hexdigest(),
        )
        result = sm.run(plan, current)
        if result.final_state is TransferState.COMPLETED:
            self._packet = packet_holder["pkt"]
        else:
            # REQ-ST-06: the packet is never partially applied; the old body
            # remains the record of last known-good operation.
            if result.final_state is TransferState.SUSPENDED:
                # TF-4: the body MUST be motion-inhibited throughout and no
                # action channel may open without governance revalidation.
                if self._adapter is not None and self._adapter is not old_adapter:
                    self._adapter.deactivate(DeactivateMode.IMMEDIATE)
                self._session_state = SessionState.CLOSED
                self._session_id = None
            elif result.final_state is TransferState.ROLLED_BACK_RUNNING:
                assert self._envelope is not None
                self._envelope.exit_degraded(governance_clearance=True)
            self.audit.append("TRANSFER_ROLLBACK", {
                "final_state": str(result.final_state),
                "old_body_class": old_descriptor.body_class,
                "error": result.error,
            })
        return result

    def resume_on_original(self, adapter: RobotAdapter, *,
                           governance_revalidate: Callable[[bytes], bool] = lambda s: True) -> None:
        """REQ-ST-06b: after a SUSPENDED transfer, retry on the ORIGINAL body
        with the intact packet."""
        if self._packet is None:
            raise TransferError(TransferState.SUSPENDED, "no packet to resume from")
        if not self._packet.verify_integrity(self._being_key):
            raise TransferError(TransferState.RESUME, "packet tampered; refusing resume")
        if not governance_revalidate(self._packet.governance_snapshot):
            raise TransferError(TransferState.RESUME, "governance revalidation failed")
        profile = None
        for art in self._packet.calibration_artifacts:
            profile = {"body_class": art.body_class, "body_serial": art.body_serial,
                       "artifacts": art.artifacts}
        self.attach_adapter(adapter, profile=profile)
        self._session_state = SessionState.IDLE
        self._session_id = None
        self.audit.append("TRANSFER_RESUMED_ORIGINAL", {"revision": self._packet.revision})
