"""Governance bus — GLV-SPEC-1.0.0 §5 (normative).

STRICTLY pass-through. The bus transports governance envelopes between the
being and upstream governance systems as OPAQUE, authenticated, ordered
envelopes. The bus reads ONLY framing fields — sender identity, auth tag,
envelope class, sequence number, expiry (REQ-GV-01). It never parses,
interprets, modifies, truncates, delays beyond QoS, or re-signs payloads
(REQ-GV-06), and it NEVER originates governance envelopes of any class
(REQ-GV-07 / INV-4); the only thing it may emit is the transport-level
GOV_UNDELIVERED notice, which is framing, not governance.

Keys: auth tags are ed25519 signatures per GLV-SPEC Appendix A. The bus
holds ONLY verification public keys (REQ-GV-02); it is structurally
incapable of signing or forging envelopes (INV-1/INV-4) because no private
key material, and no signing function, exists anywhere in this module.
Endpoint-side signing tooling lives in `glove.governance.endpoint`, which
runs at governance endpoints, never inside the Glove.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..contract.envelope import monotonic_ns


class GovClass(StrEnum):
    """Envelope classes carried (§5.2)."""

    CONSENSUS = "CONSENSUS"    # Diamond/AlphaWolf proposals/votes/decisions — opaque
    PULSE = "PULSE"            # Pulse Tether heartbeats + liveness params
    ESCALATION = "ESCALATION"  # human supervisory layers
    OVERRIDE = "OVERRIDE"      # caregiver override — highest transport priority
    RING4 = "RING4"            # Ring 4 grants, revocations, challenges
    POLICY = "POLICY"          # data-sovereignty / operational policy documents


class GovReject(StrEnum):
    AUTH_FAILED = "AUTH_FAILED"          # REQ-GV-02
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    EXPIRED = "EXPIRED"
    OUT_OF_ORDER = "OUT_OF_ORDER"        # per-sender sequence violation (REQ-GV-03)
    UNKNOWN_SENDER = "UNKNOWN_SENDER"
    UNDELIVERABLE = "UNDELIVERABLE"


AUTH_TAG_SCHEME = "ed25519"


def _framing_bytes(gov_class: str, sender: str, sender_seq: int, expires_ns: int) -> bytes:
    return json.dumps(
        {"class": gov_class, "sender": sender, "sender_seq": sender_seq, "expires_ns": expires_ns},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def verify_auth_tag(
    verify_key: bytes, gov_class: str, sender: str, sender_seq: int,
    expires_ns: int, payload: bytes, auth_tag: str,
) -> bool:
    """Verify an ed25519 auth tag over framing + payload (REQ-GV-02).

    `verify_key` is a 32-byte ed25519 PUBLIC key registered out-of-band by
    the endpoint. This is the only direction the bus ever uses key material.
    """
    if not auth_tag.startswith(AUTH_TAG_SCHEME + ":"):
        return False
    try:
        signature = bytes.fromhex(auth_tag[len(AUTH_TAG_SCHEME) + 1:])
        public = Ed25519PublicKey.from_public_bytes(verify_key)
        public.verify(signature, _framing_bytes(gov_class, sender, sender_seq, expires_ns) + payload)
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(slots=True, frozen=True)
class GovEnvelope:
    """Opaque governance envelope. `payload` is ciphertext bytes that the
    Glove NEVER parses (INV-1). Frozen dataclass: byte-identical in/out.

    Construction with a valid auth tag happens at governance ENDPOINTS via
    `glove.governance.endpoint.create_envelope`; the Glove-side bus offers
    no signing path (INV-4)."""

    gov_class: GovClass
    sender: str
    sender_seq: int
    expires_ns: int          # monotonic ns
    auth_tag: str
    payload: bytes


@dataclass(slots=True, frozen=True)
class GovUndelivered:
    """Transport-level notice (framing, not governance — REQ-GV-07)."""

    sender: str
    sender_seq: int
    gov_class: str
    reason: str


DeliverFn = Callable[[GovEnvelope], None]
NoticeFn = Callable[[GovUndelivered], None]
HookFn = Callable[[], None]


class GovernanceBus:
    """Opaque authenticated ordered transport (REQ-GV-01..08).

    Endpoints register with a verification PUBLIC key and a delivery
    callback. The bus authenticates, enforces per-sender ordering, delivers
    the envelope OBJECT ITSELF (never a copy, never mutated), preempts on
    OVERRIDE (REQ-GV-04), and measures Pulse Tether liveness locally
    against the policy-declared threshold (REQ-GV-05).
    """

    def __init__(self, *, clock: Callable[[], int] = monotonic_ns,
                 audit: Callable[[str, dict[str, Any]], None] | None = None) -> None:
        self._clock = clock
        self._audit = audit or (lambda kind, rec: None)
        self._verify_keys: dict[str, bytes] = {}  # sender -> ed25519 PUBLIC key (verification only)
        self._deliver: dict[str, DeliverFn] = {}
        self._notice_sinks: list[NoticeFn] = []
        self._last_seq: dict[str, int] = {}
        self._preempt_hook: HookFn = lambda: None
        self._pulse_loss_hook: HookFn = lambda: None
        self._pulse_threshold_ns: float | None = None
        self._last_pulse_ns: int | None = None
        self.rejected: list[tuple[str, str]] = []  # (sender, reason) audit trail

    # -- endpoint wiring ---------------------------------------------------

    def register_endpoint(self, name: str, verify_key: bytes, deliver: DeliverFn) -> None:
        """Register an endpoint with its ed25519 VERIFICATION public key.

        The bus refuses signing-capable key material: ed25519 private keys
        (seeds) and public keys are both 32 bytes, so the structural
        guarantee is that this module contains no signing code path at all
        (INV-4)."""
        Ed25519PublicKey.from_public_bytes(verify_key)  # validate it is a public key
        self._verify_keys[name] = bytes(verify_key)
        self._deliver[name] = deliver

    def add_notice_sink(self, sink: NoticeFn) -> None:
        self._notice_sinks.append(sink)

    def set_preempt_hook(self, hook: HookFn) -> None:
        """REQ-GV-04: core registers the in-flight action preemption path."""
        self._preempt_hook = hook

    def set_pulse_loss_hook(self, hook: HookFn) -> None:
        """REQ-GV-05/SE-06: core registers degraded-mode entry on tether loss."""
        self._pulse_loss_hook = hook

    def configure_pulse_threshold(self, threshold_s: float) -> None:
        """REQ-GV-08: the trigger threshold arrives as CONFIGURATION from
        policy; the decision remains attributable to the governance layer."""
        self._pulse_threshold_ns = threshold_s * 1e9

    # -- transport -----------------------------------------------------------

    def submit(self, envelope: GovEnvelope) -> bool:
        """Authenticate, order-check, and deliver one envelope.

        Returns True iff delivered byte-identical. Rejections are logged and
        NEVER delivered (REQ-GV-02); silent loss is prohibited (REQ-GV-03).
        """
        env = envelope
        framing = {"class": str(env.gov_class), "sender": env.sender, "sender_seq": env.sender_seq}
        # REQ-GV-02: authentication + integrity
        key = self._verify_keys.get(env.sender)
        if key is None:
            return self._reject(env, GovReject.UNKNOWN_SENDER)
        if not verify_auth_tag(key, str(env.gov_class), env.sender, env.sender_seq,
                               env.expires_ns, env.payload, env.auth_tag):
            return self._reject(env, GovReject.AUTH_FAILED)
        if self._clock() > env.expires_ns:
            return self._reject(env, GovReject.EXPIRED)
        # REQ-GV-03: per-sender monotonic ordering with gap detection
        last = self._last_seq.get(env.sender, 0)
        if env.sender_seq != last + 1:
            self._notify_undelivered(env, GovReject.OUT_OF_ORDER)
            return self._reject(env, GovReject.OUT_OF_ORDER)
        self._last_seq[env.sender] = env.sender_seq

        # REQ-GV-05: PULSE forwarded with priority equal to OVERRIDE;
        # arrival measured locally against the declared threshold.
        if env.gov_class is GovClass.PULSE:
            self._last_pulse_ns = self._clock()

        # REQ-GV-04: validated OVERRIDE preempts all in-flight/queued action
        # traffic BEFORE delivery (<= 50 ms end-to-end; in-process it is
        # immediate).
        if env.gov_class is GovClass.OVERRIDE:
            self._preempt_hook()

        # Deliver the SAME object: no parse, no copy, no mutation (INV-1).
        sink = self._deliver.get(env.sender) or self._deliver.get("*")
        if sink is None:
            self._notify_undelivered(env, GovReject.UNDELIVERABLE)
            return self._reject(env, GovReject.UNDELIVERABLE)
        sink(env)
        self._audit("GOV_DELIVERED", framing)  # framing metadata only (REQ-CF-09)
        return True

    # -- Pulse Tether liveness (REQ-GV-05) ----------------------------------

    def check_pulse(self) -> bool:
        """Measure heartbeat arrival locally so liveness enforcement survives
        upstream partition. Returns True if the tether is within threshold."""
        if self._pulse_threshold_ns is None or self._last_pulse_ns is None:
            return True
        if self._clock() - self._last_pulse_ns > self._pulse_threshold_ns:
            self._pulse_loss_hook()
            return False
        return True

    # -- internals -----------------------------------------------------------

    def _reject(self, env: GovEnvelope, reason: GovReject) -> bool:
        self.rejected.append((env.sender, str(reason)))
        # REQ-CF-09: audit framing metadata for every envelope, never payload.
        self._audit("GOV_REJECTED", {
            "class": str(env.gov_class), "sender": env.sender,
            "sender_seq": env.sender_seq, "reason": str(reason),
        })
        return False

    def _notify_undelivered(self, env: GovEnvelope, reason: GovReject) -> None:
        """REQ-GV-03/07: the ONLY message class the bus may originate."""
        notice = GovUndelivered(sender=env.sender, sender_seq=env.sender_seq,
                                gov_class=str(env.gov_class), reason=str(reason))
        for sink in self._notice_sinks:
            sink(notice)
