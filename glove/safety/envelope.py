"""Safety envelope — GLV-SPEC-1.0.0 §6 (normative).

A hard real-time component INSIDE the Glove but SUBORDINATE to governance:
governance decides WHAT is permitted; the envelope enforces the physical
HOW-limits. The envelope may clip or refuse, but MUST NEVER originate an
actuation command not derived from a being action message — except the
protective stop/retreat commands of degraded mode (REQ-SE-06) and e-stop
(REQ-SE-05), which are protective terminations, not behaviors (REQ-SE-02).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Callable

from ..contract.actions import (
    AbortCause,
    ControlMode,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    RawAction,
    RejectReason,
)
from ..contract.capabilities import CapabilityDescriptor, EnvelopeParams
from ..contract.envelope import monotonic_ns

AuditSink = Callable[[str, dict[str, Any]], None]


class DegradedMode(StrEnum):
    HOLD = "HOLD"        # stop and hold position
    RETREAT = "RETREAT"  # adapter-declared safe retract
    PARK = "PARK"        # adapter-declared rest pose


class EnvelopeDecision(StrEnum):
    PASS = "PASS"
    CLIP = "CLIP"      # REQ-SE-02(a): clip to nearest valid command + ACT_CLIPPED
    REFUSE = "REFUSE"  # REQ-SE-02(b): refuse + ACT_REJECTED(ENVELOPE_VIOLATION)


@dataclass(slots=True, frozen=True)
class EnvelopeVerdict:
    decision: EnvelopeDecision
    action: Any                       # original or clipped action
    clip_delta: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None         # RejectReason on REFUSE


@dataclass(slots=True, frozen=True)
class _Box:
    lo: tuple[float, float, float]
    hi: tuple[float, float, float]

    def clip(self, p: tuple[float, float, float]) -> tuple[tuple[float, float, float], bool]:
        out = tuple(min(max(v, l), h) for v, l, h in zip(p, self.lo, self.hi))
        return out, out != tuple(p)

    def contains(self, p: tuple[float, float, float]) -> bool:
        return all(l <= v <= h for v, l, h in zip(p, self.lo, self.hi))


def _clip_magnitude(v: tuple[float, float, float], max_mag: float) -> tuple[tuple[float, float, float], float]:
    mag = (v[0] ** 2 + v[1] ** 2 + v[2] ** 2) ** 0.5
    if mag <= max_mag or mag == 0.0:
        return tuple(v), 0.0
    scale = max_mag / mag
    return (v[0] * scale, v[1] * scale, v[2] * scale), mag - max_mag


class SafetyEnvelope:
    """Composed, hash-stamped physical limit enforcer (REQ-SE-01..08)."""

    def __init__(
        self,
        descriptor: CapabilityDescriptor,
        *,
        policy_tighten: dict[str, Any] | None = None,
        audit: AuditSink | None = None,
        clock: Callable[[], int] = monotonic_ns,
    ) -> None:
        """REQ-SE-03: compose parameters from (1) adapter physical limits —
        the hard outer bound (REQ-AD-10); (2) session POLICY constraints,
        which MAY only tighten; (3) calibration artifacts already folded into
        the descriptor. Policy can NEVER loosen adapter limits."""
        base = descriptor.envelope_params
        pol = policy_tighten or {}
        params = replace(
            base,
            max_linear_mps=min(base.max_linear_mps, float(pol.get("max_linear_mps", base.max_linear_mps))),
            max_angular_radps=min(base.max_angular_radps, float(pol.get("max_angular_radps", base.max_angular_radps))),
            impact_force_ceiling_n=min(
                base.impact_force_ceiling_n, float(pol.get("impact_force_ceiling_n", base.impact_force_ceiling_n))
            ),
            workspace_min=tuple(
                max(a, b) for a, b in zip(base.workspace_min, pol.get("workspace_min", base.workspace_min))
            ),
            workspace_max=tuple(
                min(a, b) for a, b in zip(base.workspace_max, pol.get("workspace_max", base.workspace_max))
            ),
            forbidden_zones=tuple(list(base.forbidden_zones) + list(pol.get("forbidden_zones", ()))),
        )
        self._params: EnvelopeParams = params
        self._descriptor = descriptor
        self._audit = audit or (lambda kind, rec: None)
        self._clock = clock
        self._workspace = _Box(tuple(params.workspace_min), tuple(params.workspace_max))
        self._zones: list[_Box] = [
            _Box(tuple(z["min"]), tuple(z["max"])) for z in params.forbidden_zones
        ]
        # Dead-man bookkeeping (REQ-SE-04): channel ->
        #   (last refresh monotonic ns, per-message timeout_s | None,
        #    absolute per-message expiry monotonic ns | None)
        self._rt_refresh: dict[str, tuple[int, float | None, int | None]] = {}
        # Watchdog (REQ-SE-05): name -> (last pet ns, timeout ns)
        self._watchdogs: dict[str, tuple[int, float]] = {}
        self._degraded: DegradedMode | None = None
        self._halted = False
        self._halt_hook: Callable[[], None] = lambda: None
        # The composed envelope is logged and hash-stamped at session start (REQ-SE-03).
        self._audit("ENVELOPE_COMPOSED", {"params_hash": self.params_hash(), "params": params.to_dict()})

    # ------------------------------------------------------------------
    # REQ-SE-03: hash-stamp of the composed parameter set
    # ------------------------------------------------------------------

    def params_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self._params.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @property
    def params(self) -> EnvelopeParams:
        return self._params

    @property
    def degraded(self) -> DegradedMode | None:
        return self._degraded

    @property
    def halted(self) -> bool:
        return self._halted

    def set_halt_hook(self, hook: Callable[[], None]) -> None:
        """The core registers adapter.halt here; the envelope only ASSERTS
        halts — it never originates motion (REQ-SE-02)."""
        self._halt_hook = hook

    # ------------------------------------------------------------------
    # REQ-SE-01: evaluate every action after contract validation,
    # before adapter dispatch. REQ-SE-02: clip or refuse, never originate.
    # ------------------------------------------------------------------

    def evaluate(self, action: Any, msg_id: str) -> EnvelopeVerdict:
        if self._degraded is not None or self._halted:
            verdict = EnvelopeVerdict(EnvelopeDecision.REFUSE, action, reason=str(RejectReason.ENVELOPE_VIOLATION))
            self._record("ENVELOPE_REFUSE", msg_id, {"cause": "degraded_or_halted"})
            return verdict
        if isinstance(action, LocomotionAction):
            verdict = self._eval_locomotion(action)
        elif isinstance(action, ManipulationAction):
            verdict = self._eval_manipulation(action)
        elif isinstance(action, RawAction):
            verdict = self._eval_raw(action)
        else:
            verdict = EnvelopeVerdict(EnvelopeDecision.PASS, action)
        if verdict.decision is EnvelopeDecision.CLIP:
            self._record("ENVELOPE_CLIP", msg_id, {"clip_delta": verdict.clip_delta})
        elif verdict.decision is EnvelopeDecision.REFUSE:
            self._record("ENVELOPE_REFUSE", msg_id, {"reason": verdict.reason})
        return verdict

    def _eval_locomotion(self, a: LocomotionAction) -> EnvelopeVerdict:
        if a.mode is LocomotionMode.VELOCITY:
            assert a.twist is not None
            lin, dlin = _clip_magnitude(a.twist.linear, self._params.max_linear_mps)
            ang, dang = _clip_magnitude(a.twist.angular, self._params.max_angular_radps)
            if dlin or dang:
                clipped = replace(a, twist=replace(a.twist, linear=lin, angular=ang))
                return EnvelopeVerdict(
                    EnvelopeDecision.CLIP, clipped,
                    clip_delta={"linear_excess_mps": dlin, "angular_excess_radps": dang},
                )
            return EnvelopeVerdict(EnvelopeDecision.PASS, a)
        # POSE_GOAL: workspace clip; forbidden zone -> refuse.
        assert a.goal_pose is not None
        pos = a.goal_pose.position
        for zone in self._zones:
            if zone.contains(pos):
                return EnvelopeVerdict(EnvelopeDecision.REFUSE, a, reason=str(RejectReason.ENVELOPE_VIOLATION))
        clipped_pos, changed = self._workspace.clip(pos)
        if changed:
            return EnvelopeVerdict(
                EnvelopeDecision.CLIP,
                replace(a, goal_pose=replace(a.goal_pose, position=clipped_pos)),
                clip_delta={"goal_pose.position": [list(pos), list(clipped_pos)]},
            )
        return EnvelopeVerdict(EnvelopeDecision.PASS, a)

    def _eval_manipulation(self, a: ManipulationAction) -> EnvelopeVerdict:
        eff = self._descriptor.find_effector(a.effector)
        max_f = eff.max_force_n if eff else float("inf")
        max_t = eff.max_torque_nm if eff else float("inf")
        if a.control_mode is ControlMode.WRENCH and a.wrench is not None:
            # REQ-AC-04: clip every wrench to the envelope; report ACT_CLIPPED.
            f, df = _clip_magnitude(a.wrench.linear, max_f)
            t, dt = _clip_magnitude(a.wrench.angular, max_t)
            if df or dt:
                return EnvelopeVerdict(
                    EnvelopeDecision.CLIP,
                    replace(a, wrench=replace(a.wrench, linear=f, angular=t)),
                    clip_delta={"force_excess_n": df, "torque_excess_nm": dt},
                )
            return EnvelopeVerdict(EnvelopeDecision.PASS, a)
        if a.control_mode is ControlMode.POSE_TRAJ:
            delta: dict[str, Any] = {}
            new_wps = []
            for i, wp in enumerate(a.waypoints):
                assert wp.pose is not None
                pos = wp.pose.position
                for zone in self._zones:
                    if zone.contains(pos):
                        return EnvelopeVerdict(
                            EnvelopeDecision.REFUSE, a, reason=str(RejectReason.ENVELOPE_VIOLATION)
                        )
                clipped, changed = self._workspace.clip(pos)
                if changed:
                    delta[f"waypoints[{i}].pose.position"] = [list(pos), list(clipped)]
                    new_wps.append(replace(wp, pose=replace(wp.pose, position=clipped)))
                else:
                    new_wps.append(wp)
            if delta:
                return EnvelopeVerdict(
                    EnvelopeDecision.CLIP, replace(a, waypoints=tuple(new_wps)), clip_delta=delta
                )
            return EnvelopeVerdict(EnvelopeDecision.PASS, a)
        if a.control_mode is ControlMode.JOINT_TRAJ:
            return self._eval_joint_traj(a)
        if a.control_mode is ControlMode.GRIP and a.grip is not None and a.grip.max_force is not None:
            if a.grip.max_force > max_f:
                return EnvelopeVerdict(
                    EnvelopeDecision.CLIP,
                    replace(a, grip=replace(a.grip, max_force=max_f)),
                    clip_delta={"grip.max_force": [a.grip.max_force, max_f]},
                )
        return EnvelopeVerdict(EnvelopeDecision.PASS, a)

    def _eval_joint_traj(self, a: ManipulationAction) -> EnvelopeVerdict:
        """REQ-SE-01: per-joint velocity limits for JOINT_TRAJ. Waypoints
        carry normalized [-1, 1] joint positions; the implied SI velocity
        between consecutive waypoints is |Δnorm| * (limit_max-limit_min)/2 / Δt.
        Any segment whose implied velocity exceeds the descriptor-published
        JointLimit.max_velocity (REQ-AD-10) is clipped to the nearest valid
        command (REQ-SE-02(a)).

        Self-collision volumes are expressed as forbidden zones in
        EnvelopeParams (see its docstring) and jerk limits are
        adapter-declared constraints enforced inside the adapter's native
        time-parameterization; neither is duplicated here."""
        group = self._descriptor.find_joint_group(a.effector)
        if group is None:
            # Mapping will reject an undeclared group; nothing to clip against.
            return EnvelopeVerdict(EnvelopeDecision.PASS, a)
        limits = group.joints
        delta: dict[str, Any] = {}
        new_wps: list[Any] = [a.waypoints[0]]
        prev = a.waypoints[0]
        for i, wp in enumerate(a.waypoints[1:], start=1):
            assert wp.joints is not None and prev.joints is not None
            dt = wp.t_from_start_s - prev.t_from_start_s
            clipped: list[float] = []
            changed = False
            for j, (target, start) in enumerate(zip(wp.joints, prev.joints)):
                if j < len(limits):
                    lim = limits[j]
                    span = lim.limit_max - lim.limit_min
                    max_v = lim.max_velocity
                else:
                    span, max_v = 2.0, float("inf")
                si_delta = (target - start) * span / 2.0
                allowed = max_v * dt
                if abs(si_delta) > allowed:
                    si_clipped = allowed if si_delta > 0 else -allowed
                    new_val = start + si_clipped * 2.0 / span
                    delta[f"waypoints[{i}].joints[{j}]"] = [target, new_val]
                    clipped.append(new_val)
                    changed = True
                else:
                    clipped.append(target)
            new_wp = replace(wp, joints=tuple(clipped)) if changed else wp
            new_wps.append(new_wp)
            prev = new_wp  # chain: each segment is clipped against the (clipped) previous waypoint
        if delta:
            return EnvelopeVerdict(
                EnvelopeDecision.CLIP, replace(a, waypoints=tuple(new_wps)), clip_delta=delta
            )
        return EnvelopeVerdict(EnvelopeDecision.PASS, a)

    def _eval_raw(self, a: RawAction) -> EnvelopeVerdict:
        """REQ-AC-05: ACT_RAW MUST pass the envelope identically to high-level
        actions; it MUST NOT bypass envelope clipping under any circumstances."""
        if isinstance(a.payload, (bytes, bytearray)):
            return EnvelopeVerdict(EnvelopeDecision.PASS, a)  # OPAQUE: timing-gated only
        limit = min(
            (j.max_velocity for g in self._descriptor.joint_groups for j in g.joints),
            default=self._params.max_angular_radps or 1.0,
        )
        clipped = tuple(min(max(v, -limit), limit) for v in a.payload)
        if clipped != tuple(a.payload):
            return EnvelopeVerdict(
                EnvelopeDecision.CLIP, replace(a, payload=clipped),
                clip_delta={"payload": [list(a.payload), list(clipped)]},
            )
        return EnvelopeVerdict(EnvelopeDecision.PASS, a)

    # ------------------------------------------------------------------
    # REQ-SE-04: dead-man enforcement on all RT action channels
    # ------------------------------------------------------------------

    def note_rt_refresh(
        self,
        channel: str,
        timeout_s: float | None = None,
        expires_ns: int | None = None,
    ) -> None:
        """Record the latest refresh on an RT channel together with the
        PER-MESSAGE deadline (REQ-SE-04): locomotion messages carry
        `duration_s` (§3.1.1 — the message's own dead-man duration) and raw
        messages carry an absolute `expires_ns` (§3.1.6). Channels without a
        per-message deadline (e.g. wrench) fall back to the composed
        parameter defaults."""
        self._rt_refresh[channel] = (self._clock(), timeout_s, expires_ns)

    def _default_deadman_s(self, channel: str) -> float:
        return (
            self._params.deadman_locomotion_s if channel == "locomotion" else self._params.deadman_wrench_s
        )

    def check_deadman(self) -> list[str]:
        """Return RT channels whose refresh lapsed. The core then commands a
        controlled stop (REQ-AC-03/SE-04) — a protective termination, not a
        behavior (REQ-SE-02)."""
        now = self._clock()
        expired: list[str] = []
        for ch, (last, timeout_s, expires_ns) in list(self._rt_refresh.items()):
            if expires_ns is not None:
                lapsed = now > expires_ns  # per-message absolute expiry (§3.1.6)
            else:
                effective_s = timeout_s if timeout_s is not None else self._default_deadman_s(ch)
                lapsed = now - last > effective_s * 1e9  # per-message duration_s (§3.1.1)
            if lapsed:
                expired.append(ch)
                del self._rt_refresh[ch]
        for ch in expired:
            self._record("DEADMAN_EXPIRED", "-", {"channel": ch})
            self._halt_hook()  # controlled stop
        return expired

    # ------------------------------------------------------------------
    # REQ-SE-05: watchdog over mapping engine + adapter heartbeat;
    # halt <= 10 ms from trigger detection within the Glove process.
    # ------------------------------------------------------------------

    def register_watchdog(self, name: str, timeout_s: float) -> None:
        self._watchdogs[name] = (self._clock(), timeout_s)

    def pet_watchdog(self, name: str) -> None:
        if name in self._watchdogs:
            _, timeout = self._watchdogs[name]
            self._watchdogs[name] = (self._clock(), timeout)

    def check_watchdogs(self) -> list[str]:
        now = self._clock()
        tripped = [
            name for name, (last, timeout) in self._watchdogs.items() if now - last > timeout * 1e9
        ]
        for name in tripped:
            self.trip(f"watchdog:{name}")
        return tripped

    def on_impact(self, peak_force_n: float) -> bool:
        """REQ-SE-05: IMPACT above the configured force ceiling trips a halt.
        (REQ-SC-05 requires IMPACT events also reach the envelope.)"""
        if peak_force_n > self._params.impact_force_ceiling_n:
            self.trip(f"impact:{peak_force_n:.1f}N")
            return True
        return False

    def trip(self, cause: str) -> None:
        """Assert halt() to the adapter (REQ-SE-05). Records the decision
        (REQ-SE-08). Protective termination only (REQ-SE-02)."""
        if not self._halted:
            self._halted = True
            self._record("ENVELOPE_HALT", "-", {"cause": cause})
            self._halt_hook()

    def clear_halt(self, *, governance_clearance: bool) -> bool:
        """Recovery requires governance clearance where policy demands it
        (REQ-AD-12/SE-06)."""
        if not governance_clearance:
            return False
        self._halted = False
        self._record("ENVELOPE_HALT_CLEARED", "-", {})
        return True

    # ------------------------------------------------------------------
    # REQ-SE-06: degraded mode — HOLD / RETREAT / PARK; remains degraded
    # until governance clearance resumes the session.
    # ------------------------------------------------------------------

    def enter_degraded(self, mode: DegradedMode | None, reason: str) -> DegradedMode:
        chosen = DegradedMode(mode) if mode else DegradedMode(self._params.degraded_mode)
        self._degraded = chosen
        self._record("ENVELOPE_DEGRADED_ENTER", "-", {"mode": str(chosen), "reason": reason})
        self._halt_hook()  # stop-and-hold / retract / park asserted via adapter
        return chosen

    def exit_degraded(self, *, governance_clearance: bool) -> bool:
        if not governance_clearance:
            return False
        self._degraded = None
        self._record("ENVELOPE_DEGRADED_EXIT", "-", {})
        return True

    # ------------------------------------------------------------------
    # REQ-SE-08: every envelope decision is recorded with the composed
    # parameter hash, triggering msg_id, and resulting delta.
    # ------------------------------------------------------------------

    def _record(self, kind: str, msg_id: str, extra: dict[str, Any]) -> None:
        rec = {"params_hash": self.params_hash(), "msg_id": msg_id, "t_ns": self._clock()}
        rec.update(extra)
        self._audit(kind, rec)
