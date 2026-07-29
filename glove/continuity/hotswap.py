"""Transfer state machine — GLV-SPEC-1.0.0 §7.2 (normative).

    RUNNING ──► QUIESCE ──► SNAPSHOT ──► DETACH ──► ATTACH ──► CALIBRATE ──► RESUME

REQ-ST-04: body transfer MUST follow this state machine; every transition
MUST be logged.
REQ-ST-05: at RESUME the governance snapshot MUST be re-validated by the
governance layer before any action channel opens; the Glove MUST NOT open
action channels on the basis of the snapshot alone.
REQ-ST-06: deterministic rollback — failure in QUIESCE/SNAPSHOT → remain on
current body, session continues; failure in ATTACH/CALIBRATE → being stays
safely suspended, packet intact, retry on the original body is offered; the
packet is never partially applied or destructively consumed.
REQ-ST-08: the whole transfer runs offline, in-process.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable

from .packet import ContinuityPacket


class TransferState(StrEnum):
    RUNNING = "RUNNING"
    QUIESCE = "QUIESCE"
    SNAPSHOT = "SNAPSHOT"
    DETACH = "DETACH"
    ATTACH = "ATTACH"
    CALIBRATE = "CALIBRATE"
    RESUME = "RESUME"
    # terminal/rollback outcomes
    COMPLETED = "COMPLETED"
    ROLLED_BACK_RUNNING = "ROLLED_BACK_RUNNING"   # stayed on original body (REQ-ST-06a)
    SUSPENDED = "SUSPENDED"                       # packet intact, retry offered (REQ-ST-06b)
    ABORTED = "ABORTED"                           # integrity/tamper detected (CF-T-ST-03)


class TransferError(Exception):
    """Stage failure; carries the state at which the transfer failed."""

    def __init__(self, state: "TransferState", reason: str):
        super().__init__(f"transfer failed in {state}: {reason}")
        self.state = state
        self.reason = reason


# Stage callbacks supplied by the orchestrator (core.glove). Each returns
# normally on success or raises to trigger REQ-ST-06 rollback.
StageFn = Callable[[], None]


@dataclass(slots=True)
class TransferPlan:
    quiesce: StageFn          # dead-man-stop RT channels, drain/abort queue, envelope HOLD
    snapshot: StageFn         # write, sign, hash-chain, persist packet locally
    detach: StageFn           # adapter deactivate + disconnect
    attach: StageFn           # new adapter connect; compatibility vs required modalities
    calibrate: StageFn        # restore calibration from packet or fresh; publish transforms
    resume: StageFn           # governance re-validation; context handle; new session; handshake


@dataclass(slots=True, frozen=True)
class TransferResult:
    final_state: TransferState
    transitions: tuple[tuple[TransferState, TransferState], ...]
    packet: ContinuityPacket
    error: str | None = None


class TransferStateMachine:
    """Executes the REQ-ST-04 machine with REQ-ST-06 rollback paths.

    The machine itself holds no policy: it sequences stage callbacks and
    records transitions. All behavior lives in the Glove core wiring and the
    governance layer above it.
    """

    ORDER: tuple[TransferState, ...] = (
        TransferState.QUIESCE,
        TransferState.SNAPSHOT,
        TransferState.DETACH,
        TransferState.ATTACH,
        TransferState.CALIBRATE,
        TransferState.RESUME,
    )

    def __init__(self, audit: Callable[[str, dict[str, Any]], None] | None = None) -> None:
        self._audit = audit or (lambda kind, rec: None)
        self.state = TransferState.RUNNING
        self.transitions: list[tuple[TransferState, TransferState]] = []

    def _go(self, to: TransferState) -> None:
        frm = self.state
        self.state = to
        self.transitions.append((frm, to))
        self._audit("TRANSFER_TRANSITION", {"from": str(frm), "to": str(to)})  # REQ-ST-04

    def run(self, plan: TransferPlan, packet: ContinuityPacket) -> TransferResult:
        stages: dict[TransferState, StageFn] = {
            TransferState.QUIESCE: plan.quiesce,
            TransferState.SNAPSHOT: plan.snapshot,
            TransferState.DETACH: plan.detach,
            TransferState.ATTACH: plan.attach,
            TransferState.CALIBRATE: plan.calibrate,
            TransferState.RESUME: plan.resume,
        }
        detached = False
        for stage in self.ORDER:
            try:
                stages[stage]()
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
                self._audit("TRANSFER_STAGE_FAILED", {"stage": str(stage), "error": err})
                # REQ-ST-06 rollback paths.
                if stage in (TransferState.QUIESCE, TransferState.SNAPSHOT):
                    # Remain on current body; session continues.
                    self._go(TransferState.ROLLED_BACK_RUNNING)
                elif detached or stage in (TransferState.ATTACH, TransferState.CALIBRATE, TransferState.RESUME):
                    # Being remains safely suspended, packet intact; retry on
                    # the original body is offered by the caller.
                    self._go(TransferState.SUSPENDED)
                else:
                    self._go(TransferState.SUSPENDED)
                return TransferResult(self.state, tuple(self.transitions), packet, err)
            self._go(stage)
            if stage is TransferState.DETACH:
                detached = True
        self._go(TransferState.COMPLETED)
        return TransferResult(self.state, tuple(self.transitions), packet)
