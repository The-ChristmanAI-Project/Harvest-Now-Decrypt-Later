"""RobotAdapter boundary — GLV-SPEC-1.0.0 §4 (normative).

The adapter is the ONLY robot-specific component in the system (REQ-AD-00).
The Glove core is identical for all bodies. Adding support for a new robot
class means implementing this boundary — nothing else.

Motion inhibition (REQ-AD-02): from connect() until successful activate(),
and after deactivate(), the adapter MUST inhibit all motion outputs
regardless of dispatch calls. This base class enforces that invariant.
"""

from __future__ import annotations

import abc
import itertools
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Iterable

from ..contract.capabilities import CapabilityDescriptor, EnvelopeParams
from ..contract.sensory import Fault, FaultSeverity


class AdapterState(StrEnum):
    """REQ-AD-01: state transitions reported via ADAPTER_STATE events."""

    DISCOVERED = "DISCOVERED"
    CONNECTED = "CONNECTED"
    CALIBRATED = "CALIBRATED"
    ACTIVE = "ACTIVE"
    INHIBITED = "INHIBITED"
    DISCONNECTED = "DISCONNECTED"
    FAULT = "FAULT"


class LifecycleFault(StrEnum):
    CONNECT_FAULT = "CONNECT_FAULT"
    CALIBRATION_FAULT = "CALIBRATION_FAULT"
    ACTIVATION_FAULT = "ACTIVATION_FAULT"


class AdapterFaultError(Exception):
    """Raised when a lifecycle method fails; `fault` carries the machine code."""

    def __init__(self, fault: LifecycleFault, reason: str):
        super().__init__(f"{fault}: {reason}")
        self.fault = fault
        self.reason = reason


class DeactivateMode(StrEnum):
    GRACEFUL = "GRACEFUL"    # complete or abort in-flight actions, then inhibit
    IMMEDIATE = "IMMEDIATE"  # abort now; MUST still reach motion-inhibited


class DispatchOutcome(StrEnum):
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAULT = "FAULT"


@dataclass(slots=True, frozen=True)
class DispatchResult:
    """REQ-AD-05: execution outcome per dispatched command, keyed by the
    core's command handle."""

    command_handle: int
    outcome: DispatchOutcome
    detail: str = ""


@dataclass(slots=True)
class MappedCommand:
    """Robot-space command handed to dispatch().

    REQ-AD-04: arrives ALREADY validated and envelope-clipped by the core.
    The adapter MUST NOT re-interpret being intent, re-plan trajectories
    beyond native-driver time-parameterization, or silently substitute a
    different action.
    """

    command_handle: int
    msg_id: str                    # original action message id (audit trace)
    kind: str                      # robot-space kind, e.g. "twist", "joint_traj", "grip"
    body: dict[str, Any]           # robot-space SI quantities from mapping tables


# Sensory sink: the core registers one callback; adapters push NORMALIZED
# sensory packets (dict payloads per §3.2) into it (REQ-AD-07).
SensorySink = Callable[[str, dict[str, Any]], None]  # (msg_type, payload)
StateEventSink = Callable[[AdapterState], None]      # ADAPTER_STATE events


class RobotAdapter(abc.ABC):
    """Abstract base for §4-conforming adapters.

    Concrete adapters override the ``_*_impl`` hooks and the abstract
    methods. The public lifecycle methods enforce ordering, motion
    inhibition (REQ-AD-02), state event emission (REQ-AD-01), and the
    no-auto-recovery rule for FATAL faults (REQ-AD-12).
    """

    def __init__(self, adapter_key: bytes = b"glove-skeleton-adapter-key") -> None:
        self._state = AdapterState.DISCONNECTED
        self._motion_inhibited = True
        self._fatal_latched = False
        self._sensory_sink: SensorySink | None = None
        self._state_sink: StateEventSink | None = None
        self._handles = itertools.count(1)
        self._adapter_key = adapter_key
        self.faults: list[Fault] = []

    # ------------------------------------------------------------------
    # wiring (called by the Glove core)
    # ------------------------------------------------------------------

    def set_sensory_sink(self, sink: SensorySink) -> None:
        self._sensory_sink = sink

    def set_state_sink(self, sink: StateEventSink) -> None:
        self._state_sink = sink

    @property
    def state(self) -> AdapterState:
        return self._state

    @property
    def motion_inhibited(self) -> bool:
        return self._motion_inhibited

    @property
    def adapter_key(self) -> bytes:
        return self._adapter_key

    def _set_state(self, state: AdapterState) -> None:
        self._state = state
        if self._state_sink is not None:
            self._state_sink(state)  # ADAPTER_STATE event (REQ-AD-01)

    def _emit_sensory(self, msg_type: str, payload: dict[str, Any]) -> None:
        """Push a normalized sensory packet to the core (REQ-AD-07/08)."""
        if self._sensory_sink is not None:
            self._sensory_sink(msg_type, payload)

    # ------------------------------------------------------------------
    # Lifecycle (§4.1, REQ-AD-01/02) — final methods, fixed semantics
    # ------------------------------------------------------------------

    def discover(self) -> list[Any]:
        """Enumerate reachable robot instances. MUST NOT throw (§4.1)."""
        try:
            handles = list(self._discover_impl())
        except Exception:
            return []
        if handles:
            self._set_state(AdapterState.DISCOVERED)
        return handles

    def connect(self, handle: Any) -> None:
        """Establish transport; verify firmware/protocol; NO motion permitted."""
        if self._fatal_latched:
            raise AdapterFaultError(LifecycleFault.CONNECT_FAULT, "FATAL latched; explicit lifecycle re-entry required (REQ-AD-12)")
        try:
            self._connect_impl(handle)
        except AdapterFaultError:
            self._set_state(AdapterState.FAULT)
            raise
        except Exception as exc:
            self._set_state(AdapterState.FAULT)
            raise AdapterFaultError(LifecycleFault.CONNECT_FAULT, str(exc)) from exc
        self._motion_inhibited = True  # REQ-AD-02
        self._set_state(AdapterState.CONNECTED)

    def calibrate(self, profile: dict[str, Any] | None = None) -> CapabilityDescriptor:
        """Load/compute calibration; publish static transforms; return the
        capability descriptor template (§4.2). Robot MUST remain
        motion-inhibited. Accepts a continuity-packet calibration snapshot."""
        try:
            descriptor = self._calibrate_impl(profile)
        except AdapterFaultError:
            self._set_state(AdapterState.FAULT)
            raise
        except Exception as exc:
            self._set_state(AdapterState.FAULT)
            raise AdapterFaultError(LifecycleFault.CALIBRATION_FAULT, str(exc)) from exc
        self._motion_inhibited = True  # REQ-AD-02
        self._set_state(AdapterState.CALIBRATED)
        return descriptor

    def activate(self) -> None:
        """Enable the action dispatch path; begin sensory ingestion at
        negotiated rates. On failure the core MUST NOT emit actions."""
        if self._state is not AdapterState.CALIBRATED:
            raise AdapterFaultError(LifecycleFault.ACTIVATION_FAULT, f"cannot activate from {self._state}")
        try:
            self._activate_impl()
        except AdapterFaultError:
            self._motion_inhibited = True
            self._set_state(AdapterState.FAULT)
            raise
        except Exception as exc:
            self._motion_inhibited = True
            self._set_state(AdapterState.FAULT)
            raise AdapterFaultError(LifecycleFault.ACTIVATION_FAULT, str(exc)) from exc
        self._motion_inhibited = False
        self._set_state(AdapterState.ACTIVE)

    def deactivate(self, mode: DeactivateMode = DeactivateMode.GRACEFUL) -> None:
        """Orderly stop; MUST reach motion-inhibited even on error (§4.1)."""
        try:
            self._deactivate_impl(DeactivateMode(mode))
        except Exception:
            pass  # inhibit regardless (§4.1 failure behavior)
        self._motion_inhibited = True
        try:
            self.halt()
        except Exception:
            pass
        self._set_state(AdapterState.INHIBITED)

    def disconnect(self) -> None:
        """Release transport and native resources. Idempotent; safe in any state."""
        self._motion_inhibited = True
        try:
            self._disconnect_impl()
        except Exception:
            pass
        self._set_state(AdapterState.DISCONNECTED)

    # ------------------------------------------------------------------
    # Action dispatch (§4.3, REQ-AD-04/05/06)
    # ------------------------------------------------------------------

    def dispatch(self, cmd: MappedCommand) -> DispatchResult:
        """Receive a robot-space command (validated + clipped by the core)
        and translate to robot-native actuation. Motion-inhibited adapters
        refuse regardless of dispatch calls (REQ-AD-02)."""
        if self._motion_inhibited or self._state is not AdapterState.ACTIVE:
            return DispatchResult(cmd.command_handle, DispatchOutcome.FAULT, "NOT_ACTIVE")
        return self._dispatch_impl(cmd)

    @abc.abstractmethod
    def halt(self) -> None:
        """REQ-AD-06: worst-case entry into the robot's safest available stop
        state within REQ-SE-05 latency. Takes precedence over all dispatch
        traffic. MUST be safe to call in any state."""

    # ------------------------------------------------------------------
    # Safety configuration (§4.5, REQ-AD-10)
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def physical_limits(self) -> EnvelopeParams:
        """Adapter-supplied physical limit set: joint/effector limits,
        forbidden zones, e-stop capabilities. Values MUST come from
        manufacturer specification or measured calibration; the core treats
        them as upper bounds that policy may only tighten (REQ-SE-03)."""

    # ------------------------------------------------------------------
    # Fault reporting (§4.6, REQ-AD-11/12)
    # ------------------------------------------------------------------

    def report_fault(self, fault: Fault) -> None:
        """Map a native fault register to an SN_INTERNAL.faults entry and,
        where the adapter can no longer meet its contract, an ADAPTER_STATE
        transition (REQ-AD-11). FATAL faults latch: no auto-recovery by
        re-enabling motion (REQ-AD-12)."""
        fault.validate()
        self.faults.append(fault)
        self._emit_sensory(
            "SN_INTERNAL",
            {"battery": {"soc": 0.0}, "faults": [
                {"code": fault.code, "severity": str(fault.severity), "message": fault.message}
            ]},
        )
        if fault.severity is FaultSeverity.FATAL:
            self._fatal_latched = True
            self._motion_inhibited = True
            try:
                self.halt()
            except Exception:
                pass
            self._set_state(AdapterState.FAULT)
        elif fault.severity is FaultSeverity.CRITICAL:
            self._set_state(AdapterState.FAULT)

    # ------------------------------------------------------------------
    # Hooks for concrete adapters
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def _discover_impl(self) -> Iterable[Any]: ...

    @abc.abstractmethod
    def _connect_impl(self, handle: Any) -> None: ...

    @abc.abstractmethod
    def _calibrate_impl(self, profile: dict[str, Any] | None) -> CapabilityDescriptor: ...

    @abc.abstractmethod
    def _activate_impl(self) -> None: ...

    @abc.abstractmethod
    def _deactivate_impl(self, mode: DeactivateMode) -> None: ...

    def _disconnect_impl(self) -> None:
        """Default: nothing to release. Override at the true driver edge."""

    @abc.abstractmethod
    def _dispatch_impl(self, cmd: MappedCommand) -> DispatchResult: ...
