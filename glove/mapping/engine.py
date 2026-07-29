"""Being-space <-> robot-space mapping engine — GLV-SPEC-1.0.0 §2.3, §9.4.

REQ-CF-08: all mappings are STATIC, VERSIONED, HUMAN-READABLE tables or
closed-form transforms, published with the capability descriptor. There are
NO trainable or adaptive components anywhere in this module. Mapping is a
pure function of (action, descriptor, table): deterministic and inspectable
(REQ-AD-08).
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any

from ..contract.actions import (
    AttentionAction,
    ControlMode,
    ExpressionAction,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    RawAction,
    ToolAction,
)
from ..contract.capabilities import CapabilityDescriptor
from ..contract.envelope import ContractError
from ..contract.sensory import denormalize_joint, normalize_joint

Action = (
    LocomotionAction | ManipulationAction | ExpressionAction
    | AttentionAction | ToolAction | RawAction
)


@dataclass(slots=True, frozen=True)
class MappingTable:
    """Static, versioned mapping table (REQ-CF-08).

    Every constant here is inspectable: scales are dimensionless gains,
    `grip_stroke_m` maps normalized aperture [0,1] linearly to physical
    stroke, and joint mapping reuses the descriptor's published REQ-SC-04
    constants. The table hash is published with the capability descriptor.
    """

    version: str
    twist_linear_scale: tuple[float, float, float] = (1.0, 1.0, 1.0)
    twist_angular_scale: tuple[float, float, float] = (1.0, 1.0, 1.0)
    grip_stroke_m: tuple[float, float] = (0.0, 0.085)  # aperture 0..1 -> stroke min..max
    head_pan_joint: str = "head.pan"
    head_tilt_joint: str = "head.tilt"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "twist_linear_scale": list(self.twist_linear_scale),
            "twist_angular_scale": list(self.twist_angular_scale),
            "grip_stroke_m": list(self.grip_stroke_m),
            "head_pan_joint": self.head_pan_joint,
            "head_tilt_joint": self.head_tilt_joint,
        }

    def hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


DEFAULT_TABLE = MappingTable(version="1.0.0")


class MappingEngine:
    """Deterministic being-space <-> robot-space translator (no learning)."""

    def __init__(self, table: MappingTable = DEFAULT_TABLE) -> None:
        self.table = table

    # ------------------------------------------------------------------
    # Efferent: being-space action -> robot-space command body
    # ------------------------------------------------------------------

    def to_robot(self, action: Action, descriptor: CapabilityDescriptor) -> tuple[str, dict[str, Any]]:
        """Map a validated, envelope-cleared action to a robot-space body.

        Pure translation: no intent re-interpretation (REQ-AD-04).
        """
        if isinstance(action, LocomotionAction):
            return self._locomotion(action)
        if isinstance(action, ManipulationAction):
            return self._manipulation(action, descriptor)
        if isinstance(action, ExpressionAction):
            return self._expression(action)
        if isinstance(action, AttentionAction):
            return self._attention(action)
        if isinstance(action, ToolAction):
            return self._tool(action)
        if isinstance(action, RawAction):
            return self._raw(action)
        raise ContractError(f"unmappable action type {type(action).__name__}")

    def _locomotion(self, a: LocomotionAction) -> tuple[str, dict[str, Any]]:
        if a.mode is LocomotionMode.VELOCITY:
            assert a.twist is not None
            lin = [v * s for v, s in zip(a.twist.linear, self.table.twist_linear_scale)]
            ang = [v * s for v, s in zip(a.twist.angular, self.table.twist_angular_scale)]
            return "twist", {"linear": lin, "angular": ang, "duration_s": a.duration_s}
        assert a.goal_pose is not None
        return "pose_goal", {
            "position": list(a.goal_pose.position),
            "orientation": list(a.goal_pose.orientation),
            "frame": a.goal_pose.frame,
        }

    def _manipulation(self, a: ManipulationAction, d: CapabilityDescriptor) -> tuple[str, dict[str, Any]]:
        if a.control_mode is ControlMode.POSE_TRAJ:
            return "pose_traj", {
                "effector": a.effector,
                "waypoints": [
                    {
                        "t_from_start_s": wp.t_from_start_s,
                        "position": list(wp.pose.position),       # type: ignore[union-attr]
                        "orientation": list(wp.pose.orientation),  # type: ignore[union-attr]
                    }
                    for wp in a.waypoints
                ],
            }
        if a.control_mode is ControlMode.JOINT_TRAJ:
            # REQ-SC-04: normalized [-1,1] -> SI via descriptor-published constants.
            group = d.find_joint_group(a.effector)
            if group is None:
                raise ContractError(f"no joint group declared for effector {a.effector!r}")
            limits = [(j.limit_min, j.limit_max) for j in group.joints]
            waypoints = []
            for wp in a.waypoints:
                joints = list(wp.joints or ())
                if len(joints) != len(limits):
                    raise ContractError(
                        f"joint vector length {len(joints)} != group dof {len(limits)} for {a.effector!r}"
                    )
                waypoints.append({
                    "t_from_start_s": wp.t_from_start_s,
                    "joints_si": [denormalize_joint(j, lo, hi) for j, (lo, hi) in zip(joints, limits)],
                })
            return "joint_traj", {"effector": a.effector, "waypoints": waypoints}
        if a.control_mode is ControlMode.WRENCH:
            assert a.wrench is not None
            return "wrench", {
                "effector": a.effector,
                "force": list(a.wrench.linear),   # N, GLOVE-TOOL
                "torque": list(a.wrench.angular),  # N·m, GLOVE-TOOL
            }
        assert a.grip is not None
        lo, hi = self.table.grip_stroke_m
        stroke = lo + a.grip.aperture * (hi - lo)  # linear aperture -> stroke
        return "grip", {
            "effector": a.effector,
            "stroke_m": stroke,
            "max_force": a.grip.max_force,
        }

    def _expression(self, a: ExpressionAction) -> tuple[str, dict[str, Any]]:
        # §3.1.3: utterance.text is passed to the adapter's TTS stage VERBATIM.
        if a.utterance is not None:
            return "speech", {
                "text": a.utterance.text,
                "locale": a.utterance.locale,
                "prosody": a.utterance.prosody,
            }
        if a.expression is not None:
            return "face", {"expression": a.expression}
        if a.posture is not None:
            return "posture", {
                "position": list(a.posture.position),
                "orientation": list(a.posture.orientation),
            }
        assert a.led is not None
        return "led", {
            "color_rgb": list(a.led.color_rgb), "duty": a.led.duty, "period_s": a.led.period_s,
        }

    def _attention(self, a: AttentionAction) -> tuple[str, dict[str, Any]]:
        # Closed-form transform (REQ-CF-08): fixation point/direction -> pan/tilt.
        if a.direction is not None:
            x, y, z = a.direction
        elif a.point is not None:
            x, y, z = a.point
            n = math.sqrt(x * x + y * y + z * z) or 1.0
            x, y, z = x / n, y / n, z / n
        else:
            return "attention", {"mode": str(a.mode), "track_id": a.track_id, "settle_s": a.settle_s}
        pan = math.atan2(y, x)                    # rad, GLOVE-HEAD
        tilt = math.atan2(z, math.hypot(x, y))    # rad
        return "attention", {
            "mode": str(a.mode),
            "pan_rad": pan,
            "tilt_rad": tilt,
            "settle_s": a.settle_s,
            "joints": [self.table.head_pan_joint, self.table.head_tilt_joint],
        }

    def _tool(self, a: ToolAction) -> tuple[str, dict[str, Any]]:
        return "tool", {
            "tool_id": a.tool_id,
            "operation": str(a.operation),
            "params": a.params or {},
            "safety_interlock": a.safety_interlock,
        }

    def _raw(self, a: RawAction) -> tuple[str, dict[str, Any]]:
        payload: Any = bytes(a.payload) if isinstance(a.payload, (bytes, bytearray)) else list(a.payload)
        return "raw", {
            "channel": a.channel,
            "encoding": str(a.encoding),
            "payload": payload,
            "expires_ns": a.expires_ns,
        }

    # ------------------------------------------------------------------
    # Afferent helpers (deterministic normalization, REQ-AD-07/08)
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_joints(si_values: list[float], limits: list[tuple[float, float]]) -> list[float]:
        """SI -> normalized [-1,1] via published constants (REQ-SC-04)."""
        return [normalize_joint(v, lo, hi) for v, (lo, hi) in zip(si_values, limits)]

    @staticmethod
    def denormalize_joints(norm_values: list[float], limits: list[tuple[float, float]]) -> list[float]:
        return [denormalize_joint(v, lo, hi) for v, (lo, hi) in zip(norm_values, limits)]
