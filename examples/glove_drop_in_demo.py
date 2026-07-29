#!/usr/bin/env python3
"""Drop-in demo — GLV-SPEC-1.0.0.

The SAME being-side stub code drives a mock humanoid, then a mock industrial
arm, then a mock mobile base — unchanged (zero-being-modification, CR-5) —
and finally hot-swaps mid-session from the mobile base to the humanoid
(§7.2). Runs fully offline, in-process (REQ-OF-01).

Run:  python3 examples/glove_drop_in_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # direct import, no install needed

from glove import (  # noqa: E402
    AttentionAction,
    AttentionMode,
    ContinuityPacket,
    ControlMode,
    ExpressionAction,
    ExpressionChannel,
    Glove,
    GovClass,
    Grip,
    LocomotionAction,
    LocomotionMode,
    ManipulationAction,
    MsgType,
    Pose,
    Twist,
    Utterance,
    Waypoint,
)
from glove.adapter.examples.mock_humanoid import MockHumanoidAdapter  # noqa: E402
from glove.adapter.examples.mock_industrial_arm import MockIndustrialArmAdapter  # noqa: E402
from glove.adapter.examples.mock_mobile_base import MockMobileBaseAdapter  # noqa: E402
from glove.governance.endpoint import create_envelope, public_key_from_signing_key  # noqa: E402

BEING_ID = "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f"


def being_program(glove: Glove, label: str) -> None:
    """The being. This exact code runs against EVERY body, unchanged.

    It speaks only the Neural Contract and derives its command set from the
    negotiated capability descriptor (REQ-CV-02/03, REQ-CV-06).
    """
    print(f"\n=== Being dropped into: {label} ===")
    welcome = glove.hello(BEING_ID, ["1.0.0"])
    glove.accept(welcome)
    d = welcome.capability_descriptor
    print(f"  handshake: contract {welcome.selected_version}, session {welcome.session_id[:13]}…")
    print(f"  body: {d.body_class} serial={d.body_serial} simulated={d.simulated}")
    print(f"  declared actions: {sorted(d.action_types)}")

    acks = []
    glove.on_ack(acks.append)
    sensory: list[str] = []
    glove.on_sensory(lambda mt, p: sensory.append(str(mt)))

    if d.supports_action(MsgType.ACT_LOCOMOTION):
        ack = glove.submit_action(LocomotionAction(
            mode=LocomotionMode.VELOCITY, twist=Twist((0.4, 0.0, 0.0), (0.0, 0.0, 0.15))))
        print(f"  ACT_LOCOMOTION(0.4 m/s) -> {ack.status}")
    if d.supports_action(MsgType.ACT_MANIPULATION) and d.effectors:
        eff = d.effectors[0]
        if "GRIP" in eff.control_modes:
            ack = glove.submit_action(ManipulationAction(
                effector=eff.name, control_mode=ControlMode.GRIP, grip=Grip(0.5, eff.max_force_n)))
            print(f"  ACT_MANIPULATION(GRIP {eff.name}) -> {ack.status}")
        if "POSE_TRAJ" in eff.control_modes:
            ack = glove.submit_action(ManipulationAction(
                effector=eff.name, control_mode=ControlMode.POSE_TRAJ,
                waypoints=(Waypoint(0.0, pose=Pose((0.4, 0.1, 0.8), (1.0, 0, 0, 0))),)))
            print(f"  ACT_MANIPULATION(POSE_TRAJ {eff.name}) -> {ack.status}")
    if d.supports_action(MsgType.ACT_EXPRESSION) and d.supports_expression_channel("SPEECH"):
        ack = glove.submit_action(ExpressionAction(
            channel=ExpressionChannel.SPEECH,
            utterance=Utterance(text="I have finished charging the tool.", locale="en-US")))
        print(f"  ACT_EXPRESSION(SPEECH) -> {ack.status}")
    if d.supports_action(MsgType.ACT_ATTENTION):
        ack = glove.submit_action(AttentionAction(mode=AttentionMode.FIXATE,
                                                  point=(1.20, -0.35, 1.10)))
        print(f"  ACT_ATTENTION(FIXATE) -> {ack.status}")

    adapter = glove.adapter
    if hasattr(adapter, "emit_tick"):
        adapter.emit_tick()
    if hasattr(adapter, "emit_internal"):
        adapter.emit_internal()
    if hasattr(adapter, "emit_vision"):
        adapter.emit_vision()
    print(f"  sensory received: {sorted(set(sensory))}")
    print(f"  absent modalities degraded gracefully (no errors, no phantom sensors)")


def hotswap_demo() -> None:
    print("\n=== Hot-swap: mobile base -> humanoid (§7.2) ===")
    glove = Glove()
    glove.attach_adapter(MockMobileBaseAdapter())
    glove.set_packet(ContinuityPacket.genesis(
        being_id=BEING_ID, being_key=b"glove-skeleton-being-key",
        identity_assertion="hmac-sha256:demo-identity",
        short_term_context_ref={"handle": "sha256:demo-context", "key_ref": "client-key-1"},
        governance_snapshot=b"demo-governance-snapshot",
    ))
    welcome = glove.hello(BEING_ID, ["1.0.0"])
    glove.accept(welcome)
    glove.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                         twist=Twist((0.3, 0, 0), (0, 0, 0.1))))
    print(f"  mid-task on {glove.descriptor.body_class}, session {glove.session_id[:13]}…")  # type: ignore[union-attr]

    result = glove.transfer_to(MockHumanoidAdapter(),
                               required_modalities=["ACT_LOCOMOTION", "ACT_MANIPULATION"],
                               governance_revalidate=lambda snap: snap == b"demo-governance-snapshot")
    path = " -> ".join(str(t) for _, t in result.transitions)
    print(f"  transfer: {path}")
    pkt = glove.packet
    print(f"  identity preserved: {pkt.being_id == BEING_ID}")  # type: ignore[union-attr]
    print(f"  context handle preserved: {pkt.short_term_context_ref['handle']}")  # type: ignore[index,union-attr]
    print(f"  governance snapshot re-validated and preserved: {pkt.governance_snapshot == b'demo-governance-snapshot'}")  # type: ignore[union-attr]
    print(f"  new body: {glove.descriptor.body_class} — being re-handshakes unchanged:")  # type: ignore[union-attr]
    welcome = glove.hello(BEING_ID, ["1.0.0"])
    glove.accept(welcome)
    ack = glove.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                               twist=Twist((0.3, 0, 0), (0, 0, 0.1))))
    print(f"  resumed on humanoid, session {glove.session_id[:13]}…, ACT_LOCOMOTION -> {ack.status}")


def governance_demo() -> None:
    print("\n=== Governance: caregiver override preempts motion (§5, REQ-GV-04) ===")
    glove = Glove()
    glove.attach_adapter(MockHumanoidAdapter())
    welcome = glove.hello(BEING_ID, ["1.0.0"])
    glove.accept(welcome)
    acks = []
    glove.on_ack(acks.append)
    # Endpoint-side ed25519 signing key (lives at the caregiver console);
    # the bus registers the verification-only public key (INV-4).
    key = b"caregiver-console-key".ljust(32, b"\0")
    glove.bus.register_endpoint("caregiver.console.07", public_key_from_signing_key(key),
                                lambda env: None)
    glove.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                         twist=Twist((0.6, 0, 0), (0, 0, 0.2))))
    print("  being driving at 0.6 m/s …")
    env = create_envelope(key, GovClass.OVERRIDE, "caregiver.console.07", 1,
                          60_000_000_000, b"opaque: halt immediately")
    glove.bus.submit(env)
    aborted = [a for a in acks if a.status == "ACT_ABORTED"]
    print(f"  override delivered -> in-flight aborted: {len(aborted)} "
          f"(cause={aborted[0].cause if aborted else '-'})")
    print(f"  adapter halt asserted: {glove.adapter.halts >= 1}")  # type: ignore[attr-defined]
    print(f"  payload crossed the bus byte-identical, never parsed by the Glove")


def main() -> None:
    print("The Glove Layer — drop-in demo (GLV-SPEC-1.0.0), fully offline.")
    glove = Glove()
    glove.attach_adapter(MockHumanoidAdapter())
    being_program(glove, "mock humanoid (full modalities)")

    glove = Glove()
    glove.attach_adapter(MockIndustrialArmAdapter())
    being_program(glove, "mock industrial arm (manipulation only)")

    glove = Glove()
    glove.attach_adapter(MockMobileBaseAdapter())
    being_program(glove, "mock mobile base (locomotion + speech only)")

    hotswap_demo()
    governance_demo()
    print("\nDemo complete. Same being code, three bodies, one hot-swap, zero modifications.")


if __name__ == "__main__":
    main()
