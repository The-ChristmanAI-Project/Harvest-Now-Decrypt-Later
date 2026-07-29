"""Governance pass-through tests — GLV-SPEC-1.0.0 §5.

Proves the bus is STRICTLY pass-through: payloads byte-identical in/out
(INV-1, REQ-GV-06), authentication/integrity rejection (REQ-GV-02,
CF-T-GOV-01), per-sender ordering with GOV_UNDELIVERED (REQ-GV-03), zero
synthesized governance (REQ-GV-07, CF-T-GOV-04), caregiver override
preemption (REQ-GV-04, CF-T-GOV-02), and Pulse Tether fail-closed behavior
(REQ-GV-05, CF-T-GOV-03).

Auth tags are ed25519 signatures (Appendix A). Signing keys exist ONLY in
this endpoint-side test tooling and in `glove.governance.endpoint`; the bus
registers verification-only public keys (INV-4).
"""

from __future__ import annotations

from glove import Glove, LocomotionAction, LocomotionMode, Twist
from glove.adapter.examples.mock_humanoid import MockHumanoidAdapter
from glove.adapter.examples.mock_mobile_base import MockMobileBaseAdapter
from glove.governance.bus import (
    GovClass,
    GovEnvelope,
    GovernanceBus,
    GovReject,
)
from glove.governance.endpoint import (
    create_envelope,
    generate_signing_key,
    public_key_from_signing_key,
)

BEING = "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f"


def _seed(label: str) -> bytes:
    """Deterministic 32-byte ed25519 seed for reproducible endpoint keys."""
    return label.encode().ljust(32, b"\0")[:32]


CONSENSUS_SK = _seed("consensus-endpoint-key")
CAREGIVER_SK = _seed("caregiver-console-key")
PULSE_SK = _seed("pulse-tether-key")


def _bus_with_endpoint(payloads_out: list) -> GovernanceBus:
    bus = GovernanceBus()
    bus.register_endpoint("diamond.consensus", public_key_from_signing_key(CONSENSUS_SK),
                          lambda env: payloads_out.append(env.payload))
    return bus


def _live_glove() -> Glove:
    g = Glove()
    g.attach_adapter(MockMobileBaseAdapter())
    w = g.hello(BEING, ["1.0.0"])
    g.accept(w)
    return g


# -- INV-1 / REQ-GV-06: byte-identical pass-through ----------------------------


def test_payload_byte_identical_in_out():
    out: list[bytes] = []
    bus = _bus_with_endpoint(out)
    payload = bytes(range(256)) * 4  # arbitrary opaque ciphertext
    env = create_envelope(CONSENSUS_SK, GovClass.CONSENSUS, "diamond.consensus", 1, 60_000_000_000, payload)
    assert bus.submit(env)
    assert len(out) == 1 and out[0] == payload
    assert out[0] is payload or bytes(out[0]) == payload  # never mutated, never re-signed


def test_bus_delivers_same_object_no_parse():
    seen: list[GovEnvelope] = []
    bus = GovernanceBus()
    bus.register_endpoint("ring4", public_key_from_signing_key(CONSENSUS_SK), seen.append)
    env = create_envelope(CONSENSUS_SK, GovClass.RING4, "ring4", 1, 60_000_000_000, b"\x00\xffopaque")
    assert bus.submit(env)
    assert seen[0] is env  # the Glove relays the envelope ITSELF (INV-1)


# -- REQ-GV-02: authentication + integrity (CF-T-GOV-01) -------------------------


def test_bit_flip_in_transit_rejected_not_delivered():
    out: list[bytes] = []
    bus = _bus_with_endpoint(out)
    env = create_envelope(CONSENSUS_SK, GovClass.CONSENSUS, "diamond.consensus", 1, 60_000_000_000, b"vote:yes")
    flipped = bytes([env.payload[0] ^ 0x01]) + env.payload[1:]
    tampered = GovEnvelope(env.gov_class, env.sender, env.sender_seq, env.expires_ns,
                           env.auth_tag, flipped)
    assert not bus.submit(tampered)
    assert out == []
    assert ("diamond.consensus", str(GovReject.AUTH_FAILED)) in bus.rejected
    assert bus.rejected


def test_wrong_key_signature_rejected():
    out: list[bytes] = []
    bus = _bus_with_endpoint(out)
    # signed by a DIFFERENT endpoint key than the one registered
    forged = create_envelope(generate_signing_key(), GovClass.CONSENSUS,
                             "diamond.consensus", 1, 60_000_000_000, b"forged")
    assert not bus.submit(forged)
    assert out == []
    assert ("diamond.consensus", str(GovReject.AUTH_FAILED)) in bus.rejected


def test_forged_tag_and_unknown_sender_rejected():
    out: list[bytes] = []
    bus = _bus_with_endpoint(out)
    bad = GovEnvelope(GovClass.OVERRIDE, "diamond.consensus", 1, 9**18,
                      "ed25519:" + "0" * 128, b"forged")
    assert not bus.submit(bad)
    legacy = GovEnvelope(GovClass.OVERRIDE, "diamond.consensus", 1, 9**18,
                         "hmac-sha256:" + "0" * 64, b"forged")
    assert not bus.submit(legacy)  # wrong scheme: not an ed25519 tag
    stranger = create_envelope(CONSENSUS_SK, GovClass.PULSE, "unknown.sender", 1, 60_000_000_000, b"hb")
    assert not bus.submit(stranger)
    assert out == []


# -- REQ-GV-03: ordering + GOV_UNDELIVERED ----------------------------------------


def test_per_sender_ordering_and_gap_notice():
    out: list[bytes] = []
    notices = []
    bus = _bus_with_endpoint(out)
    bus.add_notice_sink(notices.append)
    assert bus.submit(create_envelope(CONSENSUS_SK, GovClass.CONSENSUS, "diamond.consensus", 1, 60_000_000_000, b"a"))
    # gap: seq 3 before seq 2 -> rejected + undeliverable notice (no silent loss)
    assert not bus.submit(create_envelope(CONSENSUS_SK, GovClass.CONSENSUS, "diamond.consensus", 3, 60_000_000_000, b"c"))
    assert notices and notices[0].reason == str(GovReject.OUT_OF_ORDER)
    assert notices[0].sender_seq == 3
    assert bus.submit(create_envelope(CONSENSUS_SK, GovClass.CONSENSUS, "diamond.consensus", 2, 60_000_000_000, b"b"))
    assert out == [b"a", b"b"]  # order preserved


# -- REQ-GV-07 / INV-4: the bus cannot originate governance (CF-T-GOV-04) ----------


def test_bus_holds_verification_only_material():
    """Structural INV-1/INV-4: no signing path exists on the Glove side."""
    import glove.governance.bus as busmod

    # the bus module exposes no signing function and no envelope constructor
    assert not hasattr(busmod, "compute_auth_tag")
    assert not hasattr(GovEnvelope, "create")
    bus = GovernanceBus()
    assert not hasattr(bus, "compute_auth_tag")
    # registered keys are exactly 32-byte ed25519 public keys
    bus.register_endpoint("ep", public_key_from_signing_key(CONSENSUS_SK), lambda env: None)
    assert all(len(k) == 32 for k in bus._verify_keys.values())
    # signing machinery lives strictly on the endpoint side
    import glove.governance.endpoint as ep

    assert callable(ep.compute_auth_tag) and callable(ep.create_envelope)


def test_glove_originates_zero_governance_envelopes():
    """CF-T-GOV-04: actively try to INDUCE the Glove to synthesize governance
    envelopes — fuzz the bus with malformed/rejected traffic, drive the
    override preemption path, the Pulse-loss degraded path, dead-man ticks,
    and a full hot-swap transfer — then assert that the ONLY envelope objects
    ever delivered to any endpoint are the exact objects this test submitted
    as an endpoint (identity, not equality), i.e. zero Glove-originated
    governance envelopes."""
    delivered: list[GovEnvelope] = []
    notices = []
    g = _live_glove()
    g.on_ack(lambda a: None)
    g.bus.register_endpoint("caregiver.console.07", public_key_from_signing_key(CAREGIVER_SK),
                            delivered.append)
    g.bus.register_endpoint("pulse.tether", public_key_from_signing_key(PULSE_SK), delivered.append)
    g.bus.add_notice_sink(notices.append)
    g.bus.configure_pulse_threshold(0.5)

    # 1. Fuzz with crafted/malformed inputs (bad tags, wrong classes, replays,
    #    unknown senders, out-of-order): all rejected, none delivered.
    for env in [
        GovEnvelope(GovClass.OVERRIDE, "caregiver.console.07", 1, 9**18, "bad", b"x"),
        GovEnvelope(GovClass.PULSE, "pulse.tether", 99, 9**18, "ed25519:" + "0" * 128, b"x"),
        GovEnvelope(GovClass.RING4, "nobody", 1, 9**18, "bad", b"x"),
        GovEnvelope(GovClass.POLICY, "caregiver.console.07", 0, 9**18, "bad", b"x"),
    ]:
        assert not g.bus.submit(env)
    assert delivered == []

    # 2. Drive the override preemption path with a valid endpoint envelope.
    g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                     twist=Twist((0.4, 0, 0), (0, 0, 0))))
    override = create_envelope(CAREGIVER_SK, GovClass.OVERRIDE, "caregiver.console.07",
                               1, 60_000_000_000, b"stop now")
    assert g.bus.submit(override)
    assert g.envelope.halted  # preemption fired (REQ-GV-04)
    g.envelope.clear_halt(governance_clearance=True)

    # 3. Drive Pulse traffic + pulse-loss degraded path and dead-man ticks.
    pulse = create_envelope(PULSE_SK, GovClass.PULSE, "pulse.tether", 1,
                            60_000_000_000, b"hb")
    assert g.bus.submit(pulse)
    g.tick()
    g.bus.check_pulse()

    # 4. Drive the transfer (hot-swap) path, incl. governance snapshot handling.
    result = g.transfer_to(MockHumanoidAdapter(), required_modalities=[])
    from glove import TransferState
    assert result.final_state in (TransferState.COMPLETED, TransferState.SUSPENDED,
                                  TransferState.ROLLED_BACK_RUNNING)

    # INV-4: every delivered envelope IS an endpoint-submitted object; the
    # Glove synthesized nothing (identity check — no copy, no re-sign).
    endpoint_submitted = [override, pulse]
    assert delivered == endpoint_submitted
    assert all(any(d is s for s in endpoint_submitted) for d in delivered)
    # GOV_UNDELIVERED notices are framing, not governance envelopes.
    assert all(not isinstance(n, GovEnvelope) for n in notices)


# -- REQ-GV-04: caregiver override preempts in-flight actions (CF-T-GOV-02) ---------


def test_override_preempts_in_flight_with_abort_cause():
    g = _live_glove()
    acks = []
    g.on_ack(acks.append)
    g.bus.register_endpoint("caregiver.console.07", public_key_from_signing_key(CAREGIVER_SK),
                            lambda env: None)
    ack = g.submit_action(LocomotionAction(mode=LocomotionMode.VELOCITY,
                                           twist=Twist((0.6, 0, 0), (0, 0, 0.2))))
    assert ack.status == "ACT_EXECUTING"
    env = create_envelope(CAREGIVER_SK, GovClass.OVERRIDE, "caregiver.console.07",
                          1, 60_000_000_000, b"stop now")
    assert g.bus.submit(env)
    # in-flight action preempted: ACT_ABORTED with GOV_OVERRIDE, halt asserted
    assert any(a.status == "ACT_ABORTED" and a.cause == "GOV_OVERRIDE" for a in acks)
    assert g.adapter.halts >= 1  # type: ignore[attr-defined]
    assert g.envelope.halted  # type: ignore[union-attr]
    preempted = g.audit.entries("GOV_OVERRIDE_PREEMPTED")
    assert preempted and preempted[0]["record"]["aborted"] == 1


# -- REQ-GV-05: Pulse Tether measured locally, fail closed (CF-T-GOV-03) -------------


def test_pulse_loss_enters_policy_degraded_mode():
    clock_t = [10**12]

    def clock() -> int:
        return clock_t[0]

    g = Glove(clock=clock)
    g.attach_adapter(MockMobileBaseAdapter())
    w = g.hello(BEING, ["1.0.0"]); g.accept(w)
    g.bus.register_endpoint("pulse.tether", public_key_from_signing_key(PULSE_SK), lambda env: None)
    g.bus.configure_pulse_threshold(0.5)  # policy-declared threshold (REQ-GV-08)
    assert g.bus.submit(create_envelope(PULSE_SK, GovClass.PULSE, "pulse.tether", 1,
                                        60_000_000_000, b"hb", now_ns=clock()))
    assert g.bus.check_pulse()  # within threshold
    clock_t[0] += 600_000_000  # 0.6 s silence: past threshold
    assert not g.bus.check_pulse()
    assert g.envelope.degraded is not None  # REQ-SE-06 degraded mode entered  # type: ignore[union-attr]
    # recovery only on re-acquisition + governance clearance
    assert not g.envelope.exit_degraded(governance_clearance=False)  # type: ignore[union-attr]
