"""Continuity packet — GLV-SPEC-1.0.0 §7.1 (normative).

A persistent, versioned artifact preserving identity, short-term context
handle, governance snapshot, calibration artifacts, and schema versions
across sessions and bodies (REQ-ST-01). Encrypted at rest with client-held
keys, integrity-signed, and hash-chained across revisions so tampering or
rollback to stale state is detectable (REQ-ST-02).

REQ-ST-03: the Glove MUST NOT read or interpret `short_term_context_ref`
content or `governance_snapshot` content; it stores, transports, and
re-presents them. Signatures and hashes are verified as FRAMING only.

Cryptography note: at-rest sealing routes through a small provider
interface (:func:`get_seal_provider`). When the family crypto stack
(`christman_crypto`) is importable, sealing uses AES-256-GCM
(Tier 2, authenticated encryption) via :mod:`glove.family_crypto`;
otherwise it falls back to the inspectable stdlib SHA-256 counter-mode
keystream. The packet STRUCTURE (fields, hash chain, verification flow)
is the normative part and does not change across providers — family-sealed
blobs carry a magic prefix so `open()` routes them back correctly.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace
from typing import Any, Protocol, runtime_checkable

from .. import family_crypto as _fc
from ..contract.envelope import CONTRACT_VERSION, PACKET_VERSION, monotonic_ns, parse_semver

GENESIS_HASH = "0" * 64  # hash-chain genesis (REQ-ST-02)


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _keystream_xor(data: bytes, key: bytes) -> bytes:
    """Skeleton-grade symmetric cipher: SHA-256(key || counter) keystream.
    Deterministic and inspectable; NOT production crypto. Retained as the
    automatic fallback when the family crypto stack is not installed."""
    out = bytearray(len(data))
    counter = 0
    offset = 0
    while offset < len(data):
        block = hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        take = min(32, len(data) - offset)
        for i in range(take):
            out[offset + i] = data[offset + i] ^ block[i]
        offset += take
        counter += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# Seal-provider interface (family crypto upgrade path, REQ-ST-02/REQ-GV-10)
# ---------------------------------------------------------------------------


@runtime_checkable
class SealProvider(Protocol):
    """Symmetric at-rest protection for serialized continuity packets.

    Implementations must be self-describing (see ``_fc.AESGCM_SEAL_MAGIC``)
    or must be the stdlib fallback, so ``ContinuityPacket.open`` can route a
    stored blob without any schema change.
    """

    name: str

    def seal(self, data: bytes, client_key: bytes) -> bytes: ...
    def open(self, blob: bytes, client_key: bytes) -> bytes: ...


class _StdlibKeystreamProvider:
    """Fallback provider: SHA-256 counter-mode keystream XOR (no auth tag).
    Kept for zero-dependency deployments; superseded by AES-256-GCM whenever
    the family crypto stack is importable."""

    name = "stdlib-sha256-keystream-xor (fallback)"

    def seal(self, data: bytes, client_key: bytes) -> bytes:
        return _keystream_xor(data, client_key)

    def open(self, blob: bytes, client_key: bytes) -> bytes:
        return _keystream_xor(blob, client_key)


_STDLIB_PROVIDER = _StdlibKeystreamProvider()
_provider_override: SealProvider | None = None


def set_seal_provider(provider: SealProvider | None) -> None:
    """Explicitly pin a seal provider (deployment integration / tests).
    ``None`` restores automatic selection: family AES-256-GCM when
    importable, stdlib keystream otherwise."""
    global _provider_override
    _provider_override = provider


def get_seal_provider() -> SealProvider:
    """Resolve the active seal provider without forking the packet schema."""
    if _provider_override is not None:
        return _provider_override
    family = _fc.get_aesgcm_sealer()
    if family is not None:
        return family
    return _STDLIB_PROVIDER


@dataclass(slots=True, frozen=True)
class SessionRecord:
    session_id: str
    body_class: str
    close_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"session_id": self.session_id, "body_class": self.body_class,
                "close_reason": self.close_reason}


@dataclass(slots=True, frozen=True)
class CalibrationArtifact:
    """Per-body-class calibration results keyed by body class + serial (REQ-ST-01)."""

    body_class: str
    body_serial: str
    artifacts: dict[str, Any]  # frame transforms, mapping constants

    def to_dict(self) -> dict[str, Any]:
        return {"body_class": self.body_class, "body_serial": self.body_serial,
                "artifacts": self.artifacts}


@dataclass(slots=True, frozen=True)
class ContinuityPacket:
    """REQ-ST-01 schema. `short_term_context_ref` and `governance_snapshot`
    are OPAQUE to the Glove (REQ-ST-03)."""

    packet_version: str
    being_id: str
    identity_assertion: str                       # signed object (hex tag)
    session_history: tuple[SessionRecord, ...] = ()
    short_term_context_ref: dict[str, Any] = field(default_factory=dict)  # opaque
    governance_snapshot: bytes = b""              # opaque, governance-signed
    calibration_artifacts: tuple[CalibrationArtifact, ...] = ()
    schema_versions: dict[str, str] = field(default_factory=dict)  # contract/descriptor/envelope hashes
    created_ns: int = 0
    updated_ns: int = 0
    revision: int = 0
    prev_hash: str = GENESIS_HASH                 # hash chain over revisions (REQ-ST-02)
    integrity: str = ""                           # being-key signature over all fields

    # -- canonical body / hashing -------------------------------------------

    def body_dict(self) -> dict[str, Any]:
        return {
            "packet_version": self.packet_version,
            "being_id": self.being_id,
            "identity_assertion": self.identity_assertion,
            "session_history": [s.to_dict() for s in self.session_history],
            "short_term_context_ref": self.short_term_context_ref,
            "governance_snapshot_hex": self.governance_snapshot.hex(),
            "calibration_artifacts": [c.to_dict() for c in self.calibration_artifacts],
            "schema_versions": self.schema_versions,
            "created_ns": self.created_ns,
            "updated_ns": self.updated_ns,
            "revision": self.revision,
            "prev_hash": self.prev_hash,
        }

    def content_hash(self) -> str:
        return hashlib.sha256(_canonical(self.body_dict())).hexdigest()

    def sign(self, being_key: bytes) -> "ContinuityPacket":
        """Being-key integrity signature over ALL fields (REQ-ST-01/02)."""
        tag = hmac.new(being_key, _canonical(self.body_dict()), hashlib.sha256).hexdigest()
        return replace(self, integrity=f"hmac-sha256:{tag}")

    def verify_integrity(self, being_key: bytes) -> bool:
        """Framing-level verification only (REQ-ST-03): detects bit-flips and
        stale/partial revisions (CF-T-ST-03). Content is never interpreted."""
        expected = "hmac-sha256:" + hmac.new(
            being_key, _canonical(self.body_dict()), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.integrity, expected)

    # -- revisions ------------------------------------------------------------

    def next_revision(
        self,
        *,
        being_key: bytes,
        session_record: SessionRecord | None = None,
        calibration: CalibrationArtifact | None = None,
        schema_versions: dict[str, str] | None = None,
        short_term_context_ref: dict[str, Any] | None = None,
        governance_snapshot: bytes | None = None,
    ) -> "ContinuityPacket":
        """Produce the next hash-chained, re-signed revision. A packet is the
        single source of truth until a successful RESUME produces a new
        revision (REQ-ST-06) — it is never partially applied or destructively
        consumed; every revision is a new immutable object."""
        history = self.session_history + ((session_record,) if session_record else ())
        calib = self.calibration_artifacts + ((calibration,) if calibration else ())
        nxt = replace(
            self,
            session_history=history,
            calibration_artifacts=calib,
            schema_versions=schema_versions or dict(self.schema_versions),
            short_term_context_ref=short_term_context_ref or dict(self.short_term_context_ref),
            governance_snapshot=governance_snapshot if governance_snapshot is not None else self.governance_snapshot,
            updated_ns=monotonic_ns(),
            revision=self.revision + 1,
            prev_hash=self.content_hash(),
        )
        return nxt.sign(being_key)

    def check_chain(self, previous: "ContinuityPacket | None") -> bool:
        """Hash-chain continuity check (REQ-ST-02): a stale or forked
        revision fails here."""
        if previous is None:
            return self.revision == 0 and self.prev_hash == GENESIS_HASH
        return self.revision == previous.revision + 1 and self.prev_hash == previous.content_hash()

    # -- at-rest protection (REQ-ST-02 / REQ-GV-10) ---------------------------

    def seal(self, client_key: bytes) -> bytes:
        """Encrypt at rest with a client-held key. Key custody MUST NOT pass
        through the adapter or any vendor component (REQ-GV-10).

        Routes through :func:`get_seal_provider`: AES-256-GCM (family Tier 2)
        when `christman_crypto` is importable, stdlib keystream otherwise."""
        payload = _canonical(self.body_dict() | {"integrity": self.integrity})
        return get_seal_provider().seal(payload, client_key)

    @classmethod
    def open(cls, blob: bytes, client_key: bytes) -> "ContinuityPacket":
        # Family-sealed blobs are self-describing via the magic prefix.
        if blob.startswith(_fc.AESGCM_SEAL_MAGIC):
            sealer = _fc.get_aesgcm_sealer()
            if sealer is None:
                raise RuntimeError(
                    "continuity packet was sealed with the family crypto stack "
                    "(AES-256-GCM) but christman_crypto is not importable here"
                )
            d = json.loads(sealer.open(blob, client_key).decode("utf-8"))
        else:
            d = json.loads(_keystream_xor(blob, client_key).decode("utf-8"))
        return cls.from_dict(d)

    def to_dict(self) -> dict[str, Any]:
        return self.body_dict() | {"integrity": self.integrity}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ContinuityPacket":
        parse_semver(d["packet_version"])
        return cls(
            packet_version=d["packet_version"],
            being_id=d["being_id"],
            identity_assertion=d["identity_assertion"],
            session_history=tuple(SessionRecord(**s) for s in d.get("session_history", [])),
            short_term_context_ref=dict(d.get("short_term_context_ref", {})),
            governance_snapshot=bytes.fromhex(d.get("governance_snapshot_hex", "")),
            calibration_artifacts=tuple(CalibrationArtifact(**c) for c in d.get("calibration_artifacts", [])),
            schema_versions=dict(d.get("schema_versions", {})),
            created_ns=int(d.get("created_ns", 0)),
            updated_ns=int(d.get("updated_ns", 0)),
            revision=int(d.get("revision", 0)),
            prev_hash=d.get("prev_hash", GENESIS_HASH),
            integrity=d.get("integrity", ""),
        )

    @classmethod
    def genesis(
        cls,
        *,
        being_id: str,
        being_key: bytes,
        identity_assertion: str,
        short_term_context_ref: dict[str, Any] | None = None,
        governance_snapshot: bytes = b"",
    ) -> "ContinuityPacket":
        now = monotonic_ns()
        pkt = cls(
            packet_version=PACKET_VERSION,
            being_id=being_id,
            identity_assertion=identity_assertion,
            short_term_context_ref=short_term_context_ref or {},
            governance_snapshot=governance_snapshot,
            schema_versions={"contract_version": CONTRACT_VERSION},
            created_ns=now,
            updated_ns=now,
        )
        return pkt.sign(being_key)
