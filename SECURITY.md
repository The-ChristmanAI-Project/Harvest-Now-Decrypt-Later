# Security Policy

## What this is

`christman-crypto` is a **reference implementation** of a seven-tier
cryptographic stack, including a pure-Python NIST FIPS 203 (ML-KEM)
post-quantum implementation.

**Correct and auditable** — every algorithm is implemented faithfully
to its specification and is readable/reviewable by anyone.

**Not optimized for throughput** — the ML-KEM implementation is pure
Python. For high-throughput production systems (TLS termination,
millions of connections per second), use a compiled binding such as
[liboqs](https://github.com/open-quantum-safe/liboqs) or
[kyber-py](https://github.com/GiacomoPope/kyber-py) (which this
package will automatically use if installed).

For Riley Christman's forensic AI use case and most application-level
encryption, the performance is more than sufficient.

## Hybrid design philosophy

The PQ tier uses a **hybrid** design:
- ML-KEM (CRYSTALS-Kyber) for key encapsulation — quantum resistant
- XChaCha20-Poly1305 via libsodium for data encryption — classically
  fast and quantum resistant at 256-bit key size

**Secure as long as EITHER component remains unbroken.** This is the
architecture NIST recommends during the transition period.

## Reporting a vulnerability

If you find a security issue in this package, please open a GitHub
issue marked `[SECURITY]` or contact the author directly.

Do not publish exploit code before the maintainer has had a chance
to respond.

## Known limitations

- Tier 1 (Vigenère) is **not modern-secure**. It is included as a
  historical educational layer only. Do not use it for real secrets.
- Tier 4/5/6 (RSA) are **classically secure but quantum-vulnerable**.
  Shor's algorithm on a sufficiently large quantum computer will break
  RSA. Use the PQ tier for long-term confidentiality.
- Steganography (Tier 7) hides the *existence* of a message but does
  not encrypt it. Always encrypt before hiding.
