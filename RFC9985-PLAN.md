# RFC 9985 Optimized BFD Authentication — Implementation Plan

This document maps [RFC 9985](https://www.rfc-editor.org/rfc/rfc9985) optimized BFD authentication onto FRR `bfdd`, including the [RFC 9986](https://www.rfc-editor.org/rfc/rfc9986) Meticulous Keyed ISAAC LCI mechanism.

See the attached implementation plan for full research, normative reference analysis, phased roadmap, and file-level change list.

## Status

Experimental feature gated by `--enable-bfd-opt-auth` (off by default).

## Key RFC mechanisms

- **MCI** (More Computationally Intensive): HMAC-MD5 or HMAC-SHA-1 for significant changes
- **LCI** (Less Computationally Intensive): Meticulous Keyed ISAAC for steady-state Up packets
- Auth types **7** (Optimized MD5 Meticulous Keyed ISAAC) and **8** (Optimized SHA-1 Meticulous Keyed ISAAC)
- MCI bootstrap for ≥ Detection Time after Up before LCI
- Periodic MCI reauth via Poll sequences (`reauth-interval`, default 60s)

## Implementation location

| Component | Path |
|-----------|------|
| ISAAC PRNG | `lib/isaac.c`, `lib/isaac.h` |
| BFD ISAAC wrapper | `lib/bfd_isaac.c`, `lib/bfd_isaac.h` |
| Opt auth control plane | `bfdd/bfd_opt_auth.c`, `bfdd/bfd_opt_auth.h` |
| Packet TX/RX | `bfdd/bfd_packet.c` |
| Session lifecycle | `bfdd/bfd.c` |

## Normative references (RFC 9985 §11.1)

RFC 2119, RFC 8174, RFC 5880, RFC 3688, RFC 6020, RFC 7950, RFC 8341, RFC 8349, RFC 9314

RFC 9986 (informative in RFC 9985, functionally required for LCI): RFC 5880, RFC 8177, ISAAC (Jenkins)

## Warning

Per RFC 9985 Appendix B, optimized authentication is Experimental and implementations should not be considered RFC 5880 compliant when enabled.
