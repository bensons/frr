// SPDX-License-Identifier: CC0-1.0
/*
 * ISAAC PRNG — Bob Jenkins reference implementation (public domain).
 * Adapted from Math::Random::ISAAC::XS (Jonathan Yu) for FRR.
 */

#ifndef _FRR_ISAAC_H
#define _FRR_ISAAC_H

#include <stdint.h>

#define FRR_ISAAC_RANDSIZ 256

struct frr_isaac_ctx {
	uint32_t randcnt;
	uint32_t randrsl[FRR_ISAAC_RANDSIZ];
	uint32_t randmem[FRR_ISAAC_RANDSIZ];
	uint32_t randa;
	uint32_t randb;
	uint32_t randc;
};

void frr_isaac_init(struct frr_isaac_ctx *ctx, const uint8_t *seed, size_t seed_len);
void frr_isaac_generate(struct frr_isaac_ctx *ctx);
uint32_t frr_isaac_next_uint32(struct frr_isaac_ctx *ctx);

#endif /* _FRR_ISAAC_H */
