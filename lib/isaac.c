// SPDX-License-Identifier: CC0-1.0
/*
 * ISAAC PRNG — Bob Jenkins reference implementation (public domain).
 * Adapted from Math::Random::ISAAC::XS (Jonathan Yu) for FRR.
 */

#include <zebra.h>
#include <string.h>

#include "isaac.h"

#define cut(a) ((a) & 0xffffffffu)
#define ind(mm, x) ((mm)[((x) >> 2) & (FRR_ISAAC_RANDSIZ - 1)])

#define rngstep(mix, a, b, mm, m, m2, r, x)                                   \
	do {                                                                   \
		uint32_t y;                                                    \
		(x) = *(m);                                                    \
		(a) = cut(((a) ^ (mix)) + *(m2)++);                            \
		*(m)++ = (y) = cut(ind((mm), (x)) + (a) + (b));                \
		*(r)++ = (b) = cut(ind((mm), (y) >> 8) + (x));                \
	} while (0)

#define mix(a, b, c, d, e, f, g, h)                                          \
	do {                                                                   \
		(a) ^= (b) << 11;                                              \
		(d) += (a);                                                    \
		(b) += (c);                                                    \
		(b) ^= (c) >> 2;                                               \
		(e) += (b);                                                    \
		(c) += (d);                                                    \
		(c) ^= (d) << 8;                                               \
		(f) += (c);                                                    \
		(d) += (e);                                                    \
		(d) ^= (e) >> 16;                                              \
		(g) += (d);                                                    \
		(e) += (f);                                                    \
		(e) ^= (f) << 10;                                              \
		(h) += (e);                                                    \
		(f) += (g);                                                    \
		(f) ^= (g) >> 4;                                               \
		(a) += (f);                                                    \
		(g) += (h);                                                    \
		(g) ^= (h) << 8;                                               \
		(b) += (g);                                                    \
		(h) += (a);                                                    \
		(h) ^= (a) >> 9;                                               \
		(c) += (h);                                                    \
		(a) += (b);                                                    \
	} while (0)

#define shuffle(a, b, mm, m, m2, r, x)                                       \
	do {                                                                   \
		rngstep((a) << 13, (a), (b), (mm), (m), (m2), (r), (x));       \
		rngstep((a) >> 6, (a), (b), (mm), (m), (m2), (r), (x));        \
		rngstep((a) << 2, (a), (b), (mm), (m), (m2), (r), (x));        \
		rngstep((a) >> 16, (a), (b), (mm), (m), (m2), (r), (x));       \
	} while (0)

void frr_isaac_generate(struct frr_isaac_ctx *ctx)
{
	uint32_t a, b, x, y, *m, *mm, *m2, *r, *mend;

	mm = ctx->randmem;
	r = ctx->randrsl;
	a = ctx->randa;
	b = cut(ctx->randb + (++ctx->randc));

	m = mm;
	mend = m2 = m + (FRR_ISAAC_RANDSIZ / 2);
	while (m < mend)
		shuffle(a, b, mm, m, m2, r, x);

	m2 = mm;
	while (m2 < mend)
		shuffle(a, b, mm, m, m2, r, x);

	ctx->randb = b;
	ctx->randa = a;
}

void frr_isaac_init(struct frr_isaac_ctx *ctx, const uint8_t *seed, size_t seed_len)
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t *m, *r;
	size_t i, copy_len;

	memset(ctx, 0, sizeof(*ctx));
	m = ctx->randmem;
	r = ctx->randrsl;

	if (seed && seed_len) {
		copy_len = seed_len;
		if (copy_len > sizeof(ctx->randrsl))
			copy_len = sizeof(ctx->randrsl);
		memcpy(ctx->randrsl, seed, copy_len);
	}

	a = b = c = d = e = f = g = h = 0x9e3779b9;

	for (i = 0; i < 4; i++)
		mix(a, b, c, d, e, f, g, h);

	for (i = 0; i < FRR_ISAAC_RANDSIZ; i += 8) {
		a += r[i];
		b += r[i + 1];
		c += r[i + 2];
		d += r[i + 3];
		e += r[i + 4];
		f += r[i + 5];
		g += r[i + 6];
		h += r[i + 7];
		mix(a, b, c, d, e, f, g, h);
		m[i] = a;
		m[i + 1] = b;
		m[i + 2] = c;
		m[i + 3] = d;
		m[i + 4] = e;
		m[i + 5] = f;
		m[i + 6] = g;
		m[i + 7] = h;
	}

	for (i = 0; i < FRR_ISAAC_RANDSIZ; i += 8) {
		a += m[i];
		b += m[i + 1];
		c += m[i + 2];
		d += m[i + 3];
		e += m[i + 4];
		f += m[i + 5];
		g += m[i + 6];
		h += m[i + 7];
		mix(a, b, c, d, e, f, g, h);
		m[i] = a;
		m[i + 1] = b;
		m[i + 2] = c;
		m[i + 3] = d;
		m[i + 4] = e;
		m[i + 5] = f;
		m[i + 6] = g;
		m[i + 7] = h;
	}

	frr_isaac_generate(ctx);
	ctx->randcnt = FRR_ISAAC_RANDSIZ;
}

uint32_t frr_isaac_next_uint32(struct frr_isaac_ctx *ctx)
{
	if (ctx->randcnt-- == 0) {
		frr_isaac_generate(ctx);
		ctx->randcnt = FRR_ISAAC_RANDSIZ - 1;
	}
	return ctx->randrsl[ctx->randcnt];
}
