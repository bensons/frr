// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD Meticulous Keyed ISAAC helpers (RFC 9986).
 */

#ifndef _FRR_BFD_ISAAC_H
#define _FRR_BFD_ISAAC_H

#include <stdint.h>

#include "isaac.h"

#define BFD_ISAAC_PAGE_SIZE FRR_ISAAC_RANDSIZ
#define BFD_ISAAC_SEED_BUF_SIZE (FRR_ISAAC_RANDSIZ * 4)
#define BFD_ISAAC_MAX_KEY_LEN 128

struct bfd_isaac_page {
	uint32_t values[BFD_ISAAC_PAGE_SIZE];
};

struct bfd_isaac_state {
	struct frr_isaac_ctx ctx;
	struct bfd_isaac_page page;
	struct bfd_isaac_page next_page;
	bool next_page_ready;
	uint32_t auth_base;
	uint8_t auth_index;
	uint32_t seed;
	bool key_known;
};

void bfd_isaac_state_reset(struct bfd_isaac_state *st);
void bfd_isaac_build_seed_buffer(uint8_t *buf, size_t buf_len, uint32_t seed,
				 uint32_t your_discr, const uint8_t *secret_key,
				 size_t secret_key_len);
void bfd_isaac_init_xmit(struct bfd_isaac_state *st, uint32_t seed, uint32_t your_discr,
			 const uint8_t *secret_key, size_t secret_key_len,
			 uint32_t seq_base);
bool bfd_isaac_init_recv(struct bfd_isaac_state *st, uint32_t seed, uint32_t your_discr,
			 const uint8_t *secret_key, size_t secret_key_len,
			 uint32_t seq_num, uint32_t auth_key);
uint32_t bfd_isaac_auth_key_for_seq(struct bfd_isaac_state *st, uint32_t seq_num);
void bfd_isaac_prepare_next_page(struct bfd_isaac_state *st);

#endif /* _FRR_BFD_ISAAC_H */
