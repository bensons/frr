// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD Meticulous Keyed ISAAC helpers (RFC 9986).
 */

#include <zebra.h>
#include <string.h>

#include "bfd_isaac.h"
#include "network.h"

void bfd_isaac_state_reset(struct bfd_isaac_state *st)
{
	memset(st, 0, sizeof(*st));
}

void bfd_isaac_build_seed_buffer(uint8_t *buf, size_t buf_len, uint32_t seed,
				 uint32_t your_discr, const uint8_t *secret_key,
				 size_t secret_key_len)
{
	size_t off = 0;
	uint32_t counter;

	if (!buf || buf_len == 0)
		return;

	memset(buf, 0, buf_len);

	if (secret_key_len > BFD_ISAAC_MAX_KEY_LEN)
		secret_key_len = BFD_ISAAC_MAX_KEY_LEN;

	for (counter = 0; counter <= 50 && off < buf_len; counter++) {
		uint8_t entry[BFD_ISAAC_MAX_KEY_LEN + 12];
		size_t entry_len = 8 + secret_key_len + 4;
		size_t copy_len = entry_len;
		uint32_t seed_n = htonl(seed);
		uint32_t ydisc_n = htonl(your_discr);
		uint32_t counter_n = htonl(counter);

		memcpy(entry, &seed_n, 4);
		memcpy(entry + 4, &ydisc_n, 4);
		memcpy(entry + 8, secret_key, secret_key_len);
		memcpy(entry + 8 + secret_key_len, &counter_n, 4);

		if (off + copy_len > buf_len)
			copy_len = buf_len - off;
		memcpy(buf + off, entry, copy_len);
		off += copy_len;
	}
}

static void bfd_isaac_fill_page(struct bfd_isaac_state *st, struct bfd_isaac_page *page)
{
	for (size_t i = 0; i < BFD_ISAAC_PAGE_SIZE; i++)
		page->values[i] = frr_isaac_next_uint32(&st->ctx);
}

static void bfd_isaac_seek_page(struct bfd_isaac_state *st, uint32_t seq_num)
{
	uint32_t delta;

	if (!st->key_known)
		return;

	if (seq_num >= st->auth_base)
		delta = seq_num - st->auth_base;
	else
		delta = (UINT32_MAX - st->auth_base) + seq_num + 1;

	if (delta >= BFD_ISAAC_PAGE_SIZE) {
		while (delta >= BFD_ISAAC_PAGE_SIZE) {
			if (st->next_page_ready) {
				st->page = st->next_page;
				st->next_page_ready = false;
			} else {
				bfd_isaac_fill_page(st, &st->page);
			}
			st->auth_base += BFD_ISAAC_PAGE_SIZE;
			if (seq_num >= st->auth_base)
				delta = seq_num - st->auth_base;
			else
				delta = (UINT32_MAX - st->auth_base) + seq_num + 1;
		}
	}

	st->auth_index = delta;
}

void bfd_isaac_init_xmit(struct bfd_isaac_state *st, uint32_t seed, uint32_t your_discr,
			 const uint8_t *secret_key, size_t secret_key_len,
			 uint32_t seq_base)
{
	uint8_t seed_buf[BFD_ISAAC_SEED_BUF_SIZE];

	bfd_isaac_state_reset(st);
	bfd_isaac_build_seed_buffer(seed_buf, sizeof(seed_buf), seed, your_discr,
				    secret_key, secret_key_len);
	frr_isaac_init(&st->ctx, seed_buf, sizeof(seed_buf));
	st->seed = seed;
	st->auth_base = seq_base;
	st->auth_index = 0;
	bfd_isaac_fill_page(st, &st->page);
	st->key_known = true;
}

bool bfd_isaac_init_recv(struct bfd_isaac_state *st, uint32_t seed, uint32_t your_discr,
			 const uint8_t *secret_key, size_t secret_key_len,
			 uint32_t seq_num, uint32_t auth_key)
{
	uint32_t got;

	bfd_isaac_init_xmit(st, seed, your_discr, secret_key, secret_key_len, seq_num);
	got = bfd_isaac_auth_key_for_seq(st, seq_num);
	return got == auth_key;
}

uint32_t bfd_isaac_auth_key_for_seq(struct bfd_isaac_state *st, uint32_t seq_num)
{
	bfd_isaac_seek_page(st, seq_num);
	return st->page.values[st->auth_index];
}

void bfd_isaac_prepare_next_page(struct bfd_isaac_state *st)
{
	if (!st->key_known || st->next_page_ready)
		return;
	bfd_isaac_fill_page(st, &st->next_page);
	st->next_page_ready = true;
}
