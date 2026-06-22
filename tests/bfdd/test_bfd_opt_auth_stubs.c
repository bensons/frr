// SPDX-License-Identifier: GPL-2.0-or-later

#include "bfd.h"

void ptm_bfd_notify(struct bfd_session *bs, int state)
{
	(void)bs;
	(void)state;
}

void ptm_bfd_snd(struct bfd_session *bfd, int fbit)
{
	(void)bfd;
	(void)fbit;
}

void ptm_bfd_sess_dn(struct bfd_session *bfd, uint8_t diag, bool notify_admin_down)
{
	(void)bfd;
	(void)diag;
	(void)notify_admin_down;
}

const char *bs_to_string(struct bfd_session *bs)
{
	(void)bs;
	return "test-session";
}

void bfd_set_polling(struct bfd_session *bs)
{
	(void)bs;
}

bool bfd_isaac_init_recv(struct bfd_isaac_state *st, uint32_t seed, uint32_t your_discr,
			 const uint8_t *secret_key, size_t secret_key_len,
			 uint32_t seq_num, uint32_t auth_key)
{
	(void)st;
	(void)seed;
	(void)your_discr;
	(void)secret_key;
	(void)secret_key_len;
	(void)seq_num;
	(void)auth_key;
	return false;
}

void bfd_isaac_init_xmit(struct bfd_isaac_state *st, uint32_t seed, uint32_t your_discr,
			 const uint8_t *secret_key, size_t secret_key_len,
			 uint32_t seq_base)
{
	(void)st;
	(void)seed;
	(void)your_discr;
	(void)secret_key;
	(void)secret_key_len;
	(void)seq_base;
}

uint32_t bfd_isaac_auth_key_for_seq(struct bfd_isaac_state *st, uint32_t seq_num)
{
	(void)st;
	(void)seq_num;
	return 0;
}

void bfd_isaac_prepare_next_page(struct bfd_isaac_state *st)
{
	(void)st;
}

void bfd_isaac_state_reset(struct bfd_isaac_state *st)
{
	(void)st;
}
