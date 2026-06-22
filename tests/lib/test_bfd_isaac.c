// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "bfd_isaac.h"

struct event_loop *master;

static void test_bfd_isaac_roundtrip(void)
{
	struct bfd_isaac_state xmit, recv;
	const char *key = "test-secret-key";
	uint32_t seed = 0x12345678;
	uint32_t ydisc = 0x87654321;
	uint32_t seq = 42;
	uint32_t auth_key;

	bfd_isaac_init_xmit(&xmit, seed, ydisc, (const uint8_t *)key, strlen(key), seq);
	auth_key = bfd_isaac_auth_key_for_seq(&xmit, seq);
	assert(bfd_isaac_init_recv(&recv, seed, ydisc, (const uint8_t *)key, strlen(key), seq,
				     auth_key));
	assert(bfd_isaac_auth_key_for_seq(&recv, seq + 1) ==
	       bfd_isaac_auth_key_for_seq(&xmit, seq + 1));
}

static void test_bfd_isaac_page_seek(void)
{
	struct bfd_isaac_state st;
	const char *key = "page-test";
	uint32_t base;

	bfd_isaac_init_xmit(&st, 0xdeadbeef, 0x01020304, (const uint8_t *)key, strlen(key), 0);
	base = bfd_isaac_auth_key_for_seq(&st, 0);
	assert(base == bfd_isaac_auth_key_for_seq(&st, 0));
	assert(bfd_isaac_auth_key_for_seq(&st, 255) ==
	       bfd_isaac_auth_key_for_seq(&st, 255));
	assert(bfd_isaac_auth_key_for_seq(&st, 256) !=
	       bfd_isaac_auth_key_for_seq(&st, 0));
}

int main(int argc, char **argv)
{
	test_bfd_isaac_roundtrip();
	test_bfd_isaac_page_seek();
	return 0;
}
