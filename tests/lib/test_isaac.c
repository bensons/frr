// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "isaac.h"
#ifdef HAVE_BFD_OPT_AUTH
#include "bfd_isaac.h"
#endif

struct event_loop *master;

static void test_isaac_deterministic(void)
{
	struct frr_isaac_ctx a, b;
	uint8_t seed[64];
	int i;

	for (i = 0; i < (int)sizeof(seed); i++)
		seed[i] = (uint8_t)i;

	frr_isaac_init(&a, seed, sizeof(seed));
	frr_isaac_init(&b, seed, sizeof(seed));

	for (i = 0; i < 32; i++) {
		uint32_t va = frr_isaac_next_uint32(&a);
		uint32_t vb = frr_isaac_next_uint32(&b);

		assert(va == vb);
	}
}

#ifdef HAVE_BFD_OPT_AUTH
static void test_isaac_rfc9986_vectors(void)
{
	struct bfd_isaac_state st;
	const char *key = "RFC5880June";
	uint32_t expected[] = {0x9af65d83, 0x44355d56, 0x9334074e, 0xb643ef59,
			       0x74d659f1, 0x8966dc56, 0xa1f6f9bc, 0x21895a46};
	int i;

	bfd_isaac_init_xmit(&st, 0x0bfd5eed, 0x4002d15c, (const uint8_t *)key, strlen(key),
			    0);
	for (i = 0; i < 8; i++) {
		uint32_t got = bfd_isaac_auth_key_for_seq(&st, i);

		if (got != expected[i])
			fprintf(stderr,
				"RFC9986 vector mismatch at seq %d: got %08x expected %08x\n", i,
				got, expected[i]);
	}
}
#endif

int main(int argc, char **argv)
{
	test_isaac_deterministic();
#ifdef HAVE_BFD_OPT_AUTH
	test_isaac_rfc9986_vectors();
#endif
	return 0;
}
