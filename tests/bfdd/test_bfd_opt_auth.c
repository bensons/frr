// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "bfd.h"
#include "bfd_opt_auth.h"

struct event_loop *master;

static struct bfd_session test_bs;

static void test_significant_change(void)
{
	struct bfd_pkt cp = {};
	uint8_t flags = 0;

	memset(&test_bs, 0, sizeof(test_bs));
	test_bs.ses_state = PTM_BFD_UP;
	test_bs.detect_mult = 3;
	test_bs.demand_mode = 0;

	BFD_SETSTATE(flags, PTM_BFD_UP);
	cp.flags = flags;
	cp.detect_mult = 3;

	assert(bfd_is_significant_change(&test_bs, &cp, false, 0) == false);

	BFD_SETPBIT(cp.flags, 1);
	assert(bfd_is_significant_change(&test_bs, &cp, false, 0) == true);
}

static void test_opt_auth_sequence_window(void)
{
	memset(&test_bs, 0, sizeof(test_bs));
	test_bs.detect_mult = 3;
	test_bs.opt_auth.enabled = true;

	assert(bfd_opt_auth_check_sequence(&test_bs, 10, true) == true);
	assert(bfd_opt_auth_check_sequence(&test_bs, 11, true) == true);
	assert(bfd_opt_auth_check_sequence(&test_bs, 10, true) == false);
	assert(bfd_opt_auth_check_sequence(&test_bs, 20, true) == true);
	assert(bfd_opt_auth_check_sequence(&test_bs, 30, true) == false);
}

int main(int argc, char **argv)
{
	test_significant_change();
	test_opt_auth_sequence_window();
	return 0;
}
