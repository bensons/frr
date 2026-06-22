// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 9985 / RFC 9986 optimized BFD authentication helpers.
 */

#ifndef _BFDD_BFD_OPT_AUTH_H
#define _BFDD_BFD_OPT_AUTH_H

#include "bfd.h"

#ifdef HAVE_BFD_OPT_AUTH

struct json_object;

bool bfd_opt_auth_enabled(const struct bfd_session *bs);
void bfd_opt_auth_config_init(bool *optimized, uint32_t *reauth_interval);
void bfd_opt_auth_runtime_reset(struct bfd_session *bs);
void bfd_opt_auth_session_apply(struct bfd_session *bs);
bool bfd_is_significant_change(const struct bfd_session *bs, const struct bfd_pkt *cp,
			       bool outgoing, int fbit);
enum bfd_opt_auth_mode bfd_opt_auth_select_tx_mode(struct bfd_session *bs, int fbit);
void bfd_opt_auth_on_session_up(struct bfd_session *bs);
void bfd_opt_auth_on_session_down(struct bfd_session *bs);
void bfd_opt_auth_on_poll_final(struct bfd_session *bs, bool used_mci);
void bfd_opt_auth_bootstrap_timer(struct event *t);
void bfd_opt_auth_reauth_timer(struct event *t);
void bfd_opt_auth_reauth_timeout(struct event *t);
bool bfd_opt_auth_check_sequence(struct bfd_session *bs, uint32_t received_seq,
				 bool meticulous);
bool bfd_opt_auth_validate_rx(struct bfd_session *bs, const struct bfd_pkt *cp,
				const uint8_t *auth_section, uint8_t auth_len,
				struct key *key);
bool bfd_opt_auth_build_tx(struct bfd_session *bs, struct key *key,
			   enum bfd_auth_type auth_type, enum bfd_opt_auth_mode mode,
			   unsigned char *auth_payload_ptr, uint8_t *auth_section_len,
			   unsigned char *send_buffer, size_t packet_len, int fbit);
void bfd_opt_auth_stats_show(struct bfd_session *bs, struct vty *vty, struct json_object *jo);

#endif /* HAVE_BFD_OPT_AUTH */

#endif /* _BFDD_BFD_OPT_AUTH_H */
