// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 9985 / RFC 9986 optimized BFD authentication helpers.
 */

#include <zebra.h>

#include "bfd.h"
#include "bfd_opt_auth.h"
#include "bfd_trace.h"

#ifdef HAVE_BFD_OPT_AUTH

#include "lib/json.h"

#ifdef CRYPTO_OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#endif

#include "lib/keychain.h"
#include "lib/monotime.h"
#include "network.h"
#include "frrevent.h"

static bool bfd_opt_auth_keychain_is_optimized(const struct keychain *kc)
{
	struct listnode *node;
	struct key *key;

	if (!kc)
		return false;

	for (ALL_LIST_ELEMENTS_RO(kc->key, node, key)) {
		if (key->hash_algo == KEYCHAIN_ALGO_OPT_MD5_ISAAC ||
		    key->hash_algo == KEYCHAIN_ALGO_OPT_SHA1_ISAAC)
			return true;
	}
	return false;
}

void bfd_opt_auth_config_init(bool *optimized, uint32_t *reauth_interval)
{
	if (optimized)
		*optimized = false;
	if (reauth_interval)
		*reauth_interval = BFD_OPT_AUTH_DEFAULT_REAUTH_INTERVAL;
}

bool bfd_opt_auth_enabled(const struct bfd_session *bs)
{
	if (!bs)
		return false;
	return bs->opt_auth.enabled;
}

void bfd_opt_auth_runtime_reset(struct bfd_session *bs)
{
	if (!bs)
		return;

	event_cancel(&bs->opt_auth.bootstrap_ev);
	event_cancel(&bs->opt_auth.reauth_ev);
	event_cancel(&bs->opt_auth.reauth_timeout_ev);

	bfd_isaac_state_reset(&bs->opt_auth.xmit_isaac);
	bfd_isaac_state_reset(&bs->opt_auth.recv_isaac);

	memset(&bs->opt_auth, 0, sizeof(bs->opt_auth));
	bs->opt_auth.tx_mode = BFD_OPT_AUTH_TX_MCI;
}

void bfd_opt_auth_session_apply(struct bfd_session *bs)
{
	bool optimized = bs->peer_profile.auth_config.optimized;

	if (!optimized && bs->profile)
		optimized = bs->profile->auth_config.optimized;

	bfd_opt_auth_runtime_reset(bs);

	if (!optimized || !bs->kc || !bfd_opt_auth_keychain_is_optimized(bs->kc))
		return;

	bs->opt_auth.enabled = true;
	bs->opt_auth.tx_mode = BFD_OPT_AUTH_TX_MCI;
	bs->opt_auth.reauth_interval = bs->peer_profile.auth_config.reauth_interval;
	if (!bs->opt_auth.reauth_interval && bs->profile)
		bs->opt_auth.reauth_interval = bs->profile->auth_config.reauth_interval;
	if (!bs->opt_auth.reauth_interval)
		bs->opt_auth.reauth_interval = BFD_OPT_AUTH_DEFAULT_REAUTH_INTERVAL;
	bs->auth_meticulous = true;
	bs->auth_seq_num_update_modulo = AUTH_SEQ_NUM_MODULO_METICULOUS;
}

bool bfd_is_significant_change(const struct bfd_session *bs, const struct bfd_pkt *cp,
			       bool outgoing, int fbit)
{
	uint8_t state = outgoing ? bs->ses_state : BFD_GETSTATE(cp->flags);

	if (state != PTM_BFD_UP)
		return true;

	if (outgoing) {
		if (fbit || bs->polling)
			return true;
	} else {
		if (BFD_GETFBIT(cp->flags) || BFD_GETPBIT(cp->flags))
			return true;
	}

	if (BFD_GETDEMANDBIT(cp->flags) != bs->demand_mode)
		return true;

	if (!outgoing && cp->detect_mult != bs->detect_mult)
		return true;

	return false;
}

enum bfd_opt_auth_mode bfd_opt_auth_select_tx_mode(struct bfd_session *bs, int fbit)
{
	if (!bfd_opt_auth_enabled(bs))
		return BFD_OPT_AUTH_TX_MCI;

	if (bs->opt_auth.force_mci || bs->ses_state != PTM_BFD_UP)
		return BFD_OPT_AUTH_TX_MCI;

	if (bfd_is_significant_change(bs, NULL, true, fbit))
		return BFD_OPT_AUTH_TX_MCI;

	if (bs->polling || fbit)
		return BFD_OPT_AUTH_TX_MCI;

	if (bs->opt_auth.tx_mode == BFD_OPT_AUTH_TX_LCI && bs->opt_auth.lci_ready)
		return BFD_OPT_AUTH_TX_LCI;

	return BFD_OPT_AUTH_TX_MCI;
}

static void bfd_opt_auth_schedule_reauth(struct bfd_session *bs)
{
	uint32_t jitter;
	struct timeval tv;

	if (!bs->opt_auth.enabled || !bs->opt_auth.lci_ready ||
	    bs->opt_auth.reauth_interval == 0)
		return;

	event_cancel(&bs->opt_auth.reauth_ev);

	jitter = frr_weak_random() % (bs->opt_auth.reauth_interval / 4 + 1);
	tv.tv_sec = bs->opt_auth.reauth_interval + jitter;
	tv.tv_usec = 0;

	event_add_timer_tv(master, bfd_opt_auth_reauth_timer, bs, &tv,
			   &bs->opt_auth.reauth_ev);
}

void bfd_opt_auth_on_session_up(struct bfd_session *bs)
{
	struct timeval tv;

	if (!bfd_opt_auth_enabled(bs))
		return;

	bs->opt_auth.tx_mode = BFD_OPT_AUTH_TX_MCI;
	bs->opt_auth.lci_ready = false;
	bs->opt_auth.client_notified_up = false;
	bs->opt_auth.force_mci = false;
	bs->opt_auth.xmit_seed = (uint32_t)frr_weak_random();
	bfd_isaac_state_reset(&bs->opt_auth.xmit_isaac);
	bfd_isaac_state_reset(&bs->opt_auth.recv_isaac);

	tv.tv_sec = bs->detect_TO / 1000000;
	tv.tv_usec = bs->detect_TO % 1000000;
	if (tv.tv_sec == 0 && tv.tv_usec == 0) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
	}

	event_cancel(&bs->opt_auth.bootstrap_ev);
	event_add_timer_tv(master, bfd_opt_auth_bootstrap_timer, bs, &tv,
			   &bs->opt_auth.bootstrap_ev);
}

void bfd_opt_auth_on_session_down(struct bfd_session *bs)
{
	bool optimized;
	uint32_t reauth_interval;

	if (!bfd_opt_auth_enabled(bs))
		return;

	optimized = bs->opt_auth.enabled;
	reauth_interval = bs->opt_auth.reauth_interval;
	bfd_opt_auth_runtime_reset(bs);
	bs->opt_auth.enabled = optimized;
	bs->opt_auth.reauth_interval = reauth_interval;
	bs->opt_auth.tx_mode = BFD_OPT_AUTH_TX_MCI;
}

void bfd_opt_auth_bootstrap_timer(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	if (!bfd_opt_auth_enabled(bs) || bs->ses_state != PTM_BFD_UP)
		return;

	bs->opt_auth.tx_mode = BFD_OPT_AUTH_TX_LCI;
	ptm_bfd_snd(bs, 0);
}

void bfd_opt_auth_reauth_timer(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);
	struct timeval tv;

	if (!bfd_opt_auth_enabled(bs) || bs->ses_state != PTM_BFD_UP ||
	    bs->opt_auth.tx_mode != BFD_OPT_AUTH_TX_LCI)
		return;

	bs->opt_auth.force_mci = true;
	bs->opt_auth.reauth_poll_pending = true;
	bfd_set_polling(bs);
	ptm_bfd_snd(bs, 0);

	tv.tv_sec = (2 * bs->detect_TO) / 1000000;
	tv.tv_usec = (2 * bs->detect_TO) % 1000000;
	if (tv.tv_sec == 0 && tv.tv_usec == 0) {
		tv.tv_sec = 2;
		tv.tv_usec = 0;
	}

	event_cancel(&bs->opt_auth.reauth_timeout_ev);
	event_add_timer_tv(master, bfd_opt_auth_reauth_timeout, bs, &tv,
			   &bs->opt_auth.reauth_timeout_ev);
	bfd_opt_auth_schedule_reauth(bs);
}

void bfd_opt_auth_reauth_timeout(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	if (!bfd_opt_auth_enabled(bs) || !bs->opt_auth.reauth_poll_pending)
		return;

	zlog_warn("BFD optimized auth: MCI reauth timeout on session %s",
		  bs_to_string(bs));
	ptm_bfd_sess_dn(bs, BD_CONTROL_EXPIRED, false);
}

void bfd_opt_auth_on_poll_final(struct bfd_session *bs, bool used_mci)
{
	if (!bfd_opt_auth_enabled(bs))
		return;

	if (used_mci && bs->opt_auth.reauth_poll_pending) {
		bs->opt_auth.reauth_poll_pending = false;
		bs->opt_auth.force_mci = false;
		event_cancel(&bs->opt_auth.reauth_timeout_ev);
		if (bs->ses_state == PTM_BFD_UP)
			bs->opt_auth.tx_mode = BFD_OPT_AUTH_TX_LCI;
	}
}

bool bfd_opt_auth_check_sequence(struct bfd_session *bs, uint32_t received_seq,
				   bool meticulous)
{
	uint32_t lower, upper, window;

	if (!bs->opt_auth.auth_seq_known) {
		bs->opt_auth.auth_seq_known = true;
		bs->auth_last_rx_seq_num = received_seq;
		return true;
	}

	if (meticulous) {
		window = (uint32_t)bs->detect_mult * 3;
		if (received_seq <= bs->auth_last_rx_seq_num)
			return false;
		lower = bs->auth_last_rx_seq_num + 1;
		if (UINT32_MAX - bs->auth_last_rx_seq_num < window)
			upper = UINT32_MAX;
		else
			upper = bs->auth_last_rx_seq_num + window;
		if (received_seq < lower || received_seq > upper)
			return false;
		bs->auth_last_rx_seq_num = received_seq;
		return true;
	}

	if (received_seq < bs->auth_last_rx_seq_num)
		return false;
	if ((received_seq % bs->auth_seq_num_update_modulo) == 0)
		bs->auth_last_rx_seq_num = received_seq;
	return true;
}

#ifdef CRYPTO_OPENSSL
static bool bfd_opt_auth_verify_hmac(const struct bfd_pkt *cp, const uint8_t *auth_section,
				       uint8_t auth_len, struct key *key,
				       enum keychain_hash_algo algo, size_t digest_len)
{
	uint32_t received_seq_num;
	unsigned int computed_len;
	unsigned char computed_digest[KEYCHAIN_MAX_HASH_SIZE];
	unsigned char msgbuf[BFD_PACKET_SIZE];
	const EVP_MD *md_alg = (algo == KEYCHAIN_ALGO_OPT_MD5_ISAAC ||
				algo == KEYCHAIN_ALGO_MD5)
				       ? EVP_md5()
				       : EVP_sha1();

	memcpy(&received_seq_num, auth_section + 4, sizeof(received_seq_num));
	received_seq_num = ntohl(received_seq_num);

	memcpy(msgbuf, cp, cp->len);
	memset(msgbuf + BFD_PKT_LEN + 8, 0, digest_len);

	computed_len = digest_len;
	HMAC(md_alg, key->string, strlen(key->string), msgbuf, cp->len, computed_digest,
	     &computed_len);

	return memcmp(auth_section + 8, computed_digest, digest_len) == 0;
}
#endif

bool bfd_opt_auth_validate_rx(struct bfd_session *bs, const struct bfd_pkt *cp,
			      const uint8_t *auth_section, uint8_t auth_len,
			      struct key *key)
{
	uint8_t opt_mode = auth_section[3];
	uint8_t auth_type = auth_section[0];
	uint32_t received_seq, received_seed, received_key;
	uint8_t state = BFD_GETSTATE(cp->flags);

	if (opt_mode != BFD_OPT_AUTH_MODE_MCI && opt_mode != BFD_OPT_AUTH_MODE_LCI)
		return false;

	if (state != PTM_BFD_UP && opt_mode != BFD_OPT_AUTH_MODE_MCI)
		return false;

	if (state == PTM_BFD_UP && bfd_is_significant_change(bs, cp, false, 0) &&
	    opt_mode != BFD_OPT_AUTH_MODE_MCI)
		return false;

	memcpy(&received_seq, auth_section + 4, sizeof(received_seq));
	received_seq = ntohl(received_seq);

	if (!bfd_opt_auth_check_sequence(bs, received_seq, true))
		return false;

	if (opt_mode == BFD_OPT_AUTH_MODE_MCI) {
#ifdef CRYPTO_OPENSSL
		size_t digest_len = (auth_type == BFD_AUTH_TYPE_OPT_MD5_ISAAC) ? 16 : 20;

		if (auth_len < 8 + digest_len)
			return false;
		return bfd_opt_auth_verify_hmac(cp, auth_section, auth_len, key,
						  key->hash_algo, digest_len);
#else
		return false;
#endif
	}

	if (auth_len != 16)
		return false;

	memcpy(&received_seed, auth_section + 8, sizeof(received_seed));
	received_seed = ntohl(received_seed);
	memcpy(&received_key, auth_section + 12, sizeof(received_key));
	received_key = ntohl(received_key);

	if (bs->opt_auth.recv_isaac.key_known &&
	    received_seed != bs->opt_auth.recv_isaac.seed)
		return false;

	if (!bs->opt_auth.recv_isaac.key_known) {
		if (!bfd_isaac_init_recv(&bs->opt_auth.recv_isaac, received_seed,
					 bs->discrs.my_discr,
					 (const uint8_t *)key->string, strlen(key->string),
					 received_seq, received_key))
			return false;
		bs->opt_auth.lci_ready = true;
		if (!bs->opt_auth.client_notified_up && bs->ses_state == PTM_BFD_UP) {
			bs->opt_auth.client_notified_up = true;
			ptm_bfd_notify(bs, PTM_BFD_UP);
		}
		bfd_opt_auth_schedule_reauth(bs);
		return true;
	}

	return bfd_isaac_auth_key_for_seq(&bs->opt_auth.recv_isaac, received_seq) ==
	       received_key;
}

bool bfd_opt_auth_build_tx(struct bfd_session *bs, struct key *key,
			   enum bfd_auth_type auth_type, enum bfd_opt_auth_mode mode,
			   unsigned char *auth_payload_ptr, uint8_t *auth_section_len,
			   unsigned char *send_buffer, size_t packet_len, int fbit)
{
	uint32_t seq_num_n;

	(void)fbit;

	*auth_payload_ptr++ = auth_type;

	if (mode == BFD_OPT_AUTH_TX_LCI) {
		uint32_t auth_key;

		*auth_section_len = 16;
		*auth_payload_ptr++ = *auth_section_len;
		*auth_payload_ptr++ = key->index;
		*auth_payload_ptr++ = BFD_OPT_AUTH_MODE_LCI;

		bs->auth_seq_num++;
		seq_num_n = htonl(bs->auth_seq_num);
		memcpy(auth_payload_ptr, &seq_num_n, sizeof(seq_num_n));
		auth_payload_ptr += sizeof(seq_num_n);

		if (!bs->opt_auth.xmit_isaac.key_known) {
			bfd_isaac_init_xmit(&bs->opt_auth.xmit_isaac, bs->opt_auth.xmit_seed,
					    bs->discrs.remote_discr,
					    (const uint8_t *)key->string,
					    strlen(key->string), bs->auth_seq_num);
		}

		seq_num_n = htonl(bs->opt_auth.xmit_seed);
		memcpy(auth_payload_ptr, &seq_num_n, sizeof(seq_num_n));
		auth_payload_ptr += sizeof(seq_num_n);

		auth_key = htonl(bfd_isaac_auth_key_for_seq(&bs->opt_auth.xmit_isaac,
							    bs->auth_seq_num));
		memcpy(auth_payload_ptr, &auth_key, sizeof(auth_key));
		bfd_isaac_prepare_next_page(&bs->opt_auth.xmit_isaac);

		if (!bs->opt_auth.lci_ready) {
			bs->opt_auth.lci_ready = true;
			if (!bs->opt_auth.client_notified_up && bs->ses_state == PTM_BFD_UP) {
				bs->opt_auth.client_notified_up = true;
				ptm_bfd_notify(bs, PTM_BFD_UP);
			}
			bfd_opt_auth_schedule_reauth(bs);
		}
		return true;
	}

#ifdef CRYPTO_OPENSSL
	{
		const EVP_MD *md_alg =
			(auth_type == BFD_AUTH_TYPE_OPT_MD5_ISAAC) ? EVP_md5() : EVP_sha1();
		unsigned int digest_len = 0;
		unsigned char digest[20];
		size_t dlen = (auth_type == BFD_AUTH_TYPE_OPT_MD5_ISAAC) ? 16 : 20;

		*auth_section_len = 8 + dlen;
		*auth_payload_ptr++ = *auth_section_len;
		*auth_payload_ptr++ = key->index;
		*auth_payload_ptr++ = BFD_OPT_AUTH_MODE_MCI;

		bs->auth_seq_num++;
		seq_num_n = htonl(bs->auth_seq_num);
		memcpy(auth_payload_ptr, &seq_num_n, sizeof(seq_num_n));
		auth_payload_ptr += sizeof(seq_num_n);
		memset(auth_payload_ptr, 0, dlen);

		HMAC(md_alg, key->string, strlen(key->string), send_buffer, packet_len,
		     digest, &digest_len);
		memcpy(auth_payload_ptr, digest, dlen);
		return true;
	}
#else
	(void)send_buffer;
	(void)packet_len;
	return false;
#endif
}

void bfd_opt_auth_stats_show(struct bfd_session *bs, struct vty *vty, struct json_object *jo)
{
	const char *mode_str = "mci";

	if (!bfd_opt_auth_enabled(bs))
		return;

	if (bs->opt_auth.tx_mode == BFD_OPT_AUTH_TX_LCI)
		mode_str = "lci";

	if (jo) {
		json_object_string_add(jo, "opt-auth-mode", mode_str);
		json_object_boolean_add(jo, "lci-ready", bs->opt_auth.lci_ready);
		json_object_int_add(jo, "reauth-interval", bs->opt_auth.reauth_interval);
	} else {
		vty_out(vty, "\tOptimized auth mode: %s\n", mode_str);
		vty_out(vty, "\tLCI ready: %s\n", bs->opt_auth.lci_ready ? "yes" : "no");
		vty_out(vty, "\tReauth interval: %us\n", bs->opt_auth.reauth_interval);
	}
}

#endif /* HAVE_BFD_OPT_AUTH */
