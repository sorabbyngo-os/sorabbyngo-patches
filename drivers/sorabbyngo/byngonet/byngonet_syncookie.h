/* SPDX-License-Identifier: GPL-2.0 */
/* byngonet_syncookie.h — SYN cookie flood protection, port 7422.
 * Ported from OpenBSD pf_syncookies.c,v 1.10 (Brauer, Nedvedicky 2016/17).
 * ISN: bits31-8=24b SipHash MAC, 7-5=WSCALE, 4-2=MSS, 1=SACK, 0=oddeven */
#ifndef _BYNGONET_SYNCOOKIE_H
#define _BYNGONET_SYNCOOKIE_H
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/atomic.h>
#define BYNGONET_SYNCOOKIE_HIWAT            512
#define BYNGONET_SYNCOOKIE_LOWAT             64
#define BYNGONET_SYNCOOKIE_KEY_LIFETIME_SEC  15
#define BYNGONET_SYNCOOKIES_NEVER    0
#define BYNGONET_SYNCOOKIES_ALWAYS   1
#define BYNGONET_SYNCOOKIES_ADAPTIVE 2
union byngonet_syncookie {
	u8 cookie;
	struct { u8 oddeven:1, sack_ok:1, wscale_idx:3, mss_idx:3; } flags;
};
struct byngonet_syncookie_state {
	struct timer_list  key_timer;
	volatile uint      oddeven;
	u8                 key[2][16];
	atomic_t           halfopen;
	atomic_t           inflight[2];
	u32                hiwat, lowat;
	u8                 mode;
	bool               active;
};
int  byngonet_syncookies_init(struct byngonet_syncookie_state *sc);
void byngonet_syncookies_destroy(struct byngonet_syncookie_state *sc);
int  byngonet_syncookies_setmode(struct byngonet_syncookie_state *sc, u8 mode);
bool byngonet_synflood_check(struct byngonet_syncookie_state *sc);
void byngonet_syncookie_send(struct byngonet_syncookie_state *sc, struct sk_buff *skb);
bool byngonet_syncookie_validate(struct byngonet_syncookie_state *sc, struct sk_buff *skb);
#endif
