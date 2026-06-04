// SPDX-License-Identifier: GPL-2.0
/* byngonet_syncookie.c — Adaptive SYN cookie protection, port 7422.
 * Ported from OpenBSD sys/net/pf_syncookies.c,v 1.10 (Brauer, Nedvedicky).
 * Linux adaptations: arc4random->get_random_bytes, timeout->mod_timer,
 * KASSERT->WARN_ON_ONCE, mbuf->sk_buff, crypto/siphash->linux/siphash */
#include <linux/module.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/siphash.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/atomic.h>
#include <linux/sorabbyngo_audit.h>
#include "byngonet_syncookie.h"
#include "byngonet.h"

static const u16 msstab[] = { 216,536,1200,1360,1400,1440,1452,1460 };
static const u8  wstab[]  = { 0,0,1,2,4,6,7,8 };

static void byngonet_syncookie_rotate(struct timer_list *t);
static void byngonet_syncookie_newkey(struct byngonet_syncookie_state *sc);

static u32 cookie_mac(struct byngonet_syncookie_state *sc,
		      union byngonet_syncookie cookie,
		      __be32 sa, __be32 da, __be16 sp, __be16 dp, u32 seq)
{
	siphash_key_t *k = (siphash_key_t *)&sc->key[cookie.flags.oddeven];
	struct { __be32 sa,da; __be16 sp,dp; u32 seq; u8 cookie; } __packed
		d = {sa,da,sp,dp,seq,cookie.cookie};
	u64 h = siphash(&d, sizeof(d), k);
	return (u32)(h ^ (h >> 32));
}

int byngonet_syncookies_init(struct byngonet_syncookie_state *sc)
{
	memset(sc, 0, sizeof(*sc));
	timer_setup(&sc->key_timer, byngonet_syncookie_rotate, 0);
	sc->hiwat = BYNGONET_SYNCOOKIE_HIWAT;
	sc->lowat  = BYNGONET_SYNCOOKIE_LOWAT;
	atomic_set(&sc->halfopen,0);
	atomic_set(&sc->inflight[0],0);
	atomic_set(&sc->inflight[1],0);
	return byngonet_syncookies_setmode(sc, BYNGONET_SYNCOOKIES_ADAPTIVE);
}
EXPORT_SYMBOL_GPL(byngonet_syncookies_init);

void byngonet_syncookies_destroy(struct byngonet_syncookie_state *sc)
{
	del_timer_sync(&sc->key_timer);
	memzero_explicit(sc->key, sizeof(sc->key));
}
EXPORT_SYMBOL_GPL(byngonet_syncookies_destroy);

int byngonet_syncookies_setmode(struct byngonet_syncookie_state *sc, u8 mode)
{
	if (mode > BYNGONET_SYNCOOKIES_ADAPTIVE) return -EINVAL;
	if (sc->mode == mode) return 0;
	sc->mode = mode;
	if (mode == BYNGONET_SYNCOOKIES_ALWAYS) {
		byngonet_syncookie_newkey(sc);
		sc->active = true;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(byngonet_syncookies_setmode);

bool byngonet_synflood_check(struct byngonet_syncookie_state *sc)
{
	if (sc->mode != BYNGONET_SYNCOOKIES_ADAPTIVE)
		return sc->mode == BYNGONET_SYNCOOKIES_ALWAYS;
	if (!sc->active && atomic_read(&sc->halfopen) > (int)sc->hiwat) {
		byngonet_syncookie_newkey(sc);
		sc->active = true;
		pr_warn_ratelimited("byngonet: SYN flood port 7422 — syncookies active (halfopen=%d)\n",
			atomic_read(&sc->halfopen));
		sorabbyngo_audit_emit(SORABBYNGO_AUDIT_NET_SYNFLOOD,
			"port=7422 halfopen=%d", atomic_read(&sc->halfopen));
	}
	return sc->active;
}
EXPORT_SYMBOL_GPL(byngonet_synflood_check);

void byngonet_syncookie_send(struct byngonet_syncookie_state *sc,
			     struct sk_buff *skb)
{
	struct iphdr  *iph = ip_hdr(skb);
	struct tcphdr *th  = tcp_hdr(skb);
	union byngonet_syncookie cookie = {.cookie=0};
	u32 iss, hash; u16 mss=1460; u8 i;
	for (i=ARRAY_SIZE(msstab)-1; msstab[i]>mss && i>0; i--);
	cookie.flags.mss_idx=i; cookie.flags.oddeven=sc->oddeven;
	hash = cookie_mac(sc,cookie,iph->saddr,iph->daddr,
			  th->source,th->dest,ntohl(th->seq));
	iss = (hash & ~0xff) | (cookie.cookie ^ (hash>>24));
	byngonet_send_synack(iph->daddr,iph->saddr,th->dest,th->source,
			     iss,ntohl(th->seq)+1,mss);
	atomic_inc(&sc->inflight[sc->oddeven]);
}
EXPORT_SYMBOL_GPL(byngonet_syncookie_send);

bool byngonet_syncookie_validate(struct byngonet_syncookie_state *sc,
				 struct sk_buff *skb)
{
	struct iphdr  *iph = ip_hdr(skb);
	struct tcphdr *th  = tcp_hdr(skb);
	union byngonet_syncookie cookie;
	u32 hash, ack, seq;
	seq = ntohl(th->seq)-1;
	ack = ntohl(th->ack_seq)-1;
	cookie.cookie = (u8)((ack&0xff)^(ack>>24));
	if (atomic_read(&sc->inflight[cookie.flags.oddeven])==0) return false;
	hash = cookie_mac(sc,cookie,iph->saddr,iph->daddr,
			  th->source,th->dest,seq);
	if ((ack&~0xff) != (hash&~0xff)) return false;
	atomic_dec(&sc->inflight[cookie.flags.oddeven]);
	if (!byngonet_peer_allow(iph->saddr)) {
		pr_debug("byngonet: valid cookie, non-allowlisted %pI4 — drop\n",
			 &iph->saddr);
		return false;
	}
	sorabbyngo_audit_emit(SORABBYNGO_AUDIT_NET_SYNCOOKIE_VALID,
		"src=%pI4 port=7422", &iph->saddr);
	return true;
}
EXPORT_SYMBOL_GPL(byngonet_syncookie_validate);

static void byngonet_syncookie_newkey(struct byngonet_syncookie_state *sc)
{
	sc->oddeven = (sc->oddeven+1)&0x1;
	atomic_set(&sc->inflight[sc->oddeven],0);
	get_random_bytes(&sc->key[sc->oddeven],sizeof(sc->key[sc->oddeven]));
	mod_timer(&sc->key_timer,
		  jiffies+BYNGONET_SYNCOOKIE_KEY_LIFETIME_SEC*HZ);
}

static void byngonet_syncookie_rotate(struct timer_list *t)
{
	struct byngonet_syncookie_state *sc = from_timer(sc,t,key_timer);
	int ho=atomic_read(&sc->halfopen);
	int i0=atomic_read(&sc->inflight[0]);
	int i1=atomic_read(&sc->inflight[1]);
	if (sc->active &&
	    ((sc->mode==BYNGONET_SYNCOOKIES_ADAPTIVE && ho+i0+i1<(int)sc->lowat) ||
	     sc->mode==BYNGONET_SYNCOOKIES_NEVER)) {
		sc->active=false;
		pr_info("byngonet: syncookies deactivated (halfopen=%d)\n",ho);
	}
	if (!sc->active && i0==0 && i1==0) {
		memzero_explicit(sc->key,sizeof(sc->key));
		return;
	}
	byngonet_syncookie_newkey(sc);
}
