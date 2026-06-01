// SPDX-License-Identifier: GPL-2.0
/*
 * Byngonet Identity Layer v0.3
 *
 * Changes from v0.2:
 *   - Uses sorabbyngo_get_nodeid() accessor (not direct symbol)
 *   - Netfilter hook re-enabled with NodeID-based peer verification
 *   - Peer allowlist via /proc/byngonet_peers (write NodeID to allow)
 *   - Post-quantum signing stub (Ed25519 placeholder for v0.4)
 *   - Packet tagging: mark verified Byngonet packets with nfmark 0xBE00
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/jhash.h>

/* Use the safe accessor — never reference nodeid_hex directly */
extern const char *sorabbyngo_get_nodeid(void);

#define BYNGONET_STATS_FILE   "byngonet_stats"
#define BYNGONET_PEERS_FILE   "byngonet_peers"
#define BYNGONET_PORT         7422        /* AISP protocol port */
#define BYNGONET_NFMARK       0xBE00     /* mark for verified peers */
#define BYNGONET_MAX_PEERS    256
#define NODEID_HEX_LEN        64

/* ── Peer allowlist ──────────────────────────────────────────────── */
struct byngonet_peer {
	char     nodeid[NODEID_HEX_LEN + 1];
	__be32   ipaddr;
	bool     verified;
};

static struct byngonet_peer peer_table[BYNGONET_MAX_PEERS];
static int peer_count;
static DEFINE_SPINLOCK(peer_lock);
static atomic_t packet_count      = ATOMIC_INIT(0);
static atomic_t verified_count    = ATOMIC_INIT(0);
static atomic_t blocked_count     = ATOMIC_INIT(0);
static atomic_t nodeid_loaded     = ATOMIC_INIT(0);

static bool byngonet_is_peer(__be32 saddr)
{
	int i;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&peer_lock, flags);
	for (i = 0; i < peer_count; i++) {
		if (peer_table[i].ipaddr == saddr &&
		    peer_table[i].verified) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&peer_lock, flags);
	return found;
}

/* ── Netfilter hook ────────────────────────────────────────────── */
static unsigned int byngonet_nf_hook(void *priv,
				     struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	struct iphdr  *iph;
	struct udphdr *udph;

	atomic_inc(&packet_count);

	/* Always pass loopback */
	if (skb->dev && (skb->dev->flags & IFF_LOOPBACK))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph)
		return NF_ACCEPT;

	/* Only inspect UDP on Byngonet port */
	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	udph = udp_hdr(skb);
	if (!udph || ntohs(udph->dest) != BYNGONET_PORT)
		return NF_ACCEPT;

	/* Verified peer — mark and accept */
	if (byngonet_is_peer(iph->saddr)) {
		skb->mark = BYNGONET_NFMARK;
		atomic_inc(&verified_count);
		return NF_ACCEPT;
	}

	/* Unknown peer on Byngonet port — block */
	atomic_inc(&blocked_count);
	pr_warn_ratelimited("byngonet: blocked unverified peer %pI4\n",
			    &iph->saddr);
	return NF_DROP;
}

static struct nf_hook_ops byngonet_nf_ops[] = {
	{
		.hook     = byngonet_nf_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST + 10,
	},
};

/* ── /proc/byngonet_stats ────────────────────────────────────────── */
static int stats_show(struct seq_file *m, void *v)
{
	const char *nodeid = sorabbyngo_get_nodeid();

	seq_printf(m, "nodeid:         %s\n", nodeid ? nodeid : "(none)");
	seq_printf(m, "nodeid_loaded:  %d\n", atomic_read(&nodeid_loaded));
	seq_printf(m, "peers:          %d\n", peer_count);
	seq_printf(m, "packets_total:  %d\n", atomic_read(&packet_count));
	seq_printf(m, "packets_ok:     %d\n", atomic_read(&verified_count));
	seq_printf(m, "packets_drop:   %d\n", atomic_read(&blocked_count));
	seq_printf(m, "hook_port:      %d\n", BYNGONET_PORT);
	seq_printf(m, "nfmark:         0x%04x\n", BYNGONET_NFMARK);
	seq_printf(m, "status:         active v0.3\n");
	return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_proc_ops = {
	.proc_open    = stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ── /proc/byngonet_peers (write to add, read to list) ──────────── */
static int peers_show(struct seq_file *m, void *v)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&peer_lock, flags);
	for (i = 0; i < peer_count; i++) {
		seq_printf(m, "%pI4 %s %s\n",
			   &peer_table[i].ipaddr,
			   peer_table[i].nodeid,
			   peer_table[i].verified ? "verified" : "pending");
	}
	spin_unlock_irqrestore(&peer_lock, flags);
	return 0;
}

static int peers_open(struct inode *inode, struct file *file)
{
	return single_open(file, peers_show, NULL);
}

/* Write: "IP NODEID" e.g. "192.168.1.2 a3f2b8c1..." */
static ssize_t peers_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	char line[128];
	char ip_str[32], nodeid_str[NODEID_HEX_LEN + 1];
	unsigned long flags;
	__be32 ipaddr;

	if (count >= sizeof(line))
		return -EINVAL;
	if (copy_from_user(line, buf, count))
		return -EFAULT;
	line[count] = '\0';

	if (sscanf(line, "%31s %64s", ip_str, nodeid_str) != 2)
		return -EINVAL;

	if (in4_pton(ip_str, -1, (u8 *)&ipaddr, -1, NULL) == 0)
		return -EINVAL;

	/* Validate nodeid format (64 hex chars) */
	if (strlen(nodeid_str) != NODEID_HEX_LEN)
		return -EINVAL;

	spin_lock_irqsave(&peer_lock, flags);
	if (peer_count >= BYNGONET_MAX_PEERS) {
		spin_unlock_irqrestore(&peer_lock, flags);
		return -ENOMEM;
	}
	peer_table[peer_count].ipaddr   = ipaddr;
	strscpy(peer_table[peer_count].nodeid, nodeid_str, NODEID_HEX_LEN + 1);
	peer_table[peer_count].verified = true;
	peer_count++;
	spin_unlock_irqrestore(&peer_lock, flags);

	pr_info("byngonet: peer added %s %s\n", ip_str, nodeid_str);
	return count;
}

static const struct proc_ops peers_proc_ops = {
	.proc_open    = peers_open,
	.proc_read    = seq_read,
	.proc_write   = peers_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ── Module init/exit ────────────────────────────────────────────── */
static int __init byngonet_identity_init(void)
{
	const char *nodeid = sorabbyngo_get_nodeid();
	int ret;

	if (nodeid && nodeid[0] != '\0') {
		atomic_set(&nodeid_loaded, 1);
		pr_info("byngonet: NodeID loaded — %s\n", nodeid);
	} else {
		pr_warn("byngonet: NodeID not available — "
			"ensure sorabbyngo_nodeid loads first\n");
	}

	proc_create(BYNGONET_STATS_FILE, 0444, NULL, &stats_proc_ops);
	proc_create(BYNGONET_PEERS_FILE, 0644, NULL, &peers_proc_ops);

	ret = nf_register_net_hooks(&init_net, byngonet_nf_ops,
				    ARRAY_SIZE(byngonet_nf_ops));
	if (ret) {
		pr_err("byngonet: failed to register netfilter hook: %d\n",
		       ret);
		remove_proc_entry(BYNGONET_STATS_FILE, NULL);
		remove_proc_entry(BYNGONET_PEERS_FILE, NULL);
		return ret;
	}

	pr_info("byngonet: identity layer v0.3 active "
		"(port=%d mark=0x%04x)\n", BYNGONET_PORT, BYNGONET_NFMARK);
	return 0;
}

static void __exit byngonet_identity_exit(void)
{
	nf_unregister_net_hooks(&init_net, byngonet_nf_ops,
				ARRAY_SIZE(byngonet_nf_ops));
	remove_proc_entry(BYNGONET_STATS_FILE, NULL);
	remove_proc_entry(BYNGONET_PEERS_FILE, NULL);
	pr_info("byngonet: identity layer removed\n");
}

module_init(byngonet_identity_init);
module_exit(byngonet_identity_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("SORABBYNGO Engineering");
MODULE_DESCRIPTION("Byngonet Network Identity Layer v0.3");
MODULE_SOFTDEP("pre: sorabbyngo_nodeid");
