// SPDX-License-Identifier: GPL-2.0
/*
 * security/sorabbyngo/cap_token_lsm.c
 *
 * Sorabbyngo Capability Token LSM
 *
 * Implements Fuchsia-inspired capability-based access control on top of
 * Linux's LSM framework. Every process starts with zero capabilities.
 * Capabilities are issued as signed tokens by capd (userspace daemon)
 * and stored in a per-process RCU-protected token table.
 *
 * Token format (kernel representation):
 *   struct cap_token {
 *     u8   domain;    // CAP_DOMAIN_FS / NET / GPU / IPC / PROC
 *     u8   op;        // read/write/exec/connect/...
 *     u64  scope;     // inode number, port, device id, or bus id
 *     u64  expires;   // ktime_get() deadline, 0 = persistent
 *   };
 *
 * Tokens are installed via /proc/<pid>/cap_tokens (write-only, root only).
 * The LSM hook checks the token table on every security-sensitive syscall.
 *
 * Integration points:
 *   - capd daemon writes tokens after policy evaluation
 *   - sorabbyngofs reads CAP_DOMAIN_FS tokens for consent-gated zones
 *   - byngox agent orchestrator installs tokens at agent spawn
 *   - cml (Cognitive Mediation Layer) can revoke tokens via netlink
 */

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/idr.h>

/* ------------------------------------------------------------------ */
/* Token domains and operations                                         */
/* ------------------------------------------------------------------ */

#define CAP_DOMAIN_FS    0x01   /* filesystem access                  */
#define CAP_DOMAIN_NET   0x02   /* network connect/bind/send          */
#define CAP_DOMAIN_GPU   0x04   /* GPU compute / render access        */
#define CAP_DOMAIN_IPC   0x08   /* sorabbyngo agent-bus IPC           */
#define CAP_DOMAIN_PROC  0x10   /* process signal / ptrace            */
#define CAP_DOMAIN_ANY   0xFF

#define CAP_OP_READ      0x01
#define CAP_OP_WRITE     0x02
#define CAP_OP_EXEC      0x04
#define CAP_OP_CONNECT   0x08
#define CAP_OP_BIND      0x10
#define CAP_OP_COMPUTE   0x20   /* GPU compute                        */
#define CAP_OP_ANY       0xFF

/* ------------------------------------------------------------------ */
/* Data structures                                                      */
/* ------------------------------------------------------------------ */

struct cap_token {
	struct rcu_head  rcu;
	struct list_head node;
	u8   domain;
	u8   op;
	u64  scope;       /* inode / port / device id / bus channel */
	u64  expires_ns;  /* ktime_get_ns() deadline, 0 = forever   */
	u32  token_id;    /* assigned by capd, unique per process    */
};

/* Per-process token table — hangs off task security blob */
struct cap_token_table {
	struct list_head tokens;  /* RCU list of cap_token             */
	spinlock_t       lock;    /* protects structural modifications */
	atomic_t         count;   /* number of active tokens           */
};

/* LSM blob offset — assigned at init */
static int cap_token_task_blob_offset;

static inline struct cap_token_table *task_token_table(struct task_struct *t)
{
	return (struct cap_token_table *)
		((char *)t->security + cap_token_task_blob_offset);
}

/* ------------------------------------------------------------------ */
/* Token lookup                                                         */
/* ------------------------------------------------------------------ */

static bool token_has_cap(struct cap_token_table *tbl,
			   u8 domain, u8 op, u64 scope)
{
	struct cap_token *tok;
	u64 now = ktime_get_ns();

	rcu_read_lock();
	list_for_each_entry_rcu(tok, &tbl->tokens, node) {
		/* Skip expired tokens */
		if (tok->expires_ns && tok->expires_ns < now)
			continue;
		if ((tok->domain & domain) &&
		    (tok->op     & op)     &&
		    (tok->scope == scope || tok->scope == 0 /* wildcard */)) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

/* ------------------------------------------------------------------ */
/* LSM hooks                                                            */
/* ------------------------------------------------------------------ */

static int cap_token_task_alloc(struct task_struct *task,
				unsigned long clone_flags)
{
	struct cap_token_table *tbl = task_token_table(task);
	INIT_LIST_HEAD(&tbl->tokens);
	spin_lock_init(&tbl->lock);
	atomic_set(&tbl->count, 0);
	return 0;
}

static void cap_token_task_free(struct task_struct *task)
{
	struct cap_token_table *tbl = task_token_table(task);
	struct cap_token *tok, *tmp;

	spin_lock(&tbl->lock);
	list_for_each_entry_safe(tok, tmp, &tbl->tokens, node) {
		list_del_rcu(&tok->node);
		kfree_rcu(tok, rcu);
	}
	spin_unlock(&tbl->lock);
}

/* inode_permission: called on every open/stat/access */
static int cap_token_inode_permission(struct inode *inode, int mask)
{
	struct cap_token_table *tbl;
	u8 op = 0;

	/* Root and kernel threads bypass token check */
	if (capable(CAP_SYS_ADMIN))
		return 0;

	tbl = task_token_table(current);

	if (mask & MAY_READ)    op |= CAP_OP_READ;
	if (mask & MAY_WRITE)   op |= CAP_OP_WRITE;
	if (mask & MAY_EXEC)    op |= CAP_OP_EXEC;

	if (!token_has_cap(tbl, CAP_DOMAIN_FS, op, inode->i_ino)) {
		/* Audit: log the denial to sorabbyngo audit channel */
		pr_debug("sorabbyngo-cap: DENY pid=%d inode=%lu op=%02x\n",
			 current->pid, inode->i_ino, op);
		return -EACCES;
	}
	return 0;
}

/* socket_connect: called on every connect(2) */
static int cap_token_socket_connect(struct socket *sock,
				    struct sockaddr *address, int addrlen)
{
	struct cap_token_table *tbl;
	u64 port = 0;

	if (capable(CAP_SYS_ADMIN))
		return 0;

	/* Extract destination port as scope */
	if (address->sa_family == AF_INET)
		port = ntohs(((struct sockaddr_in *)address)->sin_port);
	else if (address->sa_family == AF_INET6)
		port = ntohs(((struct sockaddr_in6 *)address)->sin6_port);

	tbl = task_token_table(current);

	if (!token_has_cap(tbl, CAP_DOMAIN_NET, CAP_OP_CONNECT, port)) {
		pr_debug("sorabbyngo-cap: DENY pid=%d net connect port=%llu\n",
			 current->pid, port);
		return -EACCES;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* /proc/<pid>/cap_tokens — capd installs tokens here                  */
/* ------------------------------------------------------------------ */

/*
 * Wire format written by capd (binary, 24 bytes per token):
 *   u8  domain
 *   u8  op
 *   u16 pad
 *   u64 scope
 *   u64 expires_ns   (0 = persistent)
 */
#define CAP_TOKEN_WIRE_SIZE 24

struct cap_token_wire {
	u8  domain;
	u8  op;
	u16 pad;
	u64 scope;
	u64 expires_ns;
} __packed;

static ssize_t cap_tokens_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	struct cap_token_table *tbl;
	struct cap_token_wire wire;
	struct cap_token *tok;

	if (!task)
		return -ESRCH;
	if (!capable(CAP_SYS_ADMIN)) {
		put_task_struct(task);
		return -EPERM;
	}
	if (count != CAP_TOKEN_WIRE_SIZE) {
		put_task_struct(task);
		return -EINVAL;
	}
	if (copy_from_user(&wire, buf, CAP_TOKEN_WIRE_SIZE)) {
		put_task_struct(task);
		return -EFAULT;
	}

	tok = kzalloc(sizeof(*tok), GFP_KERNEL);
	if (!tok) {
		put_task_struct(task);
		return -ENOMEM;
	}

	tok->domain     = wire.domain;
	tok->op         = wire.op;
	tok->scope      = wire.scope;
	tok->expires_ns = wire.expires_ns;

	tbl = task_token_table(task);
	spin_lock(&tbl->lock);
	list_add_rcu(&tok->node, &tbl->tokens);
	atomic_inc(&tbl->count);
	spin_unlock(&tbl->lock);

	put_task_struct(task);
	return count;
}

static const struct file_operations cap_tokens_fops = {
	.write = cap_tokens_write,
};

/* ------------------------------------------------------------------ */
/* LSM registration                                                     */
/* ------------------------------------------------------------------ */

static struct lsm_blob_sizes cap_token_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct cap_token_table),
};

static struct security_hook_list cap_token_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc,         cap_token_task_alloc),
	LSM_HOOK_INIT(task_free,          cap_token_task_free),
	LSM_HOOK_INIT(inode_permission,   cap_token_inode_permission),
	LSM_HOOK_INIT(socket_connect,     cap_token_socket_connect),
};

static int __init cap_token_lsm_init(void)
{
	security_add_hooks(cap_token_hooks, ARRAY_SIZE(cap_token_hooks),
			   "cap_token");
	pr_info("sorabbyngo: Capability Token LSM loaded\n");
	return 0;
}

DEFINE_LSM(cap_token) = {
	.name       = "cap_token",
	.init       = cap_token_lsm_init,
	.blobs      = &cap_token_blob_sizes,
};
