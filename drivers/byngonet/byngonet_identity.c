// SPDX-License-Identifier: GPL-2.0
/*
 * Byngonet Identity Layer v0.2 — Safe loader
 * Netfilter hook temporarily disabled pending stack fix
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>

#define BYNGONET_STATS_FILE "byngonet_stats"

extern char nodeid_hex[65];

static atomic_t nodeid_loaded = ATOMIC_INIT(0);
static struct proc_dir_entry *byngonet_proc_entry;

static int stats_show(struct seq_file *m, void *v)
{
        seq_printf(m, "nodeid:  %s\n", nodeid_hex);
        seq_printf(m, "nodeid_loaded: %d\n", atomic_read(&nodeid_loaded));
        seq_printf(m, "status: active\n");
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

static int __init byngonet_identity_init(void)
{
        if (nodeid_hex[0] != '\0') {
                atomic_set(&nodeid_loaded, 1);
                pr_info("byngonet: NodeID loaded — %s\n", nodeid_hex);
        } else {
                pr_warn("byngonet: NodeID empty\n");
        }

        byngonet_proc_entry = proc_create(BYNGONET_STATS_FILE, 0444,
                                          NULL, &stats_proc_ops);
        pr_info("byngonet: identity layer active (hook disabled)\n");
        return 0;
}

static void __exit byngonet_identity_exit(void)
{
        if (byngonet_proc_entry)
                remove_proc_entry(BYNGONET_STATS_FILE, NULL);
        pr_info("byngonet: identity layer removed\n");
}

module_init(byngonet_identity_init);
module_exit(byngonet_identity_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("SORABBYNGO Engineering");
MODULE_DESCRIPTION("Byngonet Network Identity Layer");
