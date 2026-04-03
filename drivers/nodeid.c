// SPDX-License-Identifier: GPL-2.0
/*
 * SORABBYNGO NodeID — Hardware-bound cryptographic node identity
 * Author: SORABBYNGO Engineering
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/crypto.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/rcupdate.h>
#include <crypto/hash.h>
#include <asm/cpufeature.h>

#define SORABBYNGO_PROC_DIR     "sorabbyngo"
#define SORABBYNGO_NODEID_FILE  "nodeid"
#define NODEID_HEX_LEN          65

/* Exported — accessible by byngonet and other SORABBYNGO modules */
char nodeid_hex[NODEID_HEX_LEN];
EXPORT_SYMBOL(nodeid_hex);

static struct proc_dir_entry *sorabbyngo_proc_dir;

static void get_cpu_id(u8 *buf, size_t len)
{
        u32 eax = 1, ebx = 0, ecx = 0, edx = 0;
        cpuid(1, &eax, &ebx, &ecx, &edx);
        memcpy(buf,     &eax, sizeof(u32));
        memcpy(buf + 4, &edx, sizeof(u32));
}

static int get_primary_mac(u8 *mac_buf)
{
        struct net_device *dev;
        int found = 0;

        rcu_read_lock();
        for_each_netdev_rcu(&init_net, dev) {
                if (dev->type == ARPHRD_ETHER &&
                    !(dev->flags & IFF_LOOPBACK)) {
                        memcpy(mac_buf, dev->dev_addr, ETH_ALEN);
                        found = 1;
                        break;
                }
        }
        rcu_read_unlock();
        return found;
}

static int compute_nodeid(void)
{
        struct crypto_shash *tfm;
        struct shash_desc *desc;
        u8 cpu_buf[8];
        u8 mac_buf[ETH_ALEN];
        u8 hash[32];
        int ret, i;

        if (!get_primary_mac(mac_buf)) {
                pr_warn("sorabbyngo: no ethernet device, using zeros\n");
                memset(mac_buf, 0, ETH_ALEN);
        }

        get_cpu_id(cpu_buf, sizeof(cpu_buf));

        tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(tfm))
                return PTR_ERR(tfm);

        desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                       GFP_KERNEL);
        if (!desc) {
                crypto_free_shash(tfm);
                return -ENOMEM;
        }

        desc->tfm = tfm;
        ret = crypto_shash_init(desc);
        if (ret) goto out;
        ret = crypto_shash_update(desc, cpu_buf, sizeof(cpu_buf));
        if (ret) goto out;
        ret = crypto_shash_update(desc, mac_buf, ETH_ALEN);
        if (ret) goto out;
        ret = crypto_shash_final(desc, hash);
        if (ret) goto out;

        for (i = 0; i < 32; i++)
                sprintf(&nodeid_hex[i * 2], "%02x", hash[i]);
        nodeid_hex[64] = '\0';

out:
        kfree(desc);
        crypto_free_shash(tfm);
        return ret;
}

static int nodeid_show(struct seq_file *m, void *v)
{
        seq_printf(m, "%s\n", nodeid_hex);
        return 0;
}

static int nodeid_open(struct inode *inode, struct file *file)
{
        return single_open(file, nodeid_show, NULL);
}

static const struct proc_ops nodeid_proc_ops = {
        .proc_open    = nodeid_open,
        .proc_read    = seq_read,
        .proc_lseek   = seq_lseek,
        .proc_release = single_release,
};

static int __init sorabbyngo_nodeid_init(void)
{
        int ret;

        ret = compute_nodeid();
        if (ret) {
                pr_err("sorabbyngo: failed to compute NodeID: %d\n", ret);
                return ret;
        }

        sorabbyngo_proc_dir = proc_mkdir(SORABBYNGO_PROC_DIR, NULL);
        if (!sorabbyngo_proc_dir)
                return -ENOMEM;

        if (!proc_create(SORABBYNGO_NODEID_FILE, 0444,
                         sorabbyngo_proc_dir, &nodeid_proc_ops)) {
                remove_proc_entry(SORABBYNGO_PROC_DIR, NULL);
                return -ENOMEM;
        }

        pr_info("sorabbyngo: NodeID = %s\n", nodeid_hex);
        return 0;
}

static void __exit sorabbyngo_nodeid_exit(void)
{
        remove_proc_entry(SORABBYNGO_NODEID_FILE, sorabbyngo_proc_dir);
        remove_proc_entry(SORABBYNGO_PROC_DIR, NULL);
        pr_info("sorabbyngo: NodeID module unloaded\n");
}

module_init(sorabbyngo_nodeid_init);
module_exit(sorabbyngo_nodeid_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SORABBYNGO Engineering");
MODULE_DESCRIPTION("SORABBYNGO NodeID - Hardware-bound cryptographic identity");
