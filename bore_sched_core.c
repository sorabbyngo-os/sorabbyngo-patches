// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/sched/bore.c
 *
 * BORE — Burst-Oriented Response Enhancer for Sorabbyngo OS
 *
 * Tracks per-task CPU burst behaviour and penalises tasks that
 * consume long uninterrupted bursts — keeping latency low for
 * interactive/security/gaming workloads while still allowing
 * high-throughput in AI inference mode.
 *
 * Profile switching is exposed via:
 *   /sys/kernel/sorabbyngo/sched_profile   (rw, 0=balanced 1=latency 2=throughput)
 *
 * The domain-mode manager writes this file during mode switches.
 */

#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include "bore.h"
#include "sched.h"

/* ------------------------------------------------------------------ */
/* Global state                                                          */
/* ------------------------------------------------------------------ */

int sorabbyngo_sched_profile = SCHED_PROFILE_BALANCED;
EXPORT_SYMBOL_GPL(sorabbyngo_sched_profile);

struct bore_profile_params bore_profiles[3] = {
	[SCHED_PROFILE_BALANCED] = {
		.min_granularity_ns    = 3000000ULL,   /* 3ms  */
		.wakeup_granularity_ns = 4000000ULL,   /* 4ms  */
		.burst_penalty_scale   = 8,
		.preempt_burst         = false,
	},
	[SCHED_PROFILE_LATENCY] = {
		/* Gaming + Security: snap to interactive tasks immediately */
		.min_granularity_ns    = 500000ULL,    /* 0.5ms */
		.wakeup_granularity_ns = 1000000ULL,   /* 1ms   */
		.burst_penalty_scale   = 24,
		.preempt_burst         = true,
	},
	[SCHED_PROFILE_THROUGHPUT] = {
		/* AI inference: let compute threads run long without penalty */
		.min_granularity_ns    = 10000000ULL,  /* 10ms */
		.wakeup_granularity_ns = 8000000ULL,   /* 8ms  */
		.burst_penalty_scale   = 2,
		.preempt_burst         = false,
	},
};
EXPORT_SYMBOL_GPL(bore_profiles);

/* ------------------------------------------------------------------ */
/* Per-task burst tracking                                              */
/* ------------------------------------------------------------------ */

/*
 * bore_task_new - initialise BORE state for a freshly created task.
 * Called from sched_fork() hook in fair.c.
 */
void bore_task_new(struct sched_entity *se)
{
	struct bore_stat *bs = &se->bore;
	bs->burst_time    = 0;
	bs->burst_score   = 0;
	bs->slice_start   = sched_clock();
	bs->burst_penalty = 0;
}
EXPORT_SYMBOL_GPL(bore_task_new);

void bore_task_dead(struct sched_entity *se)
{
	/* nothing to free — bore_stat is embedded */
}
EXPORT_SYMBOL_GPL(bore_task_dead);

/*
 * bore_update_burst - called on every scheduler tick and on
 * voluntary/involuntary context switches.
 *
 * Updates the EMA burst score and recalculates penalty.
 */
void bore_update_burst(struct sched_entity *se)
{
	struct bore_stat *bs = &se->bore;
	u64 now     = sched_clock();
	u64 elapsed = now - bs->slice_start;

	/* Accumulate burst time for this slice */
	bs->burst_time += elapsed;
	bs->slice_start = now;

	/* EMA: score = (score * (2^s - 1) + burst_time) >> s */
	bs->burst_score = (bs->burst_score
		* ((1 << BORE_BURST_SMOOTHNESS) - 1)
		+ bs->burst_time)
		>> BORE_BURST_SMOOTHNESS;

	/* Reset burst accumulator each EMA window */
	bs->burst_time = 0;

	/* Recalculate penalty using active profile's scale */
	bore_calc_penalty(se);
}
EXPORT_SYMBOL_GPL(bore_update_burst);

/*
 * bore_calc_penalty - translate burst score → vruntime penalty.
 *
 * Returns additional ns to add to the task's vruntime so bursty
 * tasks yield sooner to interactive/latency-sensitive tasks.
 */
u64 bore_calc_penalty(struct sched_entity *se)
{
	struct bore_stat *bs = &se->bore;
	struct bore_profile_params *p = &bore_profiles[sorabbyngo_sched_profile];
	u64 penalty;

	/* penalty = (burst_score * scale) clamped to BORE_BURST_PENALTY_MAX ms */
	penalty = (bs->burst_score >> 20) * p->burst_penalty_scale;
	penalty = min_t(u64, penalty, (u64)BORE_BURST_PENALTY_MAX * 1000000ULL);

	bs->burst_penalty = (u8)(penalty >> 20);
	return penalty;
}
EXPORT_SYMBOL_GPL(bore_calc_penalty);

/* ------------------------------------------------------------------ */
/* Sysfs profile interface                                              */
/* ------------------------------------------------------------------ */
/* Exposes /sys/kernel/sorabbyngo/sched_profile                        */
/* Written by domain-mode manager on every mode switch                 */

static ssize_t sched_profile_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	const char *names[] = { "balanced", "latency", "throughput" };
	int p = sorabbyngo_sched_profile;
	return sysfs_emit(buf, "%d (%s)\n", p, names[p]);
}

static ssize_t sched_profile_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int val;
	if (kstrtoint(buf, 10, &val))
		return -EINVAL;
	if (val < 0 || val > 2)
		return -ERANGE;

	sorabbyngo_sched_profile = val;

	/* Update CFS tunables immediately */
	sysctl_sched_min_granularity     = bore_profiles[val].min_granularity_ns;
	sysctl_sched_wakeup_granularity  = bore_profiles[val].wakeup_granularity_ns;

	pr_info("sorabbyngo: sched_profile -> %d\n", val);
	return count;
}

static struct kobj_attribute sched_profile_attr =
	__ATTR(sched_profile, 0644, sched_profile_show, sched_profile_store);

static struct kobject *sorabbyngo_kobj;

static int __init bore_sysfs_init(void)
{
	int ret;
	sorabbyngo_kobj = kobject_create_and_add("sorabbyngo", kernel_kobj);
	if (!sorabbyngo_kobj)
		return -ENOMEM;

	ret = sysfs_create_file(sorabbyngo_kobj, &sched_profile_attr.attr);
	if (ret)
		kobject_put(sorabbyngo_kobj);

	pr_info("sorabbyngo: BORE scheduler loaded, profile=balanced\n");
	return ret;
}
late_initcall(bore_sysfs_init);
