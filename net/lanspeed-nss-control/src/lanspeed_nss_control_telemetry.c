// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "lanspeed_nss_control.h"

static atomic64_t lanspeed_ack_received = ATOMIC64_INIT(0);
static atomic64_t lanspeed_ack_timeout = ATOMIC64_INIT(0);
static atomic64_t lanspeed_ack_late = ATOMIC64_INIT(0);
static atomic64_t lanspeed_ack_latency_last_ns = ATOMIC64_INIT(0);
static atomic64_t lanspeed_ack_latency_max_ns = ATOMIC64_INIT(0);
static atomic64_t lanspeed_igs_sync_count = ATOMIC64_INIT(0);
static atomic64_t lanspeed_igs_last_sync_ns = ATOMIC64_INIT(0);
static atomic64_t lanspeed_igs_cadence_samples = ATOMIC64_INIT(0);
static atomic64_t lanspeed_igs_cadence_last_ns = ATOMIC64_INIT(0);
static atomic64_t lanspeed_igs_cadence_min_ns = ATOMIC64_INIT(0);
static atomic64_t lanspeed_igs_cadence_max_ns = ATOMIC64_INIT(0);
static atomic64_t lanspeed_peer_generation = ATOMIC64_INIT(0);
static atomic64_t lanspeed_peer_reassert_count = ATOMIC64_INIT(0);
static atomic64_t lanspeed_control_generation = ATOMIC64_INIT(0);
static atomic64_t lanspeed_hardware_generation = ATOMIC64_INIT(0);

u64 lanspeed_ack_started(void)
{
	return ktime_get_ns();
}

void lanspeed_ack_complete(u64 started_ns, bool acknowledged)
{
	u64 latency_ns = ktime_get_ns() - started_ns;
	u64 previous_max;

	atomic64_set(&lanspeed_ack_latency_last_ns, latency_ns);
	previous_max = atomic64_read(&lanspeed_ack_latency_max_ns);
	while (latency_ns > previous_max &&
	       atomic64_cmpxchg(&lanspeed_ack_latency_max_ns,
				 previous_max, latency_ns) != previous_max)
		previous_max = atomic64_read(&lanspeed_ack_latency_max_ns);
	atomic64_inc(&lanspeed_ack_received);
	if (acknowledged)
		atomic64_inc(&lanspeed_hardware_generation);
}

void lanspeed_ack_timeout_event(void)
{
	atomic64_inc(&lanspeed_ack_timeout);
}

void lanspeed_ack_late_event(void)
{
	atomic64_inc(&lanspeed_ack_late);
}

int lanspeed_ack_stats_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "v1 received=%lld timeout=%lld late=%lld\n",
			 (long long)atomic64_read(&lanspeed_ack_received),
			 (long long)atomic64_read(&lanspeed_ack_timeout),
			 (long long)atomic64_read(&lanspeed_ack_late));
}

static void lanspeed_atomic64_max(atomic64_t *value, u64 candidate)
{
	u64 previous = atomic64_read(value);

	while (candidate > previous &&
	       atomic64_cmpxchg(value, previous, candidate) != previous)
		previous = atomic64_read(value);
}

static void lanspeed_atomic64_min_nonzero(atomic64_t *value, u64 candidate)
{
	u64 previous = atomic64_read(value);

	while ((!previous || candidate < previous) &&
	       atomic64_cmpxchg(value, previous, candidate) != previous)
		previous = atomic64_read(value);
}

static u64 lanspeed_u64_add_sat(u64 left, u64 right)
{
	return U64_MAX - left < right ? U64_MAX : left + right;
}

void lanspeed_telemetry_igs_sync(struct net_device *dev,
				 u64 bytes, u64 packets, u64 drops)
{
	struct lanspeed_igs_entry *entry;
	u64 now_ns;
	u64 previous_ns;
	u64 interval_ns;
	bool found = false;

	if (!dev)
		return;
	now_ns = ktime_get_ns();
	previous_ns = 0;
	rcu_read_lock();
	list_for_each_entry_rcu(entry, &lanspeed_igs_entries, list) {
		if (READ_ONCE(entry->dev) != dev)
			continue;
		previous_ns = atomic64_xchg(&entry->stats_last_sync_ns, now_ns);
		atomic64_set(&entry->stats_bytes, bytes);
		atomic64_set(&entry->stats_packets, packets);
		atomic64_set(&entry->stats_drops, drops);
		found = true;
		break;
	}
	rcu_read_unlock();
	if (!found)
		return;
	atomic64_inc(&lanspeed_igs_sync_count);
	lanspeed_atomic64_max(&lanspeed_igs_last_sync_ns, now_ns);
	if (!previous_ns || now_ns <= previous_ns)
		return;
	interval_ns = now_ns - previous_ns;
	atomic64_set(&lanspeed_igs_cadence_last_ns, interval_ns);
	lanspeed_atomic64_min_nonzero(&lanspeed_igs_cadence_min_ns,
				      interval_ns);
	lanspeed_atomic64_max(&lanspeed_igs_cadence_max_ns, interval_ns);
	atomic64_inc(&lanspeed_igs_cadence_samples);
}

void lanspeed_telemetry_peer_apply(u16 count)
{
	atomic64_inc(&lanspeed_peer_generation);
	atomic64_add(count, &lanspeed_peer_reassert_count);
	atomic64_inc(&lanspeed_control_generation);
}

void lanspeed_telemetry_peer_reset(void)
{
	atomic64_inc(&lanspeed_peer_generation);
	atomic64_inc(&lanspeed_control_generation);
}

void lanspeed_telemetry_control_event(void)
{
	atomic64_inc(&lanspeed_control_generation);
}

void lanspeed_telemetry_snapshot(struct lanspeed_telemetry_snapshot *snapshot)
{
	struct lanspeed_igs_entry *entry;

	if (!snapshot)
		return;
	snapshot->igs_bytes = 0;
	snapshot->igs_packets = 0;
	snapshot->igs_drops = 0;
	snapshot->igs_active_nodes = 0;
	mutex_lock(&lanspeed_igs_lock);
	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		if (atomic64_read(&entry->stats_last_sync_ns))
			snapshot->igs_active_nodes++;
		snapshot->igs_bytes = lanspeed_u64_add_sat(snapshot->igs_bytes,
					atomic64_read(&entry->stats_bytes));
		snapshot->igs_packets = lanspeed_u64_add_sat(snapshot->igs_packets,
					  atomic64_read(&entry->stats_packets));
		snapshot->igs_drops = lanspeed_u64_add_sat(snapshot->igs_drops,
					atomic64_read(&entry->stats_drops));
	}
	mutex_unlock(&lanspeed_igs_lock);
	snapshot->igs_sync_count = atomic64_read(&lanspeed_igs_sync_count);
	snapshot->igs_last_sync_ns = atomic64_read(&lanspeed_igs_last_sync_ns);
	snapshot->igs_cadence_samples =
		atomic64_read(&lanspeed_igs_cadence_samples);
	snapshot->igs_cadence_last_ns =
		atomic64_read(&lanspeed_igs_cadence_last_ns);
	snapshot->igs_cadence_min_ns =
		atomic64_read(&lanspeed_igs_cadence_min_ns);
	snapshot->igs_cadence_max_ns =
		atomic64_read(&lanspeed_igs_cadence_max_ns);
	snapshot->peer_generation = atomic64_read(&lanspeed_peer_generation);
	snapshot->peer_reassert_count = atomic64_read(&lanspeed_peer_reassert_count);
	snapshot->ack_latency_last_ns = atomic64_read(&lanspeed_ack_latency_last_ns);
	snapshot->ack_latency_max_ns = atomic64_read(&lanspeed_ack_latency_max_ns);
	snapshot->ack_received = atomic64_read(&lanspeed_ack_received);
	snapshot->ack_timeout = atomic64_read(&lanspeed_ack_timeout);
	snapshot->ack_late = atomic64_read(&lanspeed_ack_late);
	snapshot->control_generation = atomic64_read(&lanspeed_control_generation);
	snapshot->hardware_generation = atomic64_read(&lanspeed_hardware_generation);
}

int lanspeed_telemetry_get(char *buffer, const struct kernel_param *kp)
{
	struct lanspeed_telemetry_snapshot snapshot;

	lanspeed_telemetry_snapshot(&snapshot);
	return scnprintf(buffer, PAGE_SIZE,
			 "v1 sync_count=%lld last_sync_ns=%lld igs_bytes=%lld "
			 "igs_packets=%lld igs_drops=%lld peer_generation=%lld "
			 "peer_reassert=%lld ack_latency_last_ns=%lld "
			 "ack_latency_max_ns=%lld ack_received=%lld ack_timeout=%lld "
			 "ack_late=%lld control_generation=%lld hardware_generation=%lld\n",
			 (long long)snapshot.igs_sync_count,
			 (long long)snapshot.igs_last_sync_ns,
			 (long long)snapshot.igs_bytes,
			 (long long)snapshot.igs_packets,
			 (long long)snapshot.igs_drops,
			 (long long)snapshot.peer_generation,
			 (long long)snapshot.peer_reassert_count,
			 (long long)snapshot.ack_latency_last_ns,
			 (long long)snapshot.ack_latency_max_ns,
			 (long long)snapshot.ack_received,
			 (long long)snapshot.ack_timeout,
			 (long long)snapshot.ack_late,
			 (long long)snapshot.control_generation,
			 (long long)snapshot.hardware_generation);
}

int lanspeed_telemetry_cadence_get(char *buffer,
				   const struct kernel_param *kp)
{
	struct lanspeed_telemetry_snapshot snapshot;

	lanspeed_telemetry_snapshot(&snapshot);
	return scnprintf(buffer, PAGE_SIZE,
			 "v1 samples=%llu last_interval_ns=%llu min_interval_ns=%llu "
			 "max_interval_ns=%llu active_nodes=%u\n",
			 (unsigned long long)snapshot.igs_cadence_samples,
			 (unsigned long long)snapshot.igs_cadence_last_ns,
			 (unsigned long long)snapshot.igs_cadence_min_ns,
			 (unsigned long long)snapshot.igs_cadence_max_ns,
			 snapshot.igs_active_nodes);
}

static const struct kernel_param_ops lanspeed_ack_stats_ops = {
	.get = lanspeed_ack_stats_get,
};

static const struct kernel_param_ops lanspeed_telemetry_ops = {
	.get = lanspeed_telemetry_get,
};

static const struct kernel_param_ops lanspeed_telemetry_cadence_ops = {
	.get = lanspeed_telemetry_cadence_get,
};

module_param_cb(ack_stats, &lanspeed_ack_stats_ops, NULL, 0444);
MODULE_PARM_DESC(ack_stats, "LAN Speed NSS ACK transaction telemetry");
module_param_cb(telemetry, &lanspeed_telemetry_ops, NULL, 0444);
MODULE_PARM_DESC(telemetry, "LAN Speed NSS hardware and control telemetry");
module_param_cb(telemetry_cadence, &lanspeed_telemetry_cadence_ops, NULL, 0444);
MODULE_PARM_DESC(telemetry_cadence, "LAN Speed per-node NSS IGS sync cadence telemetry");
