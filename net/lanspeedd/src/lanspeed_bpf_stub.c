/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Stub BPF runtime for builds that intentionally omit libbpf.
 *
 * The daemon keeps the same public surface so NSS direct / conntrack
 * collection paths remain unchanged. Every BPF operation simply reports that
 * the optional runtime loader is unavailable.
 */

#include "lanspeed_bpf.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static struct lanspeed_bpf_status g_status;

static void set_status_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(g_status.error, sizeof(g_status.error), fmt, args);
	va_end(args);
}

static void clear_runtime_state(void)
{
	g_status.object_loaded = false;
	g_status.any_attached = false;
	g_status.attached_hook_count = 0;
	g_status.last_read_ok = false;
	g_status.last_read_attempted = false;
	g_status.last_read_monotonic_ms = 0;
	g_status.last_attach_monotonic_ms = 0;
	g_status.last_sample_count = 0;
	g_status.map_full_observed = false;
	g_status.self_heal_count = 0;
	g_status.last_self_heal_monotonic_ms = 0;
	g_status.last_self_heal_reason[0] = '\0';
}

static void record_unavailable(const char *object_path)
{
	if (object_path && *object_path) {
		snprintf(g_status.object_path, sizeof(g_status.object_path),
			 "%s", object_path);
	} else {
		g_status.object_path[0] = '\0';
	}
	clear_runtime_state();
	set_status_error("bpf_runtime_loader_unavailable");
}

const struct lanspeed_bpf_status *lanspeed_bpf_get_status(void)
{
	return &g_status;
}

bool lanspeed_bpf_init(const char *object_path)
{
	memset(&g_status, 0, sizeof(g_status));
	if (!object_path || !*object_path) {
		set_status_error("bpf_object_path_empty");
		return false;
	}

	record_unavailable(object_path);
	return false;
}

void lanspeed_bpf_shutdown(void)
{
	clear_runtime_state();
}

int lanspeed_bpf_attach_iface_mode(const char *ifname, bool early_passthrough)
{
	(void)ifname;
	(void)early_passthrough;

	record_unavailable(g_status.object_path);
	return -EOPNOTSUPP;
}

int lanspeed_bpf_attach_iface(const char *ifname)
{
	return lanspeed_bpf_attach_iface_mode(ifname, false);
}

int lanspeed_bpf_detach_iface_mode(const char *ifname, bool early_passthrough)
{
	(void)ifname;
	(void)early_passthrough;

	record_unavailable(g_status.object_path);
	return -EOPNOTSUPP;
}

int lanspeed_bpf_ensure_attached(const char *ifname, bool early_passthrough,
				 const char *reason)
{
	(void)ifname;
	(void)early_passthrough;
	(void)reason;

	record_unavailable(g_status.object_path);
	return -EOPNOTSUPP;
}

void lanspeed_bpf_detach_all(void)
{
	clear_runtime_state();
}

int lanspeed_bpf_read_samples(struct lanspeed_bpf_sample *out, size_t max,
			      size_t *count)
{
	(void)out;
	(void)max;

	if (count)
		*count = 0;
	record_unavailable(g_status.object_path);
	g_status.last_read_attempted = true;
	return -EOPNOTSUPP;
}

bool lanspeed_bpf_runtime_ok(uint64_t freshness_ms)
{
	(void)freshness_ms;
	return false;
}
