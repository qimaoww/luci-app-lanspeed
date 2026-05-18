/* SPDX-License-Identifier: Apache-2.0 */
/*
 * lanspeed_bpf.c — userspace loader + tc attach + map reader for lanspeedd.
 *
 * Design notes
 * ------------
 * - We deliberately never destroy the clsact qdisc. dae, SQM and qosify may
 *   share the same hook; destroying it would break them. Detach operates on
 *   our own filter only (identified by LANSPEED_BPF_TC_PREF / HANDLE).
 * - We attach with a fixed priority/handle so the init.d safety-net
 *   (owned-filter cleanup keyed off pref 49152 and handle 0x1eed) can remove
 *   orphaned filters if the daemon dies without cleaning up.
 * - This module is the ONLY place that includes <bpf/libbpf.h>. lanspeedd.c
 *   stays libbpf-free so the rest of the daemon compiles cleanly even if
 *   future variants want a dlopen-style runtime.
 */

#include "lanspeed_bpf.h"

#include <errno.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define LANSPEED_BPF_MAP_NAME "lanspeed_clients"
#define LANSPEED_BPF_PROG_INGRESS "lanspeed_ingress"
#define LANSPEED_BPF_PROG_EGRESS "lanspeed_egress"
#define LANSPEED_BPF_PROG_INGRESS_EARLY "lanspeed_ingress_early"
#define LANSPEED_BPF_PROG_EGRESS_EARLY "lanspeed_egress_early"
#define LANSPEED_BPF_MAX_ATTACHED 16

/*
 * Layout mirrors struct lanspeed_key from lanspeed_tc.bpf.c. Keep them in
 * sync: the kernel verifier enforces the size on lookup and the map key
 * must match the in-kernel layout byte-for-byte.
 */
struct lanspeed_bpf_key {
	uint32_t ifindex;
	uint16_t vlan_or_zone;
	uint8_t direction;
	uint8_t reserved;
	uint8_t mac[6];
};

struct lanspeed_bpf_value {
	uint64_t bytes;
	uint64_t packets;
	uint64_t last_seen;
	uint32_t tcp_conns;
	uint32_t udp_conns;
};

struct attached_hook {
	int ifindex;
	enum bpf_tc_attach_point point;
	uint32_t priority;
	uint32_t handle;
	bool created_hook;
};

struct lanspeed_bpf_state {
	struct bpf_object *obj;
	int ingress_prog_fd;
	int egress_prog_fd;
	int ingress_early_prog_fd;
	int egress_early_prog_fd;
	int map_fd;
	struct attached_hook attached[LANSPEED_BPF_MAX_ATTACHED];
	size_t attached_count;
	struct lanspeed_bpf_status status;
};

static struct lanspeed_bpf_state g_state;

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void set_status_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(g_state.status.error, sizeof(g_state.status.error), fmt, args);
	va_end(args);
}

static void reset_status(void)
{
	memset(&g_state.status, 0, sizeof(g_state.status));
}

static bool hook_tracked(int ifindex, enum bpf_tc_attach_point point,
			 uint32_t priority, uint32_t handle);

const struct lanspeed_bpf_status *lanspeed_bpf_get_status(void)
{
	return &g_state.status;
}

const struct lanspeed_bpf_status *lanspeed_bpf_plugin_get_status(void)
{
	return lanspeed_bpf_get_status();
}

bool lanspeed_bpf_init(const char *object_path)
{
	struct bpf_object *obj;
	struct bpf_program *ingress_prog;
	struct bpf_program *egress_prog;
	struct bpf_program *ingress_early_prog;
	struct bpf_program *egress_early_prog;
	struct bpf_map *map;
	int ingress_fd;
	int egress_fd;
	int ingress_early_fd;
	int egress_early_fd;
	int map_fd;

	if (g_state.obj)
		return true;

	reset_status();

	if (!object_path || !*object_path) {
		set_status_error("bpf_object_path_empty");
		return false;
	}

	strncpy(g_state.status.object_path, object_path,
		sizeof(g_state.status.object_path) - 1);

	if (access(object_path, R_OK) != 0) {
		set_status_error("bpf_object_missing:%s", strerror(errno));
		return false;
	}

	/* Quiet libbpf's default debug prints; we surface errors via status. */
	libbpf_set_print(NULL);

	obj = bpf_object__open_file(object_path, NULL);
	if (!obj || libbpf_get_error(obj)) {
		long err = obj ? libbpf_get_error(obj) : -errno;

		set_status_error("bpf_object_open_failed:%ld", err);
		if (obj)
			bpf_object__close(obj);
		return false;
	}

	if (bpf_object__load(obj) != 0) {
		set_status_error("bpf_object_load_failed:%s", strerror(errno));
		bpf_object__close(obj);
		return false;
	}

	ingress_prog = bpf_object__find_program_by_name(obj,
							LANSPEED_BPF_PROG_INGRESS);
	egress_prog = bpf_object__find_program_by_name(obj,
						       LANSPEED_BPF_PROG_EGRESS);
	ingress_early_prog = bpf_object__find_program_by_name(obj,
							      LANSPEED_BPF_PROG_INGRESS_EARLY);
	egress_early_prog = bpf_object__find_program_by_name(obj,
							     LANSPEED_BPF_PROG_EGRESS_EARLY);
	map = bpf_object__find_map_by_name(obj, LANSPEED_BPF_MAP_NAME);

	if (!ingress_prog || !egress_prog || !ingress_early_prog ||
	    !egress_early_prog || !map) {
		set_status_error("bpf_object_symbols_missing");
		bpf_object__close(obj);
		return false;
	}

	ingress_fd = bpf_program__fd(ingress_prog);
	egress_fd = bpf_program__fd(egress_prog);
	ingress_early_fd = bpf_program__fd(ingress_early_prog);
	egress_early_fd = bpf_program__fd(egress_early_prog);
	map_fd = bpf_map__fd(map);

	if (ingress_fd < 0 || egress_fd < 0 || ingress_early_fd < 0 ||
	    egress_early_fd < 0 || map_fd < 0) {
		set_status_error("bpf_object_fd_invalid");
		bpf_object__close(obj);
		return false;
	}

	g_state.obj = obj;
	g_state.ingress_prog_fd = ingress_fd;
	g_state.egress_prog_fd = egress_fd;
	g_state.ingress_early_prog_fd = ingress_early_fd;
	g_state.egress_early_prog_fd = egress_early_fd;
	g_state.map_fd = map_fd;
	g_state.status.object_loaded = true;

	return true;
}

bool lanspeed_bpf_plugin_init(const char *object_path)
{
	return lanspeed_bpf_init(object_path);
}

static int attach_point(const char *ifname, int ifindex,
			enum bpf_tc_attach_point point, int prog_fd,
			uint32_t priority, uint32_t handle, bool replace)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .ifindex = ifindex,
			    .attach_point = point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			    .prog_fd = prog_fd,
			    .handle = handle,
			    .priority = priority,
			    .flags = replace ? BPF_TC_F_REPLACE : 0);
	bool created_hook = false;
	int err;

	err = bpf_tc_hook_create(&hook);
	if (err == 0) {
		created_hook = true;
	} else if (err != -EEXIST) {
		set_status_error("tc_hook_create_failed:%s:%d", ifname, err);
		return err;
	}

	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		set_status_error("tc_attach_failed:%s:%d:%s", ifname,
				 (point == BPF_TC_INGRESS) ? 0 : 1,
				 strerror(-err));
		if (created_hook)
			(void)bpf_tc_hook_destroy(&hook);
		return err;
	}

	if (!hook_tracked(ifindex, point, priority, handle) &&
	    g_state.attached_count < LANSPEED_BPF_MAX_ATTACHED) {
		g_state.attached[g_state.attached_count].ifindex = ifindex;
		g_state.attached[g_state.attached_count].point = point;
		g_state.attached[g_state.attached_count].priority = priority;
		g_state.attached[g_state.attached_count].handle = handle;
		g_state.attached[g_state.attached_count].created_hook = created_hook;
		g_state.attached_count++;
	}

	return 0;
}

static bool hook_tracked(int ifindex, enum bpf_tc_attach_point point,
			 uint32_t priority, uint32_t handle)
{
	size_t i;

	for (i = 0; i < g_state.attached_count; i++) {
		if (g_state.attached[i].ifindex == ifindex &&
		    g_state.attached[i].point == point &&
		    g_state.attached[i].priority == priority &&
		    g_state.attached[i].handle == handle)
			return true;
	}

	return false;
}

static void detach_point(int ifindex, enum bpf_tc_attach_point point,
			 uint32_t priority, uint32_t handle)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .ifindex = ifindex,
			    .attach_point = point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			    .handle = handle,
			    .priority = priority);

	(void)bpf_tc_detach(&hook, &opts);
}

static void untrack_hook(int ifindex, enum bpf_tc_attach_point point,
			 uint32_t priority, uint32_t handle)
{
	size_t i;

	for (i = 0; i < g_state.attached_count; i++) {
		if (g_state.attached[i].ifindex == ifindex &&
		    g_state.attached[i].point == point &&
		    g_state.attached[i].priority == priority &&
		    g_state.attached[i].handle == handle) {
			if (i + 1 < g_state.attached_count)
				memmove(&g_state.attached[i], &g_state.attached[i + 1],
					(g_state.attached_count - i - 1) *
					sizeof(g_state.attached[0]));
			g_state.attached_count--;
			return;
		}
	}
}

static bool hook_present(int ifindex, enum bpf_tc_attach_point point,
			 uint32_t priority, uint32_t handle)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .ifindex = ifindex,
			    .attach_point = point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			    .handle = handle,
			    .priority = priority);

	return bpf_tc_query(&hook, &opts) == 0;
}

int lanspeed_bpf_attach_iface_mode(const char *ifname, bool early_passthrough)
{
	uint32_t ingress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF;
	uint32_t ingress_handle = early_passthrough ? LANSPEED_BPF_TC_EARLY_HANDLE : LANSPEED_BPF_TC_HANDLE;
	uint32_t egress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF;
	uint32_t egress_handle = early_passthrough ? LANSPEED_BPF_TC_EARLY_HANDLE : LANSPEED_BPF_TC_HANDLE;
	int ingress_fd = early_passthrough ? g_state.ingress_early_prog_fd :
					     g_state.ingress_prog_fd;
	int egress_fd = early_passthrough ? g_state.egress_early_prog_fd :
					    g_state.egress_prog_fd;
	int ifindex;
	int err;

	if (!g_state.obj) {
		set_status_error("bpf_object_not_loaded");
		return -ENOENT;
	}
	if (!ifname || !*ifname) {
		set_status_error("ifname_empty");
		return -EINVAL;
	}

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex <= 0) {
		set_status_error("if_nametoindex_failed:%s", ifname);
		return -errno;
	}

	err = attach_point(ifname, ifindex, BPF_TC_INGRESS, ingress_fd,
			   ingress_priority, ingress_handle, false);
	if (err)
		return err;

	if (!hook_present(ifindex, BPF_TC_EGRESS, egress_priority, egress_handle)) {
		err = attach_point(ifname, ifindex, BPF_TC_EGRESS, egress_fd,
				   egress_priority, egress_handle, false);
		if (err)
			return err;
	} else if (!hook_tracked(ifindex, BPF_TC_EGRESS, egress_priority, egress_handle) &&
		   g_state.attached_count < LANSPEED_BPF_MAX_ATTACHED) {
		g_state.attached[g_state.attached_count].ifindex = ifindex;
		g_state.attached[g_state.attached_count].point = BPF_TC_EGRESS;
		g_state.attached[g_state.attached_count].priority = egress_priority;
		g_state.attached[g_state.attached_count].handle = egress_handle;
		g_state.attached[g_state.attached_count].created_hook = false;
		g_state.attached_count++;
	}

	g_state.status.any_attached = true;
	g_state.status.attached_hook_count = g_state.attached_count;
	g_state.status.last_attach_monotonic_ms = monotonic_ms();
	return 0;
}

int lanspeed_bpf_attach_iface(const char *ifname)
{
	return lanspeed_bpf_attach_iface_mode(ifname, false);
}

int lanspeed_bpf_plugin_attach_iface(const char *ifname)
{
	return lanspeed_bpf_attach_iface(ifname);
}

int lanspeed_bpf_plugin_attach_iface_mode(const char *ifname,
					  bool early_passthrough)
{
	return lanspeed_bpf_attach_iface_mode(ifname, early_passthrough);
}

int lanspeed_bpf_detach_iface_mode(const char *ifname, bool early_passthrough)
{
	uint32_t ingress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF;
	uint32_t ingress_handle = early_passthrough ? LANSPEED_BPF_TC_EARLY_HANDLE : LANSPEED_BPF_TC_HANDLE;
	uint32_t egress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF;
	uint32_t egress_handle = early_passthrough ? LANSPEED_BPF_TC_EARLY_HANDLE : LANSPEED_BPF_TC_HANDLE;
	int ifindex;

	if (!g_state.obj) {
		set_status_error("bpf_object_not_loaded");
		return -ENOENT;
	}
	if (!ifname || !*ifname) {
		set_status_error("ifname_empty");
		return -EINVAL;
	}

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex <= 0) {
		set_status_error("if_nametoindex_failed:%s", ifname);
		return -errno;
	}

	detach_point(ifindex, BPF_TC_INGRESS, ingress_priority, ingress_handle);
	untrack_hook(ifindex, BPF_TC_INGRESS, ingress_priority, ingress_handle);
	detach_point(ifindex, BPF_TC_EGRESS, egress_priority, egress_handle);
	untrack_hook(ifindex, BPF_TC_EGRESS, egress_priority, egress_handle);

	g_state.status.any_attached = g_state.attached_count > 0;
	g_state.status.attached_hook_count = g_state.attached_count;
	return 0;
}

int lanspeed_bpf_plugin_detach_iface_mode(const char *ifname,
					  bool early_passthrough)
{
	return lanspeed_bpf_detach_iface_mode(ifname, early_passthrough);
}

int lanspeed_bpf_ensure_attached(const char *ifname, bool early_passthrough,
				 const char *reason)
{
	uint32_t ingress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF;
	uint32_t ingress_handle = early_passthrough ? LANSPEED_BPF_TC_EARLY_HANDLE : LANSPEED_BPF_TC_HANDLE;
	uint32_t egress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF;
	uint32_t egress_handle = early_passthrough ? LANSPEED_BPF_TC_EARLY_HANDLE : LANSPEED_BPF_TC_HANDLE;
	int ingress_fd = early_passthrough ? g_state.ingress_early_prog_fd :
					     g_state.ingress_prog_fd;
	int egress_fd = early_passthrough ? g_state.egress_early_prog_fd :
					    g_state.egress_prog_fd;
	int ifindex;
	int restored = 0;
	int err;

	if (!g_state.obj) {
		set_status_error("bpf_object_not_loaded");
		return -ENOENT;
	}
	if (!ifname || !*ifname) {
		set_status_error("ifname_empty");
		return -EINVAL;
	}

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex <= 0) {
		set_status_error("if_nametoindex_failed:%s", ifname);
		return -errno;
	}

	if (!hook_present(ifindex, BPF_TC_INGRESS, ingress_priority, ingress_handle)) {
		err = attach_point(ifname, ifindex, BPF_TC_INGRESS, ingress_fd,
				   ingress_priority, ingress_handle, false);
		if (err)
			return err;
		restored++;
	} else if (!hook_tracked(ifindex, BPF_TC_INGRESS, ingress_priority, ingress_handle) &&
		   g_state.attached_count < LANSPEED_BPF_MAX_ATTACHED) {
		g_state.attached[g_state.attached_count].ifindex = ifindex;
		g_state.attached[g_state.attached_count].point = BPF_TC_INGRESS;
		g_state.attached[g_state.attached_count].priority = ingress_priority;
		g_state.attached[g_state.attached_count].handle = ingress_handle;
		g_state.attached[g_state.attached_count].created_hook = false;
		g_state.attached_count++;
	}

	if (!hook_present(ifindex, BPF_TC_EGRESS, egress_priority, egress_handle)) {
		err = attach_point(ifname, ifindex, BPF_TC_EGRESS, egress_fd,
				   egress_priority, egress_handle, false);
		if (err)
			return err;
		restored++;
	} else if (!hook_tracked(ifindex, BPF_TC_EGRESS, egress_priority, egress_handle) &&
		   g_state.attached_count < LANSPEED_BPF_MAX_ATTACHED) {
		g_state.attached[g_state.attached_count].ifindex = ifindex;
		g_state.attached[g_state.attached_count].point = BPF_TC_EGRESS;
		g_state.attached[g_state.attached_count].priority = egress_priority;
		g_state.attached[g_state.attached_count].handle = egress_handle;
		g_state.attached[g_state.attached_count].created_hook = false;
		g_state.attached_count++;
	}

	if (restored > 0) {
		g_state.status.self_heal_count++;
		g_state.status.last_self_heal_monotonic_ms = monotonic_ms();
		snprintf(g_state.status.last_self_heal_reason,
			 sizeof(g_state.status.last_self_heal_reason),
			 "%s", reason && *reason ? reason : "owned_tc_filter_missing");
	}

	g_state.status.any_attached = g_state.attached_count > 0;
	g_state.status.attached_hook_count = g_state.attached_count;
	return restored > 0 ? 1 : 0;
}

int lanspeed_bpf_plugin_ensure_attached(const char *ifname,
					bool early_passthrough,
					const char *reason)
{
	return lanspeed_bpf_ensure_attached(ifname, early_passthrough, reason);
}

void lanspeed_bpf_detach_all(void)
{
	size_t i;

	for (i = 0; i < g_state.attached_count; i++) {
		DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
				    .ifindex = g_state.attached[i].ifindex,
				    .attach_point = g_state.attached[i].point);
		DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
				    .handle = LANSPEED_BPF_TC_EARLY_HANDLE,
				    .priority = LANSPEED_BPF_TC_EARLY_PREF);

		(void)bpf_tc_detach(&hook, &opts);
		opts.handle = LANSPEED_BPF_TC_HANDLE;
		opts.priority = LANSPEED_BPF_TC_PREF;
		(void)bpf_tc_detach(&hook, &opts);
		/*
		 * Intentionally do NOT tear down the clsact qdisc itself
		 * here: other components (dae, SQM, qosify) may be using the
		 * same hook. Leaving their filters and the shared clsact
		 * untouched is a hard requirement of this project.
		 */
	}

	g_state.attached_count = 0;
	g_state.status.any_attached = false;
	g_state.status.attached_hook_count = 0;
}

void lanspeed_bpf_plugin_detach_all(void)
{
	lanspeed_bpf_detach_all();
}

void lanspeed_bpf_shutdown(void)
{
	lanspeed_bpf_detach_all();
	if (g_state.obj) {
		bpf_object__close(g_state.obj);
		g_state.obj = NULL;
	}
	g_state.ingress_prog_fd = -1;
	g_state.egress_prog_fd = -1;
	g_state.ingress_early_prog_fd = -1;
	g_state.egress_early_prog_fd = -1;
	g_state.map_fd = -1;
	g_state.status.object_loaded = false;
}

void lanspeed_bpf_plugin_shutdown(void)
{
	lanspeed_bpf_shutdown();
}

int lanspeed_bpf_read_samples(struct lanspeed_bpf_sample *out, size_t max,
			      size_t *count)
{
	struct lanspeed_bpf_key cur_key;
	struct lanspeed_bpf_key next_key;
	struct lanspeed_bpf_value value;
	size_t written = 0;
	bool have_cur = false;
	int err;

	g_state.status.last_read_attempted = true;
	g_state.status.last_read_ok = false;
	g_state.status.last_sample_count = 0;

	if (count)
		*count = 0;

	if (!g_state.obj || g_state.map_fd < 0) {
		set_status_error("bpf_object_not_loaded");
		return -ENOENT;
	}
	if (!out || max == 0) {
		set_status_error("bpf_read_invalid_buffer");
		return -EINVAL;
	}

	memset(&cur_key, 0, sizeof(cur_key));

	for (;;) {
		err = bpf_map_get_next_key(g_state.map_fd,
					   have_cur ? &cur_key : NULL,
					   &next_key);
		if (err) {
			if (err == -ENOENT)
				break;
			set_status_error("bpf_map_get_next_key_failed:%d", err);
			return err;
		}

		if (bpf_map_lookup_elem(g_state.map_fd, &next_key, &value) == 0 &&
		    written < max) {
			out[written].ifindex = next_key.ifindex;
			out[written].vlan = next_key.vlan_or_zone;
			out[written].direction = next_key.direction;
			out[written].reserved = 0;
			memcpy(out[written].mac, next_key.mac, 6);
			out[written].bytes = value.bytes;
			out[written].packets = value.packets;
			out[written].last_seen_ns = value.last_seen;
			out[written].tcp_conns = value.tcp_conns;
			out[written].udp_conns = value.udp_conns;
			written++;
		}

		cur_key = next_key;
		have_cur = true;

		if (written >= max) {
			g_state.status.map_full_observed = true;
			break;
		}
	}

	if (count)
		*count = written;
	g_state.status.last_sample_count = written;
	g_state.status.last_read_ok = true;
	g_state.status.last_read_monotonic_ms = monotonic_ms();
	return 0;
}

int lanspeed_bpf_plugin_read_samples(struct lanspeed_bpf_sample *out,
				     size_t max, size_t *count)
{
	return lanspeed_bpf_read_samples(out, max, count);
}

bool lanspeed_bpf_runtime_ok(uint64_t freshness_ms)
{
	uint64_t now;

	if (!g_state.status.object_loaded)
		return false;
	if (!g_state.status.any_attached)
		return false;
	if (!g_state.status.last_read_ok)
		return false;
	if (freshness_ms == 0)
		return true;

	now = monotonic_ms();
	if (now < g_state.status.last_read_monotonic_ms)
		return false;
	return (now - g_state.status.last_read_monotonic_ms) <= freshness_ms;
}

bool lanspeed_bpf_plugin_runtime_ok(uint64_t freshness_ms)
{
	return lanspeed_bpf_runtime_ok(freshness_ms);
}
