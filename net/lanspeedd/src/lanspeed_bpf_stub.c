/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Dynamic BPF runtime wrapper for builds that intentionally omit libbpf.
 *
 * The daemon keeps the same public surface so NSS direct / conntrack
 * collection paths remain unchanged. When lanspeedd-bpf is installed, this
 * wrapper loads the optional libbpf runtime plugin at runtime.
 */

#include "lanspeed_bpf.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define LANSPEED_BPF_PLUGIN_PATH "/usr/lib/lanspeed/lanspeed_bpf_plugin.so"

static struct lanspeed_bpf_status g_status;

struct lanspeed_bpf_plugin_api {
	bool (*init)(const char *object_path);
	void (*shutdown)(void);
	int (*attach_iface)(const char *ifname);
	int (*attach_iface_mode)(const char *ifname, bool early_passthrough);
	int (*detach_iface_mode)(const char *ifname, bool early_passthrough);
	int (*ensure_attached)(const char *ifname, bool early_passthrough,
			       const char *reason);
	void (*detach_all)(void);
	int (*read_samples)(struct lanspeed_bpf_sample *out, size_t max,
			    size_t *count);
	bool (*runtime_ok)(uint64_t freshness_ms);
	const struct lanspeed_bpf_status *(*get_status)(void);
};

static void *plugin_handle;
static struct lanspeed_bpf_plugin_api plugin_api;
static bool plugin_loaded;

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

static bool load_symbol(void **dst, const char *name)
{
	*dst = dlsym(plugin_handle, name);
	if (!*dst) {
		set_status_error("bpf_plugin_symbol_missing:%s", name);
		return false;
	}
	return true;
}

static bool load_plugin(void)
{
	if (plugin_loaded)
		return true;

	plugin_handle = dlopen(LANSPEED_BPF_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	if (!plugin_handle) {
		const char *error = dlerror();

		set_status_error("bpf_plugin_missing:%s",
				 error ? error : "unknown");
		return false;
	}

	if (!load_symbol((void **)&plugin_api.init, "lanspeed_bpf_plugin_init") ||
	    !load_symbol((void **)&plugin_api.shutdown, "lanspeed_bpf_plugin_shutdown") ||
	    !load_symbol((void **)&plugin_api.attach_iface, "lanspeed_bpf_plugin_attach_iface") ||
	    !load_symbol((void **)&plugin_api.attach_iface_mode, "lanspeed_bpf_plugin_attach_iface_mode") ||
	    !load_symbol((void **)&plugin_api.detach_iface_mode, "lanspeed_bpf_plugin_detach_iface_mode") ||
	    !load_symbol((void **)&plugin_api.ensure_attached, "lanspeed_bpf_plugin_ensure_attached") ||
	    !load_symbol((void **)&plugin_api.detach_all, "lanspeed_bpf_plugin_detach_all") ||
	    !load_symbol((void **)&plugin_api.read_samples, "lanspeed_bpf_plugin_read_samples") ||
	    !load_symbol((void **)&plugin_api.runtime_ok, "lanspeed_bpf_plugin_runtime_ok") ||
	    !load_symbol((void **)&plugin_api.get_status, "lanspeed_bpf_plugin_get_status")) {
		dlclose(plugin_handle);
		plugin_handle = NULL;
		memset(&plugin_api, 0, sizeof(plugin_api));
		return false;
	}

	plugin_loaded = true;
	return true;
}

const struct lanspeed_bpf_status *lanspeed_bpf_get_status(void)
{
	if (plugin_loaded && plugin_api.get_status)
		return plugin_api.get_status();
	return &g_status;
}

bool lanspeed_bpf_init(const char *object_path)
{
	memset(&g_status, 0, sizeof(g_status));
	if (!object_path || !*object_path) {
		set_status_error("bpf_object_path_empty");
		return false;
	}

	snprintf(g_status.object_path, sizeof(g_status.object_path), "%s",
		 object_path);

	if (!load_plugin()) {
		if (!g_status.error[0])
			record_unavailable(object_path);
		return false;
	}

	return plugin_api.init(object_path);
}

void lanspeed_bpf_shutdown(void)
{
	if (plugin_loaded && plugin_api.shutdown) {
		plugin_api.shutdown();
		dlclose(plugin_handle);
		plugin_handle = NULL;
		memset(&plugin_api, 0, sizeof(plugin_api));
		plugin_loaded = false;
	}
	clear_runtime_state();
}

int lanspeed_bpf_attach_iface_mode(const char *ifname, bool early_passthrough)
{
	if (plugin_loaded && plugin_api.attach_iface_mode)
		return plugin_api.attach_iface_mode(ifname, early_passthrough);

	record_unavailable(g_status.object_path);
	return -EOPNOTSUPP;
}

int lanspeed_bpf_attach_iface(const char *ifname)
{
	if (plugin_loaded && plugin_api.attach_iface)
		return plugin_api.attach_iface(ifname);
	return lanspeed_bpf_attach_iface_mode(ifname, false);
}

int lanspeed_bpf_detach_iface_mode(const char *ifname, bool early_passthrough)
{
	if (plugin_loaded && plugin_api.detach_iface_mode)
		return plugin_api.detach_iface_mode(ifname, early_passthrough);

	record_unavailable(g_status.object_path);
	return -EOPNOTSUPP;
}

int lanspeed_bpf_ensure_attached(const char *ifname, bool early_passthrough,
				 const char *reason)
{
	if (plugin_loaded && plugin_api.ensure_attached)
		return plugin_api.ensure_attached(ifname, early_passthrough, reason);

	record_unavailable(g_status.object_path);
	return -EOPNOTSUPP;
}

void lanspeed_bpf_detach_all(void)
{
	if (plugin_loaded && plugin_api.detach_all) {
		plugin_api.detach_all();
		return;
	}
	clear_runtime_state();
}

int lanspeed_bpf_read_samples(struct lanspeed_bpf_sample *out, size_t max,
			      size_t *count)
{
	if (plugin_loaded && plugin_api.read_samples)
		return plugin_api.read_samples(out, max, count);

	if (count)
		*count = 0;
	record_unavailable(g_status.object_path);
	g_status.last_read_attempted = true;
	return -EOPNOTSUPP;
}

bool lanspeed_bpf_runtime_ok(uint64_t freshness_ms)
{
	if (plugin_loaded && plugin_api.runtime_ok)
		return plugin_api.runtime_ok(freshness_ms);
	return false;
}
