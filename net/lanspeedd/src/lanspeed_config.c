/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <string.h>

#include <uci.h>

#include "lanspeed_config.h"

static bool config_bool_value(const char *value)
{
	return value && (!strcmp(value, "1") || !strcmp(value, "true"));
}

void lanspeed_config_defaults(struct lanspeed_runtime_config *config)
{
	if (!config)
		return;

	memset(config, 0, sizeof(*config));
	config->refresh_interval_ms = DEFAULT_REFRESH_INTERVAL_MS;
	config->max_clients = DEFAULT_MAX_CLIENTS;
	config->active_client_window_ms = DEFAULT_ACTIVE_CLIENT_WINDOW_MS;
	config->active_client_min_bps = DEFAULT_ACTIVE_CLIENT_MIN_BPS;
	config->overview_window_samples = DEFAULT_OVERVIEW_WINDOW_SAMPLES;
	config->enable_conntrack_fallback = true;
	config->rate_collector_mode = COLLECTOR_MODE_AUTO;
	config->conn_collector_mode = COLLECTOR_MODE_AUTO;
}

const char *collector_mode_name(enum collector_mode_setting mode)
{
	switch (mode) {
	case COLLECTOR_MODE_BPF:
		return "bpf";
	case COLLECTOR_MODE_NSS_ECM_DIRECT:
		return NSS_ECM_DIRECT_SOURCE;
	case COLLECTOR_MODE_NSS_CONNTRACK_SYNC:
		return "nss_conntrack_sync";
	case COLLECTOR_MODE_CONNTRACK_NETLINK:
		return CONNTRACK_NETLINK_SOURCE;
	case COLLECTOR_MODE_CONNTRACK_PROCFS:
		return CONNTRACK_PROCFS_SOURCE;
	case COLLECTOR_MODE_AUTO:
	default:
		return "auto";
	}
}

enum collector_mode_setting parse_rate_collector_mode(const char *value,
						      enum collector_mode_setting fallback)
{
	if (!value)
		return fallback;
	if (!strcmp(value, "bpf"))
		return COLLECTOR_MODE_BPF;
	if (!strcmp(value, NSS_ECM_DIRECT_SOURCE))
		return COLLECTOR_MODE_NSS_ECM_DIRECT;
	if (!strcmp(value, "nss_conntrack_sync") ||
	    !strcmp(value, "conntrack_ecm_sync"))
		return COLLECTOR_MODE_NSS_CONNTRACK_SYNC;
	if (!strcmp(value, "auto"))
		return COLLECTOR_MODE_AUTO;
	return fallback;
}

enum collector_mode_setting parse_conn_collector_mode(const char *value,
						      enum collector_mode_setting fallback)
{
	if (!value)
		return fallback;
	if (!strcmp(value, CONNTRACK_NETLINK_SOURCE))
		return COLLECTOR_MODE_CONNTRACK_NETLINK;
	if (!strcmp(value, CONNTRACK_PROCFS_SOURCE))
		return COLLECTOR_MODE_CONNTRACK_PROCFS;
	if (!strcmp(value, "auto"))
		return COLLECTOR_MODE_AUTO;
	return fallback;
}

void lanspeed_config_apply_legacy_collector_mode(struct lanspeed_runtime_config *config,
						 const char *value)
{
	if (!config || !value)
		return;
	if (!strcmp(value, "bpf")) {
		config->rate_collector_mode = COLLECTOR_MODE_BPF;
		return;
	}
	if (!strcmp(value, CONNTRACK_NETLINK_SOURCE)) {
		config->conn_collector_mode = COLLECTOR_MODE_CONNTRACK_NETLINK;
		return;
	}
	if (!strcmp(value, CONNTRACK_PROCFS_SOURCE)) {
		config->conn_collector_mode = COLLECTOR_MODE_CONNTRACK_PROCFS;
		return;
	}
	if (!strcmp(value, "auto")) {
		config->rate_collector_mode = COLLECTOR_MODE_AUTO;
		config->conn_collector_mode = COLLECTOR_MODE_AUTO;
	}
}

void lanspeed_config_load_uci(struct lanspeed_runtime_config *config,
			      struct uci_context *uci)
{
	struct uci_ptr ptr;
	char value[32];
	char refresh_path[] = "lanspeed.main.refresh_interval_ms";
	char active_window_path[] = "lanspeed.main.active_client_window_ms";
	char active_min_bps_path[] = "lanspeed.main.active_client_min_bps";
	char overview_window_path[] = "lanspeed.main.overview_window_samples";
	char max_clients_path[] = "lanspeed.main.max_clients";
	char collector_mode_path[] = "lanspeed.main.collector_mode";
	char rate_collector_mode_path[] = "lanspeed.main.rate_collector_mode";
	char conn_collector_mode_path[] = "lanspeed.main.conn_collector_mode";
	char bpf_path[] = "lanspeed.main.enable_bpf";
	char fallback_path[] = "lanspeed.main.enable_conntrack_fallback";

	if (!config)
		return;

	lanspeed_config_defaults(config);
	if (!uci)
		return;

	if (!uci_lookup_ptr(uci, &ptr, refresh_path, true) && ptr.o && ptr.o->v.string) {
		int parsed = atoi(ptr.o->v.string);

		if (parsed >= MIN_REFRESH_INTERVAL_MS)
			config->refresh_interval_ms = parsed;
		else if (parsed > 0) {
			config->refresh_interval_ms = MIN_REFRESH_INTERVAL_MS;
			config->refresh_interval_clamped = true;
		}
	}

	if (!uci_lookup_ptr(uci, &ptr, active_window_path, true) && ptr.o && ptr.o->v.string) {
		unsigned long long parsed = strtoull(ptr.o->v.string, NULL, 10);

		if (parsed >= MIN_ACTIVE_CLIENT_WINDOW_MS)
			config->active_client_window_ms = (uint64_t)parsed;
		else if (parsed > 0) {
			config->active_client_window_ms = MIN_ACTIVE_CLIENT_WINDOW_MS;
			config->active_client_window_clamped = true;
		}
	}

	if (!uci_lookup_ptr(uci, &ptr, active_min_bps_path, true) && ptr.o && ptr.o->v.string) {
		unsigned long long parsed = strtoull(ptr.o->v.string, NULL, 10);

		if (parsed >= DEFAULT_ACTIVE_CLIENT_MIN_BPS)
			config->active_client_min_bps = (uint64_t)parsed;
		else {
			config->active_client_min_bps = DEFAULT_ACTIVE_CLIENT_MIN_BPS;
			config->active_client_min_bps_clamped = true;
		}
	}

	if (!uci_lookup_ptr(uci, &ptr, overview_window_path, true) && ptr.o && ptr.o->v.string) {
		int parsed = atoi(ptr.o->v.string);

		if (parsed >= MIN_OVERVIEW_WINDOW_SAMPLES &&
		    parsed <= LANSPEED_OVERVIEW_WINDOW)
			config->overview_window_samples = parsed;
		else if (parsed > 0) {
			config->overview_window_samples = parsed < MIN_OVERVIEW_WINDOW_SAMPLES ?
				MIN_OVERVIEW_WINDOW_SAMPLES : LANSPEED_OVERVIEW_WINDOW;
			config->overview_window_samples_clamped = true;
		}
	}

	if (!uci_lookup_ptr(uci, &ptr, max_clients_path, true) && ptr.o && ptr.o->v.string) {
		int parsed = atoi(ptr.o->v.string);

		if (parsed >= 0)
			config->max_clients = parsed;
	}

	if (!uci_lookup_ptr(uci, &ptr, collector_mode_path, true) && ptr.o && ptr.o->v.string) {
		strncpy(value, ptr.o->v.string, sizeof(value) - 1);
		value[sizeof(value) - 1] = '\0';
		lanspeed_config_apply_legacy_collector_mode(config, value);
	}

	if (!uci_lookup_ptr(uci, &ptr, rate_collector_mode_path, true) && ptr.o && ptr.o->v.string) {
		strncpy(value, ptr.o->v.string, sizeof(value) - 1);
		value[sizeof(value) - 1] = '\0';
		config->rate_collector_mode =
			parse_rate_collector_mode(value, config->rate_collector_mode);
	}

	if (!uci_lookup_ptr(uci, &ptr, conn_collector_mode_path, true) && ptr.o && ptr.o->v.string) {
		strncpy(value, ptr.o->v.string, sizeof(value) - 1);
		value[sizeof(value) - 1] = '\0';
		config->conn_collector_mode =
			parse_conn_collector_mode(value, config->conn_collector_mode);
	}

	if (!uci_lookup_ptr(uci, &ptr, bpf_path, true) && ptr.o && ptr.o->v.string) {
		strncpy(value, ptr.o->v.string, sizeof(value) - 1);
		value[sizeof(value) - 1] = '\0';
		config->enable_bpf = config_bool_value(value);
	}

	if (!uci_lookup_ptr(uci, &ptr, fallback_path, true) && ptr.o && ptr.o->v.string) {
		strncpy(value, ptr.o->v.string, sizeof(value) - 1);
		value[sizeof(value) - 1] = '\0';
		config->enable_conntrack_fallback = config_bool_value(value);
	}

}

void lanspeed_config_load(struct lanspeed_runtime_config *config)
{
	struct uci_context *uci = uci_alloc_context();

	lanspeed_config_load_uci(config, uci);
	if (uci)
		uci_free_context(uci);
}
