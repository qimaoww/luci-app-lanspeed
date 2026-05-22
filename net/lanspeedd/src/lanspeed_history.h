/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LANSPEED_HISTORY_H
#define LANSPEED_HISTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <json-c/json.h>

#include "lanspeed_config.h"

#define LANSPEED_COVERAGE_WINDOW 16
#define LANSPEED_COVERAGE_MIN_WINDOW_MS 3000
#define LANSPEED_COVERAGE_MIN_DENOM_BYTES 524288ULL

struct lanspeed_coverage_sample {
	uint64_t ts_ms;
	uint64_t iface_rx_bytes;
	uint64_t iface_tx_bytes;
	uint64_t client_rx_bytes;
	uint64_t client_tx_bytes;
	bool iface_valid;
	bool client_valid;
};

struct lanspeed_coverage_ring {
	struct lanspeed_coverage_sample samples[LANSPEED_COVERAGE_WINDOW];
	size_t head;
	size_t count;
};

struct lanspeed_coverage_config {
	bool supported;
};

struct lanspeed_coverage_readers {
	bool (*read_iface_bytes)(void *arg, uint64_t *rx_out, uint64_t *tx_out);
	bool (*read_client_bytes)(void *arg, uint64_t *rx_out, uint64_t *tx_out);
	void *arg;
};

struct lanspeed_overview_sample {
	uint64_t ts_ms;
	uint64_t tx_bps;
	uint64_t rx_bps;
	uint32_t client_count;
	uint32_t active_clients;
	uint32_t tcp_conns;
	uint32_t udp_conns;
	uint32_t udp_dns_conns;
	uint32_t udp_other_conns;
};

struct lanspeed_overview_ring {
	struct lanspeed_overview_sample samples[LANSPEED_OVERVIEW_WINDOW];
	size_t head;
	size_t count;
};

struct lanspeed_overview_config {
	int overview_window_samples;
	uint64_t active_client_window_ms;
	uint64_t active_client_min_bps;
};

void lanspeed_coverage_reset(struct lanspeed_coverage_ring *ring);
void lanspeed_coverage_push_sample(struct lanspeed_coverage_ring *ring,
				   uint64_t now_ms,
				   const struct lanspeed_coverage_readers *readers);
void lanspeed_coverage_add_json(struct lanspeed_coverage_ring *ring,
				struct json_object *root,
				const struct lanspeed_coverage_config *config);

void lanspeed_overview_push_from_clients(struct lanspeed_overview_ring *ring,
					 struct json_object *root,
					 struct json_object *clients,
					 uint64_t now_ms,
					 const struct lanspeed_overview_config *config);
struct json_object *lanspeed_overview_to_json(const struct lanspeed_overview_ring *ring,
					      const struct lanspeed_overview_config *config);

#endif
