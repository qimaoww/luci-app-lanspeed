/* SPDX-License-Identifier: Apache-2.0 */
#include <string.h>

#include "lanspeed_history.h"

static uint64_t json_uint64_value(struct json_object *obj)
{
	int64_t value;

	if (!obj)
		return 0;
	value = json_object_get_int64(obj);
	return value > 0 ? (uint64_t)value : 0;
}

static bool client_is_active_recent(uint64_t sample_ms, uint64_t last_seen_ms,
				    const struct lanspeed_overview_config *config)
{
	if (!config || sample_ms == 0 || last_seen_ms == 0 || last_seen_ms > sample_ms)
		return false;
	return sample_ms - last_seen_ms <= config->active_client_window_ms;
}

static bool client_has_active_rate(uint64_t tx_bps, uint64_t rx_bps,
				   const struct lanspeed_overview_config *config)
{
	uint64_t total = tx_bps + rx_bps;

	if (!config)
		return false;
	if (total < tx_bps)
		total = UINT64_MAX;
	return total >= config->active_client_min_bps;
}

void lanspeed_coverage_reset(struct lanspeed_coverage_ring *ring)
{
	if (!ring)
		return;
	memset(ring, 0, sizeof(*ring));
}

void lanspeed_coverage_push_sample(struct lanspeed_coverage_ring *ring,
				   uint64_t now_ms,
				   const struct lanspeed_coverage_readers *readers)
{
	struct lanspeed_coverage_sample *slot;
	uint64_t irx = 0, itx = 0, crx = 0, ctx_bytes = 0;

	if (!ring || !readers)
		return;

	slot = &ring->samples[ring->head];
	slot->ts_ms = now_ms;
	slot->iface_valid = readers->read_iface_bytes &&
		readers->read_iface_bytes(readers->arg, &irx, &itx);
	slot->iface_rx_bytes = irx;
	slot->iface_tx_bytes = itx;
	slot->client_valid = readers->read_client_bytes &&
		readers->read_client_bytes(readers->arg, &crx, &ctx_bytes);
	slot->client_rx_bytes = crx;
	slot->client_tx_bytes = ctx_bytes;

	ring->head = (ring->head + 1) % LANSPEED_COVERAGE_WINDOW;
	if (ring->count < LANSPEED_COVERAGE_WINDOW)
		ring->count++;
}

static const struct lanspeed_coverage_sample *coverage_sample_at(
	const struct lanspeed_coverage_ring *ring, size_t idx_back)
{
	size_t offset;

	if (!ring || idx_back >= ring->count)
		return NULL;
	offset = (ring->head + LANSPEED_COVERAGE_WINDOW - 1 - idx_back) %
		 LANSPEED_COVERAGE_WINDOW;
	return &ring->samples[offset];
}

void lanspeed_coverage_add_json(struct lanspeed_coverage_ring *ring,
				struct json_object *root,
				const struct lanspeed_coverage_config *config)
{
	struct json_object *cov = json_object_new_object();
	const struct lanspeed_coverage_sample *newest = coverage_sample_at(ring, 0);
	const struct lanspeed_coverage_sample *oldest = NULL;
	size_t i;
	uint64_t window_ms = 0;
	uint64_t di_rx = 0, di_tx = 0, dc_rx = 0, dc_tx = 0;
	int pct_tx = -1, pct_rx = -1;
	const char *quality = "warmup";
	size_t sample_count = ring ? ring->count : 0;

	if (!config || !config->supported) {
		json_object_object_add(cov, "quality",
				       json_object_new_string("unsupported"));
		json_object_object_add(cov, "samples",
				       json_object_new_int((int)sample_count));
		json_object_object_add(root, "coverage", cov);
		return;
	}

	for (i = sample_count; i > 0; i--) {
		const struct lanspeed_coverage_sample *s = coverage_sample_at(ring, i - 1);
		if (s && s->iface_valid && s->client_valid) {
			oldest = s;
			break;
		}
	}

	if (newest && oldest && newest != oldest &&
	    newest->iface_valid && newest->client_valid &&
	    newest->ts_ms > oldest->ts_ms) {
		window_ms = newest->ts_ms - oldest->ts_ms;
		if (newest->iface_rx_bytes >= oldest->iface_rx_bytes &&
		    newest->iface_tx_bytes >= oldest->iface_tx_bytes &&
		    newest->client_rx_bytes >= oldest->client_rx_bytes &&
		    newest->client_tx_bytes >= oldest->client_tx_bytes) {
			di_rx = newest->iface_rx_bytes - oldest->iface_rx_bytes;
			di_tx = newest->iface_tx_bytes - oldest->iface_tx_bytes;
			dc_rx = newest->client_rx_bytes - oldest->client_rx_bytes;
			dc_tx = newest->client_tx_bytes - oldest->client_tx_bytes;

			if (window_ms < LANSPEED_COVERAGE_MIN_WINDOW_MS) {
				quality = "warmup";
			} else if (di_rx + di_tx < LANSPEED_COVERAGE_MIN_DENOM_BYTES) {
				quality = "idle";
			} else {
				if (di_rx > 0) {
					uint64_t p = dc_tx * 100ULL / di_rx;
					pct_tx = (int)(p > 100 ? 100 : p);
				}
				if (di_tx > 0) {
					uint64_t p = dc_rx * 100ULL / di_tx;
					pct_rx = (int)(p > 100 ? 100 : p);
				}
				quality = "ok";
			}
		} else {
			quality = "counter_reset";
			lanspeed_coverage_reset(ring);
			sample_count = 0;
		}
	}

	json_object_object_add(cov, "quality", json_object_new_string(quality));
	json_object_object_add(cov, "samples",
			       json_object_new_int((int)sample_count));
	json_object_object_add(cov, "window_ms",
			       json_object_new_int64((int64_t)window_ms));
	if (pct_tx >= 0)
		json_object_object_add(cov, "tx_pct", json_object_new_int(pct_tx));
	if (pct_rx >= 0)
		json_object_object_add(cov, "rx_pct", json_object_new_int(pct_rx));
	json_object_object_add(cov, "denom_rx_bytes",
			       json_object_new_int64((int64_t)di_rx));
	json_object_object_add(cov, "denom_tx_bytes",
			       json_object_new_int64((int64_t)di_tx));
	json_object_object_add(cov, "numer_rx_bytes",
			       json_object_new_int64((int64_t)dc_rx));
	json_object_object_add(cov, "numer_tx_bytes",
			       json_object_new_int64((int64_t)dc_tx));

	json_object_object_add(root, "coverage", cov);
}

void lanspeed_overview_push_from_clients(struct lanspeed_overview_ring *ring,
					 struct json_object *root,
					 struct json_object *clients,
					 uint64_t now_ms,
					 const struct lanspeed_overview_config *config)
{
	struct lanspeed_overview_sample *slot;
	struct json_object *obj = NULL;
	uint64_t tx = 0, rx = 0;
	uint64_t tcp_total = 0, udp_total = 0;
	uint64_t udp_dns_total = 0, udp_other_total = 0;
	size_t i, n;

	if (!ring || !config)
		return;

	slot = &ring->samples[ring->head];
	memset(slot, 0, sizeof(*slot));
	slot->ts_ms = now_ms;

	if (clients) {
		n = json_object_array_length(clients);
		slot->client_count = (uint32_t)n;
		for (i = 0; i < n; i++) {
			struct json_object *client = json_object_array_get_idx(clients, i);
			struct json_object *value = NULL;
			uint64_t client_tx = 0, client_rx = 0;
			uint64_t client_sample_ms = 0, client_last_seen_ms = 0;

			if (!client)
				continue;
			if (json_object_object_get_ex(client, "tx_bps", &value))
				client_tx = json_uint64_value(value);
			if (json_object_object_get_ex(client, "rx_bps", &value))
				client_rx = json_uint64_value(value);
			tx += client_tx;
			rx += client_rx;
			if (json_object_object_get_ex(client, "sample_ms", &value))
				client_sample_ms = json_uint64_value(value);
			if (json_object_object_get_ex(client, "last_seen", &value))
				client_last_seen_ms = json_uint64_value(value);
			if (client_has_active_rate(client_tx, client_rx, config) &&
			    client_is_active_recent(client_sample_ms, client_last_seen_ms, config))
				slot->active_clients++;
			if (json_object_object_get_ex(client, "tcp_conns", &value))
				tcp_total += json_uint64_value(value);
			if (json_object_object_get_ex(client, "udp_conns", &value))
				udp_total += json_uint64_value(value);
			if (json_object_object_get_ex(client, "udp_dns_conns", &value))
				udp_dns_total += json_uint64_value(value);
			if (json_object_object_get_ex(client, "udp_other_conns", &value))
				udp_other_total += json_uint64_value(value);
		}
	}

	if (root) {
		if (json_object_object_get_ex(root, "tcp_conns_total", &obj))
			tcp_total = json_uint64_value(obj);
		if (json_object_object_get_ex(root, "udp_conns_total", &obj))
			udp_total = json_uint64_value(obj);
		if (json_object_object_get_ex(root, "udp_dns_conns_total", &obj))
			udp_dns_total = json_uint64_value(obj);
		if (json_object_object_get_ex(root, "udp_other_conns_total", &obj))
			udp_other_total = json_uint64_value(obj);
	}

	slot->tx_bps = tx;
	slot->rx_bps = rx;
	slot->tcp_conns = (uint32_t)tcp_total;
	slot->udp_conns = (uint32_t)udp_total;
	slot->udp_dns_conns = (uint32_t)udp_dns_total;
	slot->udp_other_conns = (uint32_t)udp_other_total;

	ring->head = (ring->head + 1) % LANSPEED_OVERVIEW_WINDOW;
	if (ring->count < LANSPEED_OVERVIEW_WINDOW)
		ring->count++;
}

static const struct lanspeed_overview_sample *overview_sample_at(
	const struct lanspeed_overview_ring *ring, size_t idx_back)
{
	size_t offset;

	if (!ring || idx_back >= ring->count)
		return NULL;
	offset = (ring->head + LANSPEED_OVERVIEW_WINDOW - 1 - idx_back) %
		 LANSPEED_OVERVIEW_WINDOW;
	return &ring->samples[offset];
}

struct json_object *lanspeed_overview_to_json(const struct lanspeed_overview_ring *ring,
					      const struct lanspeed_overview_config *config)
{
	struct json_object *root = json_object_new_object();
	struct json_object *samples = json_object_new_array();
	size_t i;
	size_t count = ring ? ring->count : 0;

	for (i = count; i > 0; i--) {
		const struct lanspeed_overview_sample *s = overview_sample_at(ring, i - 1);
		struct json_object *sample;

		if (config && i > (size_t)config->overview_window_samples)
			continue;
		if (!s)
			continue;
		sample = json_object_new_object();
		json_object_object_add(sample, "sample_ms", json_object_new_int64((int64_t)s->ts_ms));
		json_object_object_add(sample, "tx_bps", json_object_new_int64((int64_t)s->tx_bps));
		json_object_object_add(sample, "rx_bps", json_object_new_int64((int64_t)s->rx_bps));
		json_object_object_add(sample, "client_count", json_object_new_int((int)s->client_count));
		json_object_object_add(sample, "active_clients", json_object_new_int((int)s->active_clients));
		json_object_object_add(sample, "tcp_conns", json_object_new_int((int)s->tcp_conns));
		json_object_object_add(sample, "udp_conns", json_object_new_int((int)s->udp_conns));
		json_object_object_add(sample, "udp_dns_conns", json_object_new_int((int)s->udp_dns_conns));
		json_object_object_add(sample, "udp_other_conns", json_object_new_int((int)s->udp_other_conns));
		json_object_array_add(samples, sample);
	}

	json_object_object_add(root, "samples", samples);
	json_object_object_add(root, "max_samples",
			       json_object_new_int(LANSPEED_OVERVIEW_WINDOW));
	json_object_object_add(root, "overview_window_samples",
			       json_object_new_int(config ? config->overview_window_samples : 0));
	json_object_object_add(root, "active_client_window_ms",
			       json_object_new_int64((int64_t)(config ? config->active_client_window_ms : 0)));
	json_object_object_add(root, "active_client_min_bps",
			       json_object_new_int64((int64_t)(config ? config->active_client_min_bps : 0)));
	json_object_object_add(root, "sample_source",
			       json_object_new_string("clients_refresh_daemon_ring"));
	json_object_object_add(root, "conn_semantics",
			       json_object_new_string("conntrack_current_tcp_established_assured_udp_assured_dns_split"));

	return root;
}
