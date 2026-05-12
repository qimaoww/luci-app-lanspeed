/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Userspace loader + tc attach + map reader for the lanspeedd BPF program.
 *
 * The BPF object file is produced by the optional lanspeedd-bpf package from
 * lanspeed_tc.bpf.c. This header exposes the small runtime surface that
 * lanspeedd.c uses to drive it.
 *
 * All functions are safe to call even when libbpf support is unavailable at
 * runtime (for example on installations that did not select lanspeedd-bpf).
 * In that case the initialiser simply records the reason and later calls
 * return error / empty results.
 */
#ifndef LANSPEED_BPF_H
#define LANSPEED_BPF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LANSPEED_BPF_DIR_TX 1
#define LANSPEED_BPF_DIR_RX 2

#define LANSPEED_BPF_TC_PREF 49152u
#define LANSPEED_BPF_TC_HANDLE 0x1eedu
#define LANSPEED_BPF_TC_EARLY_PREF 1u
#define LANSPEED_BPF_TC_EARLY_HANDLE 0x1eeeu

#define LANSPEED_BPF_ERROR_LEN 256

/*
 * Raw snapshot from a single BPF map entry. The daemon is responsible for
 * folding TX/RX into per-client rates and for merging the identity back to an
 * ARP/neighbour entry.
 */
struct lanspeed_bpf_sample {
	uint32_t ifindex;
	uint16_t vlan;
	uint8_t direction; /* LANSPEED_BPF_DIR_TX | LANSPEED_BPF_DIR_RX */
	uint8_t reserved;
	uint8_t mac[6];
	uint64_t bytes;
	uint64_t packets;
	uint64_t last_seen_ns;
	uint32_t tcp_conns;
	uint32_t udp_conns;
};

struct lanspeed_bpf_status {
	bool object_loaded;
	bool any_attached;
	size_t attached_hook_count;
	bool last_read_ok;
	bool last_read_attempted;
	uint64_t last_read_monotonic_ms;
	uint64_t last_attach_monotonic_ms;
	size_t last_sample_count;
	bool map_full_observed;
	char error[LANSPEED_BPF_ERROR_LEN];
	char object_path[256];
};

/*
 * Initialise the loader. Opens and loads the BPF object at object_path.
 * Returns true when the object was loaded (programs/maps available but not
 * yet attached). Returns false on any error; the reason is copied into the
 * internal status->error buffer. Calling init() twice is idempotent.
 */
bool lanspeed_bpf_init(const char *object_path);

/*
 * Detach all filters the daemon owns and release the loaded object. Safe to
 * call when init() was never called or failed.
 */
void lanspeed_bpf_shutdown(void);

/*
 * Attach both ingress and egress BPF programs to the named LAN edge
 * interface using LANSPEED_BPF_TC_PREF / LANSPEED_BPF_TC_HANDLE so init.d's
 * safety-net cleanup can identify owned filters.
 *
 * Returns 0 on success (both directions attached or already present) or a
 * negative errno-style value on failure. Partial attach is rolled back.
 */
int lanspeed_bpf_attach_iface(const char *ifname);

/*
 * Attach using the normal post-coexistence position, or an early
 * pass-through position for stacks such as daed that rewrite/redirect at TC
 * before lanspeed's default priority. The early sections return
 * TC_ACT_UNSPEC so later TC filters still run.
 */
int lanspeed_bpf_attach_iface_mode(const char *ifname, bool early_passthrough);

/*
 * Detach every filter this process has attached. Clsact qdiscs are NOT
 * destroyed so dae/SQM/qosify filters sharing the hook keep working.
 */
void lanspeed_bpf_detach_all(void);

/*
 * Read the current BPF map contents into `out` (at most `max` samples).
 * Updates internal status (last_read_ok, last_read_monotonic_ms, …). Returns
 * 0 on success with *count set, or negative errno on failure.
 */
int lanspeed_bpf_read_samples(struct lanspeed_bpf_sample *out, size_t max,
			      size_t *count);

/*
 * True iff the runtime currently satisfies the Full-mode gate:
 *  - BPF object loaded
 *  - At least one hook attached
 *  - A successful map read happened within `freshness_ms` milliseconds
 */
bool lanspeed_bpf_runtime_ok(uint64_t freshness_ms);

/* Internal status for evidence reporting. Always valid after any call. */
const struct lanspeed_bpf_status *lanspeed_bpf_get_status(void);

#ifdef __cplusplus
}
#endif

#endif /* LANSPEED_BPF_H */
