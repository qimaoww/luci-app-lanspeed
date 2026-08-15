// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stage and publish a LAN Speed-owned IFB as a QCA NSS ingress-shaper node.
 * Userspace builds and verifies NSSHTB before this module atomically publishes
 * the physical-interface or Wi-Fi peer nexthop. Keeping the NSS transaction here
 * avoids the half-published window in the vendor nssmirred action. Rate policy and client
 * identity stay in lanspeedd; this module only owns the NSS redirect lifecycle.
 */

#include <linux/module.h>
#include <linux/mutex.h>

#include "lanspeed_nss_control.h"

LIST_HEAD(lanspeed_igs_entries);
DEFINE_MUTEX(lanspeed_igs_lock);

static int __init lanspeed_nss_control_init(void)
{
	int error;

	error = lanspeed_igs_register_notifier();
	if (error)
		return error;
	error = lanspeed_tag_register();
	if (error)
		lanspeed_igs_unregister_notifier();
	if (error)
		return error;
	error = lanspeed_genl_register();
	if (error) {
		lanspeed_tag_unregister();
		lanspeed_igs_unregister_notifier();
	}
	return error;
}

static void __exit lanspeed_nss_control_exit(void)
{
	lanspeed_genl_unregister();
	lanspeed_tag_unregister();
	lanspeed_igs_unregister_notifier();
	lanspeed_igs_cleanup();
	lanspeed_published_edges_cleanup();
	lanspeed_trusted_ingress_cleanup();
	rcu_barrier();
}

module_init(lanspeed_nss_control_init);
module_exit(lanspeed_nss_control_exit);

MODULE_DESCRIPTION("LAN Speed transactional QCA NSS IGS control");
MODULE_AUTHOR("LAN Speed contributors");
MODULE_LICENSE("GPL");
