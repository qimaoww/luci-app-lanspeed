// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include "lanspeed_nss_control.h"

#define LANSPEED_MAX_EDGE_DEVICES 64

struct lanspeed_trusted_ingress {
	struct rcu_head rcu;
	u16 count;
	struct net_device *edges[LANSPEED_MAX_EDGE_DEVICES];
};

static struct lanspeed_trusted_ingress lanspeed_empty_ingress;
static struct lanspeed_trusted_ingress __rcu *lanspeed_trusted_ingress =
	&lanspeed_empty_ingress;

static void lanspeed_trusted_ingress_free(struct rcu_head *rcu)
{
	struct lanspeed_trusted_ingress *set;
	u16 index;

	set = container_of(rcu, struct lanspeed_trusted_ingress, rcu);
	for (index = 0; index < set->count; index++)
		dev_put(set->edges[index]);
	kfree(set);
}

bool lanspeed_edge_add(struct net_device *edge)
{
	struct lanspeed_trusted_ingress *old;
	struct lanspeed_trusted_ingress *set;
	u16 index;

	old = rcu_dereference_protected(lanspeed_trusted_ingress,
					lockdep_is_held(&lanspeed_igs_lock));
	for (index = 0; index < old->count; index++) {
		if (old->edges[index] == edge)
			return true;
	}
	if (old->count >= LANSPEED_MAX_EDGE_DEVICES)
		return false;
	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return false;
	for (index = 0; index < old->count; index++) {
		set->edges[index] = old->edges[index];
		dev_hold(set->edges[index]);
	}
	set->edges[old->count] = edge;
	dev_hold(edge);
	set->count = old->count + 1;
	rcu_assign_pointer(lanspeed_trusted_ingress, set);
	if (old != &lanspeed_empty_ingress)
		call_rcu(&old->rcu, lanspeed_trusted_ingress_free);
	return true;
}

bool lanspeed_edge_del(struct net_device *edge)
{
	struct lanspeed_trusted_ingress *old;
	struct lanspeed_trusted_ingress *set;
	u16 index;
	u16 output = 0;

	old = rcu_dereference_protected(lanspeed_trusted_ingress,
					lockdep_is_held(&lanspeed_igs_lock));
	for (index = 0; index < old->count; index++) {
		if (old->edges[index] == edge)
			continue;
		output++;
	}
	if (output == old->count)
		return true;
	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set)
		return false;
	output = 0;
	for (index = 0; index < old->count; index++) {
		if (old->edges[index] == edge)
			continue;
		set->edges[output++] = old->edges[index];
		dev_hold(set->edges[output - 1]);
	}
	set->count = output;
	rcu_assign_pointer(lanspeed_trusted_ingress, set);
	if (old != &lanspeed_empty_ingress)
		call_rcu(&old->rcu, lanspeed_trusted_ingress_free);
	return true;
}

bool lanspeed_edge_published(struct net_device *edge)
{
	const struct lanspeed_trusted_ingress *set;
	u16 index;

	rcu_read_lock();
	set = rcu_dereference(lanspeed_trusted_ingress);
	for (index = 0; index < set->count; index++) {
		if (set->edges[index] == edge) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

void lanspeed_trusted_ingress_cleanup(void)
{
	struct lanspeed_trusted_ingress *old;

	old = rcu_dereference_protected(lanspeed_trusted_ingress,
					lockdep_is_held(&lanspeed_igs_lock));
	RCU_INIT_POINTER(lanspeed_trusted_ingress, &lanspeed_empty_ingress);
	if (old != &lanspeed_empty_ingress)
		call_rcu(&old->rcu, lanspeed_trusted_ingress_free);
}
