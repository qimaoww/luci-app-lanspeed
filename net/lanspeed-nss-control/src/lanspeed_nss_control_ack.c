// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/slab.h>

#include <nss_api_if.h>
#include <nss_if.h>

#include "lanspeed_nss_control.h"

struct lanspeed_ack_txn {
	struct completion done;
	refcount_t refs;
	atomic_t completed;
	atomic_t callback_ref_released;
	enum nss_cmn_response response;
	u64 cookie;
	u64 started_ns;
	void *message;
};

static atomic64_t lanspeed_ack_cookie = ATOMIC64_INIT(0);

static void lanspeed_ack_release_callback_ref(struct lanspeed_ack_txn *txn)
{
	if (atomic_cmpxchg(&txn->callback_ref_released, 0, 1) == 0)
		lanspeed_ack_put(txn);
}

void lanspeed_ack_put(struct lanspeed_ack_txn *txn)
{
	if (refcount_dec_and_test(&txn->refs)) {
		module_put(THIS_MODULE);
		kfree(txn);
	}
}

struct lanspeed_ack_txn *lanspeed_ack_alloc(void)
{
	struct lanspeed_ack_txn *txn;

	txn = kzalloc(sizeof(*txn), GFP_KERNEL);
	if (!txn)
		return NULL;
	if (!try_module_get(THIS_MODULE)) {
		kfree(txn);
		return NULL;
	}
	init_completion(&txn->done);
	refcount_set(&txn->refs, 2);
	atomic_set(&txn->completed, 0);
	atomic_set(&txn->callback_ref_released, 0);
	txn->response = NSS_CMN_RESPONSE_LAST;
	txn->cookie = atomic64_inc_return(&lanspeed_ack_cookie);
	txn->started_ns = lanspeed_ack_started();
	return txn;
}

void lanspeed_ack_bind_message(struct lanspeed_ack_txn *txn, void *message)
{
	txn->message = message;
}

static void lanspeed_ack_release_message(struct lanspeed_ack_txn *txn)
{
	void *message = xchg(&txn->message, NULL);

	kfree(message);
}

void lanspeed_ack_callback(void *app_data, struct nss_cmn_msg *message)
{
	struct lanspeed_ack_txn *txn = app_data;

	if (!txn)
		return;
	if (atomic_cmpxchg(&txn->completed, 0, 1) == 0) {
		txn->response = message->response;
		lanspeed_ack_complete(txn->started_ns,
				      txn->response == NSS_CMN_RESPONSE_ACK);
		lanspeed_ack_release_message(txn);
		complete(&txn->done);
	} else {
		lanspeed_ack_late_event();
		lanspeed_ack_release_message(txn);
	}
	lanspeed_ack_release_callback_ref(txn);
}

int lanspeed_ack_wait(struct lanspeed_ack_txn *txn)
{
	if (!wait_for_completion_timeout(&txn->done,
					msecs_to_jiffies(NSS_IF_TX_TIMEOUT))) {
		if (atomic_cmpxchg(&txn->completed, 0, 1) == 0)
			lanspeed_ack_timeout_event();
		return -ETIMEDOUT;
	}
	return txn->response == NSS_CMN_RESPONSE_ACK ? 0 : -EIO;
}

void lanspeed_ack_abort(struct lanspeed_ack_txn *txn)
{
	if (atomic_cmpxchg(&txn->completed, 0, 1) == 0) {
		lanspeed_ack_release_message(txn);
		atomic_set(&txn->callback_ref_released, 1);
		lanspeed_ack_put(txn);
	}
}
