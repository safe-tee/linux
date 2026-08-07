// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS backend — KVM software planes
 *
 * Uses a KVM paravirt hypercall to communicate between plane-0 (the normal
 * guest kernel) and plane-1 (a secure kernel running in a separate KVM plane
 * managed by QEMU).
 *
 * Transport: kvm_hypercall1(KVM_HC_VBS_VTL_CALL, gpa) -> KVM_EXIT_HYPERCALL.
 *
 * The shared-memory VTL-call protocol is synchronous:
 *   1. Plane-0 fills the request buffer in the shared calling area.
 *   2. Plane-0 issues the hypercall carrying the physical address of the area.
 *   3. Plane-1 processes the request and writes a response.
 *   4. Plane-0 reads the response from the same page.
 *
 * This minimal backend implements only the plane lifecycle: init() loads
 * (connects to) the secure plane, shutdown() unloads it.
 */

#include "internal.h"

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/kvm_para.h>
#include <asm/kvm_para.h>

/* ── shared-memory calling area ────────────────────────────────────────── */

/*
 * Single shared page used for both request and response data.  The protocol
 * is synchronous, so no concurrent access is possible.
 *
 * Layout (within one 4 KiB page):
 *   [ call_pending | call_id | status | arg_size | resp_size | buffer ]
 */
struct vbs_kvm_ca {
	__u8	call_pending;	/* 1 while call is in flight            */
	__u8	rsvd[3];
	__u32	call_id;	/* enum vbs_call_id (set by caller)     */
	__s32	status;		/* return code (set by responder)       */
	__u32	arg_size;	/* request payload size                 */
	__u32	resp_size;	/* response payload size                */
	__u8	buffer[];	/* request data in, response data out   */
} __packed;

#define VBS_CA_BUF_SIZE (PAGE_SIZE - sizeof(struct vbs_kvm_ca))

static void *kvm_ca_page;	/* single calling-area page             */

/* ── low-level VTL call ────────────────────────────────────────────────── */

struct kvm_vtl_call_ctx {
	enum vbs_call_id id;
	const void	*arg;
	size_t		arg_size;
	void		*resp;
	size_t		resp_size;
};

/*
 * Issue the VTL-call hypercall.  MUST run on the BSP (CPU0): KVM switches
 * planes per logical CPU and the secure plane boots only on CPU0's sibling.
 * Driven via work_on_cpu() so the hypercall always lands on CPU0.
 */
static long kvm_planes_vtl_call_on_cpu(void *data)
{
	struct kvm_vtl_call_ctx *ctx = data;
	struct vbs_kvm_ca *ca = kvm_ca_page;
	long hc_ret;

	ca->call_id   = ctx->id;
	ca->arg_size  = ctx->arg_size;
	ca->status    = 0;
	ca->resp_size = 0;
	if (ctx->arg_size && ctx->arg)
		memcpy(ca->buffer, ctx->arg, ctx->arg_size);
	ca->call_pending = 1;

	hc_ret = kvm_hypercall1(KVM_HC_VBS_VTL_CALL, virt_to_phys(kvm_ca_page));
	ca->call_pending = 0;

	if (hc_ret) {
		pr_err_ratelimited("vbs-kvm: hypercall failed (%ld)\n", hc_ret);
		return -EIO;
	}

	if (ca->status)
		return ca->status;

	if (ctx->resp && ctx->resp_size && ca->resp_size) {
		size_t copy = min_t(size_t, ctx->resp_size, ca->resp_size);

		memcpy(ctx->resp, ca->buffer, copy);
	}
	return 0;
}

static int kvm_planes_vtl_call(enum vbs_call_id id,
			       const void *arg, size_t arg_size,
			       void *resp, size_t resp_size)
{
	struct kvm_vtl_call_ctx ctx = {
		.id        = id,
		.arg       = arg,
		.arg_size  = arg_size,
		.resp      = resp,
		.resp_size = resp_size,
	};

	if (!kvm_ca_page)
		return -ENOMEM;

	if (arg_size > VBS_CA_BUF_SIZE)
		return -E2BIG;

	/* Pin the plane switch to CPU0's secure sibling. */
	return work_on_cpu(0, kvm_planes_vtl_call_on_cpu, &ctx);
}

/* ── lifecycle: load / unload the secure plane ─────────────────────────── */

static int kvm_planes_init(void)
{
	int ret;

	kvm_ca_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!kvm_ca_page)
		return -ENOMEM;

	ret = kvm_planes_vtl_call(VBS_CALL_INIT, NULL, 0, NULL, 0);
	if (ret) {
		pr_err("vbs-kvm: plane-1 INIT call failed (%d)\n", ret);
		free_page((unsigned long)kvm_ca_page);
		kvm_ca_page = NULL;
		return ret;
	}

	pr_info("vbs-kvm: connected to plane-1 secure kernel\n");
	return 0;
}

static void kvm_planes_shutdown(void)
{
	if (!kvm_ca_page)
		return;

	kvm_planes_vtl_call(VBS_CALL_SHUTDOWN, NULL, 0, NULL, 0);
	free_page((unsigned long)kvm_ca_page);
	kvm_ca_page = NULL;
}

/* ── ops table & registration ──────────────────────────────────────────── */

static const struct vbs_ops kvm_planes_ops = {
	.name     = "kvm-planes",
	.init     = kvm_planes_init,
	.shutdown = kvm_planes_shutdown,
	.vtl_call = kvm_planes_vtl_call,
};

bool __init vbs_kvm_planes_detect(void)
{
	if (!kvm_para_available()) {
		pr_debug("vbs-kvm: KVM paravirt not available\n");
		return false;
	}
	return true;
}

const struct vbs_ops *vbs_kvm_planes_get_ops(void)
{
	return &kvm_planes_ops;
}
