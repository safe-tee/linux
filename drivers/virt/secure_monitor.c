// SPDX-License-Identifier: GPL-2.0-only
/*
 * secure_monitor - KVM VM-planes secure-plane monitor
 *
 * This is the secure-plane (plane >0) side of the VM-planes park/dispatch
 * handshake.  It lets an otherwise ordinary kernel act as the secure plane
 * (conventionally plane 1, though the index is not hard-coded) without pulling
 * in the full VBS stack (CONFIG_VBS).  Its single job is to hand control back
 * to the normal plane (plane 0) via the KVM_HC_VBS_VTL_RETURN hypercall and
 * then service VTL calls from the shared calling area.
 *
 * Control flow (all within plane 0's single KVM_RUN; see
 * arch/x86/kvm/x86.c __kvm_emulate_hypercall):
 *
 *   normal plane                   KVM                       secure plane
 *   ------------                   ---                       ------------
 *   fill calling area
 *   HC_VBS_VTL_CALL(ca_gpa) ─────▶ switch_plane ───────────▶ resume in
 *                                  (RAX := ca_gpa)            secmon_vtl_return()
 *                                                            dispatch(call_id)
 *                                                            write ca->status
 *   resume after VTL_CALL ◀─────── switch_plane ◀─────────── HC_VBS_VTL_RETURN
 *
 * All planes of a VM share the same memslots, so the secure plane sees the
 * same guest-physical address space as the normal plane and can read the
 * calling area directly.  Every VTL call is acknowledged as a no-op so the
 * normal plane can make progress; real per-call handlers are plumbed in
 * incrementally.
 *
 * Activated by the "secure_monitor" kernel command-line option; without it
 * this kernel boots normally and never parks.
 */

#define pr_fmt(fmt) "vbs-secmon: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_para.h>
#include <asm/kvm_para.h>

/*
 * Shared-memory calling area.  MUST match struct vbs_kvm_ca in
 * security/vbs/kvm_planes.c (the normal-plane <-> secure-plane wire ABI):
 *
 *   [ call_pending | call_id | status | arg_size | resp_size | buffer ]
 */
struct vbs_kvm_ca {
	__u8	call_pending;	/* 1 while call is in flight            */
	__u8	rsvd[3];
	__u32	call_id;	/* request id (set by caller)           */
	__s32	status;		/* return code (set by responder)       */
	__u32	arg_size;	/* request payload size                 */
	__u32	resp_size;	/* response payload size                */
	__u8	buffer[];	/* request data in, response data out   */
} __packed;

/* Set from the "secure_monitor" kernel command-line option. */
static bool secmon_active __ro_after_init;

static int __init secmon_setup(char *str)
{
	secmon_active = true;
	return 1;
}
__setup("secure_monitor", secmon_setup);

/*
 * Park the secure plane and hand control back to the normal plane.  On the
 * next VTL call KVM resumes us here with the calling-area GPA in the
 * hypercall return value (RAX).  @status is carried for tracing only; the
 * real result is already in the calling area.
 */
static u64 secmon_vtl_return(long status)
{
	return kvm_hypercall1(KVM_HC_VBS_VTL_RETURN, (unsigned long)status);
}

static int secmon_monitor_fn(void *unused)
{
	long status = 0;

	pr_info("secure monitor started\n");

	for (;;) {
		struct vbs_kvm_ca *ca;
		u64 ca_gpa;

		/* Park; resume with the next request's calling-area GPA. */
		ca_gpa = secmon_vtl_return(status);
		if (!ca_gpa) {
			status = -EINVAL;
			continue;
		}

		ca = memremap(ca_gpa, PAGE_SIZE, MEMREMAP_WB);
		if (!ca) {
			pr_err_ratelimited("failed to map calling area 0x%llx\n",
					   ca_gpa);
			status = -EFAULT;
			continue;
		}

		/*
		 * No handlers are plumbed in yet: acknowledge the call as a
		 * no-op so the normal plane can make progress.  Real per-call
		 * dispatch is added incrementally.
		 */
		pr_info_ratelimited("VTL call id=0x%x arg_size=%u (no-op)\n",
				    ca->call_id, ca->arg_size);
		ca->status    = 0;
		ca->resp_size = 0;
		status = 0;

		memunmap(ca);
	}

	return 0;
}

static int __init secmon_init(void)
{
	struct task_struct *t;

	if (!secmon_active)
		return 0;

	t = kthread_run(secmon_monitor_fn, NULL, "vbs-secmon");
	if (IS_ERR(t)) {
		pr_err("failed to start secure monitor: %ld\n", PTR_ERR(t));
		return PTR_ERR(t);
	}

	return 0;
}
late_initcall(secmon_init);
