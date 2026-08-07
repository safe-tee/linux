/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VBS — Virtualization-Based Security
 *
 * Transport-agnostic interface between the guest OS (plane-0) and a secure
 * kernel running in a higher-privileged plane-1.  The guest kernel calls the
 * vbs_*() functions; the active backend translates them into the appropriate
 * transport (e.g. a KVM paravirt hypercall).
 *
 * This is the core framework only.  VBS is software-only: backends are
 * software/hypervisor planes (KVM software planes now, Hyper-V VSM later).
 * Backends register via vbs_register_backend().
 */

#ifndef _LINUX_VBS_H
#define _LINUX_VBS_H

#include <linux/types.h>
#include <linux/errno.h>

/* VTL-call request codes (plane-0 -> plane-1 direction). */
enum vbs_call_id {
	VBS_CALL_INIT		= 0x0001, /* plane-0 boot complete: load plane */
	VBS_CALL_SHUTDOWN	= 0x0002, /* plane-0 shutting down: unload    */
};

/**
 * struct vbs_ops - operations provided by a VBS backend
 * @name:     backend name, e.g. "kvm-planes"
 * @init:     load/connect the secure plane; called once after drivers init
 * @shutdown: unload the secure plane; called on reboot/halt
 * @vtl_call: send an arbitrary request to the secure kernel and wait for a
 *            response.  Returns 0 on success, negative errno on failure.
 *
 * Callbacks run from process context with preemption enabled.
 */
struct vbs_ops {
	const char *name;

	int (*init)(void);
	void (*shutdown)(void);

	int (*vtl_call)(enum vbs_call_id id,
			const void *arg, size_t arg_size,
			void *resp, size_t resp_size);
};

#ifdef CONFIG_VBS

/**
 * vbs_register_backend() - register the platform-specific backend.
 *
 * Called once during boot by the platform detection code.  Only one backend
 * can be active at a time.
 */
int vbs_register_backend(const struct vbs_ops *ops);

/** vbs_available() - true if a backend is registered. */
bool vbs_available(void);

/** vbs_vtl_call() - dispatch a raw VTL call through the active backend. */
int vbs_vtl_call(enum vbs_call_id id,
		 const void *arg, size_t arg_size,
		 void *resp, size_t resp_size);

#else /* !CONFIG_VBS */

static inline bool vbs_available(void) { return false; }
static inline int vbs_vtl_call(enum vbs_call_id id,
			       const void *arg, size_t arg_size,
			       void *resp, size_t resp_size) { return -ENOSYS; }

#endif /* CONFIG_VBS */
#endif /* _LINUX_VBS_H */
