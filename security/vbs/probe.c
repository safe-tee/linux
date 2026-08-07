// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS platform detection and backend selection
 *
 * A single boot-time initcall probes the platform and registers the
 * appropriate VBS backend.  Only one backend can be active; the first
 * successful probe wins.  VBS is software-only: the only backend today is
 * KVM software planes; other software backends (e.g. Hyper-V VSM) may be
 * added later.
 */

#include "internal.h"

/* Stub for the backend when it is not configured in. */
#ifndef CONFIG_VBS_KVM_PLANES
static inline bool vbs_kvm_planes_detect(void) { return false; }
static inline const struct vbs_ops *vbs_kvm_planes_get_ops(void) { return NULL; }
#endif

struct vbs_probe_entry {
	const char *name;
	bool (*detect)(void);
	const struct vbs_ops *(*get_ops)(void);
};

static const struct vbs_probe_entry vbs_probe_table[] __initconst = {
	{ "KVM planes", vbs_kvm_planes_detect, vbs_kvm_planes_get_ops },
};

static int __init vbs_probe_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(vbs_probe_table); i++) {
		const struct vbs_probe_entry *e = &vbs_probe_table[i];

		if (!e->detect())
			continue;

		pr_info("vbs: detected %s platform\n", e->name);

		ret = vbs_register_backend(e->get_ops());
		if (ret) {
			pr_err("vbs: failed to register %s backend (%d)\n",
			       e->name, ret);
			return ret;
		}
		return 0;
	}

	pr_debug("vbs: no supported platform detected\n");
	return 0;
}

/*
 * Run at rootfs_initcall level: platform detection is complete and the VM
 * planes have been set up (init/ links before security/), but subsystems
 * that consume VBS have not yet started.  Registration only records the
 * backend; the plane is loaded later, after device drivers initialise.
 */
rootfs_initcall(vbs_probe_init);
