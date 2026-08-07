// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS — Virtualization-Based Security core
 *
 * Dispatches calls from guest kernel subsystems to the active
 * platform-specific backend.
 */

#include <linux/vbs.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel_read_file.h>
#include <linux/kstrtox.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/reboot.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

static const struct vbs_ops *vbs_backend;
static DEFINE_MUTEX(vbs_lock);

int vbs_register_backend(const struct vbs_ops *ops)
{
	int ret = 0;

	if (!ops || !ops->name)
		return -EINVAL;

	mutex_lock(&vbs_lock);
	if (vbs_backend) {
		pr_err("vbs: backend \"%s\" already registered, rejecting \"%s\"\n",
		       vbs_backend->name, ops->name);
		ret = -EBUSY;
	} else {
		vbs_backend = ops;
		pr_info("vbs: registered backend \"%s\"\n", ops->name);
	}
	mutex_unlock(&vbs_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(vbs_register_backend);

bool vbs_available(void)
{
	return READ_ONCE(vbs_backend) != NULL;
}
EXPORT_SYMBOL_GPL(vbs_available);

int vbs_vtl_call(enum vbs_call_id id,
		 const void *arg, size_t arg_size,
		 void *resp, size_t resp_size)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (!ops)
		return -ENODEV;
	if (!ops->vtl_call)
		return -EOPNOTSUPP;
	return ops->vtl_call(id, arg, arg_size, resp, resp_size);
}
EXPORT_SYMBOL_GPL(vbs_vtl_call);

/* ── enable after driver init ────────────────────────────────── */

/*
 * A registered backend is only activated when two conditions hold:
 *   1. the operator opts in on the kernel command line (enable-kvm-planes=1),
 *      and
 *   2. the boot image advertises a provisioned secure plane via a plane
 *      configuration file that enables the expected option.
 */
#define VBS_KCONFIG_PATH	"/etc/Kconfig.kvm-planes"
#define VBS_KCONFIG_TOKEN	"CONFIG_VM_PLANES=y"

static bool vbs_enable_requested;

static int __init vbs_parse_enable_kvm_planes(char *str)
{
	bool val;

	/* Bare "enable-kvm-planes" (no value) means enabled. */
	if (!str || !*str)
		vbs_enable_requested = true;
	else if (!kstrtobool(str, &val))
		vbs_enable_requested = val;
	return 0;
}
early_param("enable-kvm-planes", vbs_parse_enable_kvm_planes);

static int vbs_reboot_notify(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);

	if (ops && ops->shutdown)
		ops->shutdown();
	return NOTIFY_DONE;
}

static struct notifier_block vbs_reboot_nb = {
	.notifier_call = vbs_reboot_notify,
};

/* Return true if VBS_KCONFIG_PATH exists and enables the plane config. */
static bool __init vbs_plane_config_present(void)
{
	void *buf = NULL;
	size_t sz = 0;
	bool ok = false;
	int ret;

	ret = kernel_read_file_from_path(VBS_KCONFIG_PATH, 0, &buf, SZ_1M, &sz,
					 READING_UNKNOWN);
	if (ret < 0) {
		pr_info("vbs: %s unavailable (%d); backend left idle\n",
			VBS_KCONFIG_PATH, ret);
		return false;
	}

	if (buf && sz)
		ok = strnstr(buf, VBS_KCONFIG_TOKEN, sz) != NULL;
	vfree(buf);

	if (!ok)
		pr_info("vbs: %s present but %s not set; backend left idle\n",
			VBS_KCONFIG_PATH, VBS_KCONFIG_TOKEN);
	return ok;
}

/*
 * Enable the registered backend after device drivers have initialised.
 * Runs at late_initcall so the plane is loaded only once the plane-0 kernel
 * is otherwise up, the operator requested it (enable-kvm-planes=1), and the
 * boot image advertises a plane config.
 */
static int __init vbs_enable(void)
{
	const struct vbs_ops *ops = READ_ONCE(vbs_backend);
	int ret;

	if (!ops) {
		pr_debug("vbs: no backend registered; nothing to enable\n");
		return 0;
	}

	if (!vbs_enable_requested) {
		pr_info("vbs: enable-kvm-planes not set; backend \"%s\" left idle\n",
			ops->name);
		return 0;
	}

	if (!vbs_plane_config_present())
		return 0;

	if (ops->init) {
		ret = ops->init();
		if (ret) {
			pr_warn("vbs: backend \"%s\" init failed (%d)\n",
				ops->name, ret);
			return 0;
		}
	}

	register_reboot_notifier(&vbs_reboot_nb);
	pr_info("vbs: enabled backend \"%s\"\n", ops->name);
	return 0;
}
late_initcall(vbs_enable);
