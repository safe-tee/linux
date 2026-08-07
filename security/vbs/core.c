// SPDX-License-Identifier: GPL-2.0-only
/*
 * VBS — Virtualization-Based Security core
 *
 * Dispatches calls from guest kernel subsystems to the active
 * platform-specific backend.
 */

#include <linux/vbs.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/printk.h>

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
