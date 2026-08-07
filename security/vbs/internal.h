/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VBS internal header — shared between probe.c and backend implementations.
 */
#ifndef _SECURITY_VBS_INTERNAL_H
#define _SECURITY_VBS_INTERNAL_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/vbs.h>

/* Each backend exports a detect + get_ops pair for the centralized probe. */

#ifdef CONFIG_VBS_KVM_PLANES
bool __init vbs_kvm_planes_detect(void);
const struct vbs_ops *vbs_kvm_planes_get_ops(void);
#endif

#endif /* _SECURITY_VBS_INTERNAL_H */
