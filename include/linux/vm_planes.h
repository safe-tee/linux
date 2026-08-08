/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VM_PLANES_H
#define _LINUX_VM_PLANES_H

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/types.h>

#ifdef CONFIG_VM_PLANES

#define VM_PLANE_KERNEL_NAME_MAX	128
#define VM_PLANE_CMDLINE_MAX		512

enum vm_plane_kernel_format {
	VM_PLANE_KFMT_RAW = 0,
	VM_PLANE_KFMT_BZIMAGE,
	VM_PLANE_KFMT_ELF,
};

struct vm_plane_config {
	phys_addr_t load_offset;
	phys_addr_t memory_size;
	phys_addr_t entry_point;
	unsigned int kernel_format;
	char kernel[VM_PLANE_KERNEL_NAME_MAX];
	char cmdline[VM_PLANE_CMDLINE_MAX];
};

int __init load_vm_plane_kernels(unsigned int plane_count,
				 struct vm_plane_config *plane_cfg);

int __init alloc_vm_planes(unsigned int plane_count,
			   struct vm_plane_config *plane_cfg);

int __init activate_vm_planes(unsigned int plane_count,
			      struct vm_plane_config *plane_cfg);

int __init vm_planes_bootstrap(void);

#else /* !CONFIG_VM_PLANES */

static inline int vm_planes_bootstrap(void) { return -ENODEV; }

#endif /* CONFIG_VM_PLANES */

#endif /* _LINUX_VM_PLANES_H */
