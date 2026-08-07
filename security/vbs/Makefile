# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_VBS) += vbs.o
# probe.o links before core.o so the backend is registered (vbs_probe_init)
# early in the rootfs_initcall level.
vbs-y := probe.o core.o
