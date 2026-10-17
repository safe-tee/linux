// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Test for architecture-neutral VM plane functionality
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

#include "kvm_util.h"
#include "asm/kvm.h"
#include "linux/kvm.h"

/*
 * Port note (dwmw stack): KVM_CAP_PLANES is a VM-level opt-in that takes
 * the plane count and must precede vCPU creation; planes are not
 * always-on.  The upstream planes series' foreign-thread EBUSY subtest is
 * omitted: this kernel does not restrict vCPU ioctls to the vCPU's own
 * thread.  The assertions below are otherwise unchanged.
 */
#define NR_PLANES 2

static void enable_planes(struct kvm_vm *vm)
{
	vm_enable_cap(vm, KVM_CAP_PLANES, NR_PLANES);
}

void test_create_plane_errors(int max_planes)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int planefd, plane_vcpufd;

	/* Planes require an in-kernel (split) IRQ chip. */
	vm = vm_create_barebones_irqchip(true);
	enable_planes(vm);
	vcpu = __vm_vcpu_add(vm, 0);

	planefd = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)(unsigned long)0);
	TEST_ASSERT(planefd == -1 && errno == EEXIST,
		    "Creating existing plane, expecting EEXIST. ret: %d, errno: %d",
		    planefd, errno);

	planefd = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)(unsigned long)max_planes);
	TEST_ASSERT(planefd == -1 && errno == EINVAL,
		    "Creating plane %d, expecting EINVAL. ret: %d, errno: %d",
		    max_planes, planefd, errno);

	plane_vcpufd = __vm_ioctl(vm, KVM_CREATE_VCPU, (void *)(unsigned long)vcpu->id);
	TEST_ASSERT(plane_vcpufd == -1 && errno == EEXIST,
		    "Creating existing vCPU for plane 0, expecting EEXIST. ret: %d, errno: %d",
		    plane_vcpufd, errno);

	kvm_vm_free(vm);
	ksft_test_result_pass("error conditions\n");
}

void test_create_plane(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	int r;

	vm = vm_create_barebones_irqchip(true);
	enable_planes(vm);
	vcpu = __vm_vcpu_add(vm, 0);

	plane = vm_plane_add(vm, 1);

	/* A plane fd takes plane ioctls only; capabilities are a VM matter. */
	r = __plane_ioctl(plane, KVM_CHECK_EXTENSION, (void *)(unsigned long)KVM_CAP_PLANES);
	TEST_ASSERT(r == -1 && errno == ENOTTY,
		    "KVM_CHECK_EXTENSION on a plane fd, expecting ENOTTY. ret: %d, errno: %d",
		    r, errno);

	r = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)(unsigned long)1);
	TEST_ASSERT(r == -1 && errno == EEXIST,
		    "Creating existing plane, expecting EEXIST. ret: %d, errno: %d",
		    r, errno);

	__vm_plane_vcpu_add(vcpu, plane);

	r = __plane_ioctl(plane, KVM_CREATE_VCPU, (void *)(unsigned long)vcpu->id);
	TEST_ASSERT(r == -1 && errno == EEXIST,
		    "Creating vCPU again for plane 1. ret: %d, errno: %d",
		    r, errno);

	r = __plane_ioctl(plane, KVM_RUN, (void *)(unsigned long)0);
	TEST_ASSERT(r == -1 && errno == ENOTTY,
		    "Running plane vCPU again for plane 1. ret: %d, errno: %d",
		    r, errno);

	kvm_vm_free(vm);
	ksft_test_result_pass("basic planefd and plane_vcpufd operation\n");
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	int cap_planes = 0;

	/*
	 * kvm_arch_max_planes() reports 1 without a split irqchip, so the
	 * probe VM needs one even though the opt-in itself does not.  On
	 * architectures without KVM_CAP_SPLIT_IRQCHIP the vm_enable_cap()
	 * inside vm_create_barebones_irqchip() would assert, turning the
	 * missing feature into a failure instead of a skip.
	 */
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_SPLIT_IRQCHIP));

	vm = vm_create_barebones_irqchip(true);

	if (!__vm_enable_cap(vm, KVM_CAP_PLANES, NR_PLANES))
		cap_planes = vm_check_cap(vm, KVM_CAP_PLANES);

	kvm_vm_free(vm);
	TEST_REQUIRE(cap_planes);

	ksft_print_header();
	ksft_set_plan(2);

	pr_info("# KVM_CAP_PLANES: %d\n", cap_planes);

	test_create_plane_errors(cap_planes);

	if (cap_planes > 1)
		test_create_plane();
	else
		ksft_test_result_skip("plane creation requires KVM_CAP_PLANES > 1\n");

	ksft_finished();
}
