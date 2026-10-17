// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test the KVM_CAP_PLANES opt-in and the plane lifecycle uAPI: plane
 * creation bounds, plane vCPU creation, and the independence of
 * per-plane vCPU register state.
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "kvm_util.h"

static int plane_vcpu_fd(int plane_fd, int vcpu_id)
{
	return __kvm_ioctl(plane_fd, KVM_CREATE_VCPU, (void *)(unsigned long)vcpu_id);
}

static void test_enable_cap_bounds(void)
{
	struct kvm_vm *vm = vm_create_barebones();

	/* Planes require a split irqchip; the cap itself does not. */
	TEST_ASSERT_EQ(__vm_enable_cap(vm, KVM_CAP_PLANES, 0), -1);
	TEST_ASSERT_EQ(errno, EINVAL);

	TEST_ASSERT_EQ(__vm_enable_cap(vm, KVM_CAP_PLANES, KVM_MAX_PLANES + 1), -1);
	TEST_ASSERT_EQ(errno, EINVAL);

	vm_enable_cap(vm, KVM_CAP_PLANES, KVM_MAX_PLANES);

	kvm_vm_free(vm);
}

static void test_enable_cap_too_late(void)
{
	struct kvm_vm *vm = vm_create_barebones();
	int vcpu_fd;

	vcpu_fd = __vm_ioctl(vm, KVM_CREATE_VCPU, NULL);
	TEST_ASSERT(vcpu_fd >= 0, "KVM_CREATE_VCPU failed: errno %d", errno);

	TEST_ASSERT_EQ(__vm_enable_cap(vm, KVM_CAP_PLANES, 2), -1);
	TEST_ASSERT_EQ(errno, EEXIST);

	close(vcpu_fd);
	kvm_vm_free(vm);
}

static void test_plane_lifecycle(void)
{
	struct kvm_vm *vm = vm_create_barebones();
	struct kvm_regs regs0, regs1;
	int plane_fd, vcpu0_fd, vcpu1_fd;
	int r;

	vm_enable_cap(vm, KVM_CAP_SPLIT_IRQCHIP, 24);

	/* Without the opt-in a VM has a single plane. */
	TEST_ASSERT_EQ(vm_check_cap(vm, KVM_CAP_PLANES), 1);
	TEST_ASSERT_EQ(__vm_ioctl(vm, KVM_CREATE_PLANE, (void *)1UL), -1);
	TEST_ASSERT_EQ(errno, EINVAL);

	vm_enable_cap(vm, KVM_CAP_PLANES, 2);
	TEST_ASSERT_EQ(vm_check_cap(vm, KVM_CAP_PLANES), 2);

	/* The configured count is a hard bound, and reconfiguration a hard no. */
	TEST_ASSERT_EQ(__vm_ioctl(vm, KVM_CREATE_PLANE, (void *)2UL), -1);
	TEST_ASSERT_EQ(errno, EINVAL);

	plane_fd = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)1UL);
	TEST_ASSERT(plane_fd >= 0, "KVM_CREATE_PLANE failed: errno %d", errno);

	TEST_ASSERT_EQ(__vm_enable_cap(vm, KVM_CAP_PLANES, 3), -1);
	TEST_ASSERT_EQ(errno, EEXIST);

	/*
	 * A plane cannot host planes of its own.  Plane fds that do not
	 * implement KVM_CHECK_EXTENSION at all satisfy that trivially.
	 */
	r = __kvm_ioctl(plane_fd, KVM_CHECK_EXTENSION, (void *)KVM_CAP_PLANES);
	TEST_ASSERT(r == 0 || (r == -1 && errno == ENOTTY),
		    "plane fd reports nested plane support: %d", r);

	vcpu0_fd = __vm_ioctl(vm, KVM_CREATE_VCPU, NULL);
	TEST_ASSERT(vcpu0_fd >= 0, "KVM_CREATE_VCPU failed: errno %d", errno);

	vcpu1_fd = plane_vcpu_fd(plane_fd, 0);
	TEST_ASSERT(vcpu1_fd >= 0,
		    "KVM_CREATE_VCPU on plane 1 failed: errno %d", errno);

	/* Plane 1 starts stopped; run state is readable and writable. */
	{
		u32 state = 0xff;

		kvm_ioctl(vcpu1_fd, KVM_GET_PLANE_RUN_STATE, &state);
		TEST_ASSERT_EQ(state, KVM_PLANE_RUN_STATE_STOPPED);

		state = KVM_PLANE_RUN_STATE_RUNNABLE;
		kvm_ioctl(vcpu1_fd, KVM_SET_PLANE_RUN_STATE, &state);
		state = 0xff;
		kvm_ioctl(vcpu1_fd, KVM_GET_PLANE_RUN_STATE, &state);
		TEST_ASSERT_EQ(state, KVM_PLANE_RUN_STATE_RUNNABLE);

		state = KVM_PLANE_RUN_STATE_STOPPED;
		kvm_ioctl(vcpu1_fd, KVM_SET_PLANE_RUN_STATE, &state);

		state = 2;
		TEST_ASSERT_EQ(__kvm_ioctl(vcpu1_fd, KVM_SET_PLANE_RUN_STATE,
					   &state), -1);
		TEST_ASSERT_EQ(errno, EINVAL);
	}

	/* Register state is per plane: write plane 1, plane 0 unaffected. */
	kvm_ioctl(vcpu1_fd, KVM_GET_REGS, &regs1);
	regs1.rbx = 0x5157ca11;	/* arbitrary marker */
	kvm_ioctl(vcpu1_fd, KVM_SET_REGS, &regs1);

	kvm_ioctl(vcpu0_fd, KVM_GET_REGS, &regs0);
	TEST_ASSERT(regs0.rbx != 0x5157ca11,
		    "plane 0 RBX changed by plane 1 KVM_SET_REGS");

	memset(&regs1, 0, sizeof(regs1));
	kvm_ioctl(vcpu1_fd, KVM_GET_REGS, &regs1);
	TEST_ASSERT_EQ(regs1.rbx, 0x5157ca11);

	close(vcpu1_fd);
	close(vcpu0_fd);
	close(plane_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_PLANES));

	test_enable_cap_bounds();
	test_enable_cap_too_late();
	test_plane_lifecycle();

	return 0;
}
