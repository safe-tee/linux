// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Test for x86-specific VM plane functionality
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "apic.h"
#include "asm/kvm.h"
#include "linux/kvm.h"

/*
 * Port note (dwmw stack): KVM_CAP_PLANES is a VM-level opt-in that takes
 * the plane count and must precede vCPU creation; planes are not
 * always-on.  The KVM_CAP_PLANES_USERSPACE_SWITCH subtests of the
 * upstream planes series (userspace plane switch, lower/not-runnable
 * interrupt events, CPUID runtime bits, hugepage mixed attributes) are
 * omitted: this kernel drives plane switches through the Hyper-V VSM
 * hypercalls and has no userspace-switch capability.  The remaining
 * subtests' assertions are unchanged.
 */
#define NR_PLANES 2

static void enable_planes(struct kvm_vm *vm)
{
	vm_enable_cap(vm, KVM_CAP_PLANES, NR_PLANES);
}

static void test_plane_regs(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu;

	struct kvm_regs regs0, regs1;

	vm = vm_create_barebones_irqchip(true);
	enable_planes(vm);
	vcpu = __vm_vcpu_add(vm, 0);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_ioctl(vcpu, KVM_GET_REGS, &regs0);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_REGS, &regs1);
	regs0.rax = 0x12345678;
	regs1.rax = 0x87654321;

	vcpu_ioctl(vcpu, KVM_SET_REGS, &regs0);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_REGS, &regs1);

	vcpu_ioctl(vcpu, KVM_GET_REGS, &regs0);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_REGS, &regs1);
	TEST_ASSERT_EQ(regs0.rax, 0x12345678);
	TEST_ASSERT_EQ(regs1.rax, 0x87654321);

	kvm_vm_free(vm);
	ksft_test_result_pass("get/set regs for planes\n");
}

/*
 * The planes of a VP share one TSC: a plane vCPU created later must take the
 * TSC offset of its sibling, not start a new one.  Read the guest TSC on both
 * fds back to back; the difference is the elapsed host time, not an offset.
 */
static void test_plane_tsc_offset(void)
{
	struct {
		struct kvm_msrs header;
		struct kvm_msr_entry entry;
	} msrs0 = { .header.nmsrs = 1, .entry.index = MSR_IA32_TSC };
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_plane *plane;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	u64 tsc0, tsc1, bound;

	vm = vm_create_barebones_irqchip(true);
	enable_planes(vm);
	vcpu = __vm_vcpu_add(vm, 0);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	TEST_ASSERT_EQ(__vcpu_ioctl(vcpu, KVM_GET_MSRS, &msrs0.header), 1);
	tsc0 = msrs0.entry.data;
	TEST_ASSERT_EQ(__plane_vcpu_ioctl(plane_vcpu, KVM_GET_MSRS, &msrs0.header), 1);
	tsc1 = msrs0.entry.data;

	/* One second of guest TSC; an unshared offset is off by far more. */
	bound = (u64)__vcpu_ioctl(vcpu, KVM_GET_TSC_KHZ, NULL) * 1000;
	TEST_ASSERT(tsc1 >= tsc0 && tsc1 - tsc0 < bound,
		    "plane 1 TSC 0x%lx is not plane 0 TSC 0x%lx plus elapsed time",
		    tsc1, tsc0);

	kvm_vm_free(vm);
	ksft_test_result_pass("plane vCPU shares the TSC offset\n");
}

/* Offset of XMM0 in the legacy XSAVE area.  */
#define XSTATE_BV_OFFSET	(0x200/4)
#define XMM_OFFSET		(0xa0/4)

static void test_plane_fpu_nonshared(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu;

	struct kvm_xsave xsave0, xsave1;

	vm = vm_create_barebones_irqchip(true);
	enable_planes(vm);

	vcpu = __vm_vcpu_add(vm, 0);
	vcpu_init_cpuid(vcpu, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu);

	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_ioctl(vcpu, KVM_GET_XSAVE, &xsave0);
	xsave0.region[XSTATE_BV_OFFSET] |= XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
	xsave0.region[XMM_OFFSET] = 0x12345678;
	vcpu_ioctl(vcpu, KVM_SET_XSAVE, &xsave0);

	plane_vcpu_ioctl(plane_vcpu, KVM_GET_XSAVE, &xsave1);
	xsave1.region[XSTATE_BV_OFFSET] |= XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
	xsave1.region[XMM_OFFSET] = 0x87654321;
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_XSAVE, &xsave1);

	memset(&xsave0, 0, sizeof(xsave0));
	vcpu_ioctl(vcpu, KVM_GET_XSAVE, &xsave0);
	TEST_ASSERT_EQ(xsave0.region[XMM_OFFSET], 0x12345678);

	memset(&xsave1, 0, sizeof(xsave0));
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_XSAVE, &xsave1);
	TEST_ASSERT_EQ(xsave1.region[XMM_OFFSET], 0x87654321);

	kvm_vm_free(vm);
	ksft_test_result_pass("get/set FPU not shared across planes\n");
}

#define APIC_SPIV		0xF0
#define APIC_IRR		0x200

#define MYVEC			192

/* Physical destination mode: destination id in address bits 19:12. */
#define MAKE_MSI(cpu, vector) ((struct kvm_msi){			\
	.address_lo = APIC_DEFAULT_GPA + (((cpu) & 0xff) << 12),	\
	.address_hi = (cpu) & ~0xff,					\
	.data = (vector),						\
})

static bool has_irr(struct kvm_lapic_state *apic, int vector)
{
	int word = vector >> 5;
	int bit_in_word = vector & 31;
	int bit = (APIC_IRR + word * 16) * CHAR_BIT + (bit_in_word & 31);

	return apic->regs[bit >> 3] & (1 << (bit & 7));
}

static void do_enable_lapic(struct kvm_lapic_state *apic)
{
	/* set bit 8 */
	apic->regs[APIC_SPIV + 1] |= 1;
}

static void test_plane_msi(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu;
	int r;

	struct kvm_msi msi = MAKE_MSI(0, MYVEC);
	struct kvm_lapic_state lapic0, lapic1;

	vm = vm_create_barebones_irqchip(true);
	enable_planes(vm);

	vcpu = __vm_vcpu_add(vm, 0);
	vcpu_init_cpuid(vcpu, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu);

	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_set_msr(vcpu, MSR_IA32_APICBASE,
		     APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	do_enable_lapic(&lapic0);
	vcpu_ioctl(vcpu, KVM_SET_LAPIC, &lapic0);

	_plane_vcpu_set_msr(plane_vcpu, MSR_IA32_APICBASE,
			    APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_LAPIC, &lapic1);
	do_enable_lapic(&lapic1);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_LAPIC, &lapic1);

	/* Deliver to plane 1 (via the plane fd); it must land only in plane 1. */
	r = __plane_ioctl(plane, KVM_SIGNAL_MSI, &msi);
	TEST_ASSERT(r == 1,
		   "Delivering interrupt to plane 1. ret: %d, errno: %d", r, errno);

	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	TEST_ASSERT(!has_irr(&lapic0, MYVEC), "Vector clear in plane 0");
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_LAPIC, &lapic1);
	TEST_ASSERT(has_irr(&lapic1, MYVEC), "Vector set in plane 1");

	/* Deliver to plane 0 (via the vm fd); it must land in plane 0. */
	r = __vm_ioctl(vm, KVM_SIGNAL_MSI, &msi);
	TEST_ASSERT(r == 1,
		   "Delivering interrupt to plane 0. ret: %d, errno: %d", r, errno);
	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	TEST_ASSERT(has_irr(&lapic0, MYVEC), "Vector set in plane 0");

	kvm_vm_free(vm);
	ksft_test_result_pass("signal MSI routed per plane\n");
}

/*
 * MP_STATE is per plane vCPU: a plane vCPU whose id is not the BSP's starts
 * uninitialized while its plane-0 sibling runs; setting it does not touch the
 * sibling; an INIT signalled to the plane's LAPIC is accepted on the plane fd.
 */
static void test_plane_mp_state(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu0, *vcpu1;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu0, *plane_vcpu1;
	struct kvm_mp_state mp_state;
	struct kvm_msi init_msi = MAKE_MSI(1, 0);
	int r;

	vm = vm_create_barebones_irqchip(true);
	enable_planes(vm);

	vcpu0 = __vm_vcpu_add(vm, 0);
	vcpu_init_cpuid(vcpu0, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu0);
	vcpu1 = __vm_vcpu_add(vm, 1);
	vcpu_init_cpuid(vcpu1, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu1);

	plane = vm_plane_add(vm, 1);
	plane_vcpu0 = __vm_plane_vcpu_add(vcpu0, plane);
	plane_vcpu1 = __vm_plane_vcpu_add(vcpu1, plane);

	/* BSP id starts runnable in every plane, the others uninitialized. */
	plane_vcpu_ioctl(plane_vcpu0, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_RUNNABLE);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_UNINITIALIZED);
	vcpu_ioctl(vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_UNINITIALIZED);

	/* Setting plane 1's state leaves plane 0's alone, and vice versa. */
	mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
	plane_vcpu_ioctl(plane_vcpu1, KVM_SET_MP_STATE, &mp_state);
	vcpu_ioctl(vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_UNINITIALIZED);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_RUNNABLE);

	mp_state.mp_state = KVM_MP_STATE_HALTED;
	vcpu_ioctl(vcpu1, KVM_SET_MP_STATE, &mp_state);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_RUNNABLE);

	mp_state.mp_state = KVM_MP_STATE_INIT_RECEIVED;
	plane_vcpu_ioctl(plane_vcpu1, KVM_SET_MP_STATE, &mp_state);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_INIT_RECEIVED);

	/* An INIT to the plane's LAPIC is accepted on the plane fd. */
	init_msi.data |= APIC_DM_INIT;
	r = __plane_ioctl(plane, KVM_SIGNAL_MSI, &init_msi);
	TEST_ASSERT(r == 1, "INIT to plane 1 vCPU 1. ret: %d, errno: %d", r, errno);

	kvm_vm_free(vm);
	ksft_test_result_pass("MP_STATE per plane vCPU\n");
}

int main(int argc, char *argv[])
{
	/*
	 * kvm_arch_max_planes() reports 1 without a split irqchip, so the
	 * probe VM needs one even though the opt-in itself does not.
	 */
	struct kvm_vm *vm = vm_create_barebones_irqchip(true);
	int cap_planes = 0;

	if (!__vm_enable_cap(vm, KVM_CAP_PLANES, NR_PLANES))
		cap_planes = vm_check_cap(vm, KVM_CAP_PLANES);

	kvm_vm_free(vm);
	TEST_REQUIRE(cap_planes > 1);

	ksft_print_header();
	ksft_set_plan(5);

	pr_info("# KVM_CAP_PLANES: %d\n", cap_planes);

	test_plane_regs();
	test_plane_tsc_offset();
	test_plane_fpu_nonshared();
	test_plane_msi();
	test_plane_mp_state();

	ksft_finished();
}
