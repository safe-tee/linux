// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test KVM_CAP_HYPERV_FORWARD_HCALL: Hyper-V hypercalls that KVM does
 * not implement exit to userspace instead of failing with
 * HV_STATUS_INVALID_HYPERCALL_CODE, in both slow and fast form, and
 * userspace supplies the result the guest observes.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "hyperv.h"

/* A hypercall code KVM does not implement: HvCallGetVpRegisters. */
#define HVCALL_TEST_CODE	0x50

#define FAST_PARAM0		0x1122334455667788ULL
#define FAST_PARAM1		0x99aabbccddeeff00ULL
#define XMM_MARKER		0x5157ca11c0ffee00ULL
#define USERSPACE_STATUS	0x55AA

static void guest_code(gpa_t pgs_gpa)
{
	__sse128_u marker;
	u64 status;
	u8 vector;

	marker.as_u64[0] = XMM_MARKER;
	marker.as_u64[1] = XMM_MARKER + 1;

	wrmsr(HV_X64_MSR_GUEST_OS_ID, HYPERV_LINUX_OS_ID);
	wrmsr(HV_X64_MSR_HYPERCALL, pgs_gpa);

	/* Forwarding disabled: KVM itself fails the call. */
	vector = __hyperv_hypercall(HVCALL_TEST_CODE, pgs_gpa,
				    pgs_gpa + PAGE_SIZE, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, HV_STATUS_INVALID_HYPERCALL_CODE);
	GUEST_SYNC(1);

	/* Forwarding enabled: userspace supplies the status. */
	vector = __hyperv_hypercall(HVCALL_TEST_CODE, pgs_gpa,
				    pgs_gpa + PAGE_SIZE, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, 0);
	GUEST_SYNC(2);

	/* Fast form: register parameters reach userspace. */
	write_sse_reg(0, &marker.vec);
	vector = __hyperv_hypercall(HVCALL_TEST_CODE | HV_HYPERCALL_FAST_BIT,
				    FAST_PARAM0, FAST_PARAM1, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, USERSPACE_STATUS);

	GUEST_DONE();
}

static void handle_forwarded_hcall(struct kvm_vcpu *vcpu, u64 expect_control,
				   u64 expect_in, u64 expect_out, u64 result)
{
	struct kvm_run *run = vcpu->run;

	TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_HYPERV);
	TEST_ASSERT_EQ(run->hyperv.type, KVM_EXIT_HYPERV_HCALL);
	TEST_ASSERT_EQ(run->hyperv.u.hcall.input, expect_control);
	TEST_ASSERT_EQ(run->hyperv.u.hcall.params[0], expect_in);
	TEST_ASSERT_EQ(run->hyperv.u.hcall.params[1], expect_out);

	run->hyperv.u.hcall.result = result;
}

int main(int argc, char *argv[])
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t hcall_page;
	gpa_t hcall_gpa;
	struct kvm_fpu fpu;
	struct ucall uc;
	int stage;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_HYPERV_FORWARD_HCALL));

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vcpu_set_hv_cpuid(vcpu);

	/* Hypercall page plus an input and an output page. */
	hcall_page = vm_alloc_pages(vm, 3);
	memset(addr_gva2hva(vm, hcall_page), 0x0, 3 * getpagesize());
	hcall_gpa = addr_gva2gpa(vm, hcall_page);

	vcpu_args_set(vcpu, 1, hcall_gpa);

	for (stage = 1;; stage++) {
		vcpu_run(vcpu);

		if (vcpu->run->exit_reason == KVM_EXIT_HYPERV) {
			switch (stage) {
			case 2:
				handle_forwarded_hcall(vcpu, HVCALL_TEST_CODE,
						       hcall_gpa,
						       hcall_gpa + getpagesize(),
						       0);
				break;
			case 3:
				handle_forwarded_hcall(vcpu,
						       HVCALL_TEST_CODE | HV_HYPERCALL_FAST_BIT,
						       FAST_PARAM0, FAST_PARAM1,
						       USERSPACE_STATUS);
				/*
				 * Fast-call register state is reachable with
				 * the ordinary vCPU state ioctls.
				 */
				vcpu_fpu_get(vcpu, &fpu);
				TEST_ASSERT_EQ(*(u64 *)&fpu.xmm[0][0], XMM_MARKER);
				TEST_ASSERT_EQ(*(u64 *)&fpu.xmm[0][8], XMM_MARKER + 1);
				break;
			default:
				TEST_FAIL("Unexpected hypercall exit in stage %d", stage);
			}
			stage--;	/* same guest stage continues */
			continue;
		}

		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			TEST_ASSERT_EQ(uc.args[1], stage);
			if (stage == 1)
				vm_enable_cap(vm, KVM_CAP_HYPERV_FORWARD_HCALL, 1);
			break;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		case UCALL_DONE:
			goto done;
		default:
			TEST_FAIL("Unhandled ucall: %ld", uc.cmd);
		}
	}

done:
	kvm_vm_free(vm);
	return 0;
}
