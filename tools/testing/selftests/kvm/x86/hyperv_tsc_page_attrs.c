// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test that KVM honours plane memory attributes when it maintains the
 * Hyper-V reference TSC page.  A page whose gfn carries
 * KVM_MEMORY_ATTRIBUTE_NW in the owning plane's attributes must never
 * be written by the host, on the HV_X64_MSR_REFERENCE_TSC write or on
 * any later masterclock update; an unprotected page keeps working, and
 * re-pointing the MSR at a writable page recovers.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "hyperv.h"

struct ms_hyperv_tsc_page {
	volatile u32 tsc_sequence;
	u32 reserved1;
	volatile u64 tsc_scale;
	volatile s64 tsc_offset;
} __packed;

#define SENTINEL_SEQ	0xdeadbeef
#define SENTINEL_U64	0xcafef00dcafef00dULL

static void guest_main(struct ms_hyperv_tsc_page *page_a, gpa_t page_a_gpa,
		       struct ms_hyperv_tsc_page *page_b, gpa_t page_b_gpa)
{
	/* Set Guest OS id to enable Hyper-V emulation */
	wrmsr(HV_X64_MSR_GUEST_OS_ID, HYPERV_LINUX_OS_ID);

	/* An unprotected page is maintained by KVM as usual. */
	wrmsr(HV_X64_MSR_REFERENCE_TSC, page_a_gpa | 0x1);
	GUEST_ASSERT(page_a->tsc_sequence != 0);

	/* Fill the page about to be protected, while it is still writable. */
	page_b->tsc_sequence = SENTINEL_SEQ;
	page_b->tsc_scale = SENTINEL_U64;
	page_b->tsc_offset = SENTINEL_U64;

	GUEST_SYNC(1);	/* host sets KVM_MEMORY_ATTRIBUTE_NW on page_b */

	/*
	 * Pointing the reference TSC MSR at the protected page must not
	 * have KVM write to it: not on the MSR write itself, and not on
	 * the masterclock update the write requests.
	 */
	wrmsr(HV_X64_MSR_REFERENCE_TSC, page_b_gpa | 0x1);
	GUEST_ASSERT(page_b->tsc_sequence == SENTINEL_SEQ);
	GUEST_ASSERT(page_b->tsc_scale == SENTINEL_U64);
	GUEST_ASSERT(page_b->tsc_offset == SENTINEL_U64);

	GUEST_SYNC(2);	/* host resets kvmclock, forcing a TSC page update */

	GUEST_ASSERT(page_b->tsc_sequence == SENTINEL_SEQ);
	GUEST_ASSERT(page_b->tsc_scale == SENTINEL_U64);
	GUEST_ASSERT(page_b->tsc_offset == SENTINEL_U64);

	/* Re-pointing the MSR at a writable page recovers. */
	wrmsr(HV_X64_MSR_REFERENCE_TSC, page_a_gpa | 0x1);
	GUEST_ASSERT(page_a->tsc_sequence != 0);

	GUEST_DONE();
}

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	gva_t page_a_gva, page_b_gva;
	gpa_t page_b_gpa;
	int stage;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_HYPERV_TIME));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_MEMORY_ATTRIBUTES) &
		     KVM_MEMORY_ATTRIBUTE_NW);
	TEST_REQUIRE(sys_clocksource_is_based_on_tsc());

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);

	vcpu_set_hv_cpuid(vcpu);

	page_a_gva = vm_alloc_page(vm);
	page_b_gva = vm_alloc_page(vm);
	memset(addr_gva2hva(vm, page_a_gva), 0x0, getpagesize());
	memset(addr_gva2hva(vm, page_b_gva), 0x0, getpagesize());
	page_b_gpa = addr_gva2gpa(vm, page_b_gva);

	vcpu_args_set(vcpu, 4, page_a_gva, addr_gva2gpa(vm, page_a_gva),
		      page_b_gva, page_b_gpa);

	for (stage = 1;; stage++) {
		vcpu_run(vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			/* NOT REACHED */
		case UCALL_SYNC:
			break;
		case UCALL_DONE:
			/* Keep in sync with guest_main() */
			TEST_ASSERT(stage == 3, "Testing ended prematurely, stage %d",
				    stage);
			goto out;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}

		TEST_ASSERT(uc.args[1] == stage,
			    "Stage %d: Unexpected sync, got %lx",
			    stage, (ulong)uc.args[1]);

		if (stage == 1)
			vm_set_memory_attributes(vm, page_b_gpa, getpagesize(),
						 KVM_MEMORY_ATTRIBUTE_NW);

		/* Reset kvmclock triggering TSC page update */
		if (stage == 2) {
			struct kvm_clock_data clock = {0};

			vm_ioctl(vm, KVM_SET_CLOCK, &clock);
		}
	}

out:
	kvm_vm_free(vm);
}
