// SPDX-License-Identifier: GPL-2.0
/*
 * Test hugepage sizing over mixed memory protection attributes on x86.
 *
 * Back a 2 MiB-aligned region with a transparent hugepage and give it
 * alternating KVM_MEMORY_ATTRIBUTE_NX and _NW on its 4 KiB pages.  The
 * guest reads an NX page, which maps the region, then writes the NW page
 * next to it: the write must exit with KVM_EXIT_MEMORY_FAULT and leave
 * the page unchanged, instead of going through a 2 MiB leaf that
 * inherited the NX page's permissions.  Clearing the attribute lets the
 * write through.
 *
 * This pins the VSM memory protection boundary: a VTL1 guest protecting
 * one 4 KiB page of VTL0 memory must not have the protection widened
 * away by a neighbouring fault's hugepage.
 */
#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"

#define MIXED_GPA	0x40000000ul
#define MIXED_SLOT	10
#define MIXED_PAGES	1024	/* 4 MiB: a whole 2 MiB hugepage inside */

/*
 * MADV_HUGEPAGE is advisory and thp_configured() only checks that THP
 * exists in the host kernel: if no 2 MiB THP actually backs the region
 * (runtime policy "never", fragmentation), KVM maps 4 KiB leaves and
 * the test "passes" without covering the hugepage path it exists for.
 * Read the smaps entry covering @hva and report whether at least one
 * anonymous hugepage backs it.
 */
static bool anon_hugepage_backed(void *hva)
{
	unsigned long start, end, kb, addr = (unsigned long)hva;
	bool in_vma = false;
	char line[256];
	FILE *f;

	f = fopen("/proc/self/smaps", "r");
	TEST_ASSERT(f, "Failed to open /proc/self/smaps");

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx ", &start, &end) == 2) {
			in_vma = addr >= start && addr < end;
			continue;
		}
		if (in_vma && sscanf(line, "AnonHugePages: %lu kB", &kb) == 1) {
			fclose(f);
			return kb >= 2048;
		}
	}

	fclose(f);
	TEST_FAIL("No smaps entry covers %p", hva);
	return false;
}

static void guest_mixed_attrs(void)
{
	u64 *nx_page = (u64 *)MIXED_GPA;
	u64 *nw_page = (u64 *)(MIXED_GPA + PAGE_SIZE);

	/* The first touch maps the region: a read of a no-exec page. */
	GUEST_SYNC(READ_ONCE(*nx_page));
	/* A write to the no-write page next to it must be denied. */
	WRITE_ONCE(*nw_page, 0xbad);
	GUEST_SYNC(READ_ONCE(*nw_page));
	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct ucall uc;
	u64 *host;
	int i, r;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_MEMORY_ATTRIBUTES) &
		     KVM_MEMORY_ATTRIBUTE_NW);
	TEST_REQUIRE(thp_configured());

	vm = vm_create_with_one_vcpu(&vcpu, guest_mixed_attrs);
	run = vcpu->run;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS_THP, MIXED_GPA,
				    MIXED_SLOT, MIXED_PAGES, 0);
	virt_map(vm, MIXED_GPA, MIXED_GPA, MIXED_PAGES);
	host = addr_gpa2hva(vm, MIXED_GPA);
	memset(host, 0, MIXED_PAGES * getpagesize());
	host[0] = 0x11;
	host[PAGE_SIZE / sizeof(u64)] = 0x22;

	/* The memset faulted the region in; a THP must have materialised. */
	TEST_REQUIRE(anon_hugepage_backed(host));

	/* As VTL1 would: alternate NX and NW over the hugepage's 4 KiB pages. */
	for (i = 0; i < 512; i++)
		vm_set_memory_attributes(vm, MIXED_GPA + i * PAGE_SIZE,
					 PAGE_SIZE,
					 (i & 1) ? KVM_MEMORY_ATTRIBUTE_NW :
						   KVM_MEMORY_ATTRIBUTE_NX);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], 0x11);

	r = _vcpu_run(vcpu);
	TEST_ASSERT(r == -1 && errno == EFAULT,
		    "write to the NW page: ret %d errno %d, exit %u",
		    r, errno, run->exit_reason);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MEMORY_FAULT);
	TEST_ASSERT_EQ(run->memory_fault.gpa, MIXED_GPA + PAGE_SIZE);
	TEST_ASSERT(run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_WRITE,
		    "expected a write fault, flags 0x%llx",
		    run->memory_fault.flags);
	TEST_ASSERT_EQ(host[PAGE_SIZE / sizeof(u64)], 0x22);

	/* Lift the protection: the write goes through at the right level. */
	vm_set_memory_attributes(vm, MIXED_GPA + PAGE_SIZE, PAGE_SIZE, 0);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], 0xbad);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);

	kvm_vm_free(vm);
	return 0;
}
