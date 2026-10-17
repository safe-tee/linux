// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test that an interrupt posted to a higher plane survives the plane
 * suspending without having delivered it.
 *
 * A higher plane's pending interrupt forces entry into that plane via a
 * single-shot marker (hv_apic_event_pending) that the plane consumes when
 * it runs.  A plane that runs with IF clear until it suspends consumes
 * the marker without delivering the vector, which used to strand the
 * vector in the plane's IRR forever: with the marker gone, the lower
 * plane never again exits with KVM_EXIT_HYPERV_VTL_INTERRUPT, and a
 * guest waiting on the higher plane deadlocks.
 *
 * The test models the failing sequence: the plane-1 twin self-IPIs with
 * IF clear, keeps running (consuming the marker), then is suspended by
 * the run-state ioctl exactly like a userspace VTL switch.  Running
 * plane 0 must then report a pending VTL interrupt for plane 1, and the
 * re-entered twin must receive the vector once it sets IF.
 */
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "apic.h"

#ifndef KVM_EXIT_HYPERV_VTL_INTERRUPT
#define KVM_EXIT_HYPERV_VTL_INTERRUPT  4
#endif

#define TEST_VECTOR		0xe0
#define TWIN_SYNC_PORT		0x7e
#define TWIN_STACK_PAGES	4

static volatile bool twin_got_ipi;

static void twin_sync(uint8_t stage)
{
	asm volatile("outb %0, %1" :: "a"(stage), "Nd"((uint16_t)TWIN_SYNC_PORT));
}

static void twin_ipi_handler(struct ex_regs *regs)
{
	twin_got_ipi = true;
	x2apic_write_reg(APIC_EOI, 0);
}

/* Runs with IF clear: the initial RFLAGS has IF unset and nothing sets it. */
static void twin_guest_code(void)
{
	x2apic_enable();
	x2apic_write_reg(APIC_SELF_IPI, TEST_VECTOR);
	twin_sync(1);
	twin_sync(2);

	/* Re-entered after suspension: open the window, take the vector. */
	sti();
	while (!twin_got_ipi)
		cpu_relax();
	twin_sync(3);
	for (;;)
		twin_sync(4);
}

static void plane0_guest_code(void)
{
	GUEST_SYNC(0);
	GUEST_DONE();
}

static void set_plane_run_state(int vcpu_fd, u32 state)
{
	int r = ioctl(vcpu_fd, KVM_SET_PLANE_RUN_STATE, &state);

	TEST_ASSERT(!r, "KVM_SET_PLANE_RUN_STATE(%u) failed: errno %d",
		    state, errno);
}

static void run_twin_expect_sync(struct kvm_vcpu *vcpu0,
				 struct kvm_run *twin_run, uint8_t stage)
{
	int r = ioctl(vcpu0->fd, KVM_RUN, NULL);

	TEST_ASSERT(!r, "KVM_RUN (twin runnable) failed: errno %d", errno);
	TEST_ASSERT_EQ(twin_run->exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(twin_run->io.port, TWIN_SYNC_PORT);
	TEST_ASSERT_EQ(*((uint8_t *)twin_run + twin_run->io.data_offset), stage);
}

int main(int argc, char *argv[])
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_run *twin_run;
	struct kvm_vcpu *vcpu0;
	struct kvm_vm *vm;
	gva_t twin_stack;
	int plane_fd, twin_fd, mmap_sz, r;

	kvm_force_split_irqchip = true;
	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	kvm_force_split_irqchip = false;

	TEST_REQUIRE(vm_check_cap(vm, KVM_CAP_PLANES) >= 1);
	TEST_REQUIRE(__vm_enable_cap(vm, KVM_CAP_PLANES, 2) == 0);

	vcpu0 = vm_vcpu_add(vm, 0, plane0_guest_code);

	plane_fd = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)1UL);
	TEST_ASSERT(plane_fd >= 0, "KVM_CREATE_PLANE failed: errno %d", errno);
	twin_fd = __kvm_ioctl(plane_fd, KVM_CREATE_VCPU, NULL);
	TEST_ASSERT(twin_fd >= 0, "KVM_CREATE_VCPU on plane 1 failed: errno %d",
		    errno);

	mmap_sz = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	TEST_ASSERT(mmap_sz >= (int)sizeof(*twin_run),
		    "KVM_GET_VCPU_MMAP_SIZE failed");
	twin_run = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
			twin_fd, 0);
	TEST_ASSERT(twin_run != MAP_FAILED, "mmap of twin kvm_run failed");

	vm_install_exception_handler(vm, TEST_VECTOR, twin_ipi_handler);

	/*
	 * The twin shares the mode and page tables with plane 0: reuse
	 * plane 0's segment state and point it at its own code and stack.
	 * RFLAGS keeps IF clear.
	 */
	vcpu_sregs_get(vcpu0, &sregs);
	r = ioctl(twin_fd, KVM_SET_SREGS, &sregs);
	TEST_ASSERT(!r, "KVM_SET_SREGS on twin failed: errno %d", errno);

	twin_stack = vm_alloc_pages(vm, TWIN_STACK_PAGES);
	r = ioctl(twin_fd, KVM_GET_REGS, &regs);
	TEST_ASSERT(!r, "KVM_GET_REGS on twin failed: errno %d", errno);
	regs.rip = (unsigned long)twin_guest_code;
	regs.rsp = twin_stack + TWIN_STACK_PAGES * getpagesize() - 16;
	regs.rflags = 0x2;
	r = ioctl(twin_fd, KVM_SET_REGS, &regs);
	TEST_ASSERT(!r, "KVM_SET_REGS on twin failed: errno %d", errno);

	/*
	 * Run the twin as a userspace VTL switch would: twin runnable,
	 * plane 0 stopped.  The twin self-IPIs with IF clear, so the
	 * vector lands in its IRR without being delivered, and the
	 * second sync guarantees a fresh guest entry consumed the
	 * forced-entry marker.
	 */
	set_plane_run_state(twin_fd, KVM_PLANE_RUN_STATE_RUNNABLE);
	set_plane_run_state(vcpu0->fd, KVM_PLANE_RUN_STATE_STOPPED);
	run_twin_expect_sync(vcpu0, twin_run, 1);
	run_twin_expect_sync(vcpu0, twin_run, 2);

	/* Suspend the twin with the vector still latched in its IRR. */
	set_plane_run_state(twin_fd, KVM_PLANE_RUN_STATE_STOPPED);
	set_plane_run_state(vcpu0->fd, KVM_PLANE_RUN_STATE_RUNNABLE);

	/*
	 * Plane 0 must not run the guest: the suspended twin still has a
	 * deliverable interrupt, which must surface as a VTL interrupt
	 * exit.  On a broken kernel the marker was consumed and plane 0
	 * reaches its guest code.
	 */
	r = ioctl(vcpu0->fd, KVM_RUN, NULL);
	TEST_ASSERT(!r, "KVM_RUN (plane 0) failed: errno %d", errno);
	TEST_ASSERT(vcpu0->run->exit_reason == KVM_EXIT_HYPERV,
		    "Expected KVM_EXIT_HYPERV, got %u (%s): the twin's pending "
		    "interrupt was lost when it suspended",
		    vcpu0->run->exit_reason,
		    exit_reason_str(vcpu0->run->exit_reason));
	TEST_ASSERT_EQ(vcpu0->run->hyperv.type, KVM_EXIT_HYPERV_VTL_INTERRUPT);
	TEST_ASSERT_EQ(vcpu0->run->hyperv.plane, 1);

	/* Enter the twin as userspace would, and let it take the vector. */
	set_plane_run_state(twin_fd, KVM_PLANE_RUN_STATE_RUNNABLE);
	set_plane_run_state(vcpu0->fd, KVM_PLANE_RUN_STATE_STOPPED);
	run_twin_expect_sync(vcpu0, twin_run, 3);

	kvm_munmap(twin_run, mmap_sz);
	close(twin_fd);
	close(plane_fd);
	kvm_vm_free(vm);
	return 0;
}
