// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Microsoft Hyper-V emulation
 *
 * derived from arch/x86/kvm/x86.c
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright (C) 2008 Qumranet, Inc.
 * Copyright IBM Corporation, 2008
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 * Copyright (C) 2015 Andrey Smetanin <asmetanin@virtuozzo.com>
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Amit Shah    <amit.shah@qumranet.com>
 *   Ben-Ami Yassour <benami@il.ibm.com>
 *   Andrey Smetanin <asmetanin@virtuozzo.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "x86.h"
#include "lapic.h"
#include "ioapic.h"
#include "cpuid.h"
#include "hyperv.h"
#include "mmu.h"
#include "xen.h"

#include <linux/cpu.h>
#include <linux/kvm_host.h>
#include <linux/highmem.h>
#include <linux/sched/cputime.h>
#include <linux/spinlock.h>
#include <linux/eventfd.h>

#include <asm/apicdef.h>
#include <asm/mshyperv.h>
#include <trace/events/kvm.h>

#include "trace.h"
#include "irq.h"
#include "fpu.h"

#define KVM_HV_MAX_SPARSE_VCPU_SET_BITS DIV_ROUND_UP(KVM_MAX_VCPUS, HV_VCPUS_PER_SPARSE_BANK)

/*
 * As per Hyper-V TLFS, extended hypercalls start from 0x8001
 * (HvExtCallQueryCapabilities). Response of this hypercalls is a 64 bit value
 * where each bit tells which extended hypercall is available besides
 * HvExtCallQueryCapabilities.
 *
 * 0x8001 - First extended hypercall, HvExtCallQueryCapabilities, no bit
 * assigned.
 *
 * 0x8002 - Bit 0
 * 0x8003 - Bit 1
 * ..
 * 0x8041 - Bit 63
 *
 * Therefore, HV_EXT_CALL_MAX = 0x8001 + 64
 */
#define HV_EXT_CALL_MAX (HV_EXT_CALL_QUERY_CAPABILITIES + 64)

static void stimer_mark_pending(struct kvm_vcpu_hv_stimer *stimer,
				bool vcpu_kick);

static inline u64 synic_read_sint(struct kvm_vcpu_hv_synic *synic, int sint)
{
	return atomic64_read(&synic->sint[sint]);
}

static inline int synic_get_sint_vector(u64 sint_value)
{
	if (sint_value & HV_SYNIC_SINT_MASKED)
		return -1;
	return sint_value & HV_SYNIC_SINT_VECTOR_MASK;
}

static bool synic_has_vector_connected(struct kvm_vcpu_hv_synic *synic,
				      int vector)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(synic->sint); i++) {
		if (synic_get_sint_vector(synic_read_sint(synic, i)) == vector)
			return true;
	}
	return false;
}

static bool synic_has_vector_auto_eoi(struct kvm_vcpu_hv_synic *synic,
				     int vector)
{
	int i;
	u64 sint_value;

	for (i = 0; i < ARRAY_SIZE(synic->sint); i++) {
		sint_value = synic_read_sint(synic, i);
		if (synic_get_sint_vector(sint_value) == vector &&
		    sint_value & HV_SYNIC_SINT_AUTO_EOI)
			return true;
	}
	return false;
}

static void synic_update_vector(struct kvm_vcpu_hv_synic *synic,
				int vector)
{
	struct kvm_vcpu *vcpu = hv_synic_to_vcpu(synic);
	struct kvm_hv *hv = to_kvm_hv(vcpu->kvm);
	bool auto_eoi_old, auto_eoi_new;

	if (vector < HV_SYNIC_FIRST_VALID_VECTOR)
		return;

	if (synic_has_vector_connected(synic, vector))
		__set_bit(vector, synic->vec_bitmap);
	else
		__clear_bit(vector, synic->vec_bitmap);

	auto_eoi_old = !bitmap_empty(synic->auto_eoi_bitmap, 256);

	if (synic_has_vector_auto_eoi(synic, vector))
		__set_bit(vector, synic->auto_eoi_bitmap);
	else
		__clear_bit(vector, synic->auto_eoi_bitmap);

	auto_eoi_new = !bitmap_empty(synic->auto_eoi_bitmap, 256);

	if (auto_eoi_old == auto_eoi_new)
		return;

	if (!enable_apicv)
		return;

	down_write(&vcpu->kvm->arch.apicv_update_lock);

	if (auto_eoi_new)
		hv->synic_auto_eoi_used++;
	else
		hv->synic_auto_eoi_used--;

	/*
	 * Inhibit APICv if any vCPU is using SynIC's AutoEOI, which relies on
	 * the hypervisor to manually inject IRQs.
	 */
	__kvm_set_or_clear_apicv_inhibit(vcpu->kvm,
					 APICV_INHIBIT_REASON_HYPERV,
					 !!hv->synic_auto_eoi_used);

	up_write(&vcpu->kvm->arch.apicv_update_lock);
}

static int synic_set_sint(struct kvm_vcpu_hv_synic *synic, int sint,
			  u64 data, bool host)
{
	int vector, old_vector;
	bool masked;

	vector = data & HV_SYNIC_SINT_VECTOR_MASK;
	masked = data & HV_SYNIC_SINT_MASKED;

	/*
	 * Valid vectors are 16-255, however, nested Hyper-V attempts to write
	 * default '0x10000' value on boot and this should not #GP. We need to
	 * allow zero-initing the register from host as well.
	 */
	if (vector < HV_SYNIC_FIRST_VALID_VECTOR && !host && !masked)
		return 1;
	/*
	 * Guest may configure multiple SINTs to use the same vector, so
	 * we maintain a bitmap of vectors handled by synic, and a
	 * bitmap of vectors with auto-eoi behavior.  The bitmaps are
	 * updated here, and atomically queried on fast paths.
	 */
	old_vector = synic_read_sint(synic, sint) & HV_SYNIC_SINT_VECTOR_MASK;

	atomic64_set(&synic->sint[sint], data);

	synic_update_vector(synic, old_vector);

	synic_update_vector(synic, vector);

	/* Load SynIC vectors into EOI exit bitmap */
	kvm_make_request(KVM_REQ_SCAN_IOAPIC, hv_synic_to_vcpu(synic));
	return 0;
}

static struct kvm_vcpu *get_vcpu_by_vpidx(struct kvm *kvm, u32 vpidx)
{
	struct kvm_vcpu *vcpu = NULL;
	unsigned long i;

	if (vpidx >= KVM_MAX_VCPUS)
		return NULL;

	vcpu = kvm_get_vcpu(kvm, vpidx);
	if (vcpu && kvm_hv_get_vpindex(vcpu) == vpidx)
		return vcpu;
	kvm_for_each_vcpu(i, vcpu, kvm)
		if (kvm_hv_get_vpindex(vcpu) == vpidx)
			return vcpu;
	return NULL;
}

static struct kvm_vcpu_hv_synic *synic_get(struct kvm *kvm, u32 vpidx)
{
	struct kvm_vcpu_hv_synic *synic;
	struct kvm_vcpu_hv *hv_vcpu;
	struct kvm_vcpu *vcpu;

	vcpu = get_vcpu_by_vpidx(kvm, vpidx);
	if (!vcpu)
		return NULL;

	hv_vcpu = to_hv_vcpu_safe(vcpu);
	if (!hv_vcpu)
		return NULL;

	synic = &hv_vcpu->synic;
	return READ_ONCE(synic->active) ? synic : NULL;
}

static void kvm_hv_notify_acked_sint(struct kvm_vcpu *vcpu, u32 sint)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_hv_synic *synic = to_hv_synic(vcpu);
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	struct kvm_vcpu_hv_stimer *stimer;
	int gsi, idx;

	trace_kvm_hv_notify_acked_sint(vcpu->vcpu_id, sint);

	/* Try to deliver pending Hyper-V SynIC timers messages */
	for (idx = 0; idx < ARRAY_SIZE(hv_vcpu->stimer); idx++) {
		stimer = &hv_vcpu->stimer[idx];
		if (stimer->msg_pending && stimer->config.enable &&
		    !stimer->config.direct_mode &&
		    stimer->config.sintx == sint)
			stimer_mark_pending(stimer, false);
	}

	idx = srcu_read_lock(&kvm->irq_srcu);
	gsi = atomic_read(&synic->sint_to_gsi[sint]);
	if (gsi != -1)
		kvm_notify_acked_gsi(kvm, gsi);
	srcu_read_unlock(&kvm->irq_srcu, idx);
}

static void synic_exit(struct kvm_vcpu_hv_synic *synic, u32 msr)
{
	struct kvm_vcpu *vcpu = hv_synic_to_vcpu(synic);
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	hv_vcpu->exit.type = KVM_EXIT_HYPERV_SYNIC;
	hv_vcpu->exit.plane = vcpu->plane_level;
	hv_vcpu->exit.u.synic.msr = msr;
	hv_vcpu->exit.u.synic.control = synic->control;
	hv_vcpu->exit.u.synic.evt_page = synic->evt_page;
	hv_vcpu->exit.u.synic.msg_page = synic->msg_page;

	kvm_make_request(KVM_REQ_HV_EXIT, vcpu);
}

static int synic_set_msr(struct kvm_vcpu_hv_synic *synic,
			 u32 msr, u64 data, bool host)
{
	struct kvm_vcpu *vcpu = hv_synic_to_vcpu(synic);
	int ret;

	if (!synic->active && (!host || data))
		return 1;

	trace_kvm_hv_synic_set_msr(vcpu->vcpu_id, msr, data, host);

	ret = 0;
	switch (msr) {
	case HV_X64_MSR_SCONTROL:
		synic->control = data;
		if (!host)
			synic_exit(synic, msr);
		break;
	case HV_X64_MSR_SVERSION:
		if (!host) {
			ret = 1;
			break;
		}
		synic->version = data;
		break;
	case HV_X64_MSR_SIEFP:
		if ((data & HV_SYNIC_SIEFP_ENABLE) && !host &&
		    !synic->dont_zero_synic_pages)
			if (kvm_clear_guest(vcpu->kvm,
					    data & PAGE_MASK, PAGE_SIZE)) {
				ret = 1;
				break;
			}
		synic->evt_page = data;
		if (!host)
			synic_exit(synic, msr);
		break;
	case HV_X64_MSR_SIMP:
		if ((data & HV_SYNIC_SIMP_ENABLE) && !host &&
		    !synic->dont_zero_synic_pages)
			if (kvm_clear_guest(vcpu->kvm,
					    data & PAGE_MASK, PAGE_SIZE)) {
				ret = 1;
				break;
			}
		synic->msg_page = data;
		if (!host)
			synic_exit(synic, msr);
		break;
	case HV_X64_MSR_EOM: {
		int i;

		if (!synic->active)
			break;

		for (i = 0; i < ARRAY_SIZE(synic->sint); i++)
			kvm_hv_notify_acked_sint(vcpu, i);
		break;
	}
	case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
		ret = synic_set_sint(synic, msr - HV_X64_MSR_SINT0, data, host);
		break;
	default:
		ret = 1;
		break;
	}
	return ret;
}

static bool kvm_hv_is_syndbg_enabled(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	return hv_vcpu->cpuid_cache.syndbg_cap_eax &
		HV_X64_SYNDBG_CAP_ALLOW_KERNEL_DEBUGGING;
}

static int kvm_hv_syndbg_complete_userspace(struct kvm_vcpu *vcpu)
{
	struct kvm_hv *hv = to_kvm_hv(vcpu->kvm);

	if (vcpu->run->hyperv.u.syndbg.msr == HV_X64_MSR_SYNDBG_CONTROL)
		hv->hv_syndbg.control.status =
			vcpu->run->hyperv.u.syndbg.status;
	return 1;
}

static void syndbg_exit(struct kvm_vcpu *vcpu, u32 msr)
{
	struct kvm_hv_syndbg *syndbg = to_hv_syndbg(vcpu);
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	hv_vcpu->exit.type = KVM_EXIT_HYPERV_SYNDBG;
	hv_vcpu->exit.plane = vcpu->plane_level;
	hv_vcpu->exit.u.syndbg.msr = msr;
	hv_vcpu->exit.u.syndbg.control = syndbg->control.control;
	hv_vcpu->exit.u.syndbg.send_page = syndbg->control.send_page;
	hv_vcpu->exit.u.syndbg.recv_page = syndbg->control.recv_page;
	hv_vcpu->exit.u.syndbg.pending_page = syndbg->control.pending_page;
	vcpu->arch.complete_userspace_io =
			kvm_hv_syndbg_complete_userspace;

	kvm_make_request(KVM_REQ_HV_EXIT, vcpu);
}

static int syndbg_set_msr(struct kvm_vcpu *vcpu, u32 msr, u64 data, bool host)
{
	struct kvm_hv_syndbg *syndbg = to_hv_syndbg(vcpu);

	if (!kvm_hv_is_syndbg_enabled(vcpu) && !host)
		return 1;

	trace_kvm_hv_syndbg_set_msr(vcpu->vcpu_id,
				    to_hv_vcpu(vcpu)->vp_index, msr, data);
	switch (msr) {
	case HV_X64_MSR_SYNDBG_CONTROL:
		syndbg->control.control = data;
		if (!host)
			syndbg_exit(vcpu, msr);
		break;
	case HV_X64_MSR_SYNDBG_STATUS:
		syndbg->control.status = data;
		break;
	case HV_X64_MSR_SYNDBG_SEND_BUFFER:
		syndbg->control.send_page = data;
		break;
	case HV_X64_MSR_SYNDBG_RECV_BUFFER:
		syndbg->control.recv_page = data;
		break;
	case HV_X64_MSR_SYNDBG_PENDING_BUFFER:
		syndbg->control.pending_page = data;
		if (!host)
			syndbg_exit(vcpu, msr);
		break;
	case HV_X64_MSR_SYNDBG_OPTIONS:
		syndbg->options = data;
		break;
	default:
		break;
	}

	return 0;
}

static int syndbg_get_msr(struct kvm_vcpu *vcpu, u32 msr, u64 *pdata, bool host)
{
	struct kvm_hv_syndbg *syndbg = to_hv_syndbg(vcpu);

	if (!kvm_hv_is_syndbg_enabled(vcpu) && !host)
		return 1;

	switch (msr) {
	case HV_X64_MSR_SYNDBG_CONTROL:
		*pdata = syndbg->control.control;
		break;
	case HV_X64_MSR_SYNDBG_STATUS:
		*pdata = syndbg->control.status;
		break;
	case HV_X64_MSR_SYNDBG_SEND_BUFFER:
		*pdata = syndbg->control.send_page;
		break;
	case HV_X64_MSR_SYNDBG_RECV_BUFFER:
		*pdata = syndbg->control.recv_page;
		break;
	case HV_X64_MSR_SYNDBG_PENDING_BUFFER:
		*pdata = syndbg->control.pending_page;
		break;
	case HV_X64_MSR_SYNDBG_OPTIONS:
		*pdata = syndbg->options;
		break;
	default:
		break;
	}

	trace_kvm_hv_syndbg_get_msr(vcpu->vcpu_id, kvm_hv_get_vpindex(vcpu), msr, *pdata);

	return 0;
}

static int synic_get_msr(struct kvm_vcpu_hv_synic *synic, u32 msr, u64 *pdata,
			 bool host)
{
	int ret;

	if (!synic->active && !host)
		return 1;

	ret = 0;
	switch (msr) {
	case HV_X64_MSR_SCONTROL:
		*pdata = synic->control;
		break;
	case HV_X64_MSR_SVERSION:
		*pdata = synic->version;
		break;
	case HV_X64_MSR_SIEFP:
		*pdata = synic->evt_page;
		break;
	case HV_X64_MSR_SIMP:
		*pdata = synic->msg_page;
		break;
	case HV_X64_MSR_EOM:
		*pdata = 0;
		break;
	case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
		*pdata = atomic64_read(&synic->sint[msr - HV_X64_MSR_SINT0]);
		break;
	default:
		ret = 1;
		break;
	}
	return ret;
}

static int synic_set_irq(struct kvm_vcpu_hv_synic *synic, u32 sint)
{
	struct kvm_vcpu *vcpu = hv_synic_to_vcpu(synic);
	struct kvm_lapic_irq irq;
	int ret, vector;

	if (KVM_BUG_ON(!lapic_in_kernel(vcpu), vcpu->kvm))
		return -EINVAL;

	if (sint >= ARRAY_SIZE(synic->sint))
		return -EINVAL;

	vector = synic_get_sint_vector(synic_read_sint(synic, sint));
	if (vector < 0)
		return -ENOENT;

	memset(&irq, 0, sizeof(irq));
	irq.shorthand = APIC_DEST_SELF;
	irq.dest_mode = APIC_DEST_PHYSICAL;
	irq.delivery_mode = APIC_DM_FIXED;
	irq.vector = vector;
	irq.level = 1;

	ret = kvm_irq_delivery_to_apic(vcpu->plane, vcpu->arch.apic, &irq);
	trace_kvm_hv_synic_set_irq(vcpu->vcpu_id, sint, irq.vector, ret);
	return ret;
}

int kvm_hv_synic_set_irq(struct kvm_kernel_irq_routing_entry *e, struct kvm *kvm,
			 int irq_source_id, int level, bool line_status)
{
	struct kvm_vcpu_hv_synic *synic;

	if (!level)
		return -1;

	synic = synic_get(kvm, e->hv_sint.vcpu);
	if (!synic)
		return -EINVAL;

	return synic_set_irq(synic, e->hv_sint.sint);
}

void kvm_hv_synic_send_eoi(struct kvm_vcpu *vcpu, int vector)
{
	struct kvm_vcpu_hv_synic *synic = to_hv_synic(vcpu);
	int i;

	trace_kvm_hv_synic_send_eoi(vcpu->vcpu_id, vector);

	for (i = 0; i < ARRAY_SIZE(synic->sint); i++)
		if (synic_get_sint_vector(synic_read_sint(synic, i)) == vector)
			kvm_hv_notify_acked_sint(vcpu, i);
}

static int kvm_hv_set_sint_gsi(struct kvm *kvm, u32 vpidx, u32 sint, int gsi)
{
	struct kvm_vcpu_hv_synic *synic;

	synic = synic_get(kvm, vpidx);
	if (!synic)
		return -EINVAL;

	if (sint >= ARRAY_SIZE(synic->sint_to_gsi))
		return -EINVAL;

	atomic_set(&synic->sint_to_gsi[sint], gsi);
	return 0;
}

void kvm_hv_irq_routing_update(struct kvm *kvm)
{
	struct kvm_irq_routing_table *irq_rt;
	struct kvm_kernel_irq_routing_entry *e;
	u32 gsi;

	irq_rt = srcu_dereference_check(kvm->irq_routing, &kvm->irq_srcu,
					lockdep_is_held(&kvm->irq_lock));

	for (gsi = 0; gsi < irq_rt->nr_rt_entries; gsi++) {
		hlist_for_each_entry(e, &irq_rt->map[gsi], link) {
			if (e->type == KVM_IRQ_ROUTING_HV_SINT)
				kvm_hv_set_sint_gsi(kvm, e->hv_sint.vcpu,
						    e->hv_sint.sint, gsi);
		}
	}
}

static void synic_init(struct kvm_vcpu_hv_synic *synic)
{
	int i;

	memset(synic, 0, sizeof(*synic));
	synic->version = HV_SYNIC_VERSION_1;
	for (i = 0; i < ARRAY_SIZE(synic->sint); i++) {
		atomic64_set(&synic->sint[i], HV_SYNIC_SINT_MASKED);
		atomic_set(&synic->sint_to_gsi[i], -1);
	}
}

static u64 get_time_ref_counter(struct kvm *kvm)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	struct kvm_vcpu *vcpu;
	u64 tsc;

	/*
	 * Fall back to get_kvmclock_ns() when TSC page hasn't been set up,
	 * is broken, disabled or being updated.
	 */
	if (hv->hv_tsc_page_status != HV_TSC_PAGE_SET)
		return div_u64(get_kvmclock_ns(kvm), 100);

	vcpu = kvm_get_vcpu(kvm, 0);
	tsc = kvm_read_l1_tsc(vcpu, rdtsc());
	return mul_u64_u64_shr(tsc, hv->tsc_ref.tsc_scale, 64)
		+ hv->tsc_ref.tsc_offset;
}

static void stimer_mark_pending(struct kvm_vcpu_hv_stimer *stimer,
				bool vcpu_kick)
{
	struct kvm_vcpu *vcpu = hv_stimer_to_vcpu(stimer);

	set_bit(stimer->index, vcpu->arch.hyperv->stimer_pending_bitmap);
	kvm_make_request(KVM_REQ_HV_STIMER, vcpu);
	if (vcpu_kick)
		kvm_vcpu_kick(vcpu);

	/*
	 * A pending stimer on a suspended higher plane is only processed
	 * once that plane runs; kick the lower twins so the running one
	 * re-evaluates pending higher-plane events and forces entry.
	 */
	if (vcpu_kick && vcpu->plane_level) {
		struct kvm_vcpu *twin;
		int p;

		for (p = 0; p < vcpu->plane_level; p++) {
			twin = vcpu->common->vcpus[p];
			if (twin) {
				kvm_make_request(KVM_REQ_UNBLOCK, twin);
				kvm_vcpu_kick(twin);
			}
		}
	}
}

static void stimer_cleanup(struct kvm_vcpu_hv_stimer *stimer)
{
	struct kvm_vcpu *vcpu = hv_stimer_to_vcpu(stimer);

	trace_kvm_hv_stimer_cleanup(hv_stimer_to_vcpu(stimer)->vcpu_id,
				    stimer->index);

	hrtimer_cancel(&stimer->timer);
	clear_bit(stimer->index, vcpu->arch.hyperv->stimer_pending_bitmap);
	stimer->msg_pending = false;
	stimer->exp_time = 0;
}

static enum hrtimer_restart stimer_timer_callback(struct hrtimer *timer)
{
	struct kvm_vcpu_hv_stimer *stimer;

	stimer = container_of(timer, struct kvm_vcpu_hv_stimer, timer);
	trace_kvm_hv_stimer_callback(hv_stimer_to_vcpu(stimer)->vcpu_id,
				     stimer->index);
	stimer_mark_pending(stimer, true);

	return HRTIMER_NORESTART;
}

/*
 * Translate a stimer expiry given in 100ns reference ticks into an
 * an absolute deadline. Saturates on overflow.
 */
static ktime_t stimer_add_delta(ktime_t now, u64 delta_100ns)
{
	if (delta_100ns >= KTIME_MAX / 100)
		return KTIME_MAX;

	return ktime_add_safe(now, 100 * delta_100ns);
}

/*
 * stimer_start() assumptions:
 * a) stimer->count is not equal to 0
 * b) stimer->config has HV_STIMER_ENABLE flag
 */
static int stimer_start(struct kvm_vcpu_hv_stimer *stimer)
{
	u64 time_now;
	ktime_t ktime_now;
	ktime_t deadline;

	time_now = get_time_ref_counter(hv_stimer_to_vcpu(stimer)->kvm);
	ktime_now = ktime_get();

	if (stimer->config.periodic) {
		if (stimer->exp_time) {
			if (time_now >= stimer->exp_time) {
				u64 remainder;

				div64_u64_rem(time_now - stimer->exp_time,
					      stimer->count, &remainder);
				stimer->exp_time =
					time_now + (stimer->count - remainder);
			}
		} else
			stimer->exp_time = time_now + stimer->count;

		trace_kvm_hv_stimer_start_periodic(
					hv_stimer_to_vcpu(stimer)->vcpu_id,
					stimer->index,
					time_now, stimer->exp_time);

		deadline = stimer_add_delta(ktime_now, stimer->exp_time - time_now);
		hrtimer_start(&stimer->timer, deadline, HRTIMER_MODE_ABS);
		return 0;
	}
	stimer->exp_time = stimer->count;
	if (time_now >= stimer->count) {
		/*
		 * Expire timer according to Hypervisor Top-Level Functional
		 * specification v4(15.3.1):
		 * "If a one shot is enabled and the specified count is in
		 * the past, it will expire immediately."
		 */
		stimer_mark_pending(stimer, false);
		return 0;
	}

	trace_kvm_hv_stimer_start_one_shot(hv_stimer_to_vcpu(stimer)->vcpu_id,
					   stimer->index,
					   time_now, stimer->count);

	deadline = stimer_add_delta(ktime_now, stimer->count - time_now);
	hrtimer_start(&stimer->timer, deadline, HRTIMER_MODE_ABS);

	return 0;
}

static int stimer_set_config(struct kvm_vcpu_hv_stimer *stimer, u64 config,
			     bool host)
{
	union hv_stimer_config new_config = {.as_uint64 = config},
		old_config = {.as_uint64 = stimer->config.as_uint64};
	struct kvm_vcpu *vcpu = hv_stimer_to_vcpu(stimer);
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	struct kvm_vcpu_hv_synic *synic = to_hv_synic(vcpu);

	if (!synic->active && (!host || config))
		return 1;

	if (unlikely(!host && hv_vcpu->enforce_cpuid && new_config.direct_mode &&
		     !(hv_vcpu->cpuid_cache.features_edx &
		       HV_STIMER_DIRECT_MODE_AVAILABLE)))
		return 1;

	trace_kvm_hv_stimer_set_config(hv_stimer_to_vcpu(stimer)->vcpu_id,
				       stimer->index, config, host);

	stimer_cleanup(stimer);
	if (old_config.enable &&
	    !new_config.direct_mode && new_config.sintx == 0)
		new_config.enable = 0;
	stimer->config.as_uint64 = new_config.as_uint64;

	if (stimer->config.enable)
		stimer_mark_pending(stimer, false);

	return 0;
}

static int stimer_set_count(struct kvm_vcpu_hv_stimer *stimer, u64 count,
			    bool host)
{
	struct kvm_vcpu *vcpu = hv_stimer_to_vcpu(stimer);
	struct kvm_vcpu_hv_synic *synic = to_hv_synic(vcpu);

	if (!synic->active && (!host || count))
		return 1;

	trace_kvm_hv_stimer_set_count(hv_stimer_to_vcpu(stimer)->vcpu_id,
				      stimer->index, count, host);

	stimer_cleanup(stimer);
	stimer->count = count;
	if (!host) {
		if (stimer->count == 0)
			stimer->config.enable = 0;
		else if (stimer->config.auto_enable)
			stimer->config.enable = 1;
	}

	if (stimer->config.enable)
		stimer_mark_pending(stimer, false);

	return 0;
}

static int stimer_get_config(struct kvm_vcpu_hv_stimer *stimer, u64 *pconfig)
{
	*pconfig = stimer->config.as_uint64;
	return 0;
}

static int stimer_get_count(struct kvm_vcpu_hv_stimer *stimer, u64 *pcount)
{
	*pcount = stimer->count;
	return 0;
}

/*
 * SIMP accessors: a plane overlay page, when installed by userspace,
 * carries the live message page for this plane; the memslot holds only
 * the underlay the other planes see.
 */
static int synic_msg_page_read(struct kvm_vcpu *vcpu, gfn_t gfn, void *data,
			       int offset, int len)
{
	unsigned long uaddr = kvm_plane_overlay_uaddr(vcpu->plane, gfn);

	if (uaddr)
		return copy_from_user(data, (void __user *)(uaddr + offset),
				      len) ? -EFAULT : 0;
	/*
	 * Mirror the write side: without an overlay a higher plane's
	 * message page is backed by underlay memory that plane 0 controls.
	 * Deciding deliverability from plane-0-writable bytes would let a
	 * lower VTL plant a non-HVMSG_NONE type and silently swallow a
	 * no_retry (periodic stimer) message; fail so the delivery is
	 * retried once the overlay appears.
	 */
	if (vcpu->plane_level)
		return -EFAULT;
	return kvm_vcpu_read_guest_page(vcpu, gfn, data, offset, len);
}

static int synic_msg_page_write(struct kvm_vcpu *vcpu, gfn_t gfn,
				const void *data, int offset, int len)
{
	unsigned long uaddr = kvm_plane_overlay_uaddr(vcpu->plane, gfn);

	if (uaddr)
		return copy_to_user((void __user *)(uaddr + offset), data,
				    len) ? -EFAULT : 0;
	/*
	 * Never write a higher plane's messages into guest RAM: without an
	 * overlay installed that memory is the underlay every other plane
	 * sees, and silently corrupting plane-0-owned pages is far worse
	 * than retrying the message once the overlay appears.
	 */
	if (vcpu->plane_level)
		return -EFAULT;
	return kvm_vcpu_write_guest_page(vcpu, gfn, data, offset, len);
}

static int synic_deliver_msg(struct kvm_vcpu_hv_synic *synic, u32 sint,
			     struct hv_message *src_msg, bool no_retry)
{
	struct kvm_vcpu *vcpu = hv_synic_to_vcpu(synic);
	int msg_off = offsetof(struct hv_message_page, sint_message[sint]);
	gfn_t msg_page_gfn;
	struct hv_message_header hv_hdr;
	int r;

	if (!(synic->msg_page & HV_SYNIC_SIMP_ENABLE))
		return -ENOENT;

	msg_page_gfn = synic->msg_page >> PAGE_SHIFT;

	/*
	 * Strictly following the spec-mandated ordering would assume setting
	 * .msg_pending before checking .message_type.  However, this function
	 * is only called in vcpu context so the entire update is atomic from
	 * guest POV and thus the exact order here doesn't matter.
	 */
	r = synic_msg_page_read(vcpu, msg_page_gfn, &hv_hdr.message_type,
				msg_off + offsetof(struct hv_message,
						   header.message_type),
				sizeof(hv_hdr.message_type));
	if (r < 0)
		return r;

	if (hv_hdr.message_type != HVMSG_NONE) {
		if (no_retry)
			return 0;

		hv_hdr.message_flags.asu8 = 0;
		hv_hdr.message_flags.msg_pending = 1;
		r = synic_msg_page_write(vcpu, msg_page_gfn,
					 &hv_hdr.message_flags,
					 msg_off +
					 offsetof(struct hv_message,
						  header.message_flags),
					 sizeof(hv_hdr.message_flags));
		if (r < 0)
			return r;
		return -EAGAIN;
	}

	r = synic_msg_page_write(vcpu, msg_page_gfn, src_msg, msg_off,
				 sizeof(src_msg->header) +
				 src_msg->header.payload_size);
	if (r < 0)
		return r;

	r = synic_set_irq(synic, sint);
	if (r < 0)
		return r;
	if (r == 0)
		return -EFAULT;
	return 0;
}

static int stimer_send_msg(struct kvm_vcpu_hv_stimer *stimer)
{
	struct kvm_vcpu *vcpu = hv_stimer_to_vcpu(stimer);
	struct hv_message *msg = &stimer->msg;
	struct hv_timer_message_payload *payload =
			(struct hv_timer_message_payload *)&msg->u.payload;

	/*
	 * To avoid piling up periodic ticks, don't retry message
	 * delivery for them (within "lazy" lost ticks policy).
	 */
	bool no_retry = stimer->config.periodic;

	payload->expiration_time = stimer->exp_time;
	payload->delivery_time = get_time_ref_counter(vcpu->kvm);
	return synic_deliver_msg(to_hv_synic(vcpu),
				 stimer->config.sintx, msg,
				 no_retry);
}

static int stimer_notify_direct(struct kvm_vcpu_hv_stimer *stimer)
{
	struct kvm_vcpu *vcpu = hv_stimer_to_vcpu(stimer);
	struct kvm_lapic_irq irq = {
		.delivery_mode = APIC_DM_FIXED,
		.vector = stimer->config.apic_vector
	};

	if (lapic_in_kernel(vcpu))
		return !kvm_apic_set_irq(vcpu, &irq, NULL);
	return 0;
}

static void stimer_expiration(struct kvm_vcpu_hv_stimer *stimer)
{
	int r, direct = stimer->config.direct_mode;

	stimer->msg_pending = true;
	if (!direct)
		r = stimer_send_msg(stimer);
	else
		r = stimer_notify_direct(stimer);
	trace_kvm_hv_stimer_expiration(hv_stimer_to_vcpu(stimer)->vcpu_id,
				       stimer->index, direct, r);
	if (!r) {
		stimer->msg_pending = false;
		if (!(stimer->config.periodic))
			stimer->config.enable = 0;
	}
}

void kvm_hv_process_stimers(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	struct kvm_vcpu_hv_stimer *stimer;
	u64 time_now, exp_time;
	int i;

	if (!hv_vcpu)
		return;

	for (i = 0; i < ARRAY_SIZE(hv_vcpu->stimer); i++)
		if (test_and_clear_bit(i, hv_vcpu->stimer_pending_bitmap)) {
			stimer = &hv_vcpu->stimer[i];
			if (stimer->config.enable) {
				exp_time = stimer->exp_time;

				if (exp_time) {
					time_now =
						get_time_ref_counter(vcpu->kvm);
					if (time_now >= exp_time)
						stimer_expiration(stimer);
				}

				if ((stimer->config.enable) &&
				    stimer->count) {
					if (!stimer->msg_pending)
						stimer_start(stimer);
				} else
					stimer_cleanup(stimer);
			}
		}
}

void kvm_hv_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	int i;

	if (!hv_vcpu)
		return;

	for (i = 0; i < ARRAY_SIZE(hv_vcpu->stimer); i++)
		stimer_cleanup(&hv_vcpu->stimer[i]);

	kfree(hv_vcpu);
	vcpu->arch.hyperv = NULL;
}

bool kvm_hv_assist_page_enabled(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	if (!hv_vcpu)
		return false;

	if (!(hv_vcpu->hv_vapic & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE))
		return false;
	return vcpu->arch.pv_eoi.msr_val & KVM_MSR_ENABLED;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_hv_assist_page_enabled);

int kvm_hv_get_assist_page(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	if (!hv_vcpu || !kvm_hv_assist_page_enabled(vcpu))
		return -EFAULT;

	return kvm_read_guest_cached(vcpu->kvm, &vcpu->arch.pv_eoi.data,
				     &hv_vcpu->vp_assist_page, sizeof(struct hv_vp_assist_page));
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_hv_get_assist_page);

static void stimer_prepare_msg(struct kvm_vcpu_hv_stimer *stimer)
{
	struct hv_message *msg = &stimer->msg;
	struct hv_timer_message_payload *payload =
			(struct hv_timer_message_payload *)&msg->u.payload;

	memset(&msg->header, 0, sizeof(msg->header));
	msg->header.message_type = HVMSG_TIMER_EXPIRED;
	msg->header.payload_size = sizeof(*payload);

	payload->timer_index = stimer->index;
	payload->expiration_time = 0;
	payload->delivery_time = 0;
}

static void stimer_init(struct kvm_vcpu_hv_stimer *stimer, int timer_index)
{
	memset(stimer, 0, sizeof(*stimer));
	stimer->index = timer_index;
	hrtimer_setup(&stimer->timer, stimer_timer_callback, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	stimer_prepare_msg(stimer);
}

int kvm_hv_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	int i;

	if (hv_vcpu)
		return 0;

	hv_vcpu = kzalloc_obj(struct kvm_vcpu_hv, GFP_KERNEL_ACCOUNT);
	if (!hv_vcpu)
		return -ENOMEM;

	hv_vcpu->vcpu = vcpu;

	synic_init(&hv_vcpu->synic);

	bitmap_zero(hv_vcpu->stimer_pending_bitmap, HV_SYNIC_STIMER_COUNT);
	for (i = 0; i < ARRAY_SIZE(hv_vcpu->stimer); i++)
		stimer_init(&hv_vcpu->stimer[i], i);

	hv_vcpu->vp_index = vcpu->vcpu_idx;

	for (i = 0; i < HV_NR_TLB_FLUSH_FIFOS; i++) {
		INIT_KFIFO(hv_vcpu->tlb_flush_fifo[i].entries);
		spin_lock_init(&hv_vcpu->tlb_flush_fifo[i].write_lock);
	}

	/*
	 * Ensure the structure is fully initialized before it's visible to
	 * other tasks, as much of the state can be legally accessed without
	 * holding vcpu->mutex.
	 *
	 * Pairs with the smp_load_acquire() in to_hv_vcpu_safe().
	 */
	smp_store_release(&vcpu->arch.hyperv, hv_vcpu);
	return 0;
}

int kvm_hv_activate_synic(struct kvm_vcpu *vcpu, bool dont_zero_synic_pages)
{
	struct kvm_vcpu_hv_synic *synic;
	int r;

	r = kvm_hv_vcpu_init(vcpu);
	if (r)
		return r;

	synic = to_hv_synic(vcpu);

	WRITE_ONCE(synic->active, true);
	synic->dont_zero_synic_pages = dont_zero_synic_pages;
	synic->control = HV_SYNIC_CONTROL_ENABLE;
	return 0;
}

static bool kvm_hv_msr_partition_wide(u32 msr)
{
	bool r = false;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
	case HV_X64_MSR_HYPERCALL:
	case HV_X64_MSR_REFERENCE_TSC:
	case HV_X64_MSR_TIME_REF_COUNT:
	case HV_X64_MSR_CRASH_CTL:
	case HV_X64_MSR_CRASH_P0 ... HV_X64_MSR_CRASH_P4:
	case HV_X64_MSR_RESET:
	case HV_X64_MSR_REENLIGHTENMENT_CONTROL:
	case HV_X64_MSR_TSC_EMULATION_CONTROL:
	case HV_X64_MSR_TSC_EMULATION_STATUS:
	case HV_X64_MSR_TSC_INVARIANT_CONTROL:
	case HV_X64_MSR_SYNDBG_OPTIONS:
	case HV_X64_MSR_SYNDBG_CONTROL ... HV_X64_MSR_SYNDBG_PENDING_BUFFER:
		r = true;
		break;
	}

	return r;
}

static int kvm_hv_msr_get_crash_data(struct kvm *kvm, u32 index, u64 *pdata)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	size_t size = ARRAY_SIZE(hv->hv_crash_param);

	if (WARN_ON_ONCE(index >= size))
		return -EINVAL;

	*pdata = hv->hv_crash_param[array_index_nospec(index, size)];
	return 0;
}

static int kvm_hv_msr_get_crash_ctl(struct kvm *kvm, u64 *pdata)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);

	*pdata = hv->hv_crash_ctl;
	return 0;
}

static int kvm_hv_msr_set_crash_ctl(struct kvm *kvm, u64 data)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);

	hv->hv_crash_ctl = data & HV_CRASH_CTL_CRASH_NOTIFY;

	return 0;
}

static int kvm_hv_msr_set_crash_data(struct kvm *kvm, u32 index, u64 data)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	size_t size = ARRAY_SIZE(hv->hv_crash_param);

	if (WARN_ON_ONCE(index >= size))
		return -EINVAL;

	hv->hv_crash_param[array_index_nospec(index, size)] = data;
	return 0;
}

/*
 * The kvmclock and Hyper-V TSC page use similar formulas, and converting
 * between them is possible:
 *
 * kvmclock formula:
 *    nsec = (ticks - tsc_timestamp) * tsc_to_system_mul * 2^(tsc_shift-32)
 *           + system_time
 *
 * Hyper-V formula:
 *    nsec/100 = ticks * scale / 2^64 + offset
 *
 * When tsc_timestamp = system_time = 0, offset is zero in the Hyper-V formula.
 * By dividing the kvmclock formula by 100 and equating what's left we get:
 *    ticks * scale / 2^64 = ticks * tsc_to_system_mul * 2^(tsc_shift-32) / 100
 *            scale / 2^64 =         tsc_to_system_mul * 2^(tsc_shift-32) / 100
 *            scale        =         tsc_to_system_mul * 2^(32+tsc_shift) / 100
 *
 * Now expand the kvmclock formula and divide by 100:
 *    nsec = ticks * tsc_to_system_mul * 2^(tsc_shift-32)
 *           - tsc_timestamp * tsc_to_system_mul * 2^(tsc_shift-32)
 *           + system_time
 *    nsec/100 = ticks * tsc_to_system_mul * 2^(tsc_shift-32) / 100
 *               - tsc_timestamp * tsc_to_system_mul * 2^(tsc_shift-32) / 100
 *               + system_time / 100
 *
 * Replace tsc_to_system_mul * 2^(tsc_shift-32) / 100 by scale / 2^64:
 *    nsec/100 = ticks * scale / 2^64
 *               - tsc_timestamp * scale / 2^64
 *               + system_time / 100
 *
 * Equate with the Hyper-V formula so that ticks * scale / 2^64 cancels out:
 *    offset = system_time / 100 - tsc_timestamp * scale / 2^64
 *
 * These two equivalencies are implemented in this function.
 */
static bool compute_tsc_page_parameters(struct pvclock_vcpu_time_info *hv_clock,
					struct ms_hyperv_tsc_page *tsc_ref)
{
	u64 max_mul;

	if (!(hv_clock->flags & PVCLOCK_TSC_STABLE_BIT))
		return false;

	/*
	 * check if scale would overflow, if so we use the time ref counter
	 *    tsc_to_system_mul * 2^(tsc_shift+32) / 100 >= 2^64
	 *    tsc_to_system_mul / 100 >= 2^(32-tsc_shift)
	 *    tsc_to_system_mul >= 100 * 2^(32-tsc_shift)
	 */
	max_mul = 100ull << (32 - hv_clock->tsc_shift);
	if (hv_clock->tsc_to_system_mul >= max_mul)
		return false;

	/*
	 * Otherwise compute the scale and offset according to the formulas
	 * derived above.
	 */
	tsc_ref->tsc_scale =
		mul_u64_u32_div(1ULL << (32 + hv_clock->tsc_shift),
				hv_clock->tsc_to_system_mul,
				100);

	tsc_ref->tsc_offset = hv_clock->system_time;
	do_div(tsc_ref->tsc_offset, 100);
	tsc_ref->tsc_offset -=
		mul_u64_u64_shr(hv_clock->tsc_timestamp, tsc_ref->tsc_scale, 64);
	return true;
}

/*
 * Don't touch TSC page values if the guest has opted for TSC emulation after
 * migration. KVM doesn't fully support reenlightenment notifications and TSC
 * access emulation and Hyper-V is known to expect the values in TSC page to
 * stay constant before TSC access emulation is disabled from guest side
 * (HV_X64_MSR_TSC_EMULATION_STATUS). KVM userspace is expected to preserve TSC
 * frequency and guest visible TSC value across migration (and prevent it when
 * TSC scaling is unsupported).
 */
static inline bool tsc_page_update_unsafe(struct kvm_hv *hv)
{
	return (hv->hv_tsc_page_status != HV_TSC_PAGE_GUEST_CHANGED) &&
		hv->hv_tsc_emulation_control;
}

void kvm_hv_setup_tsc_page(struct kvm *kvm,
			   struct pvclock_vcpu_time_info *hv_clock)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	u32 tsc_seq;
	u64 gfn;

	BUILD_BUG_ON(sizeof(tsc_seq) != sizeof(hv->tsc_ref.tsc_sequence));
	BUILD_BUG_ON(offsetof(struct ms_hyperv_tsc_page, tsc_sequence) != 0);

	guard(mutex)(&hv->hv_lock);

	if (hv->hv_tsc_page_status == HV_TSC_PAGE_BROKEN ||
	    hv->hv_tsc_page_status == HV_TSC_PAGE_SET ||
	    hv->hv_tsc_page_status == HV_TSC_PAGE_UNSET)
		return;

	if (!(hv->hv_tsc_page & HV_X64_MSR_TSC_REFERENCE_ENABLE))
		return;

	gfn = hv->hv_tsc_page >> HV_X64_MSR_TSC_REFERENCE_ADDRESS_SHIFT;
	/*
	 * Because the TSC parameters only vary when there is a
	 * change in the master clock, do not bother with caching.
	 */
	if (unlikely(kvm_read_guest(kvm, gfn_to_gpa(gfn),
				    &tsc_seq, sizeof(tsc_seq))))
		goto out_err;

	if (tsc_seq && tsc_page_update_unsafe(hv)) {
		if (kvm_read_guest(kvm, gfn_to_gpa(gfn), &hv->tsc_ref, sizeof(hv->tsc_ref)))
			goto out_err;

		hv->tsc_ref_from_guest = true;
		hv->hv_tsc_page_status = HV_TSC_PAGE_SET;
		return;
	}

	/*
	 * While we're computing and writing the parameters, force the
	 * guest to use the time reference count MSR.
	 */
	hv->tsc_ref.tsc_sequence = 0;
	if (kvm_write_guest(kvm, gfn_to_gpa(gfn),
			    &hv->tsc_ref, sizeof(hv->tsc_ref.tsc_sequence)))
		goto out_err;

	if (!compute_tsc_page_parameters(hv_clock, &hv->tsc_ref))
		goto out_err;

	/* Ensure sequence is zero before writing the rest of the struct.  */
	smp_wmb();
	if (kvm_write_guest(kvm, gfn_to_gpa(gfn), &hv->tsc_ref, sizeof(hv->tsc_ref)))
		goto out_err;

	/*
	 * Now switch to the TSC page mechanism by writing the sequence.
	 */
	tsc_seq++;
	if (tsc_seq == 0xFFFFFFFF || tsc_seq == 0)
		tsc_seq = 1;

	/* Write the struct entirely before the non-zero sequence.  */
	smp_wmb();

	hv->tsc_ref.tsc_sequence = tsc_seq;
	if (kvm_write_guest(kvm, gfn_to_gpa(gfn),
			    &hv->tsc_ref, sizeof(hv->tsc_ref.tsc_sequence)))
		goto out_err;

	hv->tsc_ref_from_guest = false;
	hv->hv_tsc_page_status = HV_TSC_PAGE_SET;
	return;

out_err:
	hv->hv_tsc_page_status = HV_TSC_PAGE_BROKEN;
}

void kvm_hv_request_tsc_page_update(struct kvm *kvm)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);

	mutex_lock(&hv->hv_lock);

	if (hv->hv_tsc_page_status == HV_TSC_PAGE_SET &&
	    !tsc_page_update_unsafe(hv))
		hv->hv_tsc_page_status = HV_TSC_PAGE_HOST_CHANGED;

	mutex_unlock(&hv->hv_lock);
}

static bool hv_check_msr_access(struct kvm_vcpu_hv *hv_vcpu, u32 msr)
{
	if (!hv_vcpu->enforce_cpuid)
		return true;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
	case HV_X64_MSR_HYPERCALL:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_HYPERCALL_AVAILABLE;
	case HV_X64_MSR_VP_RUNTIME:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_VP_RUNTIME_AVAILABLE;
	case HV_X64_MSR_TIME_REF_COUNT:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_TIME_REF_COUNT_AVAILABLE;
	case HV_X64_MSR_VP_INDEX:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_VP_INDEX_AVAILABLE;
	case HV_X64_MSR_RESET:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_RESET_AVAILABLE;
	case HV_X64_MSR_REFERENCE_TSC:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_REFERENCE_TSC_AVAILABLE;
	case HV_X64_MSR_SCONTROL:
	case HV_X64_MSR_SVERSION:
	case HV_X64_MSR_SIEFP:
	case HV_X64_MSR_SIMP:
	case HV_X64_MSR_EOM:
	case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_SYNIC_AVAILABLE;
	case HV_X64_MSR_STIMER0_CONFIG:
	case HV_X64_MSR_STIMER1_CONFIG:
	case HV_X64_MSR_STIMER2_CONFIG:
	case HV_X64_MSR_STIMER3_CONFIG:
	case HV_X64_MSR_STIMER0_COUNT:
	case HV_X64_MSR_STIMER1_COUNT:
	case HV_X64_MSR_STIMER2_COUNT:
	case HV_X64_MSR_STIMER3_COUNT:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_SYNTIMER_AVAILABLE;
	case HV_X64_MSR_EOI:
	case HV_X64_MSR_ICR:
	case HV_X64_MSR_TPR:
	case HV_X64_MSR_VP_ASSIST_PAGE:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_MSR_APIC_ACCESS_AVAILABLE;
	case HV_X64_MSR_TSC_FREQUENCY:
	case HV_X64_MSR_APIC_FREQUENCY:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_ACCESS_FREQUENCY_MSRS;
	case HV_X64_MSR_REENLIGHTENMENT_CONTROL:
	case HV_X64_MSR_TSC_EMULATION_CONTROL:
	case HV_X64_MSR_TSC_EMULATION_STATUS:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_ACCESS_REENLIGHTENMENT;
	case HV_X64_MSR_TSC_INVARIANT_CONTROL:
		return hv_vcpu->cpuid_cache.features_eax &
			HV_ACCESS_TSC_INVARIANT;
	case HV_X64_MSR_CRASH_P0 ... HV_X64_MSR_CRASH_P4:
	case HV_X64_MSR_CRASH_CTL:
		return hv_vcpu->cpuid_cache.features_edx &
			HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE;
	case HV_X64_MSR_SYNDBG_OPTIONS:
	case HV_X64_MSR_SYNDBG_CONTROL ... HV_X64_MSR_SYNDBG_PENDING_BUFFER:
		return hv_vcpu->cpuid_cache.features_edx &
			HV_FEATURE_DEBUG_MSRS_AVAILABLE;
	default:
		break;
	}

	return false;
}

#define KVM_HV_WIN2016_GUEST_ID 0x1040a00003839
#define KVM_HV_WIN2016_GUEST_ID_MASK (~GENMASK_ULL(23, 16)) /* mask out the service version */

/*
 * Hyper-V enabled Windows Server 2016 SMP VMs fail to boot in !XSAVES && XSAVEC
 * configuration.
 * Such configuration can result from, for example, AMD Erratum 1386 workaround.
 *
 * Print a notice so users aren't left wondering what's suddenly gone wrong.
 */
static void __kvm_hv_xsaves_xsavec_maybe_warn(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_hv *hv = to_kvm_hv(kvm);

	/* Check again under the hv_lock.  */
	if (hv->xsaves_xsavec_checked)
		return;

	if ((hv->hv_guest_os_id[0] & KVM_HV_WIN2016_GUEST_ID_MASK) !=
	    KVM_HV_WIN2016_GUEST_ID)
		return;

	hv->xsaves_xsavec_checked = true;

	/* UP configurations aren't affected */
	if (atomic_read(&kvm->online_vcpus) < 2)
		return;

	if (guest_cpuid_has(vcpu, X86_FEATURE_XSAVES) ||
	    !guest_cpu_cap_has(vcpu, X86_FEATURE_XSAVEC))
		return;

	pr_notice_ratelimited("Booting SMP Windows KVM VM with !XSAVES && XSAVEC. "
			      "If it fails to boot try disabling XSAVEC in the VM config.\n");
}

void kvm_hv_xsaves_xsavec_maybe_warn(struct kvm_vcpu *vcpu)
{
	struct kvm_hv *hv = to_kvm_hv(vcpu->kvm);

	if (!vcpu->arch.hyperv_enabled ||
	    hv->xsaves_xsavec_checked)
		return;

	mutex_lock(&hv->hv_lock);
	__kvm_hv_xsaves_xsavec_maybe_warn(vcpu);
	mutex_unlock(&hv->hv_lock);
}

static int kvm_hv_set_msr_pw(struct kvm_vcpu *vcpu, u32 msr, u64 data,
			     bool host)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_hv *hv = to_kvm_hv(kvm);

	if (unlikely(!host && !hv_check_msr_access(to_hv_vcpu(vcpu), msr)))
		return 1;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
		hv->hv_guest_os_id[vcpu->plane_level] = data;
		/* setting guest os id to zero disables hypercall page */
		if (!hv->hv_guest_os_id[vcpu->plane_level])
			hv->hv_hypercall[vcpu->plane_level] &=
				~HV_X64_MSR_HYPERCALL_ENABLE;
		break;
	case HV_X64_MSR_HYPERCALL: {
		u8 instructions[9];
		int i = 0;
		u64 addr;

		/* if guest os id is not set hypercall should remain disabled */
		if (!hv->hv_guest_os_id[vcpu->plane_level])
			break;
		if (!(data & HV_X64_MSR_HYPERCALL_ENABLE)) {
			hv->hv_hypercall[vcpu->plane_level] = data;
			break;
		}

		/*
		 * If Xen and Hyper-V hypercalls are both enabled, disambiguate
		 * the same way Xen itself does, by setting the bit 31 of EAX
		 * which is RsvdZ in the 32-bit Hyper-V hypercall ABI and just
		 * going to be clobbered on 64-bit.
		 */
		if (kvm_xen_hypercall_enabled(kvm)) {
			/* orl $0x80000000, %eax */
			instructions[i++] = 0x0d;
			instructions[i++] = 0x00;
			instructions[i++] = 0x00;
			instructions[i++] = 0x00;
			instructions[i++] = 0x80;
		}

		/* vmcall/vmmcall */
		kvm_x86_call(patch_hypercall)(vcpu, instructions + i);
		i += 3;

		/* ret */
		((unsigned char *)instructions)[i++] = 0xc3;

		addr = data & HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK;
		if (kvm_vcpu_write_guest(vcpu, addr, instructions, i))
			return 1;
		hv->hv_hypercall[vcpu->plane_level] = data;
		break;
	}
	case HV_X64_MSR_REFERENCE_TSC:
		/*
		 * The reference TSC page is a per-VTL instance.  Plane 0 keeps
		 * the live masterclock-maintained page; a non-zero plane gets
		 * a one-shot copy of the current parameters, which stay valid
		 * while the masterclock is stable.
		 */
		if (vcpu->plane_level) {
			struct ms_hyperv_tsc_page tsc_ref = {};
			u32 tsc_seq;
			u64 gfn;

			hv->hv_tsc_page_plane[vcpu->plane_level] = data;
			if (!(data & HV_X64_MSR_TSC_REFERENCE_ENABLE))
				break;

			/*
			 * Copy only host-computed parameters.  After a
			 * masterclock change under guest TSC emulation,
			 * hv->tsc_ref holds values read back from the
			 * plane-0 page, which the lowest VTL can write;
			 * presenting those to another plane would let it
			 * forge that plane's clock.  Without usable
			 * parameters, publish an invalid (zero) sequence so
			 * the plane falls back to the TIME_REF_COUNT MSR.
			 */
			if (hv->hv_tsc_page_status == HV_TSC_PAGE_SET &&
			    !hv->tsc_ref_from_guest)
				tsc_ref = hv->tsc_ref;

			gfn = data >> HV_X64_MSR_TSC_REFERENCE_ADDRESS_SHIFT;
			tsc_seq = tsc_ref.tsc_sequence;

			/*
			 * Write the body under a zero sequence, then the
			 * real sequence, so a concurrent reader on this
			 * plane never consumes torn parameters.
			 */
			tsc_ref.tsc_sequence = 0;
			if (kvm_vcpu_write_guest(vcpu, gfn_to_gpa(gfn),
						 &tsc_ref, sizeof(tsc_ref)))
				return 1;

			if (!tsc_seq)
				break;

			tsc_ref.tsc_sequence = tsc_seq;
			if (kvm_vcpu_write_guest(vcpu, gfn_to_gpa(gfn),
						 &tsc_ref,
						 sizeof(tsc_ref.tsc_sequence)))
				return 1;
			break;
		}
		hv->hv_tsc_page = data;
		if (hv->hv_tsc_page & HV_X64_MSR_TSC_REFERENCE_ENABLE) {
			if (!host)
				hv->hv_tsc_page_status = HV_TSC_PAGE_GUEST_CHANGED;
			else
				hv->hv_tsc_page_status = HV_TSC_PAGE_HOST_CHANGED;
			kvm_make_request(KVM_REQ_MASTERCLOCK_UPDATE, vcpu);
		} else {
			hv->hv_tsc_page_status = HV_TSC_PAGE_UNSET;
		}
		break;
	case HV_X64_MSR_CRASH_P0 ... HV_X64_MSR_CRASH_P4:
		return kvm_hv_msr_set_crash_data(kvm,
						 msr - HV_X64_MSR_CRASH_P0,
						 data);
	case HV_X64_MSR_CRASH_CTL:
		if (host)
			return kvm_hv_msr_set_crash_ctl(kvm, data);

		if (data & HV_CRASH_CTL_CRASH_NOTIFY) {
			vcpu_debug(vcpu, "hv crash (0x%llx 0x%llx 0x%llx 0x%llx 0x%llx)\n",
				   hv->hv_crash_param[0],
				   hv->hv_crash_param[1],
				   hv->hv_crash_param[2],
				   hv->hv_crash_param[3],
				   hv->hv_crash_param[4]);

			/* Send notification about crash to user space */
			kvm_make_request(KVM_REQ_HV_CRASH, vcpu);
		}
		break;
	case HV_X64_MSR_RESET:
		if (data == 1) {
			vcpu_debug(vcpu, "hyper-v reset requested\n");
			kvm_make_request(KVM_REQ_HV_RESET, vcpu);
		}
		break;
	case HV_X64_MSR_REENLIGHTENMENT_CONTROL:
		hv->hv_reenlightenment_control = data;
		break;
	case HV_X64_MSR_TSC_EMULATION_CONTROL:
		hv->hv_tsc_emulation_control = data;
		break;
	case HV_X64_MSR_TSC_EMULATION_STATUS:
		if (data && !host)
			return 1;

		hv->hv_tsc_emulation_status = data;
		break;
	case HV_X64_MSR_TIME_REF_COUNT:
		/* read-only, but still ignore it if host-initiated */
		if (!host)
			return 1;
		break;
	case HV_X64_MSR_TSC_INVARIANT_CONTROL:
		/* Only bit 0 is supported */
		if (data & ~HV_EXPOSE_INVARIANT_TSC)
			return 1;

		/* The feature can't be disabled from the guest */
		if (!host && hv->hv_invtsc_control && !data)
			return 1;

		hv->hv_invtsc_control = data;
		break;
	case HV_X64_MSR_SYNDBG_OPTIONS:
	case HV_X64_MSR_SYNDBG_CONTROL ... HV_X64_MSR_SYNDBG_PENDING_BUFFER:
		return syndbg_set_msr(vcpu, msr, data, host);
	default:
		kvm_pr_unimpl_wrmsr(vcpu, msr, data);
		return 1;
	}
	return 0;
}

/* Calculate cpu time spent by current task in 100ns units */
static u64 current_task_runtime_100ns(void)
{
	u64 utime, stime;

	task_cputime_adjusted(current, &utime, &stime);

	return div_u64(utime + stime, 100);
}

static int kvm_hv_set_msr(struct kvm_vcpu *vcpu, u32 msr, u64 data, bool host)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	if (unlikely(!host && !hv_check_msr_access(hv_vcpu, msr)))
		return 1;

	switch (msr) {
	case HV_X64_MSR_VP_INDEX: {
		struct kvm_hv *hv = to_kvm_hv(vcpu->kvm);
		u32 new_vp_index = (u32)data;

		if (!host || new_vp_index >= KVM_MAX_VCPUS)
			return 1;

		if (new_vp_index == hv_vcpu->vp_index)
			return 0;

		/*
		 * The VP index is initialized to vcpu_index by
		 * kvm_hv_vcpu_postcreate so they initially match.  Now the
		 * VP index is changing, adjust num_mismatched_vp_indexes if
		 * it now matches or no longer matches vcpu_idx.
		 */
		if (hv_vcpu->vp_index == vcpu->vcpu_idx)
			atomic_inc(&hv->num_mismatched_vp_indexes);
		else if (new_vp_index == vcpu->vcpu_idx)
			atomic_dec(&hv->num_mismatched_vp_indexes);

		hv_vcpu->vp_index = new_vp_index;
		break;
	}
	case HV_X64_MSR_VP_ASSIST_PAGE: {
		u64 gfn;
		unsigned long addr;

		if (!(data & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE)) {
			hv_vcpu->hv_vapic = data;
			if (!vcpu->plane_level &&
			    kvm_lapic_set_pv_eoi(vcpu, 0, 0))
				return 1;
			break;
		}
		gfn = data >> HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT;
		addr = kvm_vcpu_gfn_to_hva(vcpu, gfn);
		if (kvm_is_error_hva(addr))
			return 1;

		/*
		 * Clear apic_assist portion of struct hv_vp_assist_page
		 * only, there can be valuable data in the rest which needs
		 * to be preserved e.g. on migration.
		 */
		if (put_user(0, (u32 __user *)addr))
			return 1;
		hv_vcpu->hv_vapic = data;
		kvm_vcpu_mark_page_dirty(vcpu, gfn);

		/*
		 * The gfn_to_hva cache behind the PV EOI / APIC assist
		 * optimization validates against plane 0's memory
		 * attributes, and a higher plane's VP assist page may
		 * live on a page the plane protected against plane 0
		 * (the Windows secure kernel's does). Don't arm PV EOI
		 * there: pv_eoi.msr_val stays clear, which keeps
		 * kvm_hv_assist_page_enabled() false for the plane, so
		 * every assist-page consumer behind it (PV EOI, nested
		 * enlightened VMCS, the SVM VP-assist read) is disabled
		 * and KVM never touches the page's contents.  The guest
		 * always performs a real EOI.
		 */
		if (!vcpu->plane_level &&
		    kvm_lapic_set_pv_eoi(vcpu,
					 gfn_to_gpa(gfn) | KVM_MSR_ENABLED,
					 sizeof(struct hv_vp_assist_page)))
			return 1;
		break;
	}
	case HV_X64_MSR_EOI:
		return kvm_hv_vapic_msr_write(vcpu, APIC_EOI, data);
	case HV_X64_MSR_ICR:
		return kvm_hv_vapic_msr_write(vcpu, APIC_ICR, data);
	case HV_X64_MSR_TPR:
		return kvm_hv_vapic_msr_write(vcpu, APIC_TASKPRI, data);
	case HV_X64_MSR_VP_RUNTIME:
		if (!host)
			return 1;
		hv_vcpu->runtime_offset = data - current_task_runtime_100ns();
		break;
	case HV_X64_MSR_SCONTROL:
	case HV_X64_MSR_SVERSION:
	case HV_X64_MSR_SIEFP:
	case HV_X64_MSR_SIMP:
	case HV_X64_MSR_EOM:
	case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
		return synic_set_msr(to_hv_synic(vcpu), msr, data, host);
	case HV_X64_MSR_STIMER0_CONFIG:
	case HV_X64_MSR_STIMER1_CONFIG:
	case HV_X64_MSR_STIMER2_CONFIG:
	case HV_X64_MSR_STIMER3_CONFIG: {
		int timer_index = (msr - HV_X64_MSR_STIMER0_CONFIG)/2;

		return stimer_set_config(to_hv_stimer(vcpu, timer_index),
					 data, host);
	}
	case HV_X64_MSR_STIMER0_COUNT:
	case HV_X64_MSR_STIMER1_COUNT:
	case HV_X64_MSR_STIMER2_COUNT:
	case HV_X64_MSR_STIMER3_COUNT: {
		int timer_index = (msr - HV_X64_MSR_STIMER0_COUNT)/2;

		return stimer_set_count(to_hv_stimer(vcpu, timer_index),
					data, host);
	}
	case HV_X64_MSR_TSC_FREQUENCY:
	case HV_X64_MSR_APIC_FREQUENCY:
		/* read-only, but still ignore it if host-initiated */
		if (!host)
			return 1;
		break;
	default:
		kvm_pr_unimpl_wrmsr(vcpu, msr, data);
		return 1;
	}

	return 0;
}

static int kvm_hv_get_msr_pw(struct kvm_vcpu *vcpu, u32 msr, u64 *pdata,
			     bool host)
{
	u64 data = 0;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_hv *hv = to_kvm_hv(kvm);

	if (unlikely(!host && !hv_check_msr_access(to_hv_vcpu(vcpu), msr)))
		return 1;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
		data = hv->hv_guest_os_id[vcpu->plane_level];
		break;
	case HV_X64_MSR_HYPERCALL:
		data = hv->hv_hypercall[vcpu->plane_level];
		break;
	case HV_X64_MSR_TIME_REF_COUNT:
		data = get_time_ref_counter(kvm);
		break;
	case HV_X64_MSR_REFERENCE_TSC:
		data = vcpu->plane_level ?
		       hv->hv_tsc_page_plane[vcpu->plane_level] :
		       hv->hv_tsc_page;
		break;
	case HV_X64_MSR_CRASH_P0 ... HV_X64_MSR_CRASH_P4:
		return kvm_hv_msr_get_crash_data(kvm,
						 msr - HV_X64_MSR_CRASH_P0,
						 pdata);
	case HV_X64_MSR_CRASH_CTL:
		return kvm_hv_msr_get_crash_ctl(kvm, pdata);
	case HV_X64_MSR_RESET:
		data = 0;
		break;
	case HV_X64_MSR_REENLIGHTENMENT_CONTROL:
		data = hv->hv_reenlightenment_control;
		break;
	case HV_X64_MSR_TSC_EMULATION_CONTROL:
		data = hv->hv_tsc_emulation_control;
		break;
	case HV_X64_MSR_TSC_EMULATION_STATUS:
		data = hv->hv_tsc_emulation_status;
		break;
	case HV_X64_MSR_TSC_INVARIANT_CONTROL:
		data = hv->hv_invtsc_control;
		break;
	case HV_X64_MSR_SYNDBG_OPTIONS:
	case HV_X64_MSR_SYNDBG_CONTROL ... HV_X64_MSR_SYNDBG_PENDING_BUFFER:
		return syndbg_get_msr(vcpu, msr, pdata, host);
	default:
		kvm_pr_unimpl_rdmsr(vcpu, msr);
		return 1;
	}

	*pdata = data;
	return 0;
}

static int kvm_hv_get_msr(struct kvm_vcpu *vcpu, u32 msr, u64 *pdata,
			  bool host)
{
	u64 data = 0;
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	if (unlikely(!host && !hv_check_msr_access(hv_vcpu, msr)))
		return 1;

	switch (msr) {
	case HV_X64_MSR_VP_INDEX:
		data = hv_vcpu->vp_index;
		break;
	case HV_X64_MSR_EOI:
		return kvm_hv_vapic_msr_read(vcpu, APIC_EOI, pdata);
	case HV_X64_MSR_ICR:
		return kvm_hv_vapic_msr_read(vcpu, APIC_ICR, pdata);
	case HV_X64_MSR_TPR:
		return kvm_hv_vapic_msr_read(vcpu, APIC_TASKPRI, pdata);
	case HV_X64_MSR_VP_ASSIST_PAGE:
		data = hv_vcpu->hv_vapic;
		break;
	case HV_X64_MSR_VP_RUNTIME:
		data = current_task_runtime_100ns() + hv_vcpu->runtime_offset;
		break;
	case HV_X64_MSR_SCONTROL:
	case HV_X64_MSR_SVERSION:
	case HV_X64_MSR_SIEFP:
	case HV_X64_MSR_SIMP:
	case HV_X64_MSR_EOM:
	case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
		return synic_get_msr(to_hv_synic(vcpu), msr, pdata, host);
	case HV_X64_MSR_STIMER0_CONFIG:
	case HV_X64_MSR_STIMER1_CONFIG:
	case HV_X64_MSR_STIMER2_CONFIG:
	case HV_X64_MSR_STIMER3_CONFIG: {
		int timer_index = (msr - HV_X64_MSR_STIMER0_CONFIG)/2;

		return stimer_get_config(to_hv_stimer(vcpu, timer_index),
					 pdata);
	}
	case HV_X64_MSR_STIMER0_COUNT:
	case HV_X64_MSR_STIMER1_COUNT:
	case HV_X64_MSR_STIMER2_COUNT:
	case HV_X64_MSR_STIMER3_COUNT: {
		int timer_index = (msr - HV_X64_MSR_STIMER0_COUNT)/2;

		return stimer_get_count(to_hv_stimer(vcpu, timer_index),
					pdata);
	}
	case HV_X64_MSR_TSC_FREQUENCY:
		data = (u64)vcpu->arch.virtual_tsc_khz * 1000;
		break;
	case HV_X64_MSR_APIC_FREQUENCY:
		data = div64_u64(1000000000ULL,
				 vcpu->kvm->arch.apic_bus_cycle_ns);
		break;
	default:
		kvm_pr_unimpl_rdmsr(vcpu, msr);
		return 1;
	}
	*pdata = data;
	return 0;
}

int kvm_hv_set_msr_common(struct kvm_vcpu *vcpu, u32 msr, u64 data, bool host)
{
	struct kvm_hv *hv = to_kvm_hv(vcpu->kvm);

	if (!host && !vcpu->arch.hyperv_enabled)
		return 1;

	if (kvm_hv_vcpu_init(vcpu))
		return 1;

	if (kvm_hv_msr_partition_wide(msr)) {
		int r;

		mutex_lock(&hv->hv_lock);
		r = kvm_hv_set_msr_pw(vcpu, msr, data, host);
		mutex_unlock(&hv->hv_lock);
		return r;
	} else
		return kvm_hv_set_msr(vcpu, msr, data, host);
}

int kvm_hv_get_msr_common(struct kvm_vcpu *vcpu, u32 msr, u64 *pdata, bool host)
{
	struct kvm_hv *hv = to_kvm_hv(vcpu->kvm);

	if (!host && !vcpu->arch.hyperv_enabled)
		return 1;

	if (kvm_hv_vcpu_init(vcpu))
		return 1;

	if (kvm_hv_msr_partition_wide(msr)) {
		int r;

		mutex_lock(&hv->hv_lock);
		r = kvm_hv_get_msr_pw(vcpu, msr, pdata, host);
		mutex_unlock(&hv->hv_lock);
		return r;
	} else
		return kvm_hv_get_msr(vcpu, msr, pdata, host);
}

static void sparse_set_to_vcpu_mask(struct kvm *kvm, u64 *sparse_banks,
				    u64 valid_bank_mask, unsigned long *vcpu_mask)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	bool has_mismatch = atomic_read(&hv->num_mismatched_vp_indexes);
	u64 vp_bitmap[KVM_HV_MAX_SPARSE_VCPU_SET_BITS];
	struct kvm_vcpu *vcpu;
	int bank, sbank = 0;
	unsigned long i;
	u64 *bitmap;

	BUILD_BUG_ON(sizeof(vp_bitmap) >
		     sizeof(*vcpu_mask) * BITS_TO_LONGS(KVM_MAX_VCPUS));

	/*
	 * If vp_index == vcpu_idx for all vCPUs, fill vcpu_mask directly, else
	 * fill a temporary buffer and manually test each vCPU's VP index.
	 */
	if (likely(!has_mismatch))
		bitmap = (u64 *)vcpu_mask;
	else
		bitmap = vp_bitmap;

	/*
	 * Each set of 64 VPs is packed into sparse_banks, with valid_bank_mask
	 * having a '1' for each bank that exists in sparse_banks.  Sets must
	 * be in ascending order, i.e. bank0..bankN.
	 */
	memset(bitmap, 0, sizeof(vp_bitmap));
	for_each_set_bit(bank, (unsigned long *)&valid_bank_mask,
			 KVM_HV_MAX_SPARSE_VCPU_SET_BITS)
		bitmap[bank] = sparse_banks[sbank++];

	if (likely(!has_mismatch))
		return;

	bitmap_zero(vcpu_mask, KVM_MAX_VCPUS);
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (test_bit(kvm_hv_get_vpindex(vcpu), (unsigned long *)vp_bitmap))
			__set_bit(i, vcpu_mask);
	}
}

static bool hv_is_vp_in_sparse_set(u32 vp_id, u64 valid_bank_mask, u64 sparse_banks[])
{
	int valid_bit_nr = vp_id / HV_VCPUS_PER_SPARSE_BANK;
	unsigned long sbank;

	BUILD_BUG_ON(BITS_PER_TYPE(valid_bank_mask) != HV_MAX_SPARSE_VCPU_BANKS);

	if (valid_bit_nr >= HV_MAX_SPARSE_VCPU_BANKS)
		return false;

	if (!test_bit(valid_bit_nr, (unsigned long *)&valid_bank_mask))
		return false;

	/*
	 * The index into the sparse bank is the number of preceding bits in
	 * the valid mask.  Optimize for VMs with <64 vCPUs by skipping the
	 * fancy math if there can't possibly be preceding bits.
	 */
	if (valid_bit_nr)
		sbank = hweight64(valid_bank_mask & GENMASK_ULL(valid_bit_nr - 1, 0));
	else
		sbank = 0;

	return test_bit(vp_id % HV_VCPUS_PER_SPARSE_BANK,
			(unsigned long *)&sparse_banks[sbank]);
}

struct kvm_hv_hcall {
	/* Hypercall input data */
	u64 param;
	u64 ingpa;
	u64 outgpa;
	u16 code;
	u16 var_cnt;
	u16 rep_cnt;
	u16 rep_idx;
	bool fast;
	bool rep;
	sse128_t xmm[HV_HYPERCALL_MAX_XMM_REGISTERS];

	/*
	 * Current read offset when KVM reads hypercall input data gradually,
	 * either offset in bytes from 'ingpa' for regular hypercalls or the
	 * number of already consumed 'XMM halves' for 'fast' hypercalls.
	 */
	union {
		gpa_t data_offset;
		int consumed_xmm_halves;
	};
};


static int kvm_hv_get_hc_data(struct kvm *kvm, struct kvm_hv_hcall *hc,
			      u16 orig_cnt, u16 cnt_cap, u64 *data)
{
	/*
	 * Preserve the original count when ignoring entries via a "cap", KVM
	 * still needs to validate the guest input (though the non-XMM path
	 * punts on the checks).
	 */
	u16 cnt = min(orig_cnt, cnt_cap);
	int i, j;

	if (hc->fast) {
		/*
		 * Each XMM holds two sparse banks, but do not count halves that
		 * have already been consumed for hypercall parameters.
		 */
		if (orig_cnt > 2 * HV_HYPERCALL_MAX_XMM_REGISTERS - hc->consumed_xmm_halves)
			return HV_STATUS_INVALID_HYPERCALL_INPUT;

		for (i = 0; i < cnt; i++) {
			j = i + hc->consumed_xmm_halves;
			if (j % 2)
				data[i] = sse128_hi(hc->xmm[j / 2]);
			else
				data[i] = sse128_lo(hc->xmm[j / 2]);
		}
		return 0;
	}

	return kvm_read_guest(kvm, hc->ingpa + hc->data_offset, data,
			      cnt * sizeof(*data));
}

static u64 kvm_get_sparse_vp_set(struct kvm *kvm, struct kvm_hv_hcall *hc,
				 u64 *sparse_banks)
{
	if (hc->var_cnt > HV_MAX_SPARSE_VCPU_BANKS)
		return -EINVAL;

	/* Cap var_cnt to ignore banks that cannot contain a legal VP index. */
	return kvm_hv_get_hc_data(kvm, hc, hc->var_cnt, KVM_HV_MAX_SPARSE_VCPU_SET_BITS,
				  sparse_banks);
}

static int kvm_hv_get_tlb_flush_entries(struct kvm *kvm, struct kvm_hv_hcall *hc, u64 entries[])
{
	return kvm_hv_get_hc_data(kvm, hc, hc->rep_cnt, hc->rep_cnt, entries);
}

static void hv_tlb_flush_enqueue(struct kvm_vcpu *vcpu, u64 *entries, int count,
				 bool is_guest_mode)
{
	struct kvm_vcpu_hv_tlb_flush_fifo *tlb_flush_fifo;
	u64 flush_all_entry = KVM_HV_TLB_FLUSHALL_ENTRY;

	tlb_flush_fifo = kvm_hv_get_tlb_flush_fifo(vcpu, is_guest_mode);
	if (!tlb_flush_fifo)
		return;

	spin_lock(&tlb_flush_fifo->write_lock);

	/*
	 * All entries should fit on the fifo leaving one free for 'flush all'
	 * entry in case another request comes in. In case there's not enough
	 * space, just put 'flush all' entry there.
	 */
	if (count && entries && count < kfifo_avail(&tlb_flush_fifo->entries)) {
		WARN_ON(kfifo_in(&tlb_flush_fifo->entries, entries, count) != count);
		goto out_unlock;
	}

	/*
	 * Note: full fifo always contains 'flush all' entry, no need to check the
	 * return value.
	 */
	kfifo_in(&tlb_flush_fifo->entries, &flush_all_entry, 1);

out_unlock:
	spin_unlock(&tlb_flush_fifo->write_lock);
}

int kvm_hv_vcpu_flush_tlb(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv_tlb_flush_fifo *tlb_flush_fifo;
	u64 entries[KVM_HV_TLB_FLUSH_FIFO_SIZE];
	int i, j, count;
	gva_t gva;

	if (!tdp_enabled)
		return -EINVAL;

	tlb_flush_fifo = kvm_hv_get_tlb_flush_fifo(vcpu, is_guest_mode(vcpu));
	if (!tlb_flush_fifo)
		return -EINVAL;

	count = kfifo_out(&tlb_flush_fifo->entries, entries, KVM_HV_TLB_FLUSH_FIFO_SIZE);

	for (i = 0; i < count; i++) {
		if (entries[i] == KVM_HV_TLB_FLUSHALL_ENTRY)
			goto out_flush_all;

		/*
		 * Lower 12 bits of 'address' encode the number of additional
		 * pages to flush.
		 */
		gva = entries[i] & PAGE_MASK;
		for (j = 0; j < (entries[i] & ~PAGE_MASK) + 1; j++) {
			if (is_noncanonical_invlpg_address(gva + j * PAGE_SIZE, vcpu))
				continue;

			kvm_x86_call(flush_tlb_gva)(vcpu, gva + j * PAGE_SIZE);
		}

		++vcpu->stat.tlb_flush;
	}
	return 0;

out_flush_all:
	kfifo_reset_out(&tlb_flush_fifo->entries);

	/* Fall back to full flush. */
	return -ENOSPC;
}

static int kvm_hv_hypercall_check_gpa(struct kvm_vcpu *vcpu, gpa_t gpa,
				      bool write)
{
	bool writable = true;
	gfn_t gfn = gpa_to_gfn(gpa);
	unsigned long addr;

	addr = kvm_vcpu_gfn_to_hva_prot(vcpu, gfn, &writable);
	if (!kvm_is_error_hva(addr) && (!write || writable))
		return 0;

	kvm_prepare_memory_fault_exit(vcpu, gfn_to_gpa(gfn), PAGE_SIZE,
				      write, false, false);
	return -EFAULT;
}

static unsigned int kvm_hv_hypercall_mem_access(u16 code)
{
	switch (code) {
	case HVCALL_SIGNAL_EVENT:
	case HVCALL_POST_MESSAGE:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX:
	case HVCALL_SEND_IPI:
	case HVCALL_SEND_IPI_EX:
		return KVM_MEMORY_EXIT_FLAG_READ;
	case HVCALL_POST_DEBUG_DATA:
	case HVCALL_RETRIEVE_DEBUG_DATA:
		return KVM_MEMORY_EXIT_FLAG_READ | KVM_MEMORY_EXIT_FLAG_WRITE;
	case HVCALL_RESET_DEBUG_SESSION:
	case HV_EXT_CALL_QUERY_CAPABILITIES:
		return KVM_MEMORY_EXIT_FLAG_WRITE;
	}

	return 0;
}

static int kvm_hv_hypercall_check_params(struct kvm_vcpu *vcpu,
					 struct kvm_hv_hcall *hc)
{
	unsigned access;
	int r;

	if (hc->fast || !vcpu->kvm->arch.hcall_fault_exit)
		return 0;

	access = kvm_hv_hypercall_mem_access(hc->code);
	if (access & KVM_MEMORY_EXIT_FLAG_READ) {
		r = kvm_hv_hypercall_check_gpa(vcpu, hc->ingpa, false);
		if (r)
			return r;
	}

	if (access & KVM_MEMORY_EXIT_FLAG_WRITE)
		return kvm_hv_hypercall_check_gpa(vcpu, hc->outgpa, true);

	return 0;
}

/*
 * A TLB flush hypercall flushes the caller's VTL view of the target VPs:
 * resolve the target to the vCPU of the caller's plane, which has its own
 * roots and TLB tag.  Fall back to plane 0 when the plane vCPU does not
 * exist (it then has no TLB to flush either).
 */
static struct kvm_vcpu *hv_flush_plane_vcpu(struct kvm_vcpu *caller,
					    struct kvm_vcpu *v)
{
	struct kvm_vcpu *pv;

	if (!caller->plane_level)
		return v;
	pv = v->common->vcpus[caller->plane_level];
	return pv ?: v;
}

static s64 kvm_hv_flush_tlb(struct kvm_vcpu *vcpu, struct kvm_hv_hcall *hc)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	unsigned long *vcpu_mask = hv_vcpu->vcpu_mask;
	u64 *sparse_banks = hv_vcpu->sparse_banks;
	struct kvm *kvm = vcpu->kvm;
	struct hv_tlb_flush_ex flush_ex;
	struct hv_tlb_flush flush;
	/*
	 * Normally, there can be no more than 'KVM_HV_TLB_FLUSH_FIFO_SIZE'
	 * entries on the TLB flush fifo. The last entry, however, needs to be
	 * always left free for 'flush all' entry which gets placed when
	 * there is not enough space to put all the requested entries.
	 */
	u64 __tlb_flush_entries[KVM_HV_TLB_FLUSH_FIFO_SIZE - 1];
	u64 *tlb_flush_entries;
	u64 valid_bank_mask;
	struct kvm_vcpu *v;
	unsigned long i;
	bool all_cpus;
	int r;

	/* Slow direct hypercalls from L2 provide a nested GPA. */
	if (!hc->fast) {
		hc->ingpa = kvm_translate_gpa(vcpu, &vcpu->arch.gva_walk, hc->ingpa,
					      PFERR_GUEST_FINAL_MASK, NULL, 0);
		if (unlikely(hc->ingpa == INVALID_GPA))
			return HV_STATUS_INVALID_HYPERCALL_INPUT;
	}

	r = kvm_hv_hypercall_check_params(vcpu, hc);
	if (r)
		return r;

	/*
	 * The Hyper-V TLFS doesn't allow more than HV_MAX_SPARSE_VCPU_BANKS
	 * sparse banks. Fail the build if KVM's max allowed number of
	 * vCPUs (>4096) exceeds this limit.
	 */
	BUILD_BUG_ON(KVM_HV_MAX_SPARSE_VCPU_SET_BITS > HV_MAX_SPARSE_VCPU_BANKS);

	if (hc->code == HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST ||
	    hc->code == HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE) {
		if (hc->fast) {
			flush.address_space = hc->ingpa;
			flush.flags = hc->outgpa;
			flush.processor_mask = sse128_lo(hc->xmm[0]);
			hc->consumed_xmm_halves = 1;
		} else {
			if (unlikely(kvm_read_guest(kvm, hc->ingpa,
						    &flush, sizeof(flush))))
				return HV_STATUS_INVALID_HYPERCALL_INPUT;
			hc->data_offset = sizeof(flush);
		}

		trace_kvm_hv_flush_tlb(flush.processor_mask,
				       flush.address_space, flush.flags,
				       is_guest_mode(vcpu));

		valid_bank_mask = BIT_ULL(0);
		sparse_banks[0] = flush.processor_mask;

		/*
		 * Work around possible WS2012 bug: it sends hypercalls
		 * with processor_mask = 0x0 and HV_FLUSH_ALL_PROCESSORS clear,
		 * while also expecting us to flush something and crashing if
		 * we don't. Let's treat processor_mask == 0 same as
		 * HV_FLUSH_ALL_PROCESSORS.
		 */
		all_cpus = (flush.flags & HV_FLUSH_ALL_PROCESSORS) ||
			flush.processor_mask == 0;
	} else {
		if (hc->fast) {
			flush_ex.address_space = hc->ingpa;
			flush_ex.flags = hc->outgpa;
			memcpy(&flush_ex.hv_vp_set,
			       &hc->xmm[0], sizeof(hc->xmm[0]));
			hc->consumed_xmm_halves = 2;
		} else {
			if (unlikely(kvm_read_guest(kvm, hc->ingpa, &flush_ex,
						    sizeof(flush_ex))))
				return HV_STATUS_INVALID_HYPERCALL_INPUT;
			hc->data_offset = sizeof(flush_ex);
		}

		trace_kvm_hv_flush_tlb_ex(flush_ex.hv_vp_set.valid_bank_mask,
					  flush_ex.hv_vp_set.format,
					  flush_ex.address_space,
					  flush_ex.flags, is_guest_mode(vcpu));

		valid_bank_mask = flush_ex.hv_vp_set.valid_bank_mask;
		all_cpus = flush_ex.hv_vp_set.format !=
			HV_GENERIC_SET_SPARSE_4K;

		if (hc->var_cnt != hweight64(valid_bank_mask))
			return HV_STATUS_INVALID_HYPERCALL_INPUT;

		if (!all_cpus) {
			if (!hc->var_cnt)
				goto ret_success;

			if (kvm_get_sparse_vp_set(kvm, hc, sparse_banks))
				return HV_STATUS_INVALID_HYPERCALL_INPUT;
		}

		/*
		 * Hyper-V TLFS doesn't explicitly forbid non-empty sparse vCPU
		 * banks (and, thus, non-zero 'var_cnt') for the 'all vCPUs'
		 * case (HV_GENERIC_SET_ALL).  Always adjust data_offset and
		 * consumed_xmm_halves to make sure TLB flush entries are read
		 * from the correct offset.
		 */
		if (hc->fast)
			hc->consumed_xmm_halves += hc->var_cnt;
		else
			hc->data_offset += hc->var_cnt * sizeof(sparse_banks[0]);
	}

	if (hc->code == HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE ||
	    hc->code == HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX ||
	    hc->rep_cnt > ARRAY_SIZE(__tlb_flush_entries)) {
		tlb_flush_entries = NULL;
	} else {
		if (kvm_hv_get_tlb_flush_entries(kvm, hc, __tlb_flush_entries))
			return HV_STATUS_INVALID_HYPERCALL_INPUT;
		tlb_flush_entries = __tlb_flush_entries;
	}

	/*
	 * vcpu->arch.cr3 may not be up-to-date for running vCPUs so we can't
	 * analyze it here, flush TLB regardless of the specified address space.
	 */
	if (all_cpus && !is_guest_mode(vcpu)) {
		kvm_for_each_vcpu(i, v, kvm) {
			v = hv_flush_plane_vcpu(vcpu, v);
			hv_tlb_flush_enqueue(v, tlb_flush_entries, hc->rep_cnt, false);
			if (vcpu->plane_level) {
				kvm_make_request(KVM_REQ_HV_TLB_FLUSH, v);
				kvm_vcpu_kick(v);
			}
		}

		if (!vcpu->plane_level)
			kvm_make_all_cpus_request(kvm, KVM_REQ_HV_TLB_FLUSH);
	} else if (!is_guest_mode(vcpu)) {
		sparse_set_to_vcpu_mask(kvm, sparse_banks, valid_bank_mask, vcpu_mask);

		for_each_set_bit(i, vcpu_mask, KVM_MAX_VCPUS) {
			v = kvm_get_vcpu(kvm, i);
			if (!v)
				continue;
			v = hv_flush_plane_vcpu(vcpu, v);
			hv_tlb_flush_enqueue(v, tlb_flush_entries, hc->rep_cnt, false);
			if (vcpu->plane_level) {
				kvm_make_request(KVM_REQ_HV_TLB_FLUSH, v);
				kvm_vcpu_kick(v);
			}
		}

		if (!vcpu->plane_level)
			kvm_make_vcpus_request_mask(kvm, KVM_REQ_HV_TLB_FLUSH,
						    vcpu_mask);
	} else {
		struct kvm_vcpu_hv *hv_v;

		bitmap_zero(vcpu_mask, KVM_MAX_VCPUS);

		kvm_for_each_vcpu(i, v, kvm) {
			hv_v = to_hv_vcpu_safe(v);

			/*
			 * The following check races with nested vCPUs entering/exiting
			 * and/or migrating between L1's vCPUs, however the only case when
			 * KVM *must* flush the TLB is when the target L2 vCPU keeps
			 * running on the same L1 vCPU from the moment of the request until
			 * kvm_hv_flush_tlb() returns. TLB is fully flushed in all other
			 * cases, e.g. when the target L2 vCPU migrates to a different L1
			 * vCPU or when the corresponding L1 vCPU temporary switches to a
			 * different L2 vCPU while the request is being processed.
			 */
			if (!hv_v || hv_v->nested.vm_id != hv_vcpu->nested.vm_id)
				continue;

			if (!all_cpus &&
			    !hv_is_vp_in_sparse_set(hv_v->nested.vp_id, valid_bank_mask,
						    sparse_banks))
				continue;

			__set_bit(i, vcpu_mask);
			hv_tlb_flush_enqueue(v, tlb_flush_entries, hc->rep_cnt, true);
		}

		kvm_make_vcpus_request_mask(kvm, KVM_REQ_HV_TLB_FLUSH, vcpu_mask);
	}

ret_success:
	/* We always do full TLB flush, set 'Reps completed' = 'Rep Count' */
	return (u64)HV_STATUS_SUCCESS |
		((u64)hc->rep_cnt << HV_HYPERCALL_REP_COMP_OFFSET);
}

static void kvm_hv_send_ipi_to_many(struct kvm *kvm, u32 vector,
				    u64 *sparse_banks, u64 valid_bank_mask,
				    int target_plane)
{
	struct kvm_lapic_irq irq = {
		.delivery_mode = APIC_DM_FIXED,
		.vector = vector
	};
	struct kvm_vcpu *vcpu;
	unsigned long i;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvm_vcpu *target = vcpu;

		if (sparse_banks &&
		    !hv_is_vp_in_sparse_set(kvm_hv_get_vpindex(vcpu),
					    valid_bank_mask, sparse_banks))
			continue;

		/*
		 * TLFS: the IPI targets the VPs' in_vtl (or the sender's
		 * VTL): deliver into that plane's APIC.
		 */
		if (target_plane) {
			target = vcpu->common->vcpus[target_plane];
			if (!target)
				continue;
		}

		/* We fail only when APIC is disabled */
		kvm_apic_set_irq(target, &irq, NULL);
	}
}

static int kvm_hv_send_ipi(struct kvm_vcpu *vcpu, struct kvm_hv_hcall *hc)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	u64 *sparse_banks = hv_vcpu->sparse_banks;
	struct kvm *kvm = vcpu->kvm;
	struct hv_send_ipi_ex send_ipi_ex;
	struct hv_send_ipi send_ipi;
	u64 valid_bank_mask;
	u32 vector;
	u8 in_vtl = 0;
	int target_plane;
	bool all_cpus;
	int r;

	r = kvm_hv_hypercall_check_params(vcpu, hc);
	if (r)
		return r;

	if (!lapic_in_kernel(vcpu))
		return HV_STATUS_INVALID_HYPERCALL_INPUT;

	if (hc->code == HVCALL_SEND_IPI) {
		if (!hc->fast) {
			if (unlikely(kvm_read_guest(kvm, hc->ingpa, &send_ipi,
						    sizeof(send_ipi))))
				return HV_STATUS_INVALID_HYPERCALL_INPUT;
			sparse_banks[0] = send_ipi.cpu_mask;
			vector = send_ipi.vector;
			in_vtl = send_ipi.in_vtl.as_uint8;
		} else {
			/* 'reserved' part of hv_send_ipi should be 0 */
			if (unlikely(hc->ingpa >> 40 != 0))
				return HV_STATUS_INVALID_HYPERCALL_INPUT;
			sparse_banks[0] = hc->outgpa;
			vector = (u32)hc->ingpa;
			in_vtl = (hc->ingpa >> 32) & 0xff;
		}

		/*
		 * Only hv_input_vtl.target_vtl (bits 3:0) and
		 * use_target_vtl (bit 4) are defined; reserved_z (7:5)
		 * must be zero in every form of the hypercall, before
		 * anything is delivered.
		 */
		if (unlikely(in_vtl & 0xe0))
			return HV_STATUS_INVALID_HYPERCALL_INPUT;

		all_cpus = false;
		valid_bank_mask = BIT_ULL(0);

		trace_kvm_hv_send_ipi(vector, sparse_banks[0]);
	} else {
		if (!hc->fast) {
			if (unlikely(kvm_read_guest(kvm, hc->ingpa, &send_ipi_ex,
						    sizeof(send_ipi_ex))))
				return HV_STATUS_INVALID_HYPERCALL_INPUT;
			in_vtl = send_ipi_ex.in_vtl.as_uint8;
		} else {
			send_ipi_ex.vector = (u32)hc->ingpa;
			send_ipi_ex.vp_set.format = hc->outgpa;
			send_ipi_ex.vp_set.valid_bank_mask = sse128_lo(hc->xmm[0]);
			in_vtl = (hc->ingpa >> 32) & 0xff;
		}

		/* As above: hv_input_vtl bits 7:5 are reserved. */
		if (unlikely(in_vtl & 0xe0))
			return HV_STATUS_INVALID_HYPERCALL_INPUT;

		trace_kvm_hv_send_ipi_ex(send_ipi_ex.vector,
					 send_ipi_ex.vp_set.format,
					 send_ipi_ex.vp_set.valid_bank_mask);

		vector = send_ipi_ex.vector;
		valid_bank_mask = send_ipi_ex.vp_set.valid_bank_mask;
		all_cpus = send_ipi_ex.vp_set.format == HV_GENERIC_SET_ALL;

		if (hc->var_cnt != hweight64(valid_bank_mask))
			return HV_STATUS_INVALID_HYPERCALL_INPUT;

		if (all_cpus)
			goto check_and_send_ipi;

		if (!hc->var_cnt)
			goto ret_success;

		if (!hc->fast)
			hc->data_offset = offsetof(struct hv_send_ipi_ex,
						   vp_set.bank_contents);
		else
			hc->consumed_xmm_halves = 1;

		if (kvm_get_sparse_vp_set(kvm, hc, sparse_banks))
			return HV_STATUS_INVALID_HYPERCALL_INPUT;
	}

check_and_send_ipi:
	if ((vector < HV_IPI_LOW_VECTOR) || (vector > HV_IPI_HIGH_VECTOR))
		return HV_STATUS_INVALID_HYPERCALL_INPUT;

	/* TLFS: in_vtl bit 4 selects an explicit target VTL. */
	if (in_vtl & 0x10)
		target_plane = in_vtl & 0xf;
	else
		target_plane = vcpu->plane_level;
	if (target_plane >= KVM_MAX_PLANES)
		return HV_STATUS_INVALID_HYPERCALL_INPUT;

	if (all_cpus)
		kvm_hv_send_ipi_to_many(kvm, vector, NULL, 0, target_plane);
	else
		kvm_hv_send_ipi_to_many(kvm, vector, sparse_banks,
					valid_bank_mask, target_plane);

ret_success:
	return HV_STATUS_SUCCESS;
}

void kvm_hv_set_cpuid(struct kvm_vcpu *vcpu, bool hyperv_enabled)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	struct kvm_cpuid_entry2 *entry;

	vcpu->arch.hyperv_enabled = hyperv_enabled;

	if (!hv_vcpu) {
		/*
		 * KVM should have already allocated kvm_vcpu_hv if Hyper-V is
		 * enabled in CPUID.
		 */
		WARN_ON_ONCE(vcpu->arch.hyperv_enabled);
		return;
	}

	memset(&hv_vcpu->cpuid_cache, 0, sizeof(hv_vcpu->cpuid_cache));

	if (!vcpu->arch.hyperv_enabled)
		return;

	entry = kvm_find_cpuid_entry(vcpu, HYPERV_CPUID_FEATURES);
	if (entry) {
		hv_vcpu->cpuid_cache.features_eax = entry->eax;
		hv_vcpu->cpuid_cache.features_ebx = entry->ebx;
		hv_vcpu->cpuid_cache.features_edx = entry->edx;
	}

	entry = kvm_find_cpuid_entry(vcpu, HYPERV_CPUID_ENLIGHTMENT_INFO);
	if (entry) {
		hv_vcpu->cpuid_cache.enlightenments_eax = entry->eax;
		hv_vcpu->cpuid_cache.enlightenments_ebx = entry->ebx;
	}

	entry = kvm_find_cpuid_entry(vcpu, HYPERV_CPUID_SYNDBG_PLATFORM_CAPABILITIES);
	if (entry)
		hv_vcpu->cpuid_cache.syndbg_cap_eax = entry->eax;

	entry = kvm_find_cpuid_entry(vcpu, HYPERV_CPUID_NESTED_FEATURES);
	if (entry) {
		hv_vcpu->cpuid_cache.nested_eax = entry->eax;
		hv_vcpu->cpuid_cache.nested_ebx = entry->ebx;
	}
}

int kvm_hv_set_enforce_cpuid(struct kvm_vcpu *vcpu, bool enforce)
{
	struct kvm_vcpu_hv *hv_vcpu;
	int ret = 0;

	if (!to_hv_vcpu(vcpu)) {
		if (enforce) {
			ret = kvm_hv_vcpu_init(vcpu);
			if (ret)
				return ret;
		} else {
			return 0;
		}
	}

	hv_vcpu = to_hv_vcpu(vcpu);
	hv_vcpu->enforce_cpuid = enforce;

	return ret;
}

static void kvm_hv_hypercall_set_result(struct kvm_vcpu *vcpu, u64 result)
{
	bool longmode;

	longmode = is_64_bit_hypercall(vcpu);
	if (longmode)
		kvm_rax_write_raw(vcpu, result);
	else {
		kvm_edx_write(vcpu, result >> 32);
		kvm_eax_write(vcpu, result);
	}
}

static int kvm_hv_hypercall_complete(struct kvm_vcpu *vcpu, u64 result)
{
	u32 tlb_lock_count = 0;
	int ret;

	if (hv_result_success(result) && is_guest_mode(vcpu) &&
	    kvm_hv_is_tlb_flush_hcall(vcpu) &&
	    kvm_read_guest(vcpu->kvm, to_hv_vcpu(vcpu)->nested.pa_page_gpa,
			   &tlb_lock_count, sizeof(tlb_lock_count)))
		result = HV_STATUS_INVALID_HYPERCALL_INPUT;

	trace_kvm_hv_hypercall_done(result);
	kvm_hv_hypercall_set_result(vcpu, result);
	++vcpu->stat.hypercalls;

	ret = kvm_skip_emulated_instruction(vcpu);

	if (tlb_lock_count)
		kvm_nested_call(hv_inject_synthetic_vmexit_post_tlb_flush)(vcpu);

	return ret;
}

static int kvm_hv_hypercall_complete_userspace(struct kvm_vcpu *vcpu)
{
	u64 result = vcpu->run->hyperv.u.hcall.result;

	/*
	 * A hypercall the VMM judged malformed beyond returning a status
	 * (such as a VTL call that is invalid in the current state) faults
	 * at the instruction instead of completing.
	 */
	if (result & KVM_HV_HCALL_RESULT_RAISE_UD) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	return kvm_hv_hypercall_complete(vcpu, result);
}

static int kvm_hvcall_signal_event(struct kvm_vcpu *vcpu, struct kvm_hv_hcall *hc)
{
	struct kvm_hv *hv = to_kvm_hv(vcpu->kvm);
	struct eventfd_ctx *eventfd;
	u64 conn_id;
	int ret;

	ret = kvm_hv_hypercall_check_params(vcpu, hc);
	if (ret)
		return ret;

	if (unlikely(!hc->fast)) {
		int ret;
		gpa_t gpa = hc->ingpa;

		if ((gpa & (__alignof__(conn_id) - 1)) ||
		    offset_in_page(gpa) + sizeof(conn_id) > PAGE_SIZE)
			return HV_STATUS_INVALID_ALIGNMENT;

		ret = kvm_vcpu_read_guest(vcpu, gpa,
					  &conn_id, sizeof(conn_id));
		if (ret < 0)
			return HV_STATUS_INVALID_ALIGNMENT;
	} else {
		conn_id = hc->ingpa;
	}

	/*
	 * Per spec, bits 32-47 contain the extra "flag number".  However, we
	 * have no use for it, and in all known usecases it is zero, so just
	 * report lookup failure if it isn't.
	 */
	if (conn_id & 0xffff00000000ULL)
		return HV_STATUS_INVALID_PORT_ID;
	/* remaining bits are reserved-zero */
	if (conn_id & ~KVM_HYPERV_CONN_ID_MASK)
		return HV_STATUS_INVALID_HYPERCALL_INPUT;

	/* the eventfd is protected by vcpu->kvm->srcu, but conn_to_evt isn't */
	rcu_read_lock();
	eventfd = idr_find(&hv->conn_to_evt, conn_id);
	rcu_read_unlock();
	if (!eventfd)
		return HV_STATUS_INVALID_PORT_ID;

	eventfd_signal(eventfd);
	return HV_STATUS_SUCCESS;
}

static bool is_xmm_fast_hypercall(struct kvm_hv_hcall *hc)
{
	switch (hc->code) {
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX:
	case HVCALL_SEND_IPI_EX:
		return true;
	}

	return false;
}

static void kvm_hv_hypercall_read_xmm(struct kvm_hv_hcall *hc)
{
	int reg;

	kvm_fpu_get();
	for (reg = 0; reg < HV_HYPERCALL_MAX_XMM_REGISTERS; reg++)
		_kvm_read_sse_reg(reg, &hc->xmm[reg]);
	kvm_fpu_put();
}

static bool hv_check_hypercall_access(struct kvm_vcpu_hv *hv_vcpu, u16 code)
{
	if (!hv_vcpu->enforce_cpuid)
		return true;

	switch (code) {
	case HVCALL_NOTIFY_LONG_SPIN_WAIT:
		return hv_vcpu->cpuid_cache.enlightenments_ebx &&
			hv_vcpu->cpuid_cache.enlightenments_ebx != U32_MAX;
	case HVCALL_POST_MESSAGE:
		return hv_vcpu->cpuid_cache.features_ebx & HV_POST_MESSAGES;
	case HVCALL_SIGNAL_EVENT:
		return hv_vcpu->cpuid_cache.features_ebx & HV_SIGNAL_EVENTS;
	case HVCALL_POST_DEBUG_DATA:
	case HVCALL_RETRIEVE_DEBUG_DATA:
	case HVCALL_RESET_DEBUG_SESSION:
		/*
		 * Return 'true' when SynDBG is disabled so the resulting code
		 * will be HV_STATUS_INVALID_HYPERCALL_CODE.
		 */
		return !kvm_hv_is_syndbg_enabled(hv_vcpu->vcpu) ||
			hv_vcpu->cpuid_cache.features_ebx & HV_DEBUGGING;
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX:
		if (!(hv_vcpu->cpuid_cache.enlightenments_eax &
		      HV_X64_EX_PROCESSOR_MASKS_RECOMMENDED))
			return false;
		fallthrough;
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST:
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE:
		return hv_vcpu->cpuid_cache.enlightenments_eax &
			HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED;
	case HVCALL_SEND_IPI_EX:
		if (!(hv_vcpu->cpuid_cache.enlightenments_eax &
		      HV_X64_EX_PROCESSOR_MASKS_RECOMMENDED))
			return false;
		fallthrough;
	case HVCALL_SEND_IPI:
		return hv_vcpu->cpuid_cache.enlightenments_eax &
			HV_X64_CLUSTER_IPI_RECOMMENDED;
	case HV_EXT_CALL_QUERY_CAPABILITIES ... HV_EXT_CALL_MAX:
		return hv_vcpu->cpuid_cache.features_ebx &
			HV_ENABLE_EXTENDED_HYPERCALLS;
	default:
		break;
	}

	return true;
}

static int kvm_hv_hypercall_userspace_exit(struct kvm_vcpu *vcpu,
					   struct kvm_hv_hcall *hc)
{
	int r;

	r = kvm_hv_hypercall_check_params(vcpu, hc);
	if (r)
		return r;

	vcpu->run->exit_reason = KVM_EXIT_HYPERV;
	vcpu->run->hyperv.type = KVM_EXIT_HYPERV_HCALL;
	vcpu->run->hyperv.plane = vcpu->plane_level;
	vcpu->run->hyperv.u.hcall.input = hc->param;
	vcpu->run->hyperv.u.hcall.params[0] = hc->ingpa;
	vcpu->run->hyperv.u.hcall.params[1] = hc->outgpa;
	vcpu->arch.complete_userspace_io = kvm_hv_hypercall_complete_userspace;
	return 0;
}


/* VTL control area in the VP assist page (TLFS struct hv_vp_vtl_control). */
#define HV_VTL_CONTROL_OFFSET		8
#define HV_VTL_ENTRY_REASON_VTL_CALL	1
#define HV_VTL_RETURN_FAST_BIT		BIT_ULL(0)

struct hv_vtl_control {
	u32 vtl_entry_reason;
	u8 vina_asserted;
	u8 reserved[3];
	u64 vtl_ret_x64rax;
	u64 vtl_ret_x64rcx;
} __packed;

static u64 hv_vtl_assist_page_gpa(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);

	if (!hv_vcpu ||
	    !(hv_vcpu->hv_vapic & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE))
		return 0;
	return hv_vcpu->hv_vapic & HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;
}

/*
 * In-kernel VTL call/return: switch between the plane vCPUs directly
 * instead of bouncing every transition through userspace.  Keeps the
 * userspace contract: VTL-shared register state (GPRs except RSP, CR2,
 * FPU) follows the switch, the entered VTL's assist page gets the entry
 * reason and the caller's RAX/RCX, and a non-fast VTL return restores
 * the lower VTL's RAX/RCX from the returning VTL's control area.  The
 * suspending plane stays suspended mid-hypercall, with
 * hcall_resume_pending set: its pending completion delivers the
 * instruction skip and the resume RAX when a later switch re-enters
 * the plane.
 *
 * Returns -ENOENT when the transition cannot be handled here (no twin
 * plane); the caller forwards the hypercall to userspace unchanged.
 */
/*
 * Enter a higher VTL because it has a pending interrupt (TLFS: higher
 * VTL interrupts preempt lower VTL execution).  The lower VTL is
 * suspended mid-instruction, not in a hypercall, so no completion is
 * pended for it: it resumes at the preempted RIP when the higher VTL
 * returns, and the entered VTL's control area carries the INTERRUPT
 * entry reason with the preempted RAX/RCX.
 */
#define HV_VTL_ENTRY_REASON_INTERRUPT	2

/*
 * States in which the in-kernel paths must not enter a plane:
 *
 *  - never entered the guest: it still holds reset state (userspace owns
 *    HvCallEnableVpVtl and runs a plane's first entry itself);
 *  - stopped by userspace with KVM_SET_PLANE_RUN_STATE: the VMM owns
 *    restarting it;
 *  - parked on a non-hypercall completion (MMIO, PIO): the completion
 *    owns the shared run union, which the resume protocol would clobber.
 *
 * The forced interrupt entry refuses such a target (the event stays
 * pending), and kvm_higher_plane_with_event() must not report its
 * pending event as a wakeup either, or a halted lower VTL spins through
 * hlt/wake with nothing able to consume the event.
 */
bool kvm_hv_vtl_entry_blocked(struct kvm_vcpu *target)
{
	if (target->arch.last_vmentry_cpu == -1)
		return true;

	if (target->plane_user_stopped)
		return true;

	if (target->arch.complete_userspace_io &&
	    target->arch.complete_userspace_io != kvm_hv_hypercall_complete_userspace)
		return true;

	return false;
}

bool kvm_hv_vtl_interrupt_entry(struct kvm_vcpu *vcpu,
				struct kvm_vcpu *target)
{
	u64 rax = kvm_rax_read(vcpu), rcx = kvm_rcx_read(vcpu);
	struct hv_vtl_control ctl;
	u64 assist;
	int i;

	static const int shared_gprs[] = {
		VCPU_REGS_RAX, VCPU_REGS_RBX, VCPU_REGS_RCX, VCPU_REGS_RDX,
		VCPU_REGS_RSI, VCPU_REGS_RDI, VCPU_REGS_RBP,
		VCPU_REGS_R8, VCPU_REGS_R9, VCPU_REGS_R10, VCPU_REGS_R11,
		VCPU_REGS_R12, VCPU_REGS_R13, VCPU_REGS_R14, VCPU_REGS_R15,
	};

	/* The event stays pending until the plane can be entered. */
	if (kvm_hv_vtl_entry_blocked(target))
		return false;

	/*
	 * Write the entered plane's control area through the entered
	 * plane's vCPU: the write must pass that plane's own memory
	 * attributes and memslot view, not the suspending plane's (which
	 * typically has no access to the higher VTL's assist page).  On
	 * failure leave both planes untouched; the event stays pending in
	 * the target and the entry is retried.
	 */
	assist = hv_vtl_assist_page_gpa(target);
	if (assist) {
		ctl = (struct hv_vtl_control) {
			.vtl_entry_reason = HV_VTL_ENTRY_REASON_INTERRUPT,
			.vtl_ret_x64rax = rax,
			.vtl_ret_x64rcx = rcx,
		};
		if (kvm_vcpu_write_guest(target, assist + HV_VTL_CONTROL_OFFSET,
					 &ctl, sizeof(ctl)))
			return false;
	}

	for (i = 0; i < ARRAY_SIZE(shared_gprs); i++)
		kvm_register_write_raw(target, shared_gprs[i],
				       kvm_register_read_raw(vcpu,
							     shared_gprs[i]));
	target->arch.cr2 = vcpu->arch.cr2;
	vcpu->common->vtl_fpu_from = vcpu->plane_level;

	if (to_hv_vcpu(target)) {
		to_hv_vcpu(target)->vtl_entry_rax = rax;
		to_hv_vcpu(target)->vtl_entry_rcx = rcx;
		to_hv_vcpu(target)->vtl_entry_regs_valid = true;
	}

	/*
	 * The target resumes its suspended hypercall, if it has one.  The
	 * resume value is the shared RAX as copied from the entering plane
	 * just above: GPRs are VTL-shared, so the retired hypercall's RAX
	 * must match what every other shared register already shows.  The
	 * value is guest-derived; strip the VMM-only RAISE_UD control bit
	 * so the completion cannot be made to inject #UD by the guest.
	 */
	if (target->arch.complete_userspace_io)
		vcpu->run->hyperv.u.hcall.result = kvm_rax_read(target) &
						   ~KVM_HV_HCALL_RESULT_RAISE_UD;

	vcpu->plane_kernel_stopped = true;
	kvm_vcpu_set_plane_stopped(vcpu);
	kvm_vcpu_set_plane_runnable(target);
	return true;
}

static int hv_vtl_switch_limit = -1;
module_param(hv_vtl_switch_limit, int, 0644);

static int kvm_hv_vtl_switch(struct kvm_vcpu *vcpu, bool is_return)
{
	static const int shared_gprs[] = {
		VCPU_REGS_RAX, VCPU_REGS_RBX, VCPU_REGS_RCX, VCPU_REGS_RDX,
		VCPU_REGS_RSI, VCPU_REGS_RDI, VCPU_REGS_RBP,
		VCPU_REGS_R8, VCPU_REGS_R9, VCPU_REGS_R10, VCPU_REGS_R11,
		VCPU_REGS_R12, VCPU_REGS_R13, VCPU_REGS_R14, VCPU_REGS_R15,
	};
	int cur = vcpu->plane_level;
	int to = is_return ? cur - 1 : cur + 1;
	u64 rax = kvm_rax_read(vcpu), rcx = kvm_rcx_read(vcpu);
	bool fast = is_return && (rax & HV_VTL_RETURN_FAST_BIT);
	int limit = READ_ONCE(hv_vtl_switch_limit);
	struct hv_vtl_control ctl;
	struct kvm_vcpu *target;
	u64 assist, resume;
	int i;

	if (to < 0 || to >= KVM_MAX_PLANES || !vcpu->common->vcpus[to])
		return -ENOENT;
	target = vcpu->common->vcpus[to];

	/*
	 * A VMM-stopped plane stays stopped until the VMM restarts it.
	 * Forward the switch so userspace can apply its own policy.
	 */
	if (target->plane_user_stopped)
		return -ENOENT;

	/*
	 * The resume protocol below delivers the result through the
	 * target's armed hypercall completion.  A target parked on any
	 * other completion (MMIO, PIO) owns the shared run union; writing
	 * hcall.result over it would feed the pending completion garbage
	 * and lose the resume value.  Forward such a switch to userspace.
	 */
	if (target->arch.complete_userspace_io &&
	    target->arch.complete_userspace_io != kvm_hv_hypercall_complete_userspace)
		return -ENOENT;

	/*
	 * Userspace owns HvCallEnableVpVtl state; the kernel only knows a
	 * plane vCPU exists, and VMMs create those at setup time.  Refuse
	 * to call into a plane that has never entered the guest: it still
	 * holds reset state, and the reference host fails such a call with
	 * HV_STATUS_INVALID_VP_STATE.  Forwarding lets userspace apply its
	 * enablement tracking (and run the plane's first entry itself).
	 */
	if (!is_return && target->arch.last_vmentry_cpu == -1)
		return -ENOENT;

	/*
	 * Debug budget on in-kernel switches, counted per VM and only for
	 * switches that pass the eligibility checks above (a forwarded
	 * switch consumes none).  The counter saturates so a guest cannot
	 * wrap it back under an operator-set limit.
	 */
	if (limit >= 0 &&
	    atomic_fetch_add_unless(&to_kvm_hv(vcpu->kvm)->vtl_switch_count,
				    1, INT_MAX) >= limit)
		return -ENOENT;

	if (is_return && !fast) {
		assist = hv_vtl_assist_page_gpa(vcpu);
		if (assist) {
			if (kvm_vcpu_read_guest(vcpu,
						assist + HV_VTL_CONTROL_OFFSET,
						&ctl, sizeof(ctl)))
				return -ENOENT;
		} else {
			/*
			 * No captured entry registers to restore: this plane
			 * was last entered by userspace (or the capture was
			 * lost across migration).  Forward the return so
			 * userspace restores the lower VTL's RAX/RCX itself.
			 */
			if (!to_hv_vcpu(vcpu)->vtl_entry_regs_valid)
				return -ENOENT;

			ctl.vtl_ret_x64rax = to_hv_vcpu(vcpu)->vtl_entry_rax;
			ctl.vtl_ret_x64rcx = to_hv_vcpu(vcpu)->vtl_entry_rcx;
		}
	} else if (!is_return) {
		/*
		 * Write the entered VTL's control area through the entered
		 * plane's vCPU: the write must pass that plane's memory
		 * attributes and memslot view, and the higher VTL normally
		 * protects its assist page against the caller's plane.
		 * Fail before any state moves (mirroring the read above);
		 * userspace then owns the switch.
		 */
		assist = hv_vtl_assist_page_gpa(target);
		if (assist) {
			ctl = (struct hv_vtl_control) {
				.vtl_entry_reason = HV_VTL_ENTRY_REASON_VTL_CALL,
				.vtl_ret_x64rax = rax,
				.vtl_ret_x64rcx = rcx,
			};
			if (kvm_vcpu_write_guest(target,
						 assist + HV_VTL_CONTROL_OFFSET,
						 &ctl, sizeof(ctl)))
				return -ENOENT;
		}
	}

	/* VTL-shared state: GPRs except RSP (RIP/RFLAGS stay private). */
	for (i = 0; i < ARRAY_SIZE(shared_gprs); i++)
		kvm_register_write_raw(target, shared_gprs[i],
				       kvm_register_read_raw(vcpu,
							     shared_gprs[i]));
	target->arch.cr2 = vcpu->arch.cr2;
	vcpu->common->vtl_fpu_from = cur;

	if (!is_return) {
		if (to_hv_vcpu(target)) {
			to_hv_vcpu(target)->vtl_entry_rax = rax;
			to_hv_vcpu(target)->vtl_entry_rcx = rcx;
			to_hv_vcpu(target)->vtl_entry_regs_valid = true;
		}
		resume = rax;
	} else {
		if (!fast)
			kvm_register_write_raw(target, VCPU_REGS_RCX,
					       ctl.vtl_ret_x64rcx);
		resume = fast ? rax : ctl.vtl_ret_x64rax;
		to_hv_vcpu(vcpu)->vtl_entry_regs_valid = false;
	}

	/*
	 * The target resumes in a hypercall of its own (any time after its
	 * very first entry).  Its pending completion delivers the deferred
	 * instruction skip and the resume RAX from the shared run struct,
	 * exactly as when userspace drives the switch; until then its
	 * suspended RIP stays at the vmcall, which the higher VTL can
	 * observe (and rewrite) through HvCallGetVpRegisters.
	 *
	 * The resume value is guest-derived in all three cases (the
	 * caller's RAX on a call or a fast return, the control area on a
	 * non-fast return): strip the VMM-only RAISE_UD control bit so
	 * the completion cannot be made to inject #UD into the suspended
	 * plane.
	 */
	resume &= ~KVM_HV_HCALL_RESULT_RAISE_UD;
	if (target->arch.complete_userspace_io)
		vcpu->run->hyperv.u.hcall.result = resume;
	else
		/*
		 * No completion is armed when the target's suspension
		 * already retired its vmcall (forwarded switch) or was a
		 * forced interrupt entry: RIP is already where the plane
		 * resumes, so deliver the resume RAX directly.  Without
		 * this the GPR copy above leaves the switching plane's raw
		 * RAX in place and a non-fast return never restores the
		 * control-area value.
		 */
		kvm_rax_write_raw(target, resume);

	/*
	 * Suspend the current plane in its uncompleted hypercall; the
	 * switch back will provide its resume value the same way.
	 */
	vcpu->arch.complete_userspace_io = kvm_hv_hypercall_complete_userspace;

	vcpu->plane_kernel_stopped = true;
	kvm_vcpu_set_plane_stopped(vcpu);
	kvm_vcpu_set_plane_runnable(target);
	kvm_make_request(KVM_REQ_PLANE_RESCHED, vcpu);
	return 0;
}

int kvm_hv_hypercall(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hv *hv_vcpu = to_hv_vcpu(vcpu);
	struct kvm_hv_hcall hc;
	u64 ret = HV_STATUS_SUCCESS;
	s64 r;

	/*
	 * hypercall generates UD from non zero cpl and real mode
	 * per HYPER-V spec
	 */
	if (kvm_x86_call(get_cpl)(vcpu) != 0 || !is_protmode(vcpu)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

#ifdef CONFIG_X86_64
	if (is_64_bit_hypercall(vcpu)) {
		hc.param = kvm_rcx_read_raw(vcpu);
		hc.ingpa = kvm_rdx_read_raw(vcpu);
		hc.outgpa = kvm_r8_read_raw(vcpu);
	} else
#endif
	{
		hc.param = ((u64)kvm_edx_read(vcpu) << 32) | kvm_eax_read(vcpu);
		hc.ingpa = ((u64)kvm_ebx_read(vcpu) << 32) | kvm_ecx_read(vcpu);
		hc.outgpa = ((u64)kvm_edi_read(vcpu) << 32) | kvm_esi_read(vcpu);
	}

	hc.code = hc.param & 0xffff;
	hc.var_cnt = (hc.param & HV_HYPERCALL_VARHEAD_MASK) >> HV_HYPERCALL_VARHEAD_OFFSET;
	hc.fast = !!(hc.param & HV_HYPERCALL_FAST_BIT);
	hc.rep_cnt = (hc.param >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
	hc.rep_idx = (hc.param >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
	hc.rep = !!(hc.rep_cnt || hc.rep_idx);

	trace_kvm_hv_hypercall(hc.code, hc.fast, hc.var_cnt, hc.rep_cnt,
			       hc.rep_idx, hc.ingpa, hc.outgpa);

	if (unlikely(!hv_check_hypercall_access(hv_vcpu, hc.code))) {
		ret = HV_STATUS_ACCESS_DENIED;
		goto hypercall_complete;
	}

	if (unlikely(hc.param & HV_HYPERCALL_RSVD_MASK)) {
		ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
		goto hypercall_complete;
	}

	if (hc.fast && is_xmm_fast_hypercall(&hc)) {
		if (unlikely(hv_vcpu->enforce_cpuid &&
			     !(hv_vcpu->cpuid_cache.features_edx &
			       HV_X64_HYPERCALL_XMM_INPUT_AVAILABLE))) {
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}

		kvm_hv_hypercall_read_xmm(&hc);
	}

	switch (hc.code) {
	case HVCALL_NOTIFY_LONG_SPIN_WAIT:
		if (unlikely(hc.rep || hc.var_cnt)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		kvm_vcpu_on_spin(vcpu, true);
		break;
	case HVCALL_SIGNAL_EVENT:
		if (unlikely(hc.rep || hc.var_cnt)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		r = kvm_hvcall_signal_event(vcpu, &hc);
		if (r < 0)
			return r;
		ret = r;
		if (ret != HV_STATUS_INVALID_PORT_ID)
			break;
		fallthrough;	/* maybe userspace knows this conn_id */
	case HVCALL_POST_MESSAGE:
		/* don't bother userspace if it has no way to handle it */
		if (unlikely(hc.rep || hc.var_cnt || !to_hv_synic(vcpu)->active)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		return kvm_hv_hypercall_userspace_exit(vcpu, &hc);
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST:
		if (unlikely(hc.var_cnt)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		fallthrough;
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX:
		if (unlikely(!hc.rep_cnt || hc.rep_idx)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		r = kvm_hv_flush_tlb(vcpu, &hc);
		if (r < 0)
			return r;
		ret = r;
		break;
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE:
		if (unlikely(hc.var_cnt)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		fallthrough;
	case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX:
		if (unlikely(hc.rep)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		r = kvm_hv_flush_tlb(vcpu, &hc);
		if (r < 0)
			return r;
		ret = r;
		break;
	case HVCALL_SEND_IPI:
		if (unlikely(hc.var_cnt)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		fallthrough;
	case HVCALL_SEND_IPI_EX:
		if (unlikely(hc.rep)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		r = kvm_hv_send_ipi(vcpu, &hc);
		if (r < 0)
			return r;
		ret = r;
		break;
	case HVCALL_POST_DEBUG_DATA:
	case HVCALL_RETRIEVE_DEBUG_DATA:
		if (unlikely(hc.fast)) {
			ret = HV_STATUS_INVALID_PARAMETER;
			break;
		}
		fallthrough;
	case HVCALL_RESET_DEBUG_SESSION: {
		struct kvm_hv_syndbg *syndbg = to_hv_syndbg(vcpu);

		if (!kvm_hv_is_syndbg_enabled(vcpu)) {
			ret = HV_STATUS_INVALID_HYPERCALL_CODE;
			break;
		}

		if (!(syndbg->options & HV_X64_SYNDBG_OPTION_USE_HCALLS)) {
			ret = HV_STATUS_OPERATION_DENIED;
			break;
		}
		return kvm_hv_hypercall_userspace_exit(vcpu, &hc);
	}
	case HV_EXT_CALL_QUERY_CAPABILITIES ... HV_EXT_CALL_MAX:
		if (unlikely(hc.fast) &&
		    !to_kvm_hv(vcpu->kvm)->hv_forward_hcalls) {
			ret = HV_STATUS_INVALID_PARAMETER;
			break;
		}
		return kvm_hv_hypercall_userspace_exit(vcpu, &hc);
	case HVCALL_VTL_CALL:
	case HVCALL_VTL_RETURN:
		/* Neither call takes a variable header or rep count. */
		if (unlikely(hc.rep || hc.var_cnt)) {
			ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
			break;
		}
		if (READ_ONCE(to_kvm_hv(vcpu->kvm)->hv_inkernel_vtl_switch) &&
		    !hc.fast &&
		    !kvm_hv_vtl_switch(vcpu, hc.code == HVCALL_VTL_RETURN)) {
			/*
			 * Suspended mid-hypercall; the pending completion
			 * delivers the result when the plane resumes.
			 */
			return 1;
		}
		if (to_kvm_hv(vcpu->kvm)->hv_forward_hcalls) {
			/*
			 * Retire the vmcall before the plane switch, like the
			 * reference hypervisor: the VMM fully owns the resumed
			 * context (GPR copy, control-area RAX/RCX restore).  A
			 * completion deferred across the suspension fires on
			 * whatever entry resumes this plane next - after a
			 * forced higher-VTL entry that can be an arbitrary
			 * interrupted instruction, which then has RAX and RIP
			 * rewritten with stale hypercall results.
			 */
			ret = kvm_hv_hypercall_userspace_exit(vcpu, &hc);
			if (!ret) {
				/*
				 * With guest TF and KVM_GUESTDBG_SINGLESTEP
				 * the skip prepares KVM_EXIT_DEBUG in the
				 * same run union, overwriting the exit just
				 * prepared; the retired vmcall would then be
				 * silently dropped and the VMM never perform
				 * the switch.  Re-prepare the hypercall exit
				 * in that case: the VMM must see it, at the
				 * price of one missed step event.
				 */
				if (!kvm_skip_emulated_instruction(vcpu))
					kvm_hv_hypercall_userspace_exit(vcpu,
									&hc);
				vcpu->arch.complete_userspace_io = NULL;
				return 0;
			}
			break;
		}
		fallthrough;
	default:
		if (to_kvm_hv(vcpu->kvm)->hv_forward_hcalls)
			return kvm_hv_hypercall_userspace_exit(vcpu, &hc);
		ret = HV_STATUS_INVALID_HYPERCALL_CODE;
		break;
	}

hypercall_complete:
	return kvm_hv_hypercall_complete(vcpu, ret);

}

void kvm_hv_init_vm(struct kvm *kvm)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);

	mutex_init(&hv->hv_lock);
	idr_init(&hv->conn_to_evt);
}

void kvm_hv_destroy_vm(struct kvm *kvm)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	struct eventfd_ctx *eventfd;
	int i;

	idr_for_each_entry(&hv->conn_to_evt, eventfd, i)
		eventfd_ctx_put(eventfd);
	idr_destroy(&hv->conn_to_evt);
}

static int kvm_hv_eventfd_assign(struct kvm *kvm, u32 conn_id, int fd)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	struct eventfd_ctx *eventfd;
	int ret;

	eventfd = eventfd_ctx_fdget(fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	mutex_lock(&hv->hv_lock);
	ret = idr_alloc(&hv->conn_to_evt, eventfd, conn_id, conn_id + 1,
			GFP_KERNEL_ACCOUNT);
	mutex_unlock(&hv->hv_lock);

	if (ret >= 0)
		return 0;

	if (ret == -ENOSPC)
		ret = -EEXIST;
	eventfd_ctx_put(eventfd);
	return ret;
}

static int kvm_hv_eventfd_deassign(struct kvm *kvm, u32 conn_id)
{
	struct kvm_hv *hv = to_kvm_hv(kvm);
	struct eventfd_ctx *eventfd;

	mutex_lock(&hv->hv_lock);
	eventfd = idr_remove(&hv->conn_to_evt, conn_id);
	mutex_unlock(&hv->hv_lock);

	if (!eventfd)
		return -ENOENT;

	synchronize_srcu(&kvm->srcu);
	eventfd_ctx_put(eventfd);
	return 0;
}

int kvm_vm_ioctl_hv_eventfd(struct kvm *kvm, struct kvm_hyperv_eventfd *args)
{
	if ((args->flags & ~KVM_HYPERV_EVENTFD_DEASSIGN) ||
	    (args->conn_id & ~KVM_HYPERV_CONN_ID_MASK))
		return -EINVAL;

	if (args->flags == KVM_HYPERV_EVENTFD_DEASSIGN)
		return kvm_hv_eventfd_deassign(kvm, args->conn_id);
	return kvm_hv_eventfd_assign(kvm, args->conn_id, args->fd);
}

int kvm_get_hv_cpuid(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid,
		     struct kvm_cpuid_entry2 __user *entries)
{
	uint16_t evmcs_ver = 0;
	struct kvm_cpuid_entry2 cpuid_entries[] = {
		{ .function = HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS },
		{ .function = HYPERV_CPUID_INTERFACE },
		{ .function = HYPERV_CPUID_VERSION },
		{ .function = HYPERV_CPUID_FEATURES },
		{ .function = HYPERV_CPUID_ENLIGHTMENT_INFO },
		{ .function = HYPERV_CPUID_IMPLEMENT_LIMITS },
		{ .function = HYPERV_CPUID_SYNDBG_VENDOR_AND_MAX_FUNCTIONS },
		{ .function = HYPERV_CPUID_SYNDBG_INTERFACE },
		{ .function = HYPERV_CPUID_SYNDBG_PLATFORM_CAPABILITIES	},
		{ .function = HYPERV_CPUID_NESTED_FEATURES },
	};
	int i, nent = ARRAY_SIZE(cpuid_entries);

	if (kvm_nested_ops.enabled)
		evmcs_ver = kvm_nested_call(get_evmcs_version)(vcpu);

	if (cpuid->nent < nent)
		return -E2BIG;

	if (cpuid->nent > nent)
		cpuid->nent = nent;

	for (i = 0; i < nent; i++) {
		struct kvm_cpuid_entry2 *ent = &cpuid_entries[i];
		u32 signature[3];

		switch (ent->function) {
		case HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS:
			memcpy(signature, "Linux KVM Hv", 12);

			ent->eax = HYPERV_CPUID_SYNDBG_PLATFORM_CAPABILITIES;
			ent->ebx = signature[0];
			ent->ecx = signature[1];
			ent->edx = signature[2];
			break;

		case HYPERV_CPUID_INTERFACE:
			ent->eax = HYPERV_CPUID_SIGNATURE_EAX;
			break;

		case HYPERV_CPUID_VERSION:
			/*
			 * We implement some Hyper-V 2016 functions so let's use
			 * this version.
			 */
			ent->eax = 0x00003839;
			ent->ebx = 0x000A0000;
			break;

		case HYPERV_CPUID_FEATURES:
			ent->eax |= HV_MSR_VP_RUNTIME_AVAILABLE;
			ent->eax |= HV_MSR_TIME_REF_COUNT_AVAILABLE;
			ent->eax |= HV_MSR_SYNIC_AVAILABLE;
			ent->eax |= HV_MSR_SYNTIMER_AVAILABLE;
			ent->eax |= HV_MSR_APIC_ACCESS_AVAILABLE;
			ent->eax |= HV_MSR_HYPERCALL_AVAILABLE;
			ent->eax |= HV_MSR_VP_INDEX_AVAILABLE;
			ent->eax |= HV_MSR_RESET_AVAILABLE;
			ent->eax |= HV_MSR_REFERENCE_TSC_AVAILABLE;
			ent->eax |= HV_ACCESS_FREQUENCY_MSRS;
			ent->eax |= HV_ACCESS_REENLIGHTENMENT;
			ent->eax |= HV_ACCESS_TSC_INVARIANT;

			ent->ebx |= HV_POST_MESSAGES;
			ent->ebx |= HV_SIGNAL_EVENTS;
			ent->ebx |= HV_ENABLE_EXTENDED_HYPERCALLS;

			ent->edx |= HV_X64_HYPERCALL_XMM_INPUT_AVAILABLE;
			ent->edx |= HV_FEATURE_FREQUENCY_MSRS_AVAILABLE;
			ent->edx |= HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE;

			ent->ebx |= HV_DEBUGGING;
			ent->edx |= HV_X64_GUEST_DEBUGGING_AVAILABLE;
			ent->edx |= HV_FEATURE_DEBUG_MSRS_AVAILABLE;
			ent->edx |= HV_FEATURE_EXT_GVA_RANGES_FLUSH;

			/*
			 * Direct Synthetic timers only make sense with in-kernel
			 * LAPIC
			 */
			if (!vcpu || lapic_in_kernel(vcpu))
				ent->edx |= HV_STIMER_DIRECT_MODE_AVAILABLE;

			break;

		case HYPERV_CPUID_ENLIGHTMENT_INFO:
			ent->eax |= HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED;
			ent->eax |= HV_X64_APIC_ACCESS_RECOMMENDED;
			ent->eax |= HV_X64_RELAXED_TIMING_RECOMMENDED;
			if (!vcpu || lapic_in_kernel(vcpu))
				ent->eax |= HV_X64_CLUSTER_IPI_RECOMMENDED;
			ent->eax |= HV_X64_EX_PROCESSOR_MASKS_RECOMMENDED;
			if (evmcs_ver)
				ent->eax |= HV_X64_ENLIGHTENED_VMCS_RECOMMENDED;
			if (!cpu_smt_possible())
				ent->eax |= HV_X64_NO_NONARCH_CORESHARING;

			ent->eax |= HV_DEPRECATING_AEOI_RECOMMENDED;
			/*
			 * Default number of spinlock retry attempts, matches
			 * HyperV 2016.
			 */
			ent->ebx = 0x00000FFF;

			break;

		case HYPERV_CPUID_IMPLEMENT_LIMITS:
			/* Maximum number of virtual processors */
			ent->eax = KVM_MAX_VCPUS;
			/*
			 * Maximum number of logical processors, matches
			 * HyperV 2016.
			 */
			ent->ebx = 64;

			break;

		case HYPERV_CPUID_NESTED_FEATURES:
			ent->eax = evmcs_ver;
			ent->eax |= HV_X64_NESTED_DIRECT_FLUSH;
			ent->eax |= HV_X64_NESTED_MSR_BITMAP;
			ent->ebx |= HV_X64_NESTED_EVMCS1_PERF_GLOBAL_CTRL;
			break;

		case HYPERV_CPUID_SYNDBG_VENDOR_AND_MAX_FUNCTIONS:
			memcpy(signature, "Linux KVM Hv", 12);

			ent->eax = 0;
			ent->ebx = signature[0];
			ent->ecx = signature[1];
			ent->edx = signature[2];
			break;

		case HYPERV_CPUID_SYNDBG_INTERFACE:
			memcpy(signature, "VS#1\0\0\0\0\0\0\0\0", 12);
			ent->eax = signature[0];
			break;

		case HYPERV_CPUID_SYNDBG_PLATFORM_CAPABILITIES:
			ent->eax |= HV_X64_SYNDBG_CAP_ALLOW_KERNEL_DEBUGGING;
			break;

		default:
			break;
		}
	}

	if (copy_to_user(entries, cpuid_entries,
			 nent * sizeof(struct kvm_cpuid_entry2)))
		return -EFAULT;

	return 0;
}
