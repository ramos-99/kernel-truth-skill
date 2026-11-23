#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;

#define NBUCKET 16	/* 250us each */

struct rec {
	u32 enable_weight, setw_calls, setw_weight, custom_slice;
	u64 setw_load_weight, se_slice;
	u64 wakeups, wake_slice_nonzero, wake_slice_sum;
	u64 stops, stops_slice_zero;
	u64 run_start, runs[NBUCKET];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct rec);
} watch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} cfg SEC(".maps");

static struct rec *rec_of(struct task_struct *p)
{
	u32 pid = p->pid;

	return bpf_map_lookup_elem(&watch, &pid);
}

/* No direct dispatch, so the kernel's default pick doesn't refill the slice. */
SEC("struct_ops/t_select_cpu")
s32 BPF_PROG(t_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;
}

SEC("struct_ops/t_enqueue")
void BPF_PROG(t_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 zero = 0;
	u64 *slice = bpf_map_lookup_elem(&cfg, &zero);

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice && *slice ? *slice : SCX_SLICE_DFL, enq_flags);
}

SEC("struct_ops/t_runnable")
void BPF_PROG(t_runnable, struct task_struct *p, u64 enq_flags)
{
	struct rec *r = rec_of(p);

	if (!r || !(enq_flags & SCX_ENQ_WAKEUP))
		return;
	r->wakeups++;
	r->wake_slice_sum += p->scx.slice;
	if (p->scx.slice)
		r->wake_slice_nonzero++;
}

SEC("struct_ops/t_running")
void BPF_PROG(t_running, struct task_struct *p)
{
	struct rec *r = rec_of(p);

	if (r)
		r->run_start = bpf_ktime_get_ns();
}

SEC("struct_ops/t_stopping")
void BPF_PROG(t_stopping, struct task_struct *p, bool runnable)
{
	struct rec *r = rec_of(p);
	u64 b;

	if (!r)
		return;
	r->stops++;
	if (!p->scx.slice)
		r->stops_slice_zero++;
	if (runnable && r->run_start) {
		b = (bpf_ktime_get_ns() - r->run_start) / 250000;
		if (b >= NBUCKET)
			b = NBUCKET - 1;
		r->runs[b]++;
	}
}

SEC("struct_ops/t_set_weight")
void BPF_PROG(t_set_weight, struct task_struct *p, u32 weight)
{
	struct rec *r = rec_of(p);

	if (!r)
		return;
	r->setw_calls++;
	r->setw_weight = weight;
	r->setw_load_weight = p->se.load.weight;
	r->custom_slice = p->se.custom_slice;
	r->se_slice = p->se.slice;
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.select_cpu	= (void *)t_select_cpu,
	.enqueue	= (void *)t_enqueue,
	.runnable	= (void *)t_runnable,
	.running	= (void *)t_running,
	.stopping	= (void *)t_stopping,
	.set_weight	= (void *)t_set_weight,
	.name		= "kt_test",
};
