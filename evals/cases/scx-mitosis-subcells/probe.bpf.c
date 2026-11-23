#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SHARED_DSQ 1
#define SLICE_NS 5000000ULL

s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;
bool scx_bpf_task_set_slice(struct task_struct *p, u64 slice) __ksym __weak;
void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data__sz) __ksym;

struct g {
	int target;
	int refill;
	int custom;
	int drain;
	u64 dsq_arg;
	s64 mkdsq_ret;
	int after_error;
	u64 running, stop_runnable, stop_sleep, runnable, quiet_sleep, quiet_other;
	u64 refills, ticks, enq, enq_last, custom_enq;
	u64 dispatch, dispatch_remote;
	u64 cgid;
	int exit_kind;
	char exit_msg[128];
} g;

static bool is_target(struct task_struct *p)
{
	return g.target && p->tgid == g.target;
}

SEC("struct_ops/enqueue")
void BPF_PROG(probe_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_target(p)) {
		g.enq++;
		if (enq_flags & SCX_ENQ_LAST)
			g.enq_last++;
	}
	if (enq_flags & SCX_ENQ_LAST) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_NS, 0);
		return;
	}
	if (g.custom) {
		g.custom_enq++;
		scx_bpf_dsq_insert(p, g.custom, SLICE_NS, enq_flags);
		return;
	}
	scx_bpf_dsq_insert(p, SHARED_DSQ, SLICE_NS, enq_flags);
}

SEC("struct_ops/dispatch")
void BPF_PROG(probe_dispatch, s32 cpu, struct task_struct *prev)
{
	g.dispatch++;
	if (cpu != bpf_get_smp_processor_id())
		g.dispatch_remote++;
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;
	if (g.drain && scx_bpf_dsq_move_to_local(g.drain))
		return;
	if (g.refill && prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		if (bpf_ksym_exists(scx_bpf_task_set_slice))
			scx_bpf_task_set_slice(prev, SLICE_NS);
		else
			prev->scx.slice = SLICE_NS;
		if (is_target(prev))
			g.refills++;
	}
}

SEC("struct_ops/runnable")
void BPF_PROG(probe_runnable, struct task_struct *p, u64 enq_flags)
{
	if (is_target(p))
		g.runnable++;
}

SEC("struct_ops/running")
void BPF_PROG(probe_running, struct task_struct *p)
{
	if (is_target(p))
		g.running++;
}

SEC("struct_ops/tick")
void BPF_PROG(probe_tick, struct task_struct *p)
{
	if (is_target(p)) {
		g.ticks++;
		g.cgid = p->cgroups->dfl_cgrp->kn->id;
	}
}

SEC("struct_ops/stopping")
void BPF_PROG(probe_stopping, struct task_struct *p, bool runnable)
{
	if (is_target(p)) {
		if (runnable)
			g.stop_runnable++;
		else
			g.stop_sleep++;
	}
}

SEC("struct_ops/quiescent")
void BPF_PROG(probe_quiescent, struct task_struct *p, u64 deq_flags)
{
	if (is_target(p)) {
		if (deq_flags & SCX_DEQ_SLEEP)
			g.quiet_sleep++;
		else
			g.quiet_other++;
	}
}

SEC("struct_ops.s/init")
s32 BPF_PROG(probe_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

SEC("struct_ops/exit")
void BPF_PROG(probe_exit, struct scx_exit_info *ei)
{
	g.exit_kind = ei->kind;
	bpf_probe_read_kernel_str(g.exit_msg, sizeof(g.exit_msg), ei->msg);
}

SEC("syscall")
int mkdsq(void *ctx)
{
	g.mkdsq_ret = scx_bpf_create_dsq(g.dsq_arg, -1);
	return 0;
}

SEC("syscall")
int mkdsq_assoc(void *ctx)
{
	g.mkdsq_ret = scx_bpf_create_dsq(g.dsq_arg, -1);
	return 0;
}

static char first_fmt[] = "first error";
static char second_fmt[] = "second error";

SEC("syscall")
int double_error(void *ctx)
{
	unsigned long long data[1] = {};

	scx_bpf_error_bstr(first_fmt, data, sizeof(data));
	scx_bpf_error_bstr(second_fmt, data, sizeof(data));
	g.after_error = 1;
	return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops probe_ops = {
	.enqueue = (void *)probe_enqueue,
	.dispatch = (void *)probe_dispatch,
	.runnable = (void *)probe_runnable,
	.running = (void *)probe_running,
	.tick = (void *)probe_tick,
	.stopping = (void *)probe_stopping,
	.quiescent = (void *)probe_quiescent,
	.init = (void *)probe_init,
	.exit = (void *)probe_exit,
	.flags = SCX_OPS_ENQ_LAST,
	.name = "probe",
};

char LICENSE[] SEC("license") = "GPL";
