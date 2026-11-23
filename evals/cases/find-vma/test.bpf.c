#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct stats {
	__u64 runs, first_ok, first_busy, first_other, second_ok, second_busy, second_other;
};

struct stats st[4] = {};

static long check_vma(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	return 0;
}

static __always_inline void twice(struct stats *s)
{
	struct task_struct *task = bpf_get_current_task_btf();
	char c[16] = {};
	__u64 addr;
	long a, b;

	bpf_get_current_comm(c, sizeof(c));
	if (c[0] != 'v' || c[1] != 'm' || c[2] != 'a' || c[3] != 't')
		return;
	addr = BPF_CORE_READ(task, mm, start_code);
	a = bpf_find_vma(task, addr, check_vma, NULL, 0);
	b = bpf_find_vma(task, addr, check_vma, NULL, 0);
	s->runs++;
	if (!a)
		s->first_ok++;
	else if (a == -16)
		s->first_busy++;
	else
		s->first_other++;
	if (!b)
		s->second_ok++;
	else if (b == -16)
		s->second_busy++;
	else
		s->second_other++;
}

SEC("raw_tp/sys_enter")
int plain_context(void *ctx)
{
	twice(&st[0]);
	return 0;
}

SEC("perf_event")
int perf_hw(void *ctx)
{
	twice(&st[1]);
	return 0;
}

SEC("perf_event")
int perf_sw(void *ctx)
{
	twice(&st[2]);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(irqs_off_no_nmi)
{
	twice(&st[3]);
	return 0;
}
