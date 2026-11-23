#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct val {
	__u64 exec_id;
	__u64 hits;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct val);
} st SEC(".maps");

struct rec {
	__u32 tid, found, zeroed, pad;
	__u64 self_exec_id, stored_exec_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, struct rec);
} out SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cnt SEC(".maps");

SEC("tp_btf/sys_enter")
int BPF_PROG(on_enter, struct pt_regs *regs, long id)
{
	struct task_struct *t = bpf_get_current_task_btf();
	__u32 zero = 0, *n;
	struct rec *r;
	struct val *v;

	if (id != 110) /* getppid */
		return 0;
	n = bpf_map_lookup_elem(&cnt, &zero);
	if (!n)
		return 0;
	r = bpf_map_lookup_elem(&out, n);
	if (!r)
		return 0;
	(*n)++;
	r->tid = (__u32)bpf_get_current_pid_tgid();
	r->self_exec_id = t->self_exec_id;
	v = bpf_task_storage_get(&st, t, 0, 0);
	r->found = v != 0;
	if (!v)
		v = bpf_task_storage_get(&st, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!v)
		return 0;
	r->zeroed = !v->exec_id && !v->hits;
	r->stored_exec_id = v->exec_id;
	v->exec_id = t->self_exec_id;
	v->hits++;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
