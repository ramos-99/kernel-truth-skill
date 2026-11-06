#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct ev_key {
	__u32 hook;
	__u32 tid;
};

struct ev_val {
	__u32 tgid;
	__s32 ctx_pid;
	__u64 mm;
	__u64 start_code;
	__s32 live;
	__s32 group_dead;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ev_key);
	__type(value, struct ev_val);
} events SEC(".maps");

static bool is_workload(void)
{
	char c[16] = {};

	bpf_get_current_comm(c, sizeof(c));
	return c[0] == 'e' && c[1] == 'x' && c[2] == 'i' && c[3] == 't' &&
	       c[4] == 'w' && c[5] == 'o' && c[6] == 'r' && c[7] == 'k';
}

static void record(__u32 hook, int ctx_pid, int group_dead)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();
	struct ev_key k = { .hook = hook, .tid = (__u32)id };
	struct ev_val v = {
		.tgid = id >> 32,
		.ctx_pid = ctx_pid,
		.group_dead = group_dead,
	};

	v.mm = (__u64)BPF_CORE_READ(task, mm);
	v.start_code = BPF_CORE_READ(task, mm, start_code);
	v.live = BPF_CORE_READ(task, signal, live.counter);
	bpf_map_update_elem(&events, &k, &v, BPF_ANY);
}

struct exit_ctx {
	__u64 common;
	char comm[16];
	int pid;
	int prio;
	__u8 past_prio;
};

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(struct exit_ctx *c)
{
	if (is_workload())
		record(1, c->pid, -1);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_exit_group_dead(struct exit_ctx *c)
{
	if (is_workload())
		record(5, c->pid, c->past_prio);
	return 0;
}

SEC("fentry/taskstats_exit")
int BPF_PROG(fentry_taskstats, struct task_struct *tsk, int group_dead)
{
	if (is_workload())
		record(2, -1, group_dead);
	return 0;
}

SEC("kprobe/acct_collect")
int BPF_KPROBE(kprobe_acct, long code, int group_dead)
{
	if (is_workload())
		record(3, -1, group_dead);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(void *c)
{
	if (is_workload())
		record(4, -1, -1);
	return 0;
}
