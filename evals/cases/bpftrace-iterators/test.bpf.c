#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern int bpf_iter_task_new(struct bpf_iter_task *it, struct task_struct *task, unsigned int flags) __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __ksym;
extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it, struct task_struct *task, __u64 addr) __ksym;
extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

// ret[] holds return codes of _new, cnt[] holds element counts.
struct out {
	long ret[8];
	long cnt[8];
} out;

struct bpf_iter_task in_map;

static __always_inline void count_tasks(int slot, struct task_struct *task, unsigned int flags)
{
	struct bpf_iter_task it;

	out.ret[slot] = bpf_iter_task_new(&it, task, flags);
	while (bpf_iter_task_next(&it))
		out.cnt[slot]++;
	bpf_iter_task_destroy(&it);
}

// Flags 0, 1, 2 as bpftrace passes them, plus the error cases.
SEC("raw_tp")
int task_modes(void *ctx)
{
	count_tasks(0, NULL, 0);
	count_tasks(1, NULL, 1);
	count_tasks(2, bpf_get_current_task_btf(), 2);
	count_tasks(3, NULL, 2);
	count_tasks(4, NULL, 3);
	return 0;
}

SEC("raw_tp")
int vma_current(void *ctx)
{
	struct bpf_iter_task_vma it;
	struct vm_area_struct *v;

	out.ret[0] = bpf_iter_task_vma_new(&it, bpf_get_current_task_btf(), 0);
	while ((v = bpf_iter_task_vma_next(&it)))
		if (v->vm_end > v->vm_start)
			out.cnt[0]++;
	bpf_iter_task_vma_destroy(&it);
	return 0;
}

// Interrupts are off in sched_switch.
SEC("tp_btf/sched_switch")
int vma_irqs_off(void *ctx)
{
	struct bpf_iter_task_vma it;
	int r = bpf_iter_task_vma_new(&it, bpf_get_current_task_btf(), 0);

	if (r == 0)
		out.cnt[0]++;
	else if (r == -16)
		out.cnt[1]++;
	else if (r == -2)
		out.cnt[2]++;
	else
		out.cnt[3]++;
	bpf_iter_task_vma_destroy(&it);
	return 0;
}

// A task from the task iterator passed on to the vma iterator.
SEC("raw_tp")
int nested_iter(void *ctx)
{
	struct bpf_iter_task it;
	struct task_struct *t;

	bpf_iter_task_new(&it, NULL, 0);
	while ((t = bpf_iter_task_next(&it))) {
		struct bpf_iter_task_vma vit;
		int r = bpf_iter_task_vma_new(&vit, t, 0);

		if (r == 0)
			out.cnt[0]++;
		else if (r == -2)
			out.cnt[1]++;
		else
			out.cnt[2]++;
		if (bpf_iter_task_vma_next(&vit))
			out.cnt[3]++;
		bpf_iter_task_vma_destroy(&vit);
	}
	bpf_iter_task_destroy(&it);
	return 0;
}

SEC("raw_tp")
int vma_untrusted(void *ctx)
{
	struct bpf_iter_task_vma it;

	bpf_iter_task_vma_new(&it, (struct task_struct *)bpf_get_current_task(), 0);
	bpf_iter_task_vma_destroy(&it);
	return 0;
}

// A stack counter written in the loop and branched on afterwards.
SEC("raw_tp")
int stack_counter_branch(void *ctx)
{
	struct bpf_iter_task it;
	long n = 0;

	bpf_iter_task_new(&it, NULL, 1);
	while (bpf_iter_task_next(&it))
		n++;
	bpf_iter_task_destroy(&it);
	if (n > 1)
		out.cnt[0] = n;
	return 0;
}

// The same counter, only stored afterwards.
SEC("raw_tp")
int stack_counter_store(void *ctx)
{
	struct bpf_iter_task it;
	long n = 0;

	bpf_iter_task_new(&it, NULL, 1);
	while (bpf_iter_task_next(&it))
		n++;
	bpf_iter_task_destroy(&it);
	out.cnt[0] = n;
	return 0;
}

// The counter in a map value, as bpftrace's scratch variables are.
SEC("raw_tp")
int map_counter_branch(void *ctx)
{
	struct bpf_iter_task it;

	out.cnt[1] = 0;
	bpf_iter_task_new(&it, NULL, 1);
	while (bpf_iter_task_next(&it))
		out.cnt[1]++;
	bpf_iter_task_destroy(&it);
	if (out.cnt[1] > 1)
		out.cnt[0] = out.cnt[1];
	return 0;
}

// Variables that start fresh on each iteration.
SEC("raw_tp")
int loop_local(void *ctx)
{
	struct bpf_iter_task it;
	struct task_struct *t;

	bpf_iter_task_new(&it, NULL, 1);
	while ((t = bpf_iter_task_next(&it))) {
		long x = t->pid, y = x + 1;

		y++;
		if (y == x + 2)
			out.cnt[0]++;
	}
	bpf_iter_task_destroy(&it);
	return 0;
}

SEC("raw_tp")
int no_destroy_on_fail(void *ctx)
{
	struct bpf_iter_task it;

	if (bpf_iter_task_new(&it, NULL, 0))
		return 0;
	while (bpf_iter_task_next(&it))
		out.cnt[0]++;
	bpf_iter_task_destroy(&it);
	return 0;
}

SEC("raw_tp")
int state_in_map(void *ctx)
{
	bpf_iter_task_new(&in_map, NULL, 0);
	while (bpf_iter_task_next(&in_map))
		out.cnt[0]++;
	bpf_iter_task_destroy(&in_map);
	return 0;
}

SEC("raw_tp")
int state_misaligned(void *ctx)
{
	__u64 buf[5] = {};
	struct bpf_iter_task *it = (void *)buf + 4;

	bpf_iter_task_new(it, NULL, 0);
	while (bpf_iter_task_next(it))
		out.cnt[0]++;
	bpf_iter_task_destroy(it);
	return 0;
}

// What bpftrace emits for `for ($i : 0..2) { for ($t : iter_task()) { ...; break; } }`:
// the inner loop has no back-edge, and the outer loop is a bpf_loop callback.
static long cb_uncond(__u64 i, void *ctx)
{
	struct bpf_iter_task it;

	if (bpf_iter_task_new(&it, NULL, 0) == 0)
		if (bpf_iter_task_next(&it))
			out.cnt[0]++;
	bpf_iter_task_destroy(&it);
	return 0;
}

static long cb_cond(__u64 i, void *ctx)
{
	struct bpf_iter_task it;

	if (bpf_iter_task_new(&it, NULL, 0) == 0)
		while (bpf_iter_task_next(&it)) {
			out.cnt[0]++;
			if (out.cnt[0] > 0)
				break;
		}
	bpf_iter_task_destroy(&it);
	return 0;
}

// Like bpftrace's range loop, the callback reads and writes a context on the
// caller's stack, so the second pass through the callback sees a new state.
struct loop_ctx {
	long i;
};

static long cb_uncond_ctx(__u64 i, struct loop_ctx *c)
{
	struct bpf_iter_task it;

	if (c->i > 100)
		return 1;
	c->i = i;
	if (bpf_iter_task_new(&it, NULL, 0) == 0)
		if (bpf_iter_task_next(&it))
			out.cnt[0]++;
	bpf_iter_task_destroy(&it);
	return 0;
}

static long cb_cond_ctx(__u64 i, struct loop_ctx *c)
{
	struct bpf_iter_task it;

	if (c->i > 100)
		return 1;
	c->i = i;
	if (bpf_iter_task_new(&it, NULL, 0) == 0)
		while (bpf_iter_task_next(&it)) {
			out.cnt[0]++;
			if (out.cnt[0] > 0)
				break;
		}
	bpf_iter_task_destroy(&it);
	return 0;
}

SEC("raw_tp")
int in_loop_uncond_break_ctx(void *ctx)
{
	struct loop_ctx c = {};

	out.cnt[0] = 0;
	bpf_loop(2, cb_uncond_ctx, &c, 0);
	return 0;
}

SEC("raw_tp")
int in_loop_cond_break_ctx(void *ctx)
{
	struct loop_ctx c = {};

	out.cnt[0] = 0;
	bpf_loop(2, cb_cond_ctx, &c, 0);
	return 0;
}

SEC("raw_tp")
int in_loop_uncond_break(void *ctx)
{
	out.cnt[0] = 0;
	bpf_loop(2, cb_uncond, NULL, 0);
	return 0;
}

SEC("raw_tp")
int in_loop_cond_break(void *ctx)
{
	out.cnt[0] = 0;
	bpf_loop(2, cb_cond, NULL, 0);
	return 0;
}

static __always_inline void first_task(void)
{
	struct bpf_iter_task it;

	bpf_iter_task_new(&it, NULL, 0);
	if (bpf_iter_task_next(&it))
		out.cnt[0]++;
	bpf_iter_task_destroy(&it);
}

SEC("kprobe/do_nanosleep")
int type_kprobe(void *ctx) { first_task(); return 0; }

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int type_tracepoint(void *ctx) { first_task(); return 0; }

SEC("perf_event")
int type_perf_event(void *ctx) { first_task(); return 0; }

SEC("uprobe.s")
int type_sleepable(void *ctx) { first_task(); return 0; }

SEC("uprobe.s")
int type_sleepable_rcu(void *ctx)
{
	bpf_rcu_read_lock();
	first_task();
	bpf_rcu_read_unlock();
	return 0;
}
