#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define VECS 10

struct vec_state {
	__u64 raised_at;
	__u32 pending_raises;
	__u32 in_handler;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, VECS);
	__type(key, __u32);
	__type(value, struct vec_state);
} states SEC(".maps");

struct totals {
	__u64 raises, entries, entry_no_raise;
	__u64 raise_newer_than_entry, raised_twice_before_entry, raised_during_handler;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, VECS);
	__type(key, __u32);
	__type(value, struct totals);
} counts SEC(".maps");

SEC("tp_btf/softirq_raise")
int BPF_PROG(on_raise, unsigned int vec)
{
	struct vec_state *s = bpf_map_lookup_elem(&states, &vec);
	struct totals *t = bpf_map_lookup_elem(&counts, &vec);

	if (!s || !t)
		return 0;
	t->raises++;
	if (s->in_handler)
		t->raised_during_handler++;
	else if (s->pending_raises)
		t->raised_twice_before_entry++;
	s->pending_raises++;
	s->raised_at = bpf_ktime_get_ns();
	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(on_entry, unsigned int vec)
{
	__u64 ts = bpf_ktime_get_ns();
	struct vec_state *s = bpf_map_lookup_elem(&states, &vec);
	struct totals *t = bpf_map_lookup_elem(&counts, &vec);

	if (!s || !t)
		return 0;
	t->entries++;
	if (!s->pending_raises)
		t->entry_no_raise++;
	if (s->raised_at > ts)
		t->raise_newer_than_entry++;
	s->pending_raises = 0;
	s->in_handler = 1;
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(on_exit, unsigned int vec)
{
	struct vec_state *s = bpf_map_lookup_elem(&states, &vec);

	if (s)
		s->in_handler = 0;
	return 0;
}
