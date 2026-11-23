#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define CALL(sec, name)                                                        \
	SEC(sec) int name(void *ctx)                                           \
	{                                                                      \
		return bpf_get_func_ip(ctx) ? 0 : 0;                           \
	}

CALL("kprobe/vfs_read", kprobe_prog)
CALL("kretprobe/vfs_read", kretprobe_prog)
CALL("fentry/vfs_read", fentry_prog)
CALL("fexit/vfs_read", fexit_prog)
CALL("tp_btf/sched_switch", tp_btf_prog)
CALL("raw_tp/sched_switch", raw_tp_prog)
CALL("tracepoint/syscalls/sys_enter_getpid", tracepoint_prog)
CALL("perf_event", perf_event_prog)
CALL("socket", socket_prog)
CALL("xdp", xdp_prog)
CALL("lsm/file_open", lsm_prog)
CALL("iter/task", iter_prog)
