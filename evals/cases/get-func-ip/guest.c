#include "vm.h"
#include <linux/bpf.h>

static const struct {
	const char *name;
	enum bpf_prog_type type;
} types[] = {
	{ "kprobe", BPF_PROG_TYPE_KPROBE },
	{ "tracepoint", BPF_PROG_TYPE_TRACEPOINT },
	{ "raw_tracepoint", BPF_PROG_TYPE_RAW_TRACEPOINT },
	{ "perf_event", BPF_PROG_TYPE_PERF_EVENT },
	{ "socket_filter", BPF_PROG_TYPE_SOCKET_FILTER },
	{ "xdp", BPF_PROG_TYPE_XDP },
	{ "tracing", BPF_PROG_TYPE_TRACING },
};

int main(void)
{
	static const char *progs[] = {
		"kprobe_prog", "kretprobe_prog", "fentry_prog", "fexit_prog", "tp_btf_prog",
		"raw_tp_prog", "tracepoint_prog", "perf_event_prog", "socket_prog", "xdp_prog",
		"lsm_prog", "iter_prog",
	};

	vm_init();
	printf("real load:\n");
	for (size_t i = 0; i < sizeof(progs) / sizeof(progs[0]); i++)
		vm_load("/test.bpf.o", progs[i]);

	printf("libbpf_probe_bpf_helper, libbpf %s (1 = says supported):\n", libbpf_version_string());
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
		printf("  %-16s %d\n", types[i].name,
		       libbpf_probe_bpf_helper(types[i].type, BPF_FUNC_get_func_ip, NULL));
	vm_done();
	return 0;
}
