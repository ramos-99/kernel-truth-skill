#define _GNU_SOURCE
#include "vm.h"
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

static int load_prog(enum bpf_prog_type type)
{
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};

	return bpf_prog_load(type, NULL, "GPL", insns, 2, NULL);
}

static void raw_tp(const char *what, const char *name, int prog)
{
	int fd = bpf_raw_tracepoint_open(name, prog);

	printf("  raw tracepoint, %-26s %s\n", what, fd < 0 ? strerror(errno) : "ok");
	if (fd >= 0)
		close(fd);
}

static void regular_tp(const char *group, const char *name)
{
	char path[128], buf[32] = {};
	struct perf_event_attr a = { .size = sizeof(a), .type = PERF_TYPE_TRACEPOINT, .sample_period = 1 };
	int prog = load_prog(BPF_PROG_TYPE_TRACEPOINT), id, pfd;

	snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/id", group, name);
	id = open(path, O_RDONLY);
	if (id < 0 || read(id, buf, sizeof(buf) - 1) <= 0) {
		printf("  regular tracepoint, %-22s no such event\n", name);
		return;
	}
	close(id);
	a.config = atoi(buf);
	pfd = syscall(SYS_perf_event_open, &a, -1, 0, -1, 0);
	if (pfd < 0) {
		printf("  regular tracepoint, %-22s perf_event_open: %s\n", name, strerror(errno));
		return;
	}
	printf("  regular tracepoint, %-22s %s\n", name,
	       ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog) ? strerror(errno) : "ok");
	close(pfd);
}

static void insmod(const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		printf("  insmod %-30s not found\n", path);
		return;
	}
	if (syscall(SYS_finit_module, fd, "", 0)) {
		// MODULE_INIT_COMPRESSED_FILE, for compressed modules on newer kernels.
		if (syscall(SYS_finit_module, fd, "", 4))
			printf("  insmod %-30s %s\n", path, strerror(errno));
	}
	close(fd);
}

static void kallsyms_check(const char *sym)
{
	char line[256];
	FILE *f = fopen("/proc/kallsyms", "r");
	int found = 0;

	while (f && fgets(line, sizeof(line), f))
		if (strstr(line, sym))
			found = 1;
	if (f)
		fclose(f);
	printf("  kallsyms has %-24s %s\n", sym, found ? "yes" : "no");
}

int main(void)
{
	int prog;

	vm_init();
	prog = load_prog(BPF_PROG_TYPE_RAW_TRACEPOINT);
	if (prog < 0) {
		printf("raw tracepoint program load failed: %s\n", strerror(errno));
		vm_done();
		return 0;
	}
	kallsyms_check("bpf_trace_modules");
	printf("before loading kvm:\n");
	raw_tp("sched_switch (built in)", "sched_switch", prog);
	raw_tp("kvm_exit", "kvm_exit", prog);

	insmod("/irqbypass.ko");
	insmod("/kvm.ko");

	printf("after loading kvm:\n");
	raw_tp("kvm_exit", "kvm_exit", prog);
	regular_tp("kvm", "kvm_exit");
	vm_done();
	return 0;
}
