#define _GNU_SOURCE
#include "vm.h"
#include <linux/capability.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int tp_id;

static void set_caps(unsigned long long caps)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2] = {};

	d[0].effective = d[0].permitted = (unsigned)caps;
	d[1].effective = d[1].permitted = (unsigned)(caps >> 32);
	syscall(SYS_capset, &h, d);
}

static int perf(int type, unsigned long long config, int pid, int cpu, int exclude_kernel)
{
	struct perf_event_attr a = {
		.size = sizeof(a), .type = type, .config = config,
		.sample_period = 1000000, .exclude_kernel = exclude_kernel,
	};

	return syscall(SYS_perf_event_open, &a, pid, cpu, -1, 0);
}

static const char *result(int fd)
{
	if (fd < 0)
		return strerror(errno);
	close(fd);
	return "ok";
}

static void tests(void)
{
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	int prog, tp;

	printf(" own_user=%-24s", result(perf(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, 0, -1, 1)));
	printf(" own_kernel=%-24s", result(perf(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, 0, -1, 0)));
	tp = perf(PERF_TYPE_TRACEPOINT, tp_id, -1, 0, 0);
	printf(" tracepoint=%-24s", tp < 0 ? strerror(errno) : "ok");
	prog = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "GPL", insns, 2, NULL);
	printf(" bpf_load=%-24s", prog < 0 ? strerror(errno) : "ok");
	if (tp >= 0 && prog >= 0)
		printf(" attach=%s", ioctl(tp, PERF_EVENT_IOC_SET_BPF, prog) ? strerror(errno) : "ok");
	printf("\n");
}

static void scenario(const char *name, unsigned long long caps)
{
	pid_t c;

	printf("  %-22s", name);
	fflush(stdout);
	c = fork();
	if (!c) {
		prctl(PR_SET_KEEPCAPS, 1);
		if (setresuid(1000, 1000, 1000))
			_exit(1);
		set_caps(caps);
		tests();
		fflush(NULL);
		_exit(0);
	}
	waitpid(c, NULL, 0);
}

static void write_str(const char *path, const char *v)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0 || write(fd, v, strlen(v)) < 0)
		printf("  write %s=%s failed: %s\n", path, v, strerror(errno));
	if (fd >= 0)
		close(fd);
}

int main(void)
{
	static const char *levels[] = { "2", "3", "4" };
	char buf[32] = {};
	int fd;

	vm_init();
	fd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
	if (fd >= 0 && read(fd, buf, sizeof(buf) - 1) > 0)
		printf("default perf_event_paranoid: %s", buf);
	if (fd >= 0)
		close(fd);
	fd = open("/sys/kernel/tracing/events/sched/sched_switch/id", O_RDONLY);
	memset(buf, 0, sizeof(buf));
	if (fd >= 0 && read(fd, buf, sizeof(buf) - 1) > 0)
		tp_id = atoi(buf);
	if (fd >= 0)
		close(fd);

	for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
		printf("perf_event_paranoid=%s\n", levels[i]);
		write_str("/proc/sys/kernel/perf_event_paranoid", levels[i]);
		scenario("no caps", 0);
		scenario("CAP_PERFMON", 1ULL << CAP_PERFMON);
		scenario("CAP_BPF+CAP_PERFMON", (1ULL << CAP_BPF) | (1ULL << CAP_PERFMON));
		scenario("CAP_SYS_ADMIN", 1ULL << CAP_SYS_ADMIN);
	}
	vm_done();
	return 0;
}
