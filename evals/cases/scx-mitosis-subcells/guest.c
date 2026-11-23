#define _GNU_SOURCE
#include "vm.h"
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <time.h>

struct g {
	int target;
	int refill;
	int custom;
	int drain;
	unsigned long long dsq_arg;
	long long mkdsq_ret;
	int after_error;
	unsigned long long running, stop_runnable, stop_sleep, runnable, quiet_sleep, quiet_other;
	unsigned long long refills, ticks, enq, enq_last, custom_enq;
	unsigned long long dispatch, dispatch_remote;
	unsigned long long cgid;
	int exit_kind;
	char exit_msg[128];
};

static struct g *g;
static struct bpf_object *obj;

static void reset(int target)
{
	g->target = 0;
	memset(&g->running, 0, (char *)&g->exit_kind - (char *)&g->running);
	g->target = target;
}

static void msleep(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

static void state(const char *when)
{
	char buf[32] = "?";
	int fd = open("/sys/kernel/sched_ext/state", O_RDONLY);

	if (fd >= 0) {
		buf[read(fd, buf, sizeof(buf) - 1)] = 0;
		close(fd);
	}
	buf[strcspn(buf, "\n")] = 0;
	printf("  sched_ext state %s: %s\n", when, buf);
}

static int run_prog(const char *name)
{
	struct bpf_program *p = bpf_object__find_program_by_name(obj, name);
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err = bpf_prog_test_run_opts(bpf_program__fd(p), &opts);

	return err ? err : (int)opts.retval;
}

static long long mkdsq(const char *prog, unsigned long long id)
{
	g->dsq_arg = id;
	g->mkdsq_ret = 12345;
	run_prog(prog);
	return g->mkdsq_ret;
}

static pid_t spawn(const char *comm, int cpu, int sleep_us, int core_cookie)
{
	pid_t pid = fork();

	if (pid)
		return pid;
	prctl(PR_SET_NAME, comm);
	if (cpu >= 0) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		sched_setaffinity(0, sizeof(set), &set);
	}
	if (core_cookie && prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, 0, 0, 0))
		printf("  PR_SCHED_CORE_CREATE: %s\n", strerror(errno));
	for (;;) {
		if (sleep_us) {
			for (volatile int i = 0; i < 20000; i++)
				;
			usleep(sleep_us);
		}
	}
}

static void stop(pid_t pid)
{
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

static void print_counts(const char *what)
{
	printf("  %-28s running %llu stopping(runnable) %llu stopping(sleep) %llu refills %llu ticks %llu enq %llu enq_last %llu\n",
	       what, g->running, g->stop_runnable, g->stop_sleep, g->refills, g->ticks, g->enq, g->enq_last);
}

static void write_file(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0 || write(fd, s, strlen(s)) < 0)
		printf("  write %s: %s\n", path, strerror(errno));
	if (fd >= 0)
		close(fd);
}

int main(void)
{
	struct bpf_link *link;
	struct bpf_map *ops, *bss;
	struct stat st;
	char buf[32];
	size_t sz;
	pid_t hog, sleeper, hogs[4];
	int err;

	vm_init();
	printf("cpus %ld\n", sysconf(_SC_NPROCESSORS_ONLN));
	mkdir("/sys/fs/cgroup", 0755);
	mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL);
	mkdir("/sys/fs/cgroup/probe", 0755);

	obj = bpf_object__open_file("/probe.bpf.o", NULL);
	err = obj ? bpf_object__load(obj) : -1;
	if (err) {
		printf("load failed: %d\n%s\n", err, vm_lib_log);
		vm_done();
	}
	ops = bpf_object__find_map_by_name(obj, "probe_ops");
	bss = bpf_object__find_map_by_name(obj, ".bss");
	g = bpf_map__initial_value(bss, &sz);

	err = bpf_program__assoc_struct_ops(bpf_object__find_program_by_name(obj, "mkdsq_assoc"), ops, NULL);
	printf("create_dsq from syscall prog (assoc_struct_ops: %s):\n", err ? strerror(-err) : "ok");
	printf("  before attach, id 1000:      %lld\n", mkdsq("mkdsq", 1000));
	printf("  before attach, assoc, 1001:  %lld\n", mkdsq("mkdsq_assoc", 1001));
	link = bpf_map__attach_struct_ops(ops);
	if (!link) {
		printf("attach failed: %s\n", strerror(errno));
		vm_done();
	}
	state("after attach");
	printf("  after attach, id 1000:       %lld\n", mkdsq("mkdsq", 1000));
	printf("  after attach, assoc, 1001:   %lld\n", mkdsq("mkdsq_assoc", 1001));
	printf("  after attach, id 1000 again: %lld\n", mkdsq("mkdsq", 1000));
	printf("  after attach, builtin bit:   %lld\n", mkdsq("mkdsq", (1ULL << 63) | 5));

	printf("solo hog pinned to cpu 3, 1s each:\n");
	hog = spawn("hog", 3, 0, 0);
	snprintf(buf, sizeof(buf), "%d", hog);
	write_file("/sys/fs/cgroup/probe/cgroup.procs", buf);
	msleep(200);
	g->refill = 1;
	reset(hog);
	msleep(1000);
	print_counts("dispatch refills slice:");
	g->refill = 0;
	reset(hog);
	msleep(1000);
	print_counts("no refill (ENQ_LAST):");
	stat("/sys/fs/cgroup/probe", &st);
	printf("  task cgroup kn->id %llu, cgroup dir inode %llu\n", g->cgid, (unsigned long long)st.st_ino);
	g->refill = 1;

	printf("5 hogs queued on DSQ 1000 created by syscall prog, 500ms:\n");
	for (int i = 0; i < 4; i++)
		hogs[i] = spawn("hog", -1, 0, 0);
	g->drain = g->custom = 1000;
	msleep(500);
	g->custom = 0;
	printf("  enqueued to DSQ 1000: %llu\n", g->custom_enq);
	state("after");
	for (int i = 0; i < 4; i++)
		stop(hogs[i]);
	stop(hog);
	sleeper = spawn("sleeper", -1, 500, 0);

	printf("sleeper (usleep 500), 1s:\n");
	reset(sleeper);
	msleep(1000);
	printf("  runnable %llu quiescent(sleep) %llu quiescent(other) %llu running %llu stopping(runnable) %llu stopping(sleep) %llu\n",
	       g->runnable, g->quiet_sleep, g->quiet_other, g->running, g->stop_runnable, g->stop_sleep);
	reset(sleeper);
	for (int i = 0; i < 200; i++) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(i % 2, &set);
		if (i % 3 == 0)
			CPU_SET(2, &set);
		sched_setaffinity(sleeper, sizeof(set), &set);
		usleep(1000);
	}
	printf("  200 sched_setaffinity calls: runnable %llu quiescent(sleep) %llu quiescent(other) %llu\n",
	       g->runnable, g->quiet_sleep, g->quiet_other);
	stop(sleeper);

	printf("dispatch(cpu) vs executing cpu, 4 unpinned hogs, 1s:\n");
	for (int cookie = 0; cookie < 2; cookie++) {
		for (int i = 0; i < 4; i++)
			hogs[i] = spawn("hog", -1, 50, cookie);
		msleep(100);
		reset(0);
		msleep(1000);
		printf("  %-22s dispatch %llu with cpu != executing cpu %llu\n",
		       cookie ? "own core-sched cookie:" : "no cookie:", g->dispatch, g->dispatch_remote);
		for (int i = 0; i < 4; i++)
			stop(hogs[i]);
	}

	printf("scx_bpf_error twice from a syscall prog:\n");
	run_prog("double_error");
	msleep(300);
	printf("  code after the calls ran: %d\n", g->after_error);
	printf("  exit kind %d, msg \"%s\"\n", g->exit_kind, g->exit_msg);
	state("after error");
	vm_done();
	return 0;
}
