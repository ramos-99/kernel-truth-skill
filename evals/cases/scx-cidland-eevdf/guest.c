#define _GNU_SOURCE
#include "vm.h"
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <sys/klog.h>
#include <sys/syscall.h>

#define NBUCKET 16

struct rec {
	__u32 enable_weight, setw_calls, setw_weight, custom_slice;
	__u64 setw_load_weight, se_slice;
	__u64 wakeups, wake_slice_nonzero, wake_slice_sum;
	__u64 stops, stops_slice_zero;
	__u64 run_start, runs[NBUCKET];
};

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static void spin_for(double secs)
{
	double end = now() + secs;

	while (now() < end)
		;
}

static int setattr(int policy, int nice, __u64 runtime)
{
	struct sched_attr a = { .size = sizeof(a), .sched_policy = policy,
				.sched_nice = nice, .sched_runtime = runtime };

	return syscall(SYS_sched_setattr, 0, &a, 0);
}

static const char *read_str(const char *path, char *buf, int n)
{
	int fd = open(path, O_RDONLY), len;

	buf[0] = 0;
	if (fd < 0)
		return "(none)";
	len = read(fd, buf, n - 1);
	close(fd);
	buf[len > 0 ? len : 0] = 0;
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = 0;
	return buf;
}

static void write_str(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0 || write(fd, s, strlen(s)) < 0)
		printf("    write %s=%s failed: %s\n", path, s, strerror(errno));
	if (fd >= 0)
		close(fd);
}

/* --- verifier loop tests --- */

static void loop_tests(void)
{
	const char *progs[] = { "plain", "volatile_step", "rodata_step", "unknown_start", "iter_num" };

	printf("-- loops (may_goto counter tracking)\n");
	for (int i = 0; i < 5; i++)
		vm_load("/loops.bpf.o", progs[i]);
}

/* --- sched_ext micro tests with a small scheduler --- */

static int watch_fd, cfg_fd;

static pid_t start_watched(void (*fn)(void *), void *arg)
{
	int p[2];
	pid_t pid;
	struct rec r = {};
	char c;

	pipe(p);
	pid = fork();
	if (!pid) {
		close(p[1]);
		read(p[0], &c, 1);
		fn(arg);
		_exit(0);
	}
	close(p[0]);
	bpf_map_update_elem(watch_fd, &pid, &r, BPF_ANY);
	write(p[1], "g", 1);
	close(p[1]);
	return pid;
}

static void get_rec(pid_t pid, struct rec *r)
{
	waitpid(pid, NULL, 0);
	memset(r, 0, sizeof(*r));
	bpf_map_lookup_elem(watch_fd, &pid, r);
}

struct wcase { const char *name; int policy, nice; __u64 runtime; };

static void do_setattr(void *arg)
{
	struct wcase *w = arg;

	if (setattr(w->policy, w->nice, w->runtime))
		printf("    setattr %s: %s\n", w->name, strerror(errno));
}

static void sleeper(void *arg)
{
	for (int i = 0; i < 5; i++) {
		spin_for(0.003);
		usleep(5000);
	}
}

static void yielder(void *arg)
{
	double end = now() + 0.2;

	pin(1);
	while (now() < end)
		sched_yield();
}

static void hog(void *arg)
{
	pin(1);
	spin_for(0.4);
}

static void slice_run(__u64 slice_ns)
{
	__u32 zero = 0;
	struct rec r1, r2;
	pid_t a, b;
	long n = 0, tot = 0, peak = 0, peak_b = 0;

	bpf_map_update_elem(cfg_fd, &zero, &slice_ns, BPF_ANY);
	a = start_watched(hog, NULL);
	b = start_watched(hog, NULL);
	get_rec(a, &r1);
	get_rec(b, &r2);
	for (int i = 0; i < NBUCKET; i++) {
		long c = r1.runs[i] + r2.runs[i];

		n += c;
		tot += c * (i * 250 + 125);
		if (c > peak) {
			peak = c;
			peak_b = i;
		}
	}
	printf("slice %4lluus: %ld preempted runs, mean %ldus, mode %ld-%ldus\n",
	       (unsigned long long)slice_ns / 1000, n, n ? tot / n : 0,
	       peak_b * 250, peak_b * 250 + 250);
	slice_ns = 0;
	bpf_map_update_elem(cfg_fd, &zero, &slice_ns, BPF_ANY);
}

static void scx_tests(void)
{
	struct wcase w[] = {
		{ "nice 0",          SCHED_NORMAL, 0, 0 },
		{ "nice 19",         SCHED_NORMAL, 19, 0 },
		{ "nice -20",        SCHED_NORMAL, -20, 0 },
		{ "SCHED_IDLE",      SCHED_IDLE, 0, 0 },
		{ "runtime 3ms",     SCHED_NORMAL, 0, 3000000 },
		{ "runtime 20us",    SCHED_NORMAL, 0, 20000 },
		{ "runtime 500ms",   SCHED_NORMAL, 0, 500000000 },
		{ "SCHED_EXT 3ms",   SCHED_EXT, 0, 3000000 },
	};
	struct bpf_object *obj;
	struct bpf_link *link;
	struct rec r;
	struct timespec res;
	char buf[128];
	pid_t pid;

	printf("-- sched_ext micro tests\n");
	obj = bpf_object__open_file("/scx.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		printf("test scheduler load failed: %s\n", vm_lib_log);
		return;
	}
	watch_fd = bpf_object__find_map_fd_by_name(obj, "watch");
	cfg_fd = bpf_object__find_map_fd_by_name(obj, "cfg");
	link = bpf_map__attach_struct_ops(bpf_object__find_map_by_name(obj, "t_ops"));
	if (!link) {
		printf("attach failed: %s\n%s\n", strerror(errno), vm_lib_log);
		return;
	}
	printf("state %s, ops %s\n", read_str("/sys/kernel/sched_ext/state", buf, sizeof(buf)),
	       read_str("/sys/kernel/sched_ext/root/ops", buf + 64, 64));

	for (unsigned i = 0; i < sizeof(w) / sizeof(w[0]); i++) {
		pid = start_watched(do_setattr, &w[i]);
		get_rec(pid, &r);
		printf("%-14s set_weight calls %u weight %u, se.load.weight %llu, custom_slice %u se.slice %llu\n",
		       w[i].name, r.setw_calls, r.setw_weight,
		       (unsigned long long)r.setw_load_weight, r.custom_slice,
		       (unsigned long long)r.se_slice);
	}

	pid = start_watched(sleeper, NULL);
	get_rec(pid, &r);
	printf("sleeper (run 3ms, sleep 5ms, default slice 20ms): %llu wakeups, %llu with slice left, mean %lluus\n",
	       (unsigned long long)r.wakeups, (unsigned long long)r.wake_slice_nonzero,
	       (unsigned long long)(r.wakeups ? r.wake_slice_sum / r.wakeups / 1000 : 0));

	pid = fork();
	if (!pid) {
		hog(NULL);
		_exit(0);
	}
	usleep(20000);
	pid_t y = start_watched(yielder, NULL);
	get_rec(y, &r);
	waitpid(pid, NULL, 0);
	printf("yielder beside a hog, no ops.yield: %llu stops, %llu with slice 0\n",
	       (unsigned long long)r.stops, (unsigned long long)r.stops_slice_zero);

	clock_getres(CLOCK_MONOTONIC_COARSE, &res);
	printf("CLOCK_MONOTONIC_COARSE resolution %ldns\n", res.tv_nsec);
	slice_run(100000);
	slice_run(700000);
	slice_run(1000000);
	slice_run(2500000);

	bpf_link__destroy(link);
	bpf_object__close(obj);
	usleep(100000);
	printf("after detach: state %s\n", read_str("/sys/kernel/sched_ext/state", buf, sizeof(buf)));
}

/* --- workloads, run under EEVDF and under scx_cidland --- */

struct job { int nice, policy, yield; const char *cgroup; };

static pid_t run_job(struct job *j, double secs)
{
	pid_t pid = fork();

	if (pid)
		return pid;
	pin(1);
	if (j->cgroup) {
		char path[128], s[16];

		snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.procs", j->cgroup);
		snprintf(s, sizeof(s), "%d", getpid());
		write_str(path, s);
	}
	if (j->policy == SCHED_IDLE)
		setattr(SCHED_IDLE, 0, 0);
	else
		setpriority(PRIO_PROCESS, 0, j->nice);
	double end = now() + secs;
	while (now() < end)
		if (j->yield)
			sched_yield();
	_exit(0);
}

static double cpu_secs(pid_t pid)
{
	struct rusage ru;

	wait4(pid, NULL, 0, &ru);
	return ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 +
	       ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
}

static void pair(const char *name, struct job a, struct job b, double secs)
{
	pid_t pa = run_job(&a, secs), pb = run_job(&b, secs);
	double ca = cpu_secs(pa), cb = cpu_secs(pb);

	printf("%-28s %6.3fs vs %6.3fs  ratio %8.2f\n", name, ca, cb, cb > 0 ? ca / cb : 0);
}

static void workloads(const char *label)
{
	printf("-- workloads under %s (two tasks pinned to CPU 1)\n", label);
	pair("nice 0 vs nice 6", (struct job){ 0 }, (struct job){ 6 }, 3);
	pair("nice 0 vs nice 19", (struct job){ 0 }, (struct job){ 19 }, 3);
	pair("nice -20 vs nice 19", (struct job){ -20 }, (struct job){ 19 }, 7);
	pair("nice 0 vs SCHED_IDLE", (struct job){ 0 }, (struct job){ .policy = SCHED_IDLE }, 3);
	pair("nice 19 vs SCHED_IDLE", (struct job){ 19 }, (struct job){ .policy = SCHED_IDLE }, 3);
	pair("spinner vs yielder", (struct job){ 0 }, (struct job){ .yield = 1 }, 3);
	pair("cpu.weight 400 vs 100", (struct job){ .cgroup = "b" }, (struct job){ .cgroup = "a" }, 3);
}


static void setup_cgroups(void)
{
	mkdir("/sys/fs/cgroup", 0755);
	if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL))
		printf("cgroup2 mount failed: %s\n", strerror(errno));
	write_str("/sys/fs/cgroup/cgroup.subtree_control", "+cpu");
	mkdir("/sys/fs/cgroup/a", 0755);
	mkdir("/sys/fs/cgroup/b", 0755);
	write_str("/sys/fs/cgroup/a/cpu.weight", "100");
	write_str("/sys/fs/cgroup/b/cpu.weight", "400");
}

static void print_klog(const char *needle)
{
	static char log[1 << 17];
	int n = klogctl(3, log, sizeof(log) - 1);

	if (n <= 0)
		return;
	log[n] = 0;
	for (char *l = strtok(log, "\n"); l; l = strtok(NULL, "\n"))
		if (strstr(l, needle))
			printf("    klog: %.200s\n", l);
}

static void cidland(void)
{
	char buf[128], ops[64];
	pid_t pid;
	int fd, i;

	pid = fork();
	if (!pid) {
		char *argv[16] = { "/scx_cidland" };
		int n = 1;
		static char args[256];

		fd = open("/cidland.args", O_RDONLY);
		if (fd >= 0) {
			int len = read(fd, args, sizeof(args) - 1);

			close(fd);
			args[len > 0 ? len : 0] = 0;
			for (char *t = strtok(args, " \n"); t && n < 15; t = strtok(NULL, " \n"))
				argv[n++] = t;
		}
		fd = open("/cidland.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
		dup2(fd, 1);
		dup2(fd, 2);
		execv(argv[0], argv);
		_exit(127);
	}
	for (i = 0; i < 100; i++) {
		if (!strcmp(read_str("/sys/kernel/sched_ext/state", buf, sizeof(buf)), "enabled"))
			break;
		usleep(100000);
	}
	printf("-- scx_cidland: state %s, ops %s\n", buf,
	       read_str("/sys/kernel/sched_ext/root/ops", ops, sizeof(ops)));
	if (strcmp(buf, "enabled"))
		goto out;
	workloads("scx_cidland");
	printf("after workloads: state %s, ops %s\n",
	       read_str("/sys/kernel/sched_ext/state", buf, sizeof(buf)),
	       read_str("/sys/kernel/sched_ext/root/ops", ops, sizeof(ops)));
out:
	kill(pid, SIGINT);
	waitpid(pid, NULL, 0);
	print_klog("sched_ext");
	fd = open("/cidland.log", O_RDONLY);
	if (fd >= 0) {
		static char log[1 << 24];
		int n = 0, r, k = 0, shown = 0;
		char *lines[12] = { 0 };

		while ((r = read(fd, log + n, sizeof(log) - 1 - n)) > 0)
			n += r;
		close(fd);
		log[n] = 0;
		printf("scx_cidland log, errors:\n");
		for (char *l = strtok(log, "\n"); l; l = strtok(NULL, "\n")) {
			lines[k++ % 12] = l;
			if (shown < 40 && (strstr(l, "rror") || strstr(l, "fail") ||
					   strstr(l, "nvalid") || strstr(l, "-22") ||
					   strstr(l, "too ") || strstr(l, "EXIT")))
				printf("    %.200s\n", l), shown++;
		}
		printf("scx_cidland log tail:\n");
		for (i = k > 12 ? k - 12 : 0; i < k; i++)
			printf("    %.200s\n", lines[i % 12]);
	}
}

int main(void)
{
	char buf[64];

	vm_init();
	printf("sched_ext state: %s\n", read_str("/sys/kernel/sched_ext/state", buf, sizeof(buf)));
	loop_tests();
	scx_tests();
	setup_cgroups();
	if (access("/scx_cidland", X_OK) == 0) {
		workloads("EEVDF");
		cidland();
	}
	vm_done();
	return 0;
}
