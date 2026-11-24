// Grading workloads for scx_cidland. Runs as init in the VM.
// Starts /scx_cidland with the arguments in /cidland.args (see adapter),
// runs the workloads and prints one line per measurement for grade/check.
// If /eevdf exists, the same workloads run first under the kernel's own
// scheduler, for reference only.
#define _GNU_SOURCE
#include "vm.h"
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static double cpu_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void pin_mask(unsigned mask)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	for (int i = 0; i < 32; i++)
		if (mask & (1u << i))
			CPU_SET(i, &set);
	sched_setaffinity(0, sizeof(set), &set);
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

/* --- tasks --- */

enum kind { SPIN, YIELD, BURST, PERIODIC };

struct job {
	int nice, policy;
	__u64 runtime;		/* sched_attr.sched_runtime, 0 = default */
	enum kind kind;
	double burst, nap;	/* BURST: cpu seconds, then sleep seconds */
};

static void apply(struct job *j)
{
	if (setattr(j->policy, j->policy == SCHED_IDLE ? 0 : j->nice, j->runtime))
		printf("    sched_setattr: %s\n", strerror(errno));
}

static pid_t run_job(struct job *j, double secs)
{
	pid_t pid = fork();

	if (pid)
		return pid;
	pin_mask(1 << 1);
	apply(j);
	double end = now() + secs;
	while (now() < end) {
		if (j->kind == YIELD) {
			sched_yield();
		} else if (j->kind == BURST) {
			double c = cpu_now() + j->burst;

			while (cpu_now() < c && now() < end)
				;
			usleep(j->nap * 1e6);
		}
	}
	_exit(0);
}

struct use { double cpu; long nivcsw, nvcsw; };

static struct use reap(pid_t pid)
{
	struct rusage ru;
	struct use u;

	wait4(pid, NULL, 0, &ru);
	u.cpu = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 +
		ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
	u.nivcsw = ru.ru_nivcsw;
	u.nvcsw = ru.ru_nvcsw;
	return u;
}

/* Two tasks on CPU 1. Prints "name: a vs b ratio R" and the switch counts. */
static void pair(const char *name, struct job a, struct job b, double secs)
{
	pid_t pa = run_job(&a, secs), pb = run_job(&b, secs);
	struct use ua = reap(pa), ub = reap(pb);

	printf("pair %-28s| %6.3fs vs %6.3fs  csw %ld/%ld  ratio %8.2f\n", name,
	       ua.cpu, ub.cpu, ua.nivcsw, ub.nivcsw, ub.cpu > 0 ? ua.cpu / ub.cpu : 0);
}

/*
 * Runs per second of each task in a pair, from involuntary context
 * switches: shows how long a task keeps the CPU per turn.
 */
static void runs(const char *name, struct job j, double secs)
{
	pid_t pa = run_job(&j, secs), pb = run_job(&j, secs);
	struct use ua = reap(pa), ub = reap(pb);

	printf("runs %-28s| %6.3fs %6.3fs  switches/s %8.1f\n", name, ua.cpu, ub.cpu,
	       (ua.nivcsw + ub.nivcsw) / secs);
}

static int cmp_d(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return x < y ? -1 : x > y;
}

/*
 * Wakeup latency: a task on CPU 1 beside a spinning @hog sleeps 1ms, runs
 * 100us of CPU and repeats. Prints how late it got the CPU after each
 * timer, median and 90th percentile in microseconds.
 */
#define NWAKE 300
static void latency(const char *name, struct job hog, struct job w)
{
	static double lat[NWAKE];
	int p[2];
	pid_t h, s;

	pipe(p);
	h = run_job(&hog, 0.2 + NWAKE * 0.0013 + 0.5);
	s = fork();
	if (!s) {
		close(p[0]);
		pin_mask(1 << 1);
		apply(&w);
		prctl(PR_SET_TIMERSLACK, 1);
		usleep(100000);
		for (int i = 0; i < NWAKE; i++) {
			struct timespec ts;
			double due, c;

			clock_gettime(CLOCK_MONOTONIC, &ts);
			due = ts.tv_sec + ts.tv_nsec / 1e9 + 0.001;
			ts.tv_nsec += 1000000;
			if (ts.tv_nsec >= 1000000000) {
				ts.tv_sec++;
				ts.tv_nsec -= 1000000000;
			}
			clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
			lat[i] = (now() - due) * 1e6;
			c = cpu_now() + 0.0001;
			while (cpu_now() < c)
				;
		}
		write(p[1], lat, sizeof(lat));
		_exit(0);
	}
	close(p[1]);
	for (size_t got = 0; got < sizeof(lat);) {
		ssize_t r = read(p[0], (char *)lat + got, sizeof(lat) - got);

		if (r <= 0)
			break;
		got += r;
	}
	close(p[0]);
	waitpid(s, NULL, 0);
	reap(h);
	qsort(lat, NWAKE, sizeof(double), cmp_d);
	printf("lat  %-28s| median %7.0fus  p90 %7.0fus\n", name,
	       lat[NWAKE / 2], lat[NWAKE * 9 / 10]);
}

/*
 * Wakeup CPU selection: a hog spins on CPU 1, CPUs 2 and 3 are idle. A
 * task is moved onto CPU 1, allowed on 1-3 again and put to sleep, so it
 * wakes with a busy previous CPU and two idle ones. Prints how many
 * wakeups ran on an idle CPU rather than behind the hog.
 */
#define NMOVE 100
static void wake_cpu(const char *name)
{
	struct job hog = { 0 };
	int p[2], away = 0;
	pid_t h, s;

	pipe(p);
	h = run_job(&hog, 0.2 + NMOVE * 0.004 + 1.0);
	s = fork();
	if (!s) {
		close(p[0]);
		usleep(100000);
		for (int i = 0; i < NMOVE; i++) {
			pin_mask(1 << 1);
			sched_yield();
			pin_mask(0xe);
			usleep(2000);
			away += sched_getcpu() != 1;
			double c = cpu_now() + 0.0002;
			while (cpu_now() < c)
				;
		}
		write(p[1], &away, sizeof(away));
		_exit(0);
	}
	close(p[1]);
	if (read(p[0], &away, sizeof(away)) != sizeof(away))
		away = -1;
	close(p[0]);
	waitpid(s, NULL, 0);
	reap(h);
	printf("wake %-28s| %d of %d on an idle cpu  ratio %8.2f\n", name, away, NMOVE,
	       (double)away / NMOVE);
}

static void workloads(const char *label)
{
	struct job n0 = { 0 }, idle = { .policy = SCHED_IDLE };

	printf("-- workloads under %s\n", label);
	/* weights */
	pair("nice 0 vs nice 6", n0, (struct job){ 6 }, 2);
	pair("nice 0 vs nice 19", n0, (struct job){ 19 }, 2);
	pair("nice 17 vs nice 18", (struct job){ 17 }, (struct job){ 18 }, 2);
	pair("nice 18 vs nice 19", (struct job){ 18 }, (struct job){ 19 }, 2);
	pair("nice 19 vs SCHED_IDLE", (struct job){ 19 }, idle, 2);
	/* yield */
	pair("spinner vs yielder", n0, (struct job){ .kind = YIELD }, 2);
	/* lag across sleeps */
	pair("spinner vs burst 1ms/50us", n0,
	     (struct job){ .kind = BURST, .burst = 0.001, .nap = 0.00005 }, 2);
	pair("nice 5 vs burst 1ms/50us", (struct job){ 5 },
	     (struct job){ .kind = BURST, .burst = 0.001, .nap = 0.00005 }, 2);
	pair("spinner vs burst 3ms/5ms", n0,
	     (struct job){ .kind = BURST, .burst = 0.003, .nap = 0.005 }, 2);
	/* sched_runtime */
	runs("default request", n0, 1.5);
	runs("request 100ms", (struct job){ .runtime = 100000000 }, 1.5);
	runs("request 20ms", (struct job){ .runtime = 20000000 }, 1.5);
	/* wakeup preemption */
	latency("waker beside nice 0", n0, n0);
	latency("waker beside SCHED_IDLE", idle, n0);
	latency("waker beside 20ms request", (struct job){ .runtime = 20000000 }, n0);
	/* wakeup cpu selection */
	wake_cpu("busy prev, idle siblings");
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
	printf("loaded: %s\n", buf);
	if (strcmp(buf, "enabled"))
		goto out;
	workloads("scx_cidland");
	printf("after workloads: %s\n", read_str("/sys/kernel/sched_ext/state", buf, sizeof(buf)));
	printf("ops: %s\n", read_str("/sys/kernel/sched_ext/root/ops", ops, sizeof(ops)));
out:
	kill(pid, SIGINT);
	waitpid(pid, NULL, 0);
	fd = open("/cidland.log", O_RDONLY);
	if (fd >= 0) {
		static char log[1 << 22];
		int n = 0, r, k = 0;
		char *lines[30] = { 0 };

		while ((r = read(fd, log + n, sizeof(log) - 1 - n)) > 0)
			n += r;
		close(fd);
		log[n] = 0;
		for (char *l = strtok(log, "\n"); l; l = strtok(NULL, "\n"))
			lines[k++ % 30] = l;
		printf("scx_cidland log tail:\n");
		for (i = k > 30 ? k - 30 : 0; i < k; i++)
			printf("    %.200s\n", lines[i % 30]);
	}
}

int main(void)
{
	char buf[64];

	vm_init();
	printf("cpus: %ld, sched_ext state: %s\n", sysconf(_SC_NPROCESSORS_ONLN),
	       read_str("/sys/kernel/sched_ext/state", buf, sizeof(buf)));
	printf("llc of cpu1: %s\n",
	       read_str("/sys/devices/system/cpu/cpu1/cache/index3/shared_cpu_list", buf, sizeof(buf)));
	if (access("/eevdf", F_OK) == 0)
		workloads("EEVDF");
	if (access("/scx_cidland", X_OK) == 0)
		cidland();
	else
		printf("loaded: no /scx_cidland\n");
	vm_done();
	return 0;
}
