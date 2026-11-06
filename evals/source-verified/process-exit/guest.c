// Runs as PID 1 inside a throwaway VM. Also the workload, when given an argument.
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

struct key { unsigned hook, tid; };
struct val { unsigned tgid; int ctx_pid; unsigned long long mm, start_code; int live, group_dead; };

static const char *hook_name[] = { "?", "tracepoint", "fentry_taskstats", "kprobe_acct", "exec", "tp_group_dead" };

#define RACE_THREADS 8
#define RACE_PROCS 200

static pthread_barrier_t barrier;

static void *late_worker(void *arg)
{
	usleep(300000);
	return NULL;
}

static void *race_worker(void *arg)
{
	pthread_barrier_wait(&barrier);
	return NULL;
}

static int workload(const char *mode)
{
	pthread_t t;

	if (!strcmp(mode, "single"))
		return 0;
	if (!strcmp(mode, "leader")) {
		pthread_create(&t, NULL, late_worker, NULL);
		pthread_exit(NULL);
	}
	pthread_barrier_init(&barrier, NULL, RACE_THREADS + 1);
	for (int i = 0; i < RACE_THREADS; i++)
		pthread_create(&t, NULL, race_worker, NULL);
	pthread_barrier_wait(&barrier);
	pthread_exit(NULL);
}

static pid_t run(const char *mode)
{
	pid_t pid = fork();

	if (!pid) {
		execl("/exitwork", "/exitwork", mode, NULL);
		_exit(127);
	}
	waitpid(pid, NULL, 0);
	return pid;
}

static void show_events(int fd, pid_t tgid)
{
	struct key k, next;
	struct val v;
	void *prev = NULL;

	while (!bpf_map_get_next_key(fd, prev, &next)) {
		k = next;
		prev = &k;
		if (bpf_map_lookup_elem(fd, &k, &v) || v.tgid != (unsigned)tgid)
			continue;
		printf("  %-17s tid=%-5u tid_is_tgid=%d ctx_pid=%-5d mm=%s start_code=0x%llx live=%d group_dead=%d\n",
		       hook_name[k.hook], k.tid, k.tid == v.tgid, v.ctx_pid,
		       v.mm ? "set " : "NULL", v.start_code, v.live, v.group_dead);
	}
}

static void race_tally(int fd, pid_t *tgids)
{
	int live_one = 0, live_many = 0, live_none = 0;
	int arg_one = 0, arg_other = 0, gd_one = 0, gd_other = 0, extra_lines = 0;

	for (int i = 0; i < RACE_PROCS; i++) {
		struct key k, next;
		struct val v;
		void *prev = NULL;
		int live0 = 0, arg = 0, gd = 0;

		while (!bpf_map_get_next_key(fd, prev, &next)) {
			k = next;
			prev = &k;
			if (bpf_map_lookup_elem(fd, &k, &v) || v.tgid != (unsigned)tgids[i])
				continue;
			if (k.hook == 1 && v.live == 0)
				live0++;
			if (k.hook == 5 && v.group_dead == 1)
				gd++;
			if (k.hook == 2 && v.group_dead)
				arg++;
		}
		if (live0 == 1)
			live_one++;
		else if (live0 > 1)
			live_many++, extra_lines += live0 - 1;
		else
			live_none++;
		if (arg == 1)
			arg_one++;
		else
			arg_other++;
		if (gd == 1)
			gd_one++;
		else
			gd_other++;
	}
	printf("  tracepoint, signal->live==0: exactly one thread in %d processes, several in %d (%d extra lines), none in %d\n",
	       live_one, live_many, extra_lines, live_none);
	printf("  tracepoint, group_dead field==1: exactly one in %d, otherwise %d\n", gd_one, gd_other);
	printf("  fentry taskstats_exit group_dead arg: exactly one in %d, otherwise %d\n", arg_one, arg_other);
}

static int vprint(enum libbpf_print_level l, const char *f, va_list a)
{
	return l == LIBBPF_DEBUG ? 0 : vprintf(f, a);
}

static void show_format(void)
{
	char buf[2048];
	int fd = open("/sys/kernel/tracing/events/sched/sched_process_exit/format", O_RDONLY);
	ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof(buf) - 1);

	if (n <= 0) {
		printf("format: unreadable\n");
		return;
	}
	buf[n] = 0;
	for (char *l = strtok(buf, "\n"); l; l = strtok(NULL, "\n"))
		if (strstr(l, "field:") && !strstr(l, "common_"))
			printf("format:%s\n", l);
}

static void guest_main(void)
{
	static pid_t tgids[RACE_PROCS];
	struct rlimit inf = { RLIM_INFINITY, RLIM_INFINITY };
	struct bpf_object *obj;
	struct bpf_program *p;
	struct utsname u;
	int fd;

	mkdir("/dev", 0755);
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, NULL);
	mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL);
	fd = open("/dev/console", O_RDWR);
	if (fd >= 0) {
		dup2(fd, 1);
		dup2(fd, 2);
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	setrlimit(RLIMIT_MEMLOCK, &inf);
	libbpf_set_print(vprint);

	uname(&u);
	printf("\n=== KERNEL %s\n", u.release);
	printf("btf: %s\n", access("/sys/kernel/btf/vmlinux", R_OK) ? "missing" : "present");
	show_format();

	obj = bpf_object__open_file("/probe.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		printf("LOAD FAILED\n");
		return;
	}
	bpf_object__for_each_program(p, obj) {
		printf("attach %-18s %s\n", bpf_program__name(p),
		       bpf_program__attach(p) ? "ok" : "FAILED");
	}
	fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));

	printf("--- single-threaded process\n");
	show_events(fd, run("single"));
	printf("--- main thread exits first, worker exits last\n");
	show_events(fd, run("leader"));
	printf("--- %d processes, %d threads each, exiting together\n", RACE_PROCS, RACE_THREADS + 1);
	for (int i = 0; i < RACE_PROCS; i++)
		tgids[i] = run("race");
	race_tally(fd, tgids);
	printf("=== DONE\n");
}

int main(int argc, char **argv)
{
	if (argc > 1)
		return workload(argv[1]);
	guest_main();
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
