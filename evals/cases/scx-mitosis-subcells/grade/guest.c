#define _GNU_SOURCE
#include "vm.h"
#include <signal.h>
#include <sys/prctl.h>
#include <time.h>

#define NGROUPS 3
static const char *names[NGROUPS] = { "worker-a", "worker-b", "worker-c" };
static const int counts[NGROUPS] = { 6, 1, 1 };
static pid_t workers[NGROUPS][8];

static void msleep(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

static void cat(const char *path)
{
	char buf[256] = "";
	int fd = open(path, O_RDONLY), n = -1;

	if (fd >= 0) {
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
	}
	buf[n > 0 ? n : 0] = 0;
	buf[strcspn(buf, "\n")] = 0;
	printf("%s: %s\n", path, fd < 0 ? strerror(errno) : buf);
}

static void write_file(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0 || write(fd, s, strlen(s)) < 0)
		printf("write %s: %s\n", path, strerror(errno));
	if (fd >= 0)
		close(fd);
}

static pid_t spawn(const char *comm)
{
	pid_t pid = fork();

	if (pid)
		return pid;
	prctl(PR_SET_NAME, comm);
	for (;;)
		;
}

static pid_t churn(void)
{
	char path[64];
	pid_t pid = fork();

	if (pid)
		return pid;
	prctl(PR_SET_NAME, "churn");
	mkdir("/sys/fs/cgroup/churn", 0755);
	for (int i = 0;; i++) {
		snprintf(path, sizeof(path), "/sys/fs/cgroup/churn/c%d", i % 8);
		mkdir(path, 0755);
		rmdir(path);
	}
}

static int task_cpu(pid_t pid)
{
	char path[64], buf[1024], *p;
	int fd, n, field = 2;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	p = strrchr(buf, ')');
	for (; p && *p; p++)
		if (*p == ' ' && ++field == 39)
			return atoi(p + 1);
	return -1;
}

static pid_t start_scheduler(void)
{
	static char line[64][256];
	char *argv[66] = { "/sched" };
	int argc = 1;
	FILE *f = fopen("/cmd", "r");
	pid_t pid;

	while (f && argc < 64 && fgets(line[argc], sizeof(line[argc]), f)) {
		line[argc][strcspn(line[argc], "\n")] = 0;
		argv[argc] = line[argc];
		argc++;
	}
	argv[argc] = NULL;
	printf("scheduler:");
	for (int i = 0; i < argc; i++)
		printf(" %s", argv[i]);
	printf("\n");
	pid = fork();
	if (!pid) {
		execv("/sched", argv);
		printf("exec: %s\n", strerror(errno));
		_exit(127);
	}
	return pid;
}

int main(void)
{
	unsigned long long seen[NGROUPS][64] = {};
	char buf[32];
	pid_t sched, churner;
	int status;

	vm_init();
	printf("cpus %ld\n", sysconf(_SC_NPROCESSORS_ONLN));
	mkdir("/tmp", 01777);
	mkdir("/sys/fs/cgroup", 0755);
	mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL);
	mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL);
	write_file("/sys/fs/cgroup/cgroup.subtree_control", "+cpuset +cpu");
	mkdir("/sys/fs/cgroup/workload.slice", 0755);

	for (int g = 0; g < NGROUPS; g++)
		for (int i = 0; i < counts[g]; i++) {
			workers[g][i] = spawn(names[g]);
			snprintf(buf, sizeof(buf), "%d", workers[g][i]);
			write_file("/sys/fs/cgroup/workload.slice/cgroup.procs", buf);
		}

	sched = start_scheduler();
	churner = churn();
	msleep(4000);
	cat("/sys/kernel/sched_ext/state");
	cat("/sys/kernel/sched_ext/root/ops");

	for (int s = 0; s < 60; s++) {
		for (int g = 0; g < NGROUPS; g++)
			for (int i = 0; i < counts[g]; i++) {
				int cpu = task_cpu(workers[g][i]);

				if (cpu >= 0 && cpu < 64)
					seen[g][cpu]++;
			}
		msleep(100);
	}

	printf("worker cpus over 6s (cpu:samples):\n");
	for (int g = 0; g < NGROUPS; g++) {
		printf("  %s x%d:", names[g], counts[g]);
		for (int c = 0; c < 64; c++)
			if (seen[g][c])
				printf(" %d:%llu", c, seen[g][c]);
		printf("\n");
	}

	kill(churner, SIGKILL);
	cat("/sys/kernel/sched_ext/state");
	printf("scheduler still running: %s\n", waitpid(sched, &status, WNOHANG) == 0 ? "yes" : "no");
	kill(sched, SIGINT);
	for (int i = 0; i < 30 && waitpid(sched, &status, WNOHANG) == 0; i++)
		msleep(100);
	printf("scheduler exit status %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	vm_done();
	return 0;
}
