// Starts tetragon with /policy.yaml, then runs /t/targets once per line of
// /scenarios ("<expected exit> <mode>") and prints the exit codes.
#include "vm.h"
#include <signal.h>
#include <time.h>

static char tg_log[1 << 20];

static int log_has(const char *s)
{
	int fd = open("/tmp/tg.log", O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return 0;
	n = read(fd, tg_log, sizeof(tg_log) - 1);
	close(fd);
	tg_log[n > 0 ? n : 0] = 0;
	return strstr(tg_log, s) != NULL;
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int run_target(const char *mode)
{
	pid_t pid = fork();
	double end = now() + 15;
	int st;

	if (pid == 0) {
		execl("/t/targets", "/t/targets", mode, NULL);
		_exit(253);
	}
	while (waitpid(pid, &st, WNOHANG) == 0) {
		if (now() > end) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			return -1;
		}
		usleep(10000);
	}
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

int main(void)
{
	char mode[64], line[128];
	int want, got, loaded = 0, st;
	double start;
	FILE *f;
	pid_t tg;

	vm_init();
	mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL);
	mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL);
	mkdir("/tmp", 01777);
	mkdir("/run", 0755);

	tg = fork();
	if (tg == 0) {
		int fd = open("/tmp/tg.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);

		dup2(fd, 1);
		dup2(fd, 2);
		setenv("PATH", "/bin", 1);
		execl("/tetragon", "/tetragon", "--bpf-lib", "/bpf/",
		      "--tracing-policy", "/policy.yaml",
		      "--server-address", "", "--health-server-address", "",
		      "--export-filename", "/tmp/events.json", NULL);
		_exit(1);
	}
	start = now();
	while (now() - start < 80) {
		if (log_has("Added TracingPolicy with success")) {
			loaded = 1;
			break;
		}
		if (waitpid(tg, &st, WNOHANG) == tg) {
			tg = 0;
			break;
		}
		usleep(200000);
	}
	printf("policy %s after %.0fs\n", loaded ? "loaded" : "NOT loaded", now() - start);

	f = fopen("/scenarios", "r");
	while (loaded && f && fscanf(f, "%d %63s", &want, mode) == 2) {
		got = run_target(mode);
		printf("%-10s exit %3d, want %3d  %s\n", mode, got, want, got == want ? "ok" : "FAIL");
	}

	if (tg > 0) {
		kill(tg, SIGTERM);
		waitpid(tg, NULL, 0);
	}
	log_has("");
	for (char *l = strtok(tg_log, "\n"); l; l = strtok(NULL, "\n"))
		if (strstr(l, "level=error") || strstr(l, "level=fatal"))
			printf("  log: %.300s\n", l);
	vm_done();
	return 0;
}
