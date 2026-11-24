// Runs /bpftrace -e on each script and prints all of its output. grade/check
// decides the verdict. Copy bpftrace and its libraries in with VM_EXTRA.
//
// Before the scripts run, this process (pid 1) starts NTHREADS extra threads
// that sleep in short syscalls. That gives the guest one multi-threaded
// process, so iter_task and iter_threads must give different counts, and the
// tp_task_threads script can catch one of those threads in a tracepoint and
// count its thread group.
//
// Every script except control runs twice: as written, and again as NAME:s0
// with on_stack_limit = 0, which moves all variables to scratch maps. The
// iterator state must stay on the stack, so the second pass catches state that
// gets moved with them.
//
// A script that runs past PER_SCRIPT seconds is killed and reported as exit 124.
// Once BUDGET seconds have gone by, the rest are reported as exit 124 without
// running, so a hanging bpftrace still reaches === DONE before the VM timeout.
#include "vm.h"
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#define NTHREADS 8
#define PER_SCRIPT 8
#define BUDGET 85

// GUESTPID in a script is replaced by this process's pid.
static const char *progs[][2] = {
	{ "control", "begin { $n = 0; for ($i : 0..3) { $n++; } print($n); }" },
	{ "prompt", "begin { $n = 0; for ($t : iter_threads()) { $n++; } if ($n > 1) { print($n); } }" },
	{ "counts", "begin { $p = 0; for ($t : iter_task()) { $p++; } $h = 0; for ($t : iter_threads()) { $h++; } printf(\"procs %d threads %d\\n\", $p, $h); }" },
	{ "task_threads", "begin { $n = 0; $me = 0; for ($t : iter_task_threads(curtask)) { $n++; if ($t == curtask) { $me = 1; } } printf(\"threads %d me %d\\n\", $n, $me); }" },
	{ "tp_task_threads", "tracepoint:raw_syscalls:sys_enter /pid == GUESTPID/ { $n = 0; $same = 0; for ($t : iter_task_threads(curtask)) { $n++; if ($t->tgid == GUESTPID) { $same++; } } printf(\"threads %d same %d\\n\", $n, $same); exit(); }" },
	{ "break", "begin { $n = 0; for ($t : iter_task()) { $n++; if ($n == 2) { break; } } print($n); }" },
	{ "continue", "begin { $seen = 0; for ($t : iter_task()) { if ($t->pid != GUESTPID) { continue; } $seen = 1; } print($seen); }" },
	{ "return", "begin { for ($t : iter_task()) { if ($t->pid == GUESTPID) { return; } } print(\"end\"); }" },
	{ "map_write", "begin { for ($t : iter_task()) { if ($t->pid == GUESTPID) { @[$t->pid] = 1; } } print(@); clear(@); }" },
	{ "loop_local", "begin { $n = 0; for ($t : iter_threads()) { $x = $t->pid; let $y = $x + 1; $y++; if ($y == $x + 2) { $n++; } } if ($n > 1) { print(\"ok\"); } }" },
	{ "vma", "begin { for ($v : iter_task_vma(curtask)) { if ($v->vm_end > $v->vm_start) { print(\"ok\"); break; } } }" },
	{ "vma_addr", "begin { $n = 0; $first = (uint64)0; $last = (uint64)0; for ($v : iter_task_vma(curtask)) { if ($n == 0) { $first = $v->vm_end; } $n++; $last = $v->vm_start; } $a = 0; for ($v : iter_task_vma(curtask, $first)) { $a++; } $b = 0; for ($v : iter_task_vma(curtask, $last)) { $b++; } printf(\"all %d from_second %d from_last %d\\n\", $n, $a, $b); }" },
	{ "tp_vma_irqs_off", "tracepoint:sched:sched_switch { $n = 0; for ($v : iter_task_vma(curtask)) { $n++; } printf(\"ran %d\\n\", $n); exit(); }" },
	{ "nested_iter", "begin { $c = 0; for ($t : iter_task()) { for ($v : iter_task_vma($t)) { $c++; break; } } if ($c > 0) { print(\"ok\"); } }" },
	{ "range_cond_break", "begin { $n = 0; for ($i : 0..2) { for ($t : iter_task()) { $n++; if ($n > 0) { break; } } } print($n); }" },
	{ "range_uncond_break", "begin { $n = 0; for ($i : 0..2) { for ($t : iter_task()) { $n++; break; } } print($n); }" },
};

static void *sleeper(void *arg)
{
	for (;;)
		usleep(20000);
	return arg;
}

static void count_proc(long *procs, long *threads)
{
	DIR *d = opendir("/proc"), *t;
	struct dirent *e, *te;
	char path[64];

	*procs = *threads = 0;
	while ((e = readdir(d))) {
		if (e->d_name[0] < '1' || e->d_name[0] > '9')
			continue;
		(*procs)++;
		snprintf(path, sizeof(path), "/proc/%s/task", e->d_name);
		if (!(t = opendir(path)))
			continue;
		while ((te = readdir(t)))
			if (te->d_name[0] != '.')
				(*threads)++;
		closedir(t);
	}
	closedir(d);
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static double start;

static void run(const char *name, const char *pre, const char *fmt)
{
	static char buf[1 << 16];
	char prog[2048];
	int fd[2], status, code;
	ssize_t len = 0, r;
	pid_t pid, me = getpid();
	double deadline;
	struct pollfd pfd;

	if (now() - start > BUDGET) {
		printf("### %s exit 124\n    (not run, time budget used up)\n", name);
		return;
	}
	char *o = prog + sprintf(prog, "%s", pre);
	for (const char *p = fmt; *p && o < prog + sizeof(prog) - 16; )
		if (!strncmp(p, "GUESTPID", 8)) {
			o += sprintf(o, "%d", me);
			p += 8;
		} else
			*o++ = *p++;
	*o = 0;
	pipe(fd);
	pid = fork();
	if (!pid) {
		dup2(fd[1], 1);
		dup2(fd[1], 2);
		execl("/bpftrace", "bpftrace", "-e", prog, NULL);
		_exit(127);
	}
	close(fd[1]);
	deadline = now() + PER_SCRIPT;
	pfd.fd = fd[0];
	pfd.events = POLLIN;
	code = -1;
	for (;;) {
		int left = (deadline - now()) * 1000;

		if (left <= 0 || poll(&pfd, 1, left) == 0) {
			kill(pid, SIGKILL);
			code = 124;
			break;
		}
		r = read(fd[0], buf + len, sizeof(buf) - 1 - len);
		if (r <= 0)
			break;
		len += r;
	}
	buf[len] = 0;
	close(fd[0]);
	waitpid(pid, &status, 0);
	if (code < 0)
		code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	printf("### %s exit %d\n", name, code);
	for (char *l = strtok(buf, "\n"); l; l = strtok(NULL, "\n"))
		if (strncmp(l, "Attached", 8))
			printf("    %.300s\n", l);
}

int main(void)
{
	long procs, threads;
	pthread_t th;

	vm_init();
	mkdir("/tmp", 01777);
	symlink("/proc/self/fd", "/dev/fd");
	setenv("PATH", "/", 1);
	setenv("HOME", "/tmp", 1);
	for (int i = 0; i < NTHREADS; i++)
		pthread_create(&th, NULL, sleeper, NULL);
	usleep(200000);
	count_proc(&procs, &threads);
	printf("/proc: %ld processes, %ld threads, pid %d, extra threads %d\n",
	       procs, threads, getpid(), NTHREADS);
	start = now();
	for (size_t i = 0; i < sizeof(progs) / sizeof(*progs); i++)
		run(progs[i][0], "", progs[i][1]);
	for (size_t i = 1; i < sizeof(progs) / sizeof(*progs); i++) {
		char name[64];

		snprintf(name, sizeof(name), "%s:s0", progs[i][0]);
		run(name, "config = { on_stack_limit = 0 } ", progs[i][1]);
	}
	vm_done();
	return 0;
}
