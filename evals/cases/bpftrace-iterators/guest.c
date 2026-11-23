#define _GNU_SOURCE
#include "vm.h"
#include <dirent.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sys/syscall.h>

struct out {
	long ret[8];
	long cnt[8];
};

static void *idle_thread(void *arg)
{
	pause();
	return NULL;
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
		t = opendir(path);
		while (t && (te = readdir(t)))
			if (te->d_name[0] != '.')
				(*threads)++;
		if (t)
			closedir(t);
	}
	closedir(d);
}

// Prints the verifier's last lines, without instructions or the 7.x explanation.
static void print_tail(void)
{
	char *lines[4] = { 0 };
	int n = 0, skip = 0;

	for (char *l = strtok(vm_log, "\n"); l; l = strtok(NULL, "\n")) {
		if (strstr(l, "verifier bug")) {
			printf("    %.150s\n", l);
			continue;
		}
		if (!strncmp(l, "Verification failed", 19) || !strncmp(l, "Suggestion:", 11))
			skip = 1;
		if (skip || !strncmp(l, "processed ", 10) || strchr("0123456789;", l[0]) || strstr(l, " | "))
			continue;
		lines[n++ % 4] = l;
	}
	for (int i = n > 4 ? n - 4 : 0; i < n; i++)
		printf("    %.150s\n", lines[i % 4]);
}

// Loads one program and, unless load_only, runs it and returns its output.
// Returns -1 if it didn't load.
static int run(const char *name, struct out *o, int load_only)
{
	struct bpf_object *obj = bpf_object__open_file("/test.bpf.o", NULL);
	struct bpf_program *prog, *p = NULL;
	struct bpf_map *m;
	int zero = 0, err;

	bpf_object__for_each_program(prog, obj) {
		int match = !strcmp(bpf_program__name(prog), name);

		bpf_program__set_autoload(prog, match);
		if (match)
			p = prog;
	}
	vm_log[0] = vm_lib_log[0] = 0;
	bpf_program__set_log_buf(p, vm_log, sizeof(vm_log));
	bpf_program__set_log_level(p, 1);
	err = bpf_object__load(obj);
	if (err) {
		printf("%-24s REJECT errno %d\n", name, -err);
		print_tail();
		for (char *l = strtok(vm_lib_log, "\n"); l; l = strtok(NULL, "\n"))
			if (strstr(l, "extern"))
				printf("    libbpf: %.110s\n", l);
		bpf_object__close(obj);
		return -1;
	}
	if (load_only) {
		printf("%-24s LOAD\n", name);
		bpf_object__close(obj);
		return 0;
	}
	if (bpf_program__type(p) == BPF_PROG_TYPE_RAW_TRACEPOINT) {
		LIBBPF_OPTS(bpf_test_run_opts, opts);
		err = bpf_prog_test_run_opts(bpf_program__fd(p), &opts);
		if (err)
			printf("%-24s test_run failed: %s\n", name, strerror(errno));
	} else {
		struct bpf_link *l = bpf_program__attach(p);

		usleep(500000);
		bpf_link__destroy(l);
	}
	memset(o, 0, sizeof(*o));
	bpf_object__for_each_map(m, obj)
		if (strstr(bpf_map__name(m), ".bss"))
			bpf_map_lookup_elem(bpf_map__fd(m), &zero, o);
	bpf_object__close(obj);
	return 0;
}

static const char *load_only[] = {
	"vma_untrusted", "stack_counter_branch", "stack_counter_store", "map_counter_branch",
	"no_destroy_on_fail", "state_in_map", "state_misaligned", "in_loop_cond_break",
	"type_kprobe", "type_tracepoint", "type_perf_event", "type_sleepable", "type_sleepable_rcu",
};

int main(void)
{
	struct out o;
	pthread_t th;
	long procs, threads;

	vm_init();
	pthread_create(&th, NULL, idle_thread, NULL);
	usleep(100000);
	count_proc(&procs, &threads);
	printf("/proc: %ld processes, %ld threads, this process has 2 threads\n", procs, threads);

	if (!run("task_modes", &o, 0))
		for (int i = 0; i < 5; i++)
			printf("task_modes flags=%d task=%s: ret %ld, %ld tasks\n", i == 4 ? 3 : i < 3 ? i : 2,
			       i == 2 ? "curtask" : "NULL", o.ret[i], o.cnt[i]);
	if (!run("vma_current", &o, 0))
		printf("vma_current: ret %ld, %ld vmas\n", o.ret[0], o.cnt[0]);
	if (!run("vma_irqs_off", &o, 0))
		printf("vma_irqs_off: ok %ld, EBUSY %ld, ENOENT %ld, other %ld\n", o.cnt[0], o.cnt[1], o.cnt[2], o.cnt[3]);
	if (!run("nested_iter", &o, 0))
		printf("nested_iter: ok %ld, ENOENT %ld, other %ld, with a first vma %ld\n", o.cnt[0], o.cnt[1], o.cnt[2], o.cnt[3]);
	if (!run("loop_local", &o, 0))
		printf("loop_local: %ld\n", o.cnt[0]);
	if (!run("in_loop_uncond_break", &o, 0))
		printf("in_loop_uncond_break: %ld\n", o.cnt[0]);
	if (!run("in_loop_uncond_break_ctx", &o, 0))
		printf("in_loop_uncond_break_ctx: %ld\n", o.cnt[0]);
	if (!run("in_loop_cond_break_ctx", &o, 0))
		printf("in_loop_cond_break_ctx: %ld\n", o.cnt[0]);
	for (size_t i = 0; i < sizeof(load_only) / sizeof(*load_only); i++)
		run(load_only[i], &o, 1);
	vm_done();
	return 0;
}
