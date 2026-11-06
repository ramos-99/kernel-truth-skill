#define _GNU_SOURCE
#include "vm.h"
#include <linux/perf_event.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>

struct stats {
	unsigned long long runs, first_ok, first_busy, first_other, second_ok, second_busy, second_other;
};

static pid_t start_workload(void)
{
	pid_t pid = fork();

	if (!pid) {
		prctl(PR_SET_NAME, "vmatest");
		for (unsigned long i = 0;; i++) {
			syscall(SYS_getpid);
			if (!(i & 0xfff))
				usleep(100);
		}
	}
	return pid;
}

static int perf_open(pid_t pid, int type, int config)
{
	struct perf_event_attr a = {
		.size = sizeof(a), .type = type, .config = config,
		.freq = 1, .sample_freq = 1000, .disabled = 0,
	};

	return syscall(SYS_perf_event_open, &a, pid, -1, -1, 0);
}

static void phase(struct bpf_object *obj, int map, const char *name, int idx, int type, int config)
{
	struct bpf_program *p = bpf_object__find_program_by_name(obj, name);
	struct bpf_link *link;
	struct stats st[4] = {};
	int key = 0, pfd = -1;
	pid_t w = start_workload();

	if (type >= 0) {
		pfd = perf_open(w, type, config);
		if (pfd < 0) {
			printf("%-18s perf_event_open failed: %s\n", name, strerror(errno));
			kill(w, SIGKILL);
			waitpid(w, NULL, 0);
			return;
		}
		link = bpf_program__attach_perf_event(p, pfd);
	} else {
		link = bpf_program__attach(p);
	}
	if (!link) {
		printf("%-18s attach failed: %s\n", name, strerror(errno));
	} else {
		sleep(2);
		bpf_link__destroy(link);
		bpf_map_lookup_elem(map, &key, st);
		printf("%-18s runs=%llu first: ok=%llu ebusy=%llu other=%llu  second: ok=%llu ebusy=%llu other=%llu\n",
		       name, st[idx].runs, st[idx].first_ok, st[idx].first_busy, st[idx].first_other,
		       st[idx].second_ok, st[idx].second_busy, st[idx].second_other);
	}
	if (pfd >= 0)
		close(pfd);
	kill(w, SIGKILL);
	waitpid(w, NULL, 0);
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_map *m, *bss = NULL;

	vm_init();
	obj = bpf_object__open_file("/test.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		printf("load failed: %s\n", vm_lib_log[0] ? "see below" : "");
		printf("%.400s\n", vm_lib_log);
		vm_done();
		return 0;
	}
	bpf_object__for_each_map(m, obj)
		if (strstr(bpf_map__name(m), ".bss"))
			bss = m;
	phase(obj, bpf_map__fd(bss), "plain_context", 0, -1, 0);
	phase(obj, bpf_map__fd(bss), "perf_hw", 1, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
	phase(obj, bpf_map__fd(bss), "perf_sw", 2, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
	phase(obj, bpf_map__fd(bss), "irqs_off_no_nmi", 3, -1, 0);
	vm_done();
	return 0;
}
