// Task storage across fork, exec and threads, and task->self_exec_id.
#include "vm.h"
#include <pthread.h>
#include <sys/syscall.h>

static const char *steps[] = {
	"pid 1, first call", "pid 1, second call", "forked child", "forked child again",
	"child after exec", "new thread",
};

static void *thread(void *arg)
{
	syscall(SYS_getppid);
	return NULL;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct rec { __u32 tid, found, zeroed, pad; __u64 self_exec_id, stored_exec_id; } r;
	pthread_t th;
	pid_t pid;
	int fd;

	if (argc > 1) {
		syscall(SYS_getppid);
		return 0;
	}
	vm_init();
	obj = bpf_object__open_file("/test.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		printf("load failed: %s", vm_lib_log);
		vm_done();
	}
	prog = bpf_object__find_program_by_name(obj, "on_enter");
	if (!bpf_program__attach(prog)) {
		printf("attach failed\n");
		vm_done();
	}

	syscall(SYS_getppid);
	syscall(SYS_getppid);
	pid = fork();
	if (pid == 0) {
		syscall(SYS_getppid);
		syscall(SYS_getppid);
		execl("/init", "/init", "exec", NULL);
		_exit(1);
	}
	waitpid(pid, NULL, 0);
	pthread_create(&th, NULL, thread, NULL);
	pthread_join(th, NULL);

	fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "out"));
	printf("%-20s %5s %6s %7s %13s %15s\n", "step", "tid", "found", "zeroed", "self_exec_id", "stored_exec_id");
	for (__u32 i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
		if (bpf_map_lookup_elem(fd, &i, &r) || !r.tid) {
			printf("%-20s missing\n", steps[i]);
			continue;
		}
		printf("%-20s %5u %6u %7u %13llu %15llu\n", steps[i], r.tid, r.found, r.zeroed,
		       r.self_exec_id, r.stored_exec_id);
	}
	vm_done();
	return 0;
}
