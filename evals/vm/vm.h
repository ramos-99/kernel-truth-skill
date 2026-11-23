// Shared setup for test programs that run as PID 1 in a throwaway VM.
#ifndef VM_H
#define VM_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
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

static char vm_lib_log[8192];
static char vm_log[1 << 20];

static int vm_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	size_t n = strlen(vm_lib_log);

	if (level != LIBBPF_DEBUG && n < sizeof(vm_lib_log) - 1)
		vsnprintf(vm_lib_log + n, sizeof(vm_lib_log) - n, fmt, args);
	return 0;
}

static void vm_init(void)
{
	struct rlimit inf = { RLIM_INFINITY, RLIM_INFINITY };
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
	libbpf_set_print(vm_print);
	uname(&u);
	printf("\n=== KERNEL %s\n", u.release);
}

static void vm_done(void)
{
	printf("=== DONE\n");
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
}

static void vm_print_log_tail(void)
{
	char *lines[3] = { 0 };
	int n = 0;

	for (char *l = strtok(vm_log, "\n"); l; l = strtok(NULL, "\n"))
		if (strncmp(l, "processed ", 10) != 0)
			lines[n++ % 3] = l;
	for (int i = n > 3 ? n - 3 : 0; i < n; i++)
		printf("    %s\n", lines[i % 3]);
}

// Loads one program from an object, without attaching it, and prints the result.
static int vm_load(const char *path, const char *name)
{
	struct bpf_object *obj = bpf_object__open_file(path, NULL);
	struct bpf_program *prog;
	int err;

	if (!obj) {
		printf("%-24s can't open %s\n", name, path);
		return -1;
	}
	bpf_object__for_each_program(prog, obj) {
		int match = !strcmp(bpf_program__name(prog), name);

		bpf_program__set_autoload(prog, match);
		if (match) {
			vm_log[0] = 0;
			bpf_program__set_log_buf(prog, vm_log, sizeof(vm_log));
			bpf_program__set_log_level(prog, 1);
		}
	}
	vm_lib_log[0] = 0;
	err = bpf_object__load(obj);
	printf("%-24s %s\n", name, err ? "REJECT" : "LOAD");
	if (err) {
		printf("    errno %d (%s)\n", -err, strerror(-err));
		vm_print_log_tail();
		for (char *l = strtok(vm_lib_log, "\n"); l; l = strtok(NULL, "\n"))
			if (strstr(l, "relo") && !strstr(l, "failed to load"))
				printf("    libbpf: %.110s\n", l);
	}
	bpf_object__close(obj);
	return err;
}

#endif
