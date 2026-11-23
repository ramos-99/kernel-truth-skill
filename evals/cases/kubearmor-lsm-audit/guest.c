#define _GNU_SOURCE
#include "vm.h"
#include "state.h"
#include <dirent.h>

static struct tstate *st;
static int events;

static int has_bpf_lsm(void)
{
	char buf[256] = "";
	int fd;

	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);
	fd = open("/sys/kernel/security/lsm", O_RDONLY);
	if (fd >= 0) {
		read(fd, buf, sizeof(buf) - 1);
		close(fd);
	}
	printf("active LSMs: %s\n", buf);
	return strstr(buf, "bpf") != NULL;
}

static void clear_pins(void)
{
	DIR *d = opendir("/sys/fs/bpf");
	struct dirent *e;
	char p[300];

	while (d && (e = readdir(d)))
		if (e->d_name[0] != '.') {
			snprintf(p, sizeof(p), "/sys/fs/bpf/%s", e->d_name);
			unlink(p);
		}
	if (d)
		closedir(d);
}

// KubeArmor's Go side creates this map of maps before loading its objects.
static void reset_pins(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, o);
	int inner, outer;

	clear_pins();
	inner = bpf_map_create(BPF_MAP_TYPE_HASH, "inner", 400, 4, 256, NULL);
	o.inner_map_fd = inner;
	outer = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "kubearmor_conta", 8, 4, 256, &o);
	if (bpf_obj_pin(outer, "/sys/fs/bpf/kubearmor_containers"))
		printf("pin kubearmor_containers: %s\n", strerror(errno));
	close(inner);
	close(outer);
}

// Loads every program of every KubeArmor object in /ka, one at a time.
static void load_kubearmor(void)
{
	DIR *d = opendir("/ka");
	struct dirent *e;
	char path[300];

	while (d && (e = readdir(d))) {
		struct bpf_object *obj;
		struct bpf_program *prog;
		int n = 0, bad = 0;

		if (!strstr(e->d_name, ".o"))
			continue;
		snprintf(path, sizeof(path), "/ka/%s", e->d_name);
		obj = bpf_object__open_file(path, NULL);
		if (!obj)
			continue;
		printf("-- %s\n", e->d_name);
		bpf_object__for_each_program(prog, obj) {
			reset_pins();
			n++;
			if (vm_load(path, bpf_program__name(prog)))
				bad++;
		}
		printf("   %d programs, %d rejected\n", n, bad);
		bpf_object__close(obj);
	}
	clear_pins();
	if (d)
		closedir(d);
}

static int on_event(void *ctx, void *data, size_t len)
{
	events++;
	return 0;
}

static void try_open(const char *what)
{
	int fd = open("/target", O_RDONLY);

	printf("%-28s open=%s", what, fd >= 0 ? "ok" : strerror(errno));
	if (fd >= 0)
		close(fd);
}

static struct bpf_link *attach(struct bpf_object *obj, const char *name)
{
	struct bpf_link *l = bpf_program__attach(bpf_object__find_program_by_name(obj, name));

	if (!l)
		printf("attach %s failed: %s\n", name, strerror(errno));
	return l;
}

// Child changes uid/gid and does what fn says once the parent has made it the target.
static void as_user(void (*fn)(void))
{
	int p[2];
	char c;
	pid_t pid;

	pipe(p);
	pid = fork();
	if (!pid) {
		read(p[0], &c, 1);
		setresgid(2000, 2000, 2000);
		setresuid(1000, 1000, 1000);
		fn();
		_exit(0);
	}
	st->target_tgid = pid;
	write(p[1], "x", 1);
	waitpid(pid, NULL, 0);
	close(p[0]);
	close(p[1]);
}

static void user_open(void)
{
	int fd = open("/target", O_RDONLY);

	printf("uid 1000 gid 2000 open=%s\n", fd >= 0 ? "ok" : strerror(errno));
}

static void user_mkdir(void)
{
	printf("uid 1000 mkdir /pub/new=%s\n", mkdir("/pub/new", 0755) ? strerror(errno) : "ok");
}

static void lsm_runtime(void)
{
	struct bpf_object *obj = bpf_object__open_file("/test.bpf.o", NULL);
	struct bpf_program *prog;
	struct ring_buffer *rb;
	struct bpf_link *obs, *gate, *mk;
	struct stat sb;
	size_t sz;
	const char *modes[] = { "allow", "audit", "block" };

	bpf_object__for_each_program(prog, obj) {
		const char *n = bpf_program__name(prog);

		bpf_program__set_autoload(prog, !strcmp(n, "gate") || !strcmp(n, "observer") ||
						!strcmp(n, "mkdir_probe"));
	}
	if (bpf_object__load(obj)) {
		printf("runtime load failed\n");
		return;
	}
	st = bpf_map__initial_value(bpf_object__find_map_by_name(obj, ".bss"), &sz);
	rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "rb"), on_event, NULL, NULL);

	close(open("/target", O_CREAT | O_WRONLY, 0644));
	stat("/target", &sb);
	st->target_ino = sb.st_ino;
	st->target_tgid = getpid();

	// observer is attached first, so it runs after gate.
	obs = attach(obj, "observer");
	gate = attach(obj, "gate");
	for (int m = 0; m < 3; m++) {
		st->mode = m;
		st->gate_runs = st->observer_runs = 0;
		st->gate_ret = st->observer_ret = 12345;
		events = 0;
		try_open(modes[m]);
		ring_buffer__consume(rb);
		printf(" gate_runs=%d gate_ret=%d events=%d observer_runs=%d observer_ret=%d\n",
		       st->gate_runs, st->gate_ret, events, st->observer_runs, st->observer_ret);
	}
	st->mode = 0;
	as_user(user_open);
	printf("bpf_get_current_uid_gid=0x%llx\n", st->uid_gid);

	mk = attach(obj, "mkdir_probe");
	mkdir("/pub", 0777);
	chmod("/pub", 0777);
	as_user(user_mkdir);
	printf("path_mkdir runs=%d negative_dentry=%d dentry_uid=%u parent_uid=%u uid_gid=0x%llx\n",
	       st->mkdir_runs, st->mkdir_negative, st->mkdir_uid, st->mkdir_parent_uid, st->uid_gid);
	bpf_link__destroy(mk);
	bpf_link__destroy(gate);
	bpf_link__destroy(obs);
	ring_buffer__free(rb);

	// Positive returns, only where the verifier accepts them.
	struct bpf_object *pobj = bpf_object__open_file("/test.bpf.o", NULL);

	bpf_object__for_each_program(prog, pobj)
		bpf_program__set_autoload(prog, !strcmp(bpf_program__name(prog), "pos_open") ||
						!strcmp(bpf_program__name(prog), "pos_exec"));
	if (bpf_object__load(pobj)) {
		printf("pos_open/pos_exec not loadable here\n");
		return;
	}
	struct tstate *ps = bpf_map__initial_value(bpf_object__find_map_by_name(pobj, ".bss"), &sz);
	struct bpf_link *l;

	ps->target_ino = sb.st_ino;
	ps->target_tgid = getpid();
	l = attach(pobj, "pos_open");
	try_open("file_open returns 1");
	printf("\n");
	bpf_link__destroy(l);

	l = attach(pobj, "pos_exec");
	int p[2];
	char c;
	pid_t pid;

	pipe(p);
	pid = fork();
	if (!pid) {
		read(p[0], &c, 1);
		char *argv[] = { "/init", "exit42", NULL };
		long r = execve("/init", argv, NULL);

		printf("bprm_check_security returns 1: execve returned %ld errno=%d\n", r, r < 0 ? errno : 0);
		_exit(0);
	}
	ps->target_tgid = pid;
	write(p[1], "x", 1);
	int status;

	waitpid(pid, &status, 0);
	printf("exec child exit status %d\n", WEXITSTATUS(status));
	bpf_link__destroy(l);
	bpf_object__close(pobj);
}

static void print_fork_format(void)
{
	char buf[4096] = "", *l;
	int fd = open("/sys/kernel/tracing/events/sched/sched_process_fork/format", O_RDONLY);

	if (fd < 0)
		return;
	read(fd, buf, sizeof(buf) - 1);
	close(fd);
	for (l = strtok(buf, "\n"); l; l = strtok(NULL, "\n"))
		if (strstr(l, "comm") || strstr(l, "_pid;"))
			printf("  %s\n", l + strspn(l, " \t"));
}

// Runs the merged process_monitor object's own programs.
static void process_monitor(const char *path)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int cfg, args, pids, p[2];
	unsigned int key = 6, one = 1, k, next;
	unsigned long long val = 0x1122334455667788ULL;
	char c;
	pid_t pid;

	reset_pins();
	obj = bpf_object__open_file(path, NULL);
	vm_lib_log[0] = 0;
	if (!obj || bpf_object__load(obj)) {
		printf("process_monitor load failed: %s\n", vm_lib_log);
		return;
	}
	bpf_object__for_each_program(prog, obj)
		if (!bpf_program__attach(prog))
			printf("attach %s failed: %s\n", bpf_program__name(prog), strerror(errno));
	cfg = bpf_object__find_map_fd_by_name(obj, "kubearmor_config");
	args = bpf_object__find_map_fd_by_name(obj, "kubearmor_args_store");
	pids = bpf_object__find_map_fd_by_name(obj, "kubearmor_exec_pids");
	bpf_map_update_elem(cfg, &key, &one, BPF_ANY);

	// Literal strings sit in pages the child never touched; stack copies are resident.
	for (int stack = 0; stack < 2; stack++) {
		pid = fork();
		if (!pid) {
			char a0[] = "/init", a1[] = "argtest", a2[] = "hello";
			char *lit[] = { "/init", "argtest", "hello", NULL };
			char *stk[] = { a0, a1, a2, NULL };

			execve("/init", stack ? stk : lit, NULL);
			_exit(1);
		}
		waitpid(pid, NULL, 0);
		struct { unsigned long long tgid, ind; } ak, an, *ap = NULL;
		char v[4096];

		printf("execve argv from %s:", stack ? "stack" : "literals");
		while (!bpf_map_get_next_key(args, ap, &an)) {
			ak = an;
			ap = &ak;
			if ((ak.tgid >> 32) == (unsigned)pid && !bpf_map_lookup_elem(args, &ak, v))
				printf(" [%llu]=\"%s\"", ak.ind, v);
		}
		printf("\n");
	}

	print_fork_format();
	k = getpid();
	bpf_map_update_elem(pids, &k, &val, BPF_ANY);
	pipe(p);
	pid = fork();
	if (!pid) {
		read(p[0], &c, 1);
		_exit(0);
	}
	usleep(100000);
	printf("forked child pid %d; exec_pids entries:\n", pid);
	unsigned int *kp = NULL;

	while (!bpf_map_get_next_key(pids, kp, &next)) {
		k = next;
		kp = &k;
		bpf_map_lookup_elem(pids, &k, &val);
		printf("  key=%u (0x%x) value=0x%llx%s\n", k, k, val, k == (unsigned)pid ? "  <- child" : "");
	}
	write(p[1], "x", 1);
	waitpid(pid, NULL, 0);
	bpf_object__close(obj);
	clear_pins();
}

int main(int argc, char **argv)
{
	if (getpid() != 1)
		return argc > 1 && !strcmp(argv[1], "exit42") ? 42 : 0;

	vm_init();
	mkdir("/sys/fs/bpf", 0755);
	mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL);
	int bpf_lsm = has_bpf_lsm();

	printf("== verifier: own programs\n");
	vm_load("/test.bpf.o", "code_leak");
	vm_load("/test.bpf.o", "code_mapped");
	vm_load("/test.bpf.o", "ret_prev");
	vm_load("/test.bpf.o", "pos_open");
	vm_load("/test.bpf.o", "pos_exec");
	printf("== verifier: KubeArmor objects\n");
	load_kubearmor();
	if (bpf_lsm) {
		printf("== runtime\n");
		lsm_runtime();
	} else {
		printf("== runtime skipped, bpf not in active LSMs\n");
	}
	DIR *d = opendir("/ka");
	struct dirent *e;
	char path[300];

	while (d && (e = readdir(d)))
		if (strstr(e->d_name, "process_monitor.bpf.o")) {
			snprintf(path, sizeof(path), "/ka/%s", e->d_name);
			printf("== %s\n", e->d_name);
			process_monitor(path);
		}
	if (d)
		closedir(d);
	vm_done();
	return 0;
}
