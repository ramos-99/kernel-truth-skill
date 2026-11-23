#define _GNU_SOURCE
#include "vm.h"

#define RULE_EXEC 1
#define RULE_READ 4
#define RULE_WRITE 2
#define RULE_DENY 128

struct key { char path[200], source[200]; };
struct val { unsigned short processmask, filemask; };

static struct bpf_object *obj;
static int outer, audit_bit = 1 << 10, nev;
static long long last_ret;
static unsigned last_id;

static int on_event(void *ctx, void *data, size_t len)
{
	nev++;
	last_id = *(unsigned *)(data + 36);
	last_ret = *(long long *)(data + 40);
	return 0;
}

static void set_rule(const char *path, struct val v)
{
	unsigned long long okey = 0;
	struct key k = {};
	int inner = bpf_map_create(BPF_MAP_TYPE_HASH, "inner", 400, 4, 256, NULL);

	strcpy(k.path, path);
	bpf_map_update_elem(inner, &k, &v, BPF_ANY);
	bpf_map_update_elem(outer, &okey, &inner, BPF_ANY);
	close(inner);
}

static void report(const char *what, const char *result, struct ring_buffer *rb)
{
	nev = 0;
	ring_buffer__consume(rb);
	printf("%-12s %-28s events=%d", what, result, nev);
	if (nev)
		printf(" event_id=%u retval=%lld", last_id, last_ret);
	printf("\n");
}

static void run_exec(const char *what, struct ring_buffer *rb)
{
	char res[64];
	int st;
	pid_t pid = fork();

	if (!pid) {
		char *argv[] = { "/init", "exit42", NULL };
		long r = execve("/init", argv, NULL);

		_exit(r < 0 ? 100 + errno : 99);
	}
	waitpid(pid, &st, 0);
	st = WEXITSTATUS(st);
	if (st == 42)
		snprintf(res, sizeof(res), "exec ran");
	else if (st == 99)
		snprintf(res, sizeof(res), "execve returned >= 0, no exec");
	else
		snprintf(res, sizeof(res), "execve failed: %s", strerror(st - 100));
	report(what, res, rb);
}

static void run_open(const char *what, struct ring_buffer *rb)
{
	int fd = open("/target", O_RDONLY);

	report(what, fd >= 0 ? "open ok" : strerror(errno), rb);
	if (fd >= 0)
		close(fd);
}

static int load(const char *name)
{
	struct bpf_program *p;

	obj = bpf_object__open_file("/enforcer.bpf.o", NULL);
	bpf_object__for_each_program(p, obj)
		bpf_program__set_autoload(p, !strcmp(bpf_program__name(p), name));
	if (bpf_object__load(obj) || !bpf_program__attach(bpf_object__find_program_by_name(obj, name))) {
		printf("%s: load/attach failed\n", name);
		bpf_object__close(obj);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_map_create_opts, o);
	struct ring_buffer *rb;
	FILE *f;

	if (getpid() != 1)
		return argc > 1 && !strcmp(argv[1], "exit42") ? 42 : 0;
	vm_init();
	mkdir("/sys/fs/bpf", 0755);
	mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL);
	if ((f = fopen("/audit_bit", "r"))) {
		fscanf(f, "%i", &audit_bit);
		fclose(f);
	}
	close(open("/target", O_CREAT | O_WRONLY, 0644));
	o.inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "inner", 400, 4, 256, NULL);
	outer = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "kubearmor_conta", 8, 4, 256, &o);
	bpf_obj_pin(outer, "/sys/fs/bpf/kubearmor_containers");

	if (!load("enforce_proc")) {
		rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "kubearmor_events"), on_event, NULL, NULL);
		run_exec("exec none", rb);
		set_rule("/init", (struct val){ RULE_EXEC | audit_bit, 0 });
		run_exec("exec audit", rb);
		set_rule("/init", (struct val){ RULE_EXEC | RULE_DENY, 0 });
		run_exec("exec block", rb);
		set_rule("/nothing", (struct val){ 0, 0 });
		ring_buffer__free(rb);
		bpf_object__close(obj);
	}
	if (!load("enforce_file")) {
		rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "kubearmor_events"), on_event, NULL, NULL);
		run_open("open none", rb);
		set_rule("/target", (struct val){ 0, RULE_READ | RULE_WRITE | audit_bit });
		run_open("open audit", rb);
		set_rule("/target", (struct val){ 0, RULE_READ | RULE_WRITE | RULE_DENY });
		run_open("open block", rb);
		set_rule("/nothing", (struct val){ 0, 0 });
		ring_buffer__free(rb);
		bpf_object__close(obj);
	}
	vm_done();
	return 0;
}
