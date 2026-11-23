// Loads each program in paths.bpf.o on its own. Nothing is attached or pinned.
#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

static const struct {
	const char *name, *expected;
} cases[] = {
	{ "lsm_perm_none", "LOAD" },
	{ "lsm_perm_helper", "REJECT" },
	{ "lsm_s_perm_none", "REJECT" },
	{ "lsm_s_perm_helper", "REJECT" },
	{ "lsm_open_helper", "LOAD" },
	{ "lsm_s_open_helper", "LOAD" },
	{ "lsm_perm_kfunc", "LOAD" },
	{ "lsm_open_kfunc", "LOAD" },
	{ "fentry_perm_helper", "LOAD" },
	{ "fentry_vfs_read_helper", "REJECT" },
};

static char log_buf[1 << 20];

static int quiet(enum libbpf_print_level level, const char *fmt, va_list args)
{
	return 0;
}

static void print_log_tail(void)
{
	char *lines[2] = { 0 };
	int n = 0;

	for (char *l = strtok(log_buf, "\n"); l; l = strtok(NULL, "\n"))
		if (strncmp(l, "processed ", 10) != 0)
			lines[n++ % 2] = l;
	for (int i = n > 2 ? n - 2 : 0; i < n; i++)
		printf("  %s\n", lines[i % 2]);
}

static int run(const char *path, const char *name, const char *expected)
{
	struct bpf_object *obj = bpf_object__open_file(path, NULL);
	struct bpf_program *prog;

	if (!obj) {
		fprintf(stderr, "can't open %s\n", path);
		return 1;
	}
	bpf_object__for_each_program(prog, obj) {
		int match = !strcmp(bpf_program__name(prog), name);

		bpf_program__set_autoload(prog, match);
		if (match) {
			log_buf[0] = 0;
			bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
			bpf_program__set_log_level(prog, 1);
		}
	}

	int err = bpf_object__load(obj);
	const char *got = err ? "REJECT" : "LOAD";
	int same = !strcmp(got, expected);

	printf("%-24s %-6s expected %-6s %s\n", name, got, expected, same ? "ok" : "DIFF");
	if (err)
		print_log_tail();
	bpf_object__close(obj);
	return !same;
}

int main(int argc, char **argv)
{
	size_t total = sizeof(cases) / sizeof(cases[0]);
	struct utsname u;
	int diffs = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s paths.bpf.o\n", argv[0]);
		return 2;
	}
	if (geteuid()) {
		fprintf(stderr, "needs root: without it every load fails with EPERM\n");
		return 2;
	}
	libbpf_set_print(quiet);
	uname(&u);
	printf("kernel %s\n", u.release);

	for (size_t i = 0; i < total; i++)
		diffs += run(argv[1], cases[i].name, cases[i].expected);

	printf("%d of %zu differ\n", diffs, total);
	return diffs != 0;
}
