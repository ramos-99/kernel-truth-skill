// Grading guest for kubearmor-lsm-audit. Runs as PID 1 with bpf in lsm=.
// Loads every program in /enforcer.bpf.o and /enforcer_path.bpf.o the way
// KubeArmor does (whole object, all attached), writes rules into the pinned
// kubearmor_containers map and checks what each hook allows and reports.
// Prints "ok <check>", "FAIL <check>: ..." or "ENV <reason>" lines.
#define _GNU_SOURCE
#include "vm.h"
#include "adapter.h"
#include <bpf/btf.h>
#include <arpa/inet.h>
#include <grp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

// From the parent commit (KubeArmor/BPF/shared.h, syscalls.h).
#define RULE_EXEC 1
#define RULE_WRITE 2
#define RULE_READ 4
#define RULE_OWNER 8
#define SOCK_PROTO_KEY 3 // enum network_check_type sock_proto
#define CAPABLE_KEY 200
#define DFILE 102 // enum deny_by_default dfile
#define EV_EXEC 352 // _SECURITY_BPRM_CHECK
#define EV_OPEN 450 // _FILE_OPEN
#define EV_PERM 451 // _FILE_PERMISSION
#define EV_MKDIR 454 // _FILE_MKDIR
#define EV_SOCK 461 // _SOCKET_CREATE
#define EV_CONN 462 // _SOCKET_CONNECT
#define EV_CAP 464 // _CAPABLE

#define UID 1000 // unprivileged caller for owner-only checks
#define GID 2000 // differs from UID so uid/gid mixups show
#define OWN 3000 // owner of other users' files, so oid != 0 and != caller

struct key { unsigned char path[200], source[200]; };
struct field { int off, size; };

static struct field f_id, f_ret, f_oid;
static int outer, nfail, nev, info_only;
static struct { unsigned id; long long ret; long long oid; } ev[256];

// ---- event layout from BTF ----

static int find_field(const struct btf *btf, const struct btf_type *t, const char *name, struct field *f)
{
	const struct btf_member *m = btf_members(t);

	for (int i = 0; i < btf_vlen(t); i++, m++)
		if (!strcmp(btf__name_by_offset(btf, m->name_off), name)) {
			f->off = btf_member_bit_offset(t, i) / 8;
			f->size = btf__resolve_size(btf, m->type);
			return 0;
		}
	return -1;
}

// /event-layout.o is built from the implementation's shared.h (see
// event-layout.c), so this follows whatever layout it chose.
static int event_layout(void)
{
	struct btf *btf = btf__parse("/event-layout.o", NULL);
	const struct btf_type *t;
	int id;

	if (!btf)
		return -1;
	id = btf__find_by_name_kind(btf, "event", BTF_KIND_TYPEDEF);
	if (id < 0)
		id = btf__find_by_name_kind(btf, "event", BTF_KIND_STRUCT);
	if (id < 0)
		return -1;
	t = btf__type_by_id(btf, btf__resolve_type(btf, id));
	if (!t || !btf_is_struct(t))
		return -1;
	if (find_field(btf, t, AD_EV_ID, &f_id) || find_field(btf, t, AD_EV_RET, &f_ret))
		return -1;
	if (find_field(btf, t, AD_EV_OID, &f_oid)) {
		// Event ids and retval predate the PR, the owner id is new.
		printf("FAIL owner id: event has no \"%s\" field\n", AD_EV_OID);
		nfail++;
		f_oid.size = 0;
	}
	return 0;
}

static long long get_field(void *data, size_t len, struct field f)
{
	if (f.off + f.size > (int)len)
		return -99999;
	switch (f.size) {
	case 1: return *(signed char *)(data + f.off);
	case 2: return *(short *)(data + f.off);
	case 4: return *(int *)(data + f.off);
	case 8: return *(long long *)(data + f.off);
	}
	return -99999;
}

static int on_event(void *ctx, void *data, size_t len)
{
	if (nev < 256) {
		ev[nev].id = (unsigned)get_field(data, len, f_id);
		ev[nev].ret = get_field(data, len, f_ret);
		ev[nev].oid = (unsigned)get_field(data, len, f_oid);
	}
	nev++;
	return 0;
}

// ---- rules ----

static struct key path_key(const char *p)
{
	struct key k = {};

	strcpy((char *)k.path, p);
	return k;
}

static struct key pair_key(int a, int b)
{
	struct key k = {};

	k.path[0] = a;
	k.path[1] = b;
	return k;
}

// Replaces the host's rule map (outer key 0) with one rule and, if
// posture >= 0, a default-posture entry for files.
static void set_rule(struct key k, enum ad_kind kind, unsigned short mask, enum ad_action a, int posture)
{
	unsigned long long okey = 0;
	char val[AD_VAL_SIZE];
	int inner = bpf_map_create(BPF_MAP_TYPE_HASH, "inner", sizeof(struct key), AD_VAL_SIZE, 256, NULL);

	memset(val, 0, sizeof(val));
	ad_rule(val, kind, mask, a);
	bpf_map_update_elem(inner, &k, val, BPF_ANY);
	if (posture >= 0) {
		struct key pk = pair_key(DFILE, 0);

		memset(val, 0, sizeof(val));
		ad_posture(val, posture);
		bpf_map_update_elem(inner, &pk, val, BPF_ANY);
	}
	bpf_map_update_elem(outer, &okey, &inner, BPF_ANY);
	close(inner);
}

static void clear_rules(void)
{
	set_rule(path_key("/nothing/here"), AD_FILE, 0, AD_ALLOW, -1);
}

// ---- operations, run in a child; return 0 or errno ----

static int op_exec(void)
{
	char *argv[] = { "/init", "exit0", NULL };

	execve("/init", argv, NULL);
	return errno;
}

static int op_open(const char *p)
{
	int fd = open(p, O_RDONLY);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int op_write(const char *p)
{
	int fd = open(p, O_WRONLY), r = 0;

	if (fd < 0)
		return 1000 + errno; // open itself must not fail here
	if (write(fd, "x", 1) != 1)
		r = errno;
	close(fd);
	return r;
}

static int op_socket(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int conn_fd = -1;

static int op_connect(void)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9) };

	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return connect(conn_fd, (void *)&a, sizeof(a)) ? errno : 0;
}

static int op_chown(void)
{
	return chown("/chowned", UID, -1) ? errno : 0;
}

static const char *op_arg;
static int op_open_arg(void) { return op_open(op_arg); }
static int op_write_arg(void) { return op_write(op_arg); }
static int op_mkdir_arg(void) { return mkdir(op_arg, 0755) ? errno : 0; }
static int op_exec_arg(void) { char *a[] = { (char *)op_arg, "exit0", NULL }; execve(op_arg, a, NULL); return errno; }

// Runs op in a child (as UID/GID if unpriv) and collects its events.
// Exit codes: 0 ok, 1..255 errno, 254 execve returned >= 0.
static int run(int (*op)(void), int unpriv, struct ring_buffer *rb)
{
	int st;
	pid_t pid;

	ring_buffer__consume(rb); // drop anything left from earlier output
	pid = fork();

	if (!pid) {
		if (unpriv && (setgroups(0, NULL) || setresgid(GID, GID, GID) || setresuid(UID, UID, UID)))
			_exit(253);
		int r = op();

		if (op == op_exec || op == op_exec_arg)
			_exit(r ? (r & 0xff) : 254);
		_exit(r > 252 ? 252 : r);
	}
	waitpid(pid, &st, 0);
	nev = 0;
	ring_buffer__consume(rb);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 255;
}

enum want { OK, DENIED };

// res: what run() returned. Events with event_id == id are counted and must
// number min..max, each with retval >= 0 (sign > 0) or < 0 (sign < 0), and
// owner id == oid when oid >= 0.
static void check(const char *name, int res, enum want w, unsigned id, int min, int max, int sign, long long oid)
{
	char why[256] = "";
	int n = 0;

	if (w == OK && res != 0)
		snprintf(why, sizeof(why), "operation failed: %s",
			 res == 254 ? "execve returned >= 0 without exec" : strerror(res));
	if (w == DENIED && res != EACCES && res != EPERM)
		snprintf(why, sizeof(why), "operation not denied (%s)", res ? strerror(res) : "succeeded");
	for (int i = 0; i < nev && i < 256; i++) {
		if (ev[i].id != id)
			continue;
		n++;
		if (!*why && sign > 0 && ev[i].ret < 0)
			snprintf(why, sizeof(why), "event retval %lld, want >= 0", ev[i].ret);
		if (!*why && sign < 0 && ev[i].ret >= 0)
			snprintf(why, sizeof(why), "event retval %lld, want < 0", ev[i].ret);
		if (!*why && oid >= 0 && f_oid.size && ev[i].oid != oid)
			snprintf(why, sizeof(why), "event owner id %lld, want %lld", ev[i].oid, oid);
	}
	if (!*why && (n < min || n > max))
		snprintf(why, sizeof(why), "%d events with id %u, want %d%s", n, id, min,
			 max > min ? " or more" : "");
	if (*why && info_only) {
		printf("info %s: %s (not scored)\n", name, why);
	} else if (*why) {
		printf("FAIL %s: %s\n", name, why);
		nfail++;
	} else {
		printf("ok   %s (%d events)\n", name, n);
	}
}

// ---- setup ----

static void env(const char *why)
{
	printf("ENV %s\n", why);
	vm_done();
	exit(0);
}

static struct bpf_object *load(const char *path)
{
	LIBBPF_OPTS(bpf_object_open_opts, oo, .kernel_log_buf = vm_log, .kernel_log_size = sizeof(vm_log));
	struct bpf_object *obj = bpf_object__open_file(path, &oo);
	struct bpf_program *p;

	if (!obj) {
		printf("FAIL load %s: can't open\n", path);
		nfail++;
		return NULL;
	}
	vm_lib_log[0] = vm_log[0] = 0;
	if (bpf_object__load(obj)) {
		printf("FAIL load %s: verifier rejected a program\n", path);
		for (char *l = strtok(vm_lib_log, "\n"); l; l = strtok(NULL, "\n"))
			if (strstr(l, "failed to load") || strstr(l, "should have been"))
				printf("    %.150s\n", l);
		vm_print_log_tail();
		nfail++;
		bpf_object__close(obj);
		return NULL;
	}
	bpf_object__for_each_program(p, obj)
		if (!bpf_program__attach(p)) {
			printf("FAIL attach %s: %s\n", bpf_program__name(p), strerror(errno));
			nfail++;
		}
	printf("ok   load+attach %s\n", path);
	return obj;
}

static void mkfile(const char *p, mode_t m, uid_t u, gid_t g)
{
	close(open(p, O_CREAT | O_WRONLY, m));
	chmod(p, m);
	chown(p, u, g);
}

static void mkd(const char *p, mode_t m, uid_t u, gid_t g)
{
	mkdir(p, m);
	chmod(p, m);
	chown(p, u, g);
}

static void lo_up(void)
{
	struct ifreq r = { .ifr_name = "lo" };
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	ioctl(s, SIOCGIFFLAGS, &r);
	r.ifr_flags |= IFF_UP;
	ioctl(s, SIOCSIFFLAGS, &r);
	close(s);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_map_create_opts, o);
	struct bpf_object *enf, *path = NULL;
	struct ring_buffer *rb;
	struct utsname u;
	char lsm[256] = "";
	int maj = 0, min = 0, r;
	FILE *f;

	if (getpid() != 1)
		return 0; // exec target
	vm_init();

	// Supported: mainline >= 6.15, where the parent's objects load whole
	// with clang 23 (earlier kernels reject parts of the parent too).
	uname(&u);
	sscanf(u.release, "%d.%d", &maj, &min);
	if (maj * 100 + min < 615)
		env("kernel older than 6.15: the parent's objects don't fully load here");
	mkdir("/sys/kernel/security", 0755);
	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);
	if ((f = fopen("/sys/kernel/security/lsm", "r"))) {
		fgets(lsm, sizeof(lsm), f);
		fclose(f);
	}
	if (!strstr(lsm, "bpf"))
		env("bpf is not in the active LSM list");

	mkdir("/sys/fs/bpf", 0755);
	mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL);
	o.inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "inner", sizeof(struct key), AD_VAL_SIZE, 256, NULL);
	outer = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "kubearmor_conta", 8, 4, 256, &o);
	if (outer < 0 || bpf_obj_pin(outer, "/sys/fs/bpf/kubearmor_containers"))
		env("can't create the rule map (check AD_VAL_SIZE in adapter.h)");
	clear_rules();

	mkfile("/target", 0644, 0, 0);
	mkfile("/wtarget", 0666, 0, 0);
	mkfile("/chowned", 0644, 0, 0);
	mkfile("/own0", 0644, OWN, OWN);
	mkfile("/wown", 0666, OWN, OWN);
	{ int i = open("/init", O_RDONLY), o = open("/xown", O_CREAT|O_WRONLY, 0755); char b[65536]; ssize_t n; while ((n = read(i, b, sizeof(b))) > 0) write(o, b, n); close(i); close(o); chmod("/xown", 0755); chown("/xown", OWN, OWN); }
	mkfile("/own1000", 0644, UID, UID);
	mkd("/d0", 0777, OWN, OWN);
	mkd("/d1000", 0755, UID, UID);
	lo_up();

	enf = load("/enforcer.bpf.o");
	if (!access("/enforcer_path.bpf.o", F_OK))
		path = load("/enforcer_path.bpf.o");
	if (!enf) {
		vm_done();
		return 0;
	}
	if (event_layout())
		env("no event type with the adapter's field names in event-layout.o (check adapter.h)");
	rb = ring_buffer__new(bpf_object__find_map_fd_by_name(enf, "kubearmor_events"), on_event, NULL, NULL);
	if (!rb)
		env("no kubearmor_events ring buffer");

	// Process rules (bprm_check_security).
	r = run(op_exec, 0, rb);
	check("exec none", r, OK, EV_EXEC, 0, 0, 0, -1);
	set_rule(path_key("/init"), AD_PROC, RULE_EXEC, AD_AUDIT, -1);
	r = run(op_exec, 0, rb);
	check("exec audit", r, OK, EV_EXEC, 1, 1, 1, -1);
	set_rule(path_key("/init"), AD_PROC, RULE_EXEC, AD_BLOCK, -1);
	r = run(op_exec, 0, rb);
	check("exec block", r, DENIED, EV_EXEC, 1, 1, -1, -1);
	clear_rules();

	// File rules (file_open).
	op_arg = "/target";
	r = run(op_open_arg, 0, rb);
	check("open none", r, OK, EV_OPEN, 0, 0, 0, -1);
	set_rule(path_key("/target"), AD_FILE, RULE_READ | RULE_WRITE, AD_AUDIT, -1);
	r = run(op_open_arg, 0, rb);
	check("open audit", r, OK, EV_OPEN, 1, 1, 1, -1);
	set_rule(path_key("/target"), AD_FILE, RULE_READ | RULE_WRITE, AD_BLOCK, -1);
	r = run(op_open_arg, 0, rb);
	check("open block", r, DENIED, EV_OPEN, 1, 1, -1, -1);
	clear_rules();

	// Read-only file rules (file_permission on write).
	op_arg = "/wtarget";
	r = run(op_write_arg, 0, rb);
	check("write none", r, OK, EV_PERM, 0, 0, 0, -1);
	set_rule(path_key("/wtarget"), AD_FILE, RULE_READ, AD_AUDIT, -1);
	r = run(op_write_arg, 0, rb);
	check("write readonly audit", r, OK, EV_PERM, 1, 1, 1, -1);
	set_rule(path_key("/wtarget"), AD_FILE, RULE_READ, AD_BLOCK, -1);
	r = run(op_write_arg, 0, rb);
	check("write readonly block", r, DENIED, EV_PERM, 1, 1, -1, -1);
	clear_rules();

	// Owner-only file rules, caller uid 1000 gid 2000.
	op_arg = "/own1000";
	set_rule(path_key("/own1000"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_AUDIT, -1);
	r = run(op_open_arg, 1, rb);
	check("open owner-only audit, own file", r, OK, EV_OPEN, 0, 0, 0, -1);
	op_arg = "/own0";
	set_rule(path_key("/own0"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_AUDIT, -1);
	r = run(op_open_arg, 1, rb);
	check("open owner-only audit, other's file", r, OK, EV_OPEN, 1, 1, 1, OWN);
	set_rule(path_key("/own0"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_BLOCK, -1);
	r = run(op_open_arg, 1, rb);
	check("open owner-only block, other's file", r, DENIED, EV_OPEN, 1, 1, -1, OWN);
	// Owner-only allow rule under a default posture.
	set_rule(path_key("/own0"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_ALLOW, AD_AUDIT);
	r = run(op_open_arg, 1, rb);
	check("open owner-only allow, audit posture", r, OK, EV_OPEN, 1, 4, 1, -1);
	set_rule(path_key("/own0"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_ALLOW, AD_BLOCK);
	r = run(op_open_arg, 1, rb);
	clear_rules(); // block posture also stops init writing to the console
	// Not scored: the merged PR allows this on file_open (the parent blocked it).
	info_only = 1;
	check("open owner-only allow, block posture", r, DENIED, EV_OPEN, 1, 4, -1, -1);
	info_only = 0;

	// Owner-only on path_mkdir: the owner is the parent directory's.
	op_arg = "/d1000/a";
	set_rule(path_key("/d1000/a"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_BLOCK, -1);
	r = run(op_mkdir_arg, 1, rb);
	check("mkdir owner-only block, own dir", r, OK, EV_MKDIR, 0, 0, 0, -1);
	op_arg = "/d0/b";
	set_rule(path_key("/d0/b"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_AUDIT, -1);
	r = run(op_mkdir_arg, 1, rb);
	check("mkdir owner-only audit, other's dir", r, OK, EV_MKDIR, 1, 1, 1, OWN);
	op_arg = "/d0/c";
	set_rule(path_key("/d0/c"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_BLOCK, -1);
	r = run(op_mkdir_arg, 1, rb);
	check("mkdir owner-only block, other's dir", r, DENIED, EV_MKDIR, 1, 1, -1, OWN);
	clear_rules();
	op_arg = "/xown";
	set_rule(path_key("/xown"), AD_PROC, RULE_OWNER | RULE_EXEC, AD_AUDIT, -1);
	r = run(op_exec_arg, 1, rb);
	check("exec owner-only audit, other's binary", r, OK, EV_EXEC, 1, 1, 1, OWN);
	set_rule(path_key("/xown"), AD_PROC, RULE_OWNER | RULE_EXEC, AD_BLOCK, -1);
	r = run(op_exec_arg, 1, rb);
	check("exec owner-only block, other's binary", r, DENIED, EV_EXEC, 1, 1, -1, OWN);
	op_arg = "/wown";
	set_rule(path_key("/wown"), AD_FILE, RULE_OWNER | RULE_READ | RULE_WRITE, AD_AUDIT, -1);
	r = run(op_write_arg, 1, rb);
	check("write owner-only audit, other's file", r, OK, EV_PERM, 1, 1, 1, OWN);

	clear_rules();

	// Network rules: UDP protocol on socket_create and socket_connect.
	r = run(op_socket, 0, rb);
	check("socket none", r, OK, EV_SOCK, 0, 0, 0, -1);
	set_rule(pair_key(SOCK_PROTO_KEY, IPPROTO_UDP), AD_NET, 0, AD_AUDIT, -1);
	r = run(op_socket, 0, rb);
	check("socket audit", r, OK, EV_SOCK, 1, 1, 1, -1);
	set_rule(pair_key(SOCK_PROTO_KEY, IPPROTO_UDP), AD_NET, 0, AD_BLOCK, -1);
	r = run(op_socket, 0, rb);
	check("socket block", r, DENIED, EV_SOCK, 1, 1, -1, -1);
	clear_rules();
	conn_fd = socket(AF_INET, SOCK_DGRAM, 0);
	set_rule(pair_key(SOCK_PROTO_KEY, IPPROTO_UDP), AD_NET, 0, AD_AUDIT, -1);
	r = run(op_connect, 0, rb);
	check("connect audit", r, OK, EV_CONN, 1, 1, 1, -1);
	set_rule(pair_key(SOCK_PROTO_KEY, IPPROTO_UDP), AD_NET, 0, AD_BLOCK, -1);
	r = run(op_connect, 0, rb);
	check("connect block", r, DENIED, EV_CONN, 1, 1, -1, -1);
	clear_rules();
	close(conn_fd);

	// Capability rules (capable), CAP_CHOWN via chown to another uid.
	r = run(op_chown, 0, rb);
	check("chown none", r, OK, EV_CAP, 0, 0, 0, -1);
	set_rule(pair_key(CAPABLE_KEY, 0 /* CAP_CHOWN */), AD_CAP, 0, AD_AUDIT, -1);
	r = run(op_chown, 0, rb);
	check("capability audit", r, OK, EV_CAP, 1, 8, 1, -1);
	set_rule(pair_key(CAPABLE_KEY, 0), AD_CAP, 0, AD_BLOCK, -1);
	r = run(op_chown, 0, rb);
	check("capability block", r, DENIED, EV_CAP, 1, 8, -1, -1);
	clear_rules();

	printf("RESULT %s (%d failed)\n", nfail ? "FAIL" : "PASS", nfail);
	ring_buffer__free(rb);
	vm_done();
	return 0;
}
