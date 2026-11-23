#define _GNU_SOURCE
#include "vm.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>

#define VECS 10

static const char *names[VECS] = { "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU" };

struct totals {
	unsigned long long raises, entries, entry_no_raise;
	unsigned long long raise_newer_than_entry, raised_twice_before_entry, raised_during_handler;
};

static void lo_up(void)
{
	struct ifreq r = {};
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	strcpy(r.ifr_name, "lo");
	r.ifr_flags = IFF_UP | IFF_RUNNING;
	if (ioctl(s, SIOCSIFFLAGS, &r))
		printf("lo up failed: %s\n", strerror(errno));
	close(s);
}

static int nic_up;

// With a virtual NIC, completions arrive as hardware interrupts, like the thread's
// real NIC. Addresses are QEMU's user networking defaults.
static void eth_up(void)
{
	struct ifreq r = {};
	struct sockaddr_in *a = (void *)&r.ifr_addr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	strcpy(r.ifr_name, "eth0");
	a->sin_family = AF_INET;
	a->sin_addr.s_addr = inet_addr("10.0.2.15");
	if (ioctl(s, SIOCSIFADDR, &r)) {
		printf("no eth0: %s, using loopback only\n", strerror(errno));
		close(s);
		return;
	}
	a->sin_addr.s_addr = inet_addr("255.255.255.0");
	ioctl(s, SIOCSIFNETMASK, &r);
	r.ifr_flags = IFF_UP | IFF_RUNNING;
	nic_up = !ioctl(s, SIOCSIFFLAGS, &r);
	printf("eth0 up: %d\n", nic_up);
	close(s);
}

// UDP on every CPU, so NET_RX is raised constantly.
static void flood(void)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9000),
				 .sin_addr.s_addr = nic_up ? inet_addr("10.0.2.2") : htonl(INADDR_LOOPBACK) };
	char buf[64] = {};
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	for (;;)
		sendto(s, buf, sizeof(buf), MSG_DONTWAIT, (void *)&a, sizeof(a));
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *p;
	pid_t kids[4];
	int counts, ncpu;

	vm_init();
	lo_up();
	eth_up();
	obj = bpf_object__open_file("/test.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		printf("load failed\n%.800s\n", vm_lib_log);
		vm_done();
		return 0;
	}
	bpf_object__for_each_program(p, obj)
		if (!bpf_program__attach(p))
			printf("attach %s: %s\n", bpf_program__name(p), strerror(errno));
	counts = bpf_object__find_map_fd_by_name(obj, "counts");
	ncpu = libbpf_num_possible_cpus();

	for (int i = 0; i < 4; i++) {
		kids[i] = fork();
		if (!kids[i])
			flood();
	}
	sleep(5);
	for (int i = 0; i < 4; i++)
		kill(kids[i], SIGKILL);
	for (int i = 0; i < 4; i++)
		waitpid(kids[i], NULL, 0);

	printf("%-9s %10s %10s %9s %13s %15s %16s\n", "vec", "raises", "entries", "no_raise", "newer_than_ts", "twice_before", "during_handler");
	for (unsigned v = 0; v < VECS; v++) {
		struct totals per[ncpu], sum = {};

		if (bpf_map_lookup_elem(counts, &v, per))
			continue;
		for (int c = 0; c < ncpu; c++) {
			sum.raises += per[c].raises;
			sum.entries += per[c].entries;
			sum.entry_no_raise += per[c].entry_no_raise;
			sum.raise_newer_than_entry += per[c].raise_newer_than_entry;
			sum.raised_twice_before_entry += per[c].raised_twice_before_entry;
			sum.raised_during_handler += per[c].raised_during_handler;
		}
		if (sum.raises || sum.entries)
			printf("%-9s %10llu %10llu %9llu %13llu %15llu %16llu\n", names[v], sum.raises, sum.entries,
			       sum.entry_no_raise, sum.raise_newer_than_entry, sum.raised_twice_before_entry,
			       sum.raised_during_handler);
	}
	vm_done();
	return 0;
}
