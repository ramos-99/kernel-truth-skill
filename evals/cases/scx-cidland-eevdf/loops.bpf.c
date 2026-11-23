#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define can_loop ({ __label__ l_break, l_continue; bool ret = true;	\
	asm volatile goto("may_goto %l[l_break]" :::: l_break);		\
	goto l_continue;						\
	l_break: ret = false;						\
	l_continue:;							\
	ret; })

#define NR (1 << 20)

u64 arr[1024];
u64 out;
static volatile u32 one = 1;
static volatile u32 zero;
static const volatile u32 one_ro = 1;

SEC("syscall")
int plain(void *ctx)
{
	u64 sum = 0;
	u32 i;

	for (i = 0; i < NR && can_loop; i++)
		sum += arr[i & 1023];
	out = sum;
	return 0;
}

SEC("syscall")
int volatile_step(void *ctx)
{
	u64 sum = 0;
	u32 i;

	for (i = 0; i < NR && can_loop; i += one)
		sum += arr[i & 1023];
	out = sum;
	return 0;
}

SEC("syscall")
int rodata_step(void *ctx)
{
	u64 sum = 0;
	u32 i;

	for (i = 0; i < NR && can_loop; i += one_ro)
		sum += arr[i & 1023];
	out = sum;
	return 0;
}

SEC("syscall")
int unknown_start(void *ctx)
{
	u64 sum = 0;
	u32 i;

	for (i = zero; i < NR && can_loop; i++)
		sum += arr[i & 1023];
	out = sum;
	return 0;
}

SEC("syscall")
int iter_num(void *ctx)
{
	u64 sum = 0;
	int i;

	bpf_for(i, 0, NR)
		sum += arr[i & 1023];
	out = sum;
	return 0;
}
