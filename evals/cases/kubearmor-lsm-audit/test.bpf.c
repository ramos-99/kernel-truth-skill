#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "state.h"

#define EPERM 1
#define AUDIT 1
#define BLOCK 2

char LICENSE[] SEC("license") = "GPL";

struct tstate st;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb SEC(".maps");

static bool is_target(struct file *file)
{
	return (bpf_get_current_pid_tgid() >> 32) == st.target_tgid &&
	       BPF_CORE_READ(file, f_inode, i_ino) == st.target_ino;
}

/* Internal codes leak: AUDIT (1) can reach the return. */
SEC("lsm/file_open")
int BPF_PROG(code_leak, struct file *file, int ret)
{
	int retval = 0;

	if (st.policy & 1)
		retval = AUDIT;
	if (st.policy & 2)
		retval = BLOCK;
	if (retval == BLOCK)
		retval = -EPERM;
	return retval;
}

/* Same decision, only -EPERM or 0 returned. */
SEC("lsm/file_open")
int BPF_PROG(code_mapped, struct file *file, int ret)
{
	int retval = 0;

	if (st.policy & 1)
		retval = AUDIT;
	if (st.policy & 2)
		retval = BLOCK;
	return retval == BLOCK ? -EPERM : 0;
}

SEC("lsm/file_open")
int BPF_PROG(ret_prev, struct file *file, int ret)
{
	return ret;
}

SEC("lsm/file_open")
int BPF_PROG(gate, struct file *file, int ret)
{
	int *e;

	if (!is_target(file))
		return 0;
	st.gate_runs++;
	st.gate_ret = ret;
	st.uid_gid = bpf_get_current_uid_gid();
	if (st.mode) {
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (e) {
			*e = st.mode;
			bpf_ringbuf_submit(e, 0);
		}
	}
	return st.mode == BLOCK ? -EPERM : 0;
}

SEC("lsm/file_open")
int BPF_PROG(observer, struct file *file, int ret)
{
	if (!is_target(file))
		return 0;
	st.observer_runs++;
	st.observer_ret = ret;
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(pos_open, struct file *file)
{
	return is_target(file) ? 1 : 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(pos_exec, struct linux_binprm *bprm)
{
	return (bpf_get_current_pid_tgid() >> 32) == st.target_tgid ? 1 : 0;
}

SEC("lsm/path_mkdir")
int BPF_PROG(mkdir_probe, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	if ((bpf_get_current_pid_tgid() >> 32) != st.target_tgid)
		return 0;
	st.mkdir_runs++;
	st.mkdir_negative = BPF_CORE_READ(dentry, d_inode) == NULL;
	st.mkdir_uid = BPF_CORE_READ(dentry, d_inode, i_uid.val);
	st.mkdir_parent_uid = BPF_CORE_READ(dentry, d_parent, d_inode, i_uid.val);
	st.uid_gid = bpf_get_current_uid_gid();
	return 0;
}
