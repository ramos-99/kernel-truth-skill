#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern int bpf_path_d_path(const struct path *path, char *buf, size_t buf__sz) __ksym;

#define NONE(sec, name)                                                        \
	SEC(sec) int BPF_PROG(name, struct file *file) { return 0; }

#define HELPER(sec, name)                                                      \
	SEC(sec) int BPF_PROG(name, struct file *file)                         \
	{                                                                      \
		char buf[64] = {};                                             \
		bpf_d_path((struct path *)&file->f_path, buf, sizeof(buf));    \
		return 0;                                                      \
	}

#define KFUNC(sec, name)                                                       \
	SEC(sec) int BPF_PROG(name, struct file *file)                         \
	{                                                                      \
		char buf[64] = {};                                             \
		bpf_path_d_path(&file->f_path, buf, sizeof(buf));              \
		return 0;                                                      \
	}

NONE("lsm/file_permission", lsm_perm_none)
HELPER("lsm/file_permission", lsm_perm_helper)
NONE("lsm.s/file_permission", lsm_s_perm_none)
HELPER("lsm.s/file_permission", lsm_s_perm_helper)
HELPER("lsm/file_open", lsm_open_helper)
HELPER("lsm.s/file_open", lsm_s_open_helper)
KFUNC("lsm/file_permission", lsm_perm_kfunc)
KFUNC("lsm/file_open", lsm_open_kfunc)
HELPER("fentry/security_file_permission", fentry_perm_helper)
HELPER("fentry/vfs_read", fentry_vfs_read_helper)
