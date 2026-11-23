#ifndef STATE_H
#define STATE_H

struct tstate {
	int target_tgid;
	int mode; /* 0 allow, 1 audit, 2 block */
	unsigned long long target_ino;
	int policy;
	int gate_runs, gate_ret, events;
	int observer_runs, observer_ret;
	unsigned long long uid_gid;
	int mkdir_runs, mkdir_negative;
	unsigned int mkdir_uid, mkdir_parent_uid;
};

#endif
