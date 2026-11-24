// Adapter: the only implementation-specific part of the grader.
// Read the implementation, then check the three things below. The defaults
// match the merged PR (f2b2da64). Nothing else in the grader needs editing,
// and the scoring in guest.c doesn't depend on these choices.
#ifndef ADAPTER_H
#define ADAPTER_H

#include <string.h>

enum ad_kind { AD_PROC, AD_FILE, AD_NET, AD_CAP };
enum ad_action { AD_ALLOW, AD_AUDIT, AD_BLOCK };

// 1. Names of the fields in the BPF `event` type (found through the
//    object's BTF, so their offsets and sizes don't matter).
#define AD_EV_ID "event_id"
#define AD_EV_RET "retval"
#define AD_EV_OID "oid" // owner id in owner-only alerts

// 2. Size of the value in the inner rule maps of kubearmor_containers.
#define AD_VAL_SIZE 4

// 3. How a rule is written into an inner-map value. `mask` uses the parent
//    commit's bits (RULE_EXEC 1, RULE_WRITE 2, RULE_READ 4, RULE_OWNER 8).
//    The parent's value is struct data_t { u16 processmask, filemask; };
//    file rules use filemask, the others processmask, and Block is
//    RULE_DENY (1 << 7). Audit is whatever the implementation added.
#define AD_RULE_DENY (1 << 7)
#define AD_RULE_AUDIT (1 << 10)

static void ad_rule(void *val, enum ad_kind kind, unsigned short mask, enum ad_action action)
{
	unsigned short v[2] = { 0, 0 };

	if (action == AD_BLOCK)
		mask |= AD_RULE_DENY;
	else if (action == AD_AUDIT)
		mask |= AD_RULE_AUDIT;
	v[kind == AD_FILE] = mask;
	memcpy(val, v, sizeof(v));
}

// Default-posture entry (key path[0] = dfile etc.), unchanged from the parent:
// processmask = 140 for audit, 141 for block.
static void ad_posture(void *val, enum ad_action action)
{
	unsigned short v[2] = { action == AD_BLOCK ? 141 : 140, 0 };

	memcpy(val, v, sizeof(v));
}

#endif
