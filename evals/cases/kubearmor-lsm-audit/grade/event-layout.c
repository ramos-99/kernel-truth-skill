// Compiled by build-ka.sh against the implementation's own KubeArmor/BPF
// headers, so its BTF describes the implementation's `event` type. The
// grading guest reads field offsets from here; the enforcer objects
// themselves don't carry the type in their BTF.
#include "shared.h"

event kt_event_layout;
