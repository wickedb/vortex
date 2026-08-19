#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// Every task probes tenant 0's buffer, records what it saw and where it ran,
// then writes: core-0 tasks into their own (tenant 0's) buffer, core-1 tasks
// into tenant 0's buffer (the attack — must be dropped) and into tenant 1's
// own buffer (must land). The host sorts out expectations per task using the
// recorded core id, so the demo is independent of how the CTA dispatcher
// distributes blocks across the two cores.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t core = (uint32_t)vx_core_id();
	auto secret = reinterpret_cast<volatile uint32_t*>(arg->secret_addr);
	auto t1own  = reinterpret_cast<uint32_t*>(arg->t1_addr);
	auto probe  = reinterpret_cast<uint32_t*>(arg->probe_addr);
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);

	// Read attempt on tenant 0's data: real on core 0, poison on core 1.
	probe[idx]  = secret[idx];
	origin[idx] = core;

	if (core == 0) {
		secret[idx] = MARK_T0(idx);  // own-buffer write: must land
	} else {
		secret[idx] = MARK_XT(idx);  // cross-tenant write: must be dropped
		t1own[idx]  = MARK_T1(idx);  // own-buffer write: must land
	}
}
