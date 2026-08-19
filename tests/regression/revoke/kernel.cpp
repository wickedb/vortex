#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// Same kernel for both launches: every task probes the granted buffer and
// records (value, core). After revocation (phase 2), owner-core tasks also
// write their cell — showing the owner's access survives the revocation that
// cut off tenant 1.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t core = (uint32_t)vx_core_id();
	auto shared = reinterpret_cast<volatile uint32_t*>(arg->shared_addr);
	auto probe  = reinterpret_cast<uint32_t*>(arg->probe_addr);
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);

	probe[idx]  = shared[idx];
	origin[idx] = core;

	if (arg->phase == 2 && core == 0) {
		shared[idx] = MARK_T0(idx);
	}
}
