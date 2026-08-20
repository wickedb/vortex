#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// Same kernel for both launches: each task reads the buffer it does NOT
// own via the shared grant — core 0 reads bufB (owner 1's buffer), core 1
// reads bufA (owner 0's buffer) — and records (value, core). Whether that
// read sees real data or poison depends entirely on that owner's epoch-table
// entry, which is exactly the property this test probes.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t core = (uint32_t)vx_core_id();
	auto bufA   = reinterpret_cast<volatile uint32_t*>(arg->bufA_addr);
	auto bufB   = reinterpret_cast<volatile uint32_t*>(arg->bufB_addr);
	auto probe  = reinterpret_cast<uint32_t*>(arg->probe_addr);
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);

	probe[idx]  = (core == 0) ? bufB[idx] : bufA[idx];
	origin[idx] = core;
}
