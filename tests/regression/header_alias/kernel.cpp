#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// Every task probes both buffers and records which core it ran on. Reading
// both in one kernel is what makes the two halves of the assertion — bufA
// protected, bufB unprotected — observations of the same run.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t core = (uint32_t)vx_core_id();
	auto bufA   = reinterpret_cast<volatile uint32_t*>(arg->bufA_addr);
	auto bufB   = reinterpret_cast<volatile uint32_t*>(arg->bufB_addr);
	auto probeA = reinterpret_cast<uint32_t*>(arg->probeA_addr);
	auto probeB = reinterpret_cast<uint32_t*>(arg->probeB_addr);
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);

	probeA[idx] = bufA[idx];
	probeB[idx] = bufB[idx];
	origin[idx] = core;
}
