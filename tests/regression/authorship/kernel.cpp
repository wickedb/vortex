#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// One kernel spanning both cores; core c runs as tenant c. The host keys its
// expectations on the core each task recorded.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t core = (uint32_t)vx_core_id();
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);
	origin[idx] = core;

	if (arg->mode == MODE_HIJACK) {
		// Count the launches that ran with this argument block.
		auto count = reinterpret_cast<uint32_t*>(arg->count_addr);
		count[idx] += 1;
		return;
	}

	auto secret = reinterpret_cast<volatile uint32_t*>(arg->secret_addr);
	auto probe  = reinterpret_cast<uint32_t*>(arg->probe_addr);
	probe[idx] = secret[idx];

	if (arg->mode == MODE_FOREIGN) {
		auto grant  = reinterpret_cast<volatile uint32_t*>(arg->grant_addr);
		auto probe2 = reinterpret_cast<uint32_t*>(arg->probe2_addr);
		probe2[idx] = grant[idx];
	} else {
		// Tenant 1's buffer: core 1's write lands, core 0's is dropped.
		auto t1own = reinterpret_cast<uint32_t*>(arg->t1_addr);
		t1own[idx] = (core == 1) ? MARK_T1(idx) : MARK_T0(idx);
	}
}
