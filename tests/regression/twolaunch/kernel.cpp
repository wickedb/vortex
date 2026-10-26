#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	if (idx >= arg->num_points)
		return;
	auto secret = reinterpret_cast<volatile uint32_t*>(arg->secret_addr);
	auto t1     = reinterpret_cast<uint32_t*>(arg->t1_addr);
	auto probe  = reinterpret_cast<uint32_t*>(arg->probe_addr);
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);

	probe[idx]  = secret[idx];
	origin[idx] = (uint32_t)vx_core_id();
	if (arg->mode == 0) {
		secret[idx] = MARK_A(idx);
	} else {
		secret[idx] = MARK_B(idx);   // must be dropped
		t1[idx]     = MARK_T(idx);   // tenant 1's own buffer: must land
	}
}
