#include <vx_spawn2.h>
#include "common.h"

__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	if (idx < arg->num_points)
		reinterpret_cast<uint32_t*>(arg->dst_addr)[idx] = VALUE(idx);
}
