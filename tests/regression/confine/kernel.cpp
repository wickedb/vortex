#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// Core 1 (M) does the work; core 0 (H) only records where its tasks ran.
// Every core-1 write that follows a confined read must land in a granule H
// co-owns, or the checker refuses it. The origin buffer is jointly owned so
// that recording it never depends on the taint.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t n    = arg->num_points;
	uint32_t core = (uint32_t)vx_core_id();
	auto images = reinterpret_cast<volatile uint32_t*>(arg->images_addr);
	auto mown   = reinterpret_cast<volatile uint32_t*>(arg->mown_addr);
	auto pub    = reinterpret_cast<volatile uint32_t*>(arg->pub_addr);
	auto out    = reinterpret_cast<volatile uint32_t*>(arg->out_addr);
	auto origin = reinterpret_cast<volatile uint32_t*>(arg->origin_addr);

	origin[arg->phase * n + idx] = core;
	uint32_t who = arg->by_core ? core : arg->role;
	if (who != TENANT_M)
		return;

	if (arg->phase == PHASE_TRAIN) {
		uint32_t v = images[idx];   // confined read: core 1's taint becomes {H}
		out[idx]  = v ^ KEY;        // joint output: covers {H}, lands
		mown[idx] = v;              // M's own buffer: launder, refused
		pub[idx]  = v;              // unclaimed memory: launder, refused
	} else {
		uint32_t v = out[idx];      // joint while H co-owns it: taints {H}
		mown[arg->phase * n + idx] = v;  // export: refused early, lands late
	}
}
