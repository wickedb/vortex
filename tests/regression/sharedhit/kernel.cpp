#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// Every task touches all SHARED_SECTORS sectors, at an offset taken from its
// low index bits, so both cores cover every shared word whatever the CTA
// dispatcher's block-to-core assignment. Indexing by `idx % SHARED_WORDS`
// instead would let the 16-task blocks alternate cores and keep the two
// tenants in disjoint sectors -- which is exactly the case this test exists
// to rule out.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t core = (uint32_t)vx_core_id();
	auto secret = reinterpret_cast<volatile uint32_t*>(arg->secret_addr);
	auto probe  = reinterpret_cast<uint32_t*>(arg->probe_addr);
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);

	origin[idx] = core;
	for (uint32_t s = 0; s < SHARED_SECTORS; ++s) {
		if (arg->mode == 0) {
			// Both tenants read the same words.
			uint32_t w = s * SECTOR_WORDS + (idx % SECTOR_WORDS);
			probe[idx * SHARED_SECTORS + s] = secret[w];
		} else {
			// Same sectors, interleaved words: even for tenant 0, odd for
			// tenant 1. All tasks on a core write the same value to a word.
			uint32_t w = s * SECTOR_WORDS + 2 * (idx % (SECTOR_WORDS / 2)) + (core & 1);
			secret[w] = (core == 0) ? MARK_T0(w) : MARK_XT(w);
		}
	}
}
