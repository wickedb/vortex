#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// A dependent pointer-chase over the granted buffer: each word holds the index
// of the next word to load, so every load must complete before the next one
// issues. That makes cycles/step the load-to-use latency of the level the data
// is sitting in — not throughput, which at any real occupancy hides the level
// completely.
//
// Nothing privileged is used: vx_rdcycle() and the values loaded are all a
// co-resident tenant has. A denied load comes back as the checker's poison
// block, which is not a valid index, so the chase both measures latency and
// classifies every step as served or denied.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx  = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t core = (uint32_t)vx_core_id();

	auto shared = reinterpret_cast<volatile uint32_t*>(arg->shared_addr);
	auto cycles = reinterpret_cast<uint32_t*>(arg->cycles_addr);
	auto poison = reinterpret_cast<uint32_t*>(arg->poison_addr);
	auto plain  = reinterpret_cast<uint32_t*>(arg->plain_addr);
	auto origin = reinterpret_cast<uint32_t*>(arg->origin_addr);

	const uint32_t ws    = arg->ws_words;
	const uint32_t iters = arg->iters;

	// One measurer per block. Blocks land on distinct cores, so this gives one
	// timed chase per core with the rest of the core idle. A dependent chase
	// only reports load-to-use latency when it is not queued behind its
	// neighbours; with every task chasing, the core saturates and the number
	// collapses to occupancy-limited throughput, which hides the cache level
	// completely. Everyone else records their core and leaves.
	origin[idx] = core;
	if (threadIdx.x != 0) {
		cycles[idx] = 0;
		poison[idx] = 0;
		plain [idx] = 0;
		return;
	}

	// Warm-up: walk the chase once so the working set is resident before
	// anything is timed. This is the entire "attack" — one pass over the data
	// while the grant is still live.
	uint32_t w = 0;
	for (uint32_t i = 0; i < ws; ++i) {
		uint32_t nx = shared[w];
		// On a denied load the returned word is poison, not an index. Step to
		// the next line rather than restarting, so the walk keeps covering
		// fresh lines instead of spinning on the one poisoned line.
		w = (nx < ws) ? nx : ((w + WORDS_PER_LINE) % ws);
	}

	uint32_t npoison = 0, nplain = 0;
	uint32_t pos = 0;

	uint64_t t0 = vx_rdcycle();
	for (uint32_t it = 0; it < iters; ++it) {
		uint32_t nx = shared[pos];
		if (nx < ws) { ++nplain;  pos = nx; }
		else         { ++npoison; pos = (pos + WORDS_PER_LINE) % ws; }
	}
	uint64_t t1 = vx_rdcycle();

	cycles[idx] = (uint32_t)(t1 - t0);
	poison[idx] = npoison;
	plain [idx] = nplain;
}
