#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// B's compute kernel. Reads the chunk A granted it this epoch and reduces a
// `taps`-wide window into B's own output.
//
// Deliberately a real reduction rather than a copy: the Tier-3 curve plots
// policy overhead as a *share* of total cycles, so the denominator has to be
// real work whose size we can sweep. `taps` is that knob — it scales the read
// stream and the arithmetic per output point while leaving the footprint, the
// claim geometry and the per-epoch policy cost untouched, which is exactly
// what an amortization curve needs held constant.
//
// No security API, no DCR call, no awareness a checker exists — the §4 claim
// that tenant compute code is unmodified has to be true of this kernel too,
// or the workload would be arguing against the paper.
__kernel void kernel_main(kernel_arg_t* __UNIFORM__ arg) {
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t n    = arg->num_points;
	uint32_t taps = arg->taps;
	if (idx >= n)
		return;

	auto in  = reinterpret_cast<volatile uint32_t*>(arg->in_addr);
	auto out = reinterpret_cast<uint32_t*>(arg->out_addr);

	// Sum a wrapping window. The wrap keeps every read inside the granted
	// chunk, so the checker sees one owner's granule for the whole stream.
	uint32_t acc = 0;
	for (uint32_t k = 0; k < taps; ++k) {
		uint32_t j = idx + k;
		if (j >= n)
			j -= n;
		acc += in[j];
	}
	out[idx] = acc;
}
