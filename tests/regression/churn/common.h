#ifndef _COMMON_H_
#define _COMMON_H_

// churn — Tier-3 policy-churn amortization workload.
//
// The contribution axis (PROJECT.md §12, figure 3): no baseline system can run
// this, which is why it has to exist. Steady-state residency is something CC
// also does well; what separates this design is the *cost of changing policy*,
// and that is what this measures.
//
// Shape: owner A (eid 0) holds a dataset split into chunks. Per epoch, A grants
// B (eid 1) read on one chunk, B runs a real reduction kernel over it into
// B-owned output, A revokes, then re-grants the next chunk. That is the
// hospital / ML-provider scenario reduced to its mechanism.
//
// Per epoch the host issues 9 DCR ring writes — 7 to re-grant (a new
// grant_epoch) and 2 to revoke — around one launch. The grant is live for the
// whole of each launch, so a correct run has deny=0: this measures the *cost*
// of policy change, not denial. Denial is what revoke / revoke_scope cover.
//
// DCR register numbers are NOT mirrored here. They come from the generated
// <VX_types.h> ([dcr_checker] in VX_types.toml), which is also what the RTL
// decoder reads — the mirroring in the older tests' common.h is how a window
// drifts from its enforcement.

#include <cstdint>

// The checker's poison fill is 0xDD bytes (mem_checker.cpp). A granted read
// that returns this means the grant was not live when the request reached the
// enforcement point.
#define POISON_WORD 0xDDDDDDDDu

// Dataset values are chunk-tagged so a wrong-chunk read is distinguishable
// from poison and from zero.
#define CHUNK_VAL(chunk, i) (0x5E000000u | ((uint32_t)(chunk) << 20) | ((uint32_t)(i) & 0xFFFFFu))

typedef struct {
  uint32_t num_points;   // points per chunk
  uint32_t taps;         // reduction width — the work-per-epoch knob
  uint32_t chunk;        // which chunk this launch reads (for verification)
  uint32_t pad;
  uint64_t in_addr;      // A-owned, granted to B for this epoch
  uint64_t out_addr;     // B-owned
} kernel_arg_t;

#endif
