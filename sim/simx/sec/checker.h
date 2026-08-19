// Data-plane access checker — LLC→DRAM boundary.
//
// Part of the data-centric TEE prototype; see files/thesis.md and
// files/vortex_simx.md. Kept under sec/ so the thesis work stays separable
// from upstream Vortex in a diff.

#pragma once

#include <cstdint>
#include <iosfwd>

namespace vortex {

struct MemReq;

// Sits on the memory-controller boundary, where every request that misses the
// last-level cache must pass. This is the point at which the design intends to
// resolve a request's buffer header and allow or deny it.
//
// PHASE 1 SCOPE — pass-through. Each request accepted by the DRAM model is
// observed, classified and counted, then forwarded unchanged. No decision is
// made and no latency is injected, so a run with the checker installed is
// bit-identical to the unprotected baseline *by construction*: it is attached
// via Memory::PreSendHook, which receives `const MemReq&` and has no way to
// stall, delay, or mutate the request (phase0/checker_hook_map.md §2.4,
// mechanism A).
//
// Later phases swap this for a real gate against a header store + header
// cache, at which point the checker moves onto the wire as a SimObject spliced
// into the l3cache_→memsim_ binding so it *can* stall and delay. The counter
// surface below is deliberately shaped to survive that move unchanged.
class Checker {
public:
  struct PerfStats {
    uint64_t reqs = 0;         // total requests crossing the boundary
    uint64_t reads = 0;
    uint64_t writes = 0;
    uint64_t global_reqs = 0;  // AddrType::Global — the population a real check gates
    uint64_t other_reqs = 0;   // IO / local-mem traffic; carries no buffer header
  };

  Checker() = default;

  void reset();

  // Called once per request accepted by the DRAM model. Exactly once: the
  // Memory model peeks the request, invokes the hook, then unconditionally
  // pops it (mem/memory.cpp:117,147), so there is no re-observation on stall.
  void observe(const MemReq& req);

  const PerfStats& perf_stats() const { return perf_stats_; }

  // Emits the counters as a single "CHECKER:" line.
  void dump(std::ostream& os) const;

  // Reporting is opt-in (VX_CHECKER_STATS=1) so that a default run's output
  // stays byte-identical to baseline and can be diffed directly.
  static bool stats_enabled();

private:
  PerfStats perf_stats_;
};

}
