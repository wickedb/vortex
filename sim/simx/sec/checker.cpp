// Data-plane access checker — LLC→DRAM boundary. See checker.h.

#include "checker.h"
#include "types.h"

#include <cstdlib>
#include <ostream>

using namespace vortex;

void Checker::reset() {
  perf_stats_ = PerfStats();
}

void Checker::observe(const MemReq& req) {
  ++perf_stats_.reqs;
  if (req.is_write()) {
    ++perf_stats_.writes;
  } else {
    ++perf_stats_.reads;
  }

  // Only global device memory carries a buffer header; IO and local-mem
  // traffic is never gated. Phase 1 just separates the two populations so the
  // Phase 2 gate has an honest denominator to report a hit rate against.
  if (req.addr_type() == AddrType::Global) {
    ++perf_stats_.global_reqs;
  } else {
    ++perf_stats_.other_reqs;
  }
}

void Checker::dump(std::ostream& os) const {
  os << "CHECKER: reqs=" << perf_stats_.reqs
     << " (r=" << perf_stats_.reads
     << ", w=" << perf_stats_.writes
     << "), global=" << perf_stats_.global_reqs
     << ", other=" << perf_stats_.other_reqs
     << std::endl;
}

bool Checker::stats_enabled() {
  const char* env = std::getenv("VX_CHECKER_STATS");
  return env != nullptr && env[0] != '\0' && env[0] != '0';
}
