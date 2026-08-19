// Data-plane access checker — inline module on the LLC→DRAM wire.
//
// Part of the data-centric TEE prototype; see files/thesis.md and
// files/vortex_simx.md. Kept under sec/ so the thesis work stays separable
// from upstream Vortex in a diff.

#pragma once

#include <simobject.h>
#include <cstdint>
#include <iosfwd>
#include <vector>
#include "types.h"

namespace vortex {

// Buffer policy header. One of these covers a whole buffer chunk
// (2^buffer_log2 bytes, ~MB by design), which is what makes the metadata
// working set small enough for the header cache to hold.
//
// Read-only in steady state: revocation advances `current_epoch` on the
// checker rather than writing headers, so the check stays a pure cacheable
// read that can overlap the DRAM access it gates (thesis §6).
struct BufferHeader {
  uint32_t owner_eid = 0;
  uint32_t perms = 0;         // owner access — not epoch-gated
  uint32_t shared_perms = 0;  // non-owner access, valid while the grant holds
  uint64_t grant_epoch = 0;   // shared grant valid while current_epoch <= grant_epoch
};

constexpr uint32_t PERM_R = 0x1;
constexpr uint32_t PERM_W = 0x2;

// Wildcard owner: any tenant may access (subject to perms + epoch). The boot
// default for every header — unclaimed memory (kernel code, stacks, args) is
// system/shared; DCR claims narrow specific buffer ranges to specific owners.
constexpr uint32_t OWNER_ANY = 0xFFFFFFFFu;

// DCR setup path (Phase 3 step 4). Range 0x300+ reserved for the checker
// (phase0/checker_hook_map.md §2.5: 0x280–0xFFF free, DXA ends at 0x280).
// A buffer claim is staged across BUF_* registers and installed by a write to
// BUF_COMMIT; the staged values persist across commits so a later re-grant
// (Phase 4) can rewrite just BUF_EPOCH and commit again. These model the
// attested channel as trusted configuration, per the threat model.
// Mirrored in tests/regression/twotenant/common.h for the host side.
constexpr uint32_t DCR_CHECKER_BASE       = 0x300;
constexpr uint32_t DCR_CHECKER_BUF_BASE   = 0x300;  // buffer base address
constexpr uint32_t DCR_CHECKER_BUF_SIZE   = 0x301;  // buffer size in bytes
constexpr uint32_t DCR_CHECKER_BUF_OWNER  = 0x302;  // owner eid (OWNER_ANY = shared)
constexpr uint32_t DCR_CHECKER_BUF_PERMS  = 0x303;  // PERM_R | PERM_W
constexpr uint32_t DCR_CHECKER_BUF_EPOCH  = 0x304;  // grant epoch (0xFFFFFFFF = no expiry)
constexpr uint32_t DCR_CHECKER_BUF_COMMIT = 0x305;  // write installs the staged claim
constexpr uint32_t DCR_CHECKER_EPOCH      = 0x306;  // sets current_epoch (Phase 4 revocation)
constexpr uint32_t DCR_CHECKER_BUF_SHARED = 0x307;  // staged non-owner perms (grant to others)
constexpr uint32_t DCR_CHECKER_END        = 0x340;

// Spliced into the l3cache_→memsim_ binding, which is the off-chip boundary in
// every cache configuration (the L3 SimObject is constructed even when
// VX_CFG_L3_ENABLED=0, where it acts as a transparent arbiter — so this hook
// point does not move when the sweep changes cache config).
//
// PHASE 2 SCOPE — static single-owner. The header store is populated at
// construction with one owner covering all of global memory; the checker
// resolves a request's buffer, looks the header up through the header cache,
// and allows or denies on owner + permission match. The DCR-driven who's-who
// setup that populates this from the host is Phase 3; the epoch register is
// wired but never advanced until Phase 4.
//
// Latency model: a header-cache hit forwards with `hit_latency` added, a miss
// with `miss_latency` (the cost of fetching the header from the isolated
// store). Nothing else about the request is touched — no data, no reordering.
//
// PHASE 3 — fault delivery. The DRAM→LLC response binding stays direct and
// untouched (splicing a buffered stage into it measurably perturbs baseline
// timing); instead the checker holds a tap on each response channel and
// injects synthesized fault responses into free slots — the try_send/retry
// semantics is the response-bus mux a hardware checker would use. With
// `enforce` set, a denied request is not forwarded to DRAM:
//   - denied read:  a MemRsp carrying a poison block is injected after the
//     check latency, so the LLC's outstanding fill completes and the requester
//     observably receives poison instead of the protected data.
//   - denied write: dropped. Writes are posted at this boundary (the DRAM
//     model responds only to reads), and the functional RAM write happens
//     inside the DRAM model — so a dropped write never lands, which is the
//     denial semantics, not just its timing.
// This mirrors what real memory-side protection hardware does (poison + log);
// precise traps to the offending warp are architecturally out of reach from
// behind the LLC. The first fault is latched in FaultStatus for readback.
class MemChecker : public SimObject<MemChecker> {
public:
  struct Config {
    uint32_t num_ports = 1;
    uint32_t buffer_log2 = 20;      // log2 bytes covered by one header (1 MB)
    uint32_t hcache_entries = 16;   // 0 disables the cache: every check is a miss
    uint32_t hcache_assoc = 4;
    uint32_t hit_latency = 0;       // cycles added on a header-cache hit
    // Cycles added on a miss (isolated-store fetch). 4 is Vortex's own array
    // latency for an on-chip SRAM of the size the 1 MB-granularity design point
    // implies (a 64 KB header store); both VX_CFG_DCACHE_LATENCY's and
    // VX_CFG_L2_LATENCY's scaling rules give 4 there. Fine granularities push
    // the store off chip and cost a real memory access instead — the harness
    // sets those explicitly. See phase2/latency_model.md.
    uint32_t miss_latency = 4;
    bool     enforce = false;       // Phase 3: a deny actually blocks the request
    // Mechanism self-test. 0 = off; 1 = deny every check (with enforce this
    // poisons instruction fetches too — the victim executes garbage and the
    // run never terminates, so it only suits counter checks without enforce);
    // 2 = deny writes only, which completes cleanly under enforcement: the
    // kernel's output never reaches RAM and host verification fails.
    uint32_t test_deny = 0;
  };

  struct PerfStats {
    uint64_t reqs = 0;          // requests crossing the boundary
    uint64_t checked = 0;       // AddrType::Global — subject to a policy check
    uint64_t bypassed = 0;      // IO / local-mem — carries no header, never gated
    uint64_t allows = 0;
    uint64_t denies = 0;
    uint64_t hc_hits = 0;
    uint64_t hc_misses = 0;
    uint64_t added_cycles = 0;  // total latency injected across all requests
    uint64_t faulted_reads = 0;   // enforced denies answered with a poison MemRsp
    uint64_t dropped_writes = 0;  // enforced denies dropped (writes are posted)
    uint64_t dcr_claims = 0;      // buffer claims committed over the DCR path
    uint64_t headers_written = 0; // header-store entries those claims installed
  };

  // First denied access, latched for status readback (the sim-level stand-in
  // for a fault status register). `count` keeps advancing after the latch.
  struct FaultStatus {
    bool     valid = false;
    bool     is_write = false;
    uint64_t addr = 0;
    uint32_t hart_id = 0;
    uint64_t count = 0;
  };

  std::vector<SimChannel<MemReq>> req_in;
  std::vector<SimChannel<MemReq>> req_out;

  MemChecker(const SimContext& ctx, const char* name, const Config& config);
  ~MemChecker();

  // Response-bus tap for fault injection (Phase 3): `chan` is the LLC-side
  // response channel for `port` (the same one DRAM responses arrive on). The
  // checker only ever try_sends into free slots; with no enforced denies it
  // never touches the channel at all.
  void attach_rsp_port(uint32_t port, SimChannel<MemRsp>* chan);

  // Installs one owner over all of global memory. Boot default is
  // OWNER_ANY (unclaimed = system/shared); DCR claims then narrow specific
  // ranges. Phase 2's single-owner rows are the OWNER_ANY case observed
  // from a single core.
  void install_single_owner(uint32_t owner_eid, uint32_t perms);

  // Phase 3 step 4: the who's-who setup path. Handles DCR_CHECKER_BASE..END;
  // returns 0. Setup writes are configuration, not data-plane traffic — they
  // take effect immediately and cost no modelled cycles (the attested channel
  // is pre-launch setup, not on the measured path).
  int dcr_write(uint32_t addr, uint32_t value);

  // Phase 4 revocation: bumping this invalidates every grant whose
  // grant_epoch has fallen behind. No per-access write to any header.
  void set_epoch(uint64_t epoch);

  const PerfStats& perf_stats() const;
  const FaultStatus& fault_status() const;

  void dump(std::ostream& os) const;

  // Config is read from the environment so a sweep can vary granularity and
  // header-cache size without a rebuild. Returns enabled=false when
  // VX_CHECKER is unset, in which case the checker is not constructed at all
  // and the l3→dram binding stays exactly as upstream leaves it.
  static bool env_config(Config* out);

protected:
  void on_reset();
  void on_tick();

private:
  class Impl;
  Impl* impl_;

  friend class SimObject<MemChecker>;
};

}
