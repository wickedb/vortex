// Data-plane access checker — inline module on the LLC→DRAM wire.
//
// Part of the data-centric TEE prototype; the argument and the measured
// results are in playground_2626/PROJECT.md. Kept under sec/ so the thesis work stays separable
// from upstream Vortex in a diff.

#pragma once

#include <simobject.h>
#include <cstdint>
#include <iosfwd>
#include <vector>
#include "types.h"
#include "label.h"

namespace vortex {

// Buffer policy header. One of these covers a whole buffer chunk
// (2^buffer_log2 bytes, ~MB by design), which is what makes the header store
// small enough to keep on chip.
//
// Read-only in steady state: revocation advances `current_epoch` on the
// checker rather than writing headers, so the check stays a pure cacheable
// read that can overlap the DRAM access it gates (thesis §6).
//
// Headers live in a direct-mapped, *tagged* store (see MemChecker::Config
// ::header_entries). A granule with no installed header is unclaimed and is
// governed by the boot default rather than by whatever entry it indexes —
// which is what makes an untagged store's silent aliasing impossible here.
//
// Header v2 (P1_and_taint_specv2.md T2, kernel_identity_oct16.md): an owner
// *set*, so unclaimed is the empty set and the wildcard owner is gone; X; and
// a grant that names the one tenant it is for. A grant exists only on a
// granule with a single owner (S4), whose epoch gates it.
struct BufferHeader {
  uint32_t owners = 0;        // tenant bitmask; empty = unclaimed
  uint32_t perms = 0;         // R|W|X for every owner — not epoch-gated
  uint32_t grantee = 0;       // the tenant the grant is for
  uint32_t grant_perms = 0;   // R|W|X for the grantee while the grant holds
  uint64_t grant_epoch = 0;   // grant valid while epoch(owner) <= grant_epoch
  bool     confined = false;  // the grant is confined: its reader is tainted
};

constexpr uint32_t PERM_R = 0x1;
constexpr uint32_t PERM_W = 0x2;
constexpr uint32_t PERM_X = 0x4;

// No tenant has this id, so a claim naming it is refused (it names someone
// other than the issuer). Header v2 has no wildcard owner: unclaimed memory
// is the empty owner set, governed by Config::default_perms.
constexpr uint32_t OWNER_ANY = 0xFFFFFFFFu;

// DCR setup path (Phase 3 step 4). Range 0x300+ reserved for the checker
// (0x280–0xFFF is free; DXA ends at 0x280. See playground_2626/PROJECT.md §2.4.)
// A buffer claim is staged across BUF_* registers and installed by a write to
// BUF_COMMIT; the staged values persist across commits so a later re-grant
// (Phase 4) can rewrite just BUF_EPOCH and commit again. These model the
// attested channel as trusted configuration, per the threat model.
// Mirrored in tests/regression/twotenant/common.h for the host side.
//
// "Attested channel" means the host command ring, and only that. The whole
// range is refused when it is reached from a device-resident command bundle
// (a CMD_LAUNCH_QMD descriptor or an OP_DRAW step list), which lives in
// tenant-writable memory and would otherwise let a tenant forge
// {BUF_OWNER, self} + {BUF_COMMIT, 1} and claim a victim's buffer — see
// CommandProcessor::DCR_PRIV_BEGIN in sim/common/cmd_processor.h, which
// mem_checker.cpp static_asserts against BASE/END below.
constexpr uint32_t DCR_CHECKER_BASE       = 0x300;
constexpr uint32_t DCR_CHECKER_BUF_BASE   = 0x300;  // buffer base address
constexpr uint32_t DCR_CHECKER_BUF_SIZE   = 0x301;  // buffer size in bytes
constexpr uint32_t DCR_CHECKER_BUF_OWNER  = 0x302;  // owner eid; must equal the issuer
constexpr uint32_t DCR_CHECKER_BUF_PERMS  = 0x303;  // PERM_R | PERM_W
constexpr uint32_t DCR_CHECKER_BUF_EPOCH  = 0x304;  // grant epoch (0xFFFFFFFF = no expiry)
constexpr uint32_t DCR_CHECKER_BUF_COMMIT = 0x305;  // write installs the staged claim
// Sets the issuer's entry in the per-owner epoch table (Phase 4 revocation):
// a tenant revokes its own grants, and only its own. Monotonic: a value that
// does not strictly increase the owner's current epoch is ignored, so
// revocation cannot be reversed by writing an earlier value back.
constexpr uint32_t DCR_CHECKER_EPOCH      = 0x306;
constexpr uint32_t DCR_CHECKER_BUF_SHARED = 0x307;  // staged non-owner perms (grant to others)
// Retired by authorship (spec D3). It staged which owner the next EPOCH write
// advanced, which let any writer expire any owner's grants. EPOCH now
// advances the issuer's own epoch; writes here are ignored.
constexpr uint32_t DCR_CHECKER_REVOKE_OWNER = 0x308;
// Confinement by taint (kernel_identity_oct16.md, SimX proof of concept;
// active only with VX_CHECKER_TAINT=1). BUF_JOINT stages the co-owner mask
// and BUF_CONFINED the confined bit for the next BUF_COMMIT. BUF_LEAVE
// removes one owner (the value) from every granule of the staged range:
// the release; the leaving owner must be the issuer.
constexpr uint32_t DCR_CHECKER_BUF_JOINT    = 0x309;
constexpr uint32_t DCR_CHECKER_BUF_CONFINED = 0x30A;
constexpr uint32_t DCR_CHECKER_BUF_LEAVE    = 0x30B;
// Header v2: the one tenant the staged grant (BUF_SHARED) is for.
constexpr uint32_t DCR_CHECKER_BUF_GRANTEE  = 0x30C;
constexpr uint32_t DCR_CHECKER_END        = 0x340;

// Spliced into the l3cache_→memsim_ binding, which is the off-chip boundary in
// every cache configuration (the L3 SimObject is constructed even when
// VX_CFG_L3_ENABLED=0, where it acts as a transparent arbiter — so this hook
// point does not move when the sweep changes cache config).
//
// PHASE 2 SCOPE — static single-owner. The header store is populated at
// construction with one owner covering all of global memory; the checker
// resolves a request's buffer, reads its header from the store,
// and allows or denies on owner + permission match. The DCR-driven who's-who
// setup that populates this from the host is Phase 3; the epoch register is
// wired but never advanced until Phase 4.
//
// Latency model: every lookup forwards with `lookup_latency` added (0 at the
// design point: the store is on chip). Nothing else about the request is
// touched — no data, no reordering.
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
class MemChecker : public SimObject<MemChecker>, public LabelAuthority {
public:
  struct Config {
    uint32_t num_ports = 1;
    uint32_t buffer_log2 = 20;      // log2 bytes covered by one header (1 MB)
    // Entries in the isolated header store. 0 = size it to cover the whole
    // device address space at this granularity, which is the design point (no
    // buffer can then fail to get an entry). A non-zero value models a store
    // too small for the address space, which is what a fine-granularity sweep
    // forces; claims that would collide in it are refused rather than aliased,
    // so the capacity limit shows up as claims_aliased instead of as silent
    // policy corruption. Rounded up to a power of two.
    uint32_t header_entries = 0;
    // Cycles every header-store lookup adds. 0 is the design point: the store
    // is on chip and R5 closed its read at 300 MHz with slack (there is no
    // header cache in front of it). Fine granularities push the store off chip
    // and cost a real memory access instead; the harness sets those explicitly.
    uint32_t lookup_latency = 0;
    bool     enforce = false;       // Phase 3: a deny actually blocks the request
    // Mechanism self-test. 0 = off; 1 = deny every check (with enforce this
    // poisons instruction fetches too — the victim executes garbage and the
    // run never terminates, so it only suits counter checks without enforce);
    // 2 = deny writes only, which completes cleanly under enforcement: the
    // kernel's output never reaches RAM and host verification fails.
    uint32_t test_deny = 0;
    // Confinement by taint (VX_CHECKER_TAINT=1). Off: the confined bit is
    // stored but ignored, and nothing taints or is refused for taint. Joint
    // owners are owners either way: the owner set is the header (v2).
    bool     taint = false;
    // Perms of unclaimed memory (VX_CHECKER_DEFAULT_PERMS, default
    // VX_CFG_CHECKER_DEFAULT_PERMS). D9 decided R|X; the build keeps R|W|X
    // until the stack rule (T12) and claim-what-you-write land.
    uint32_t default_perms = PERM_R | PERM_W | PERM_X;
  };

  struct PerfStats {
    uint64_t reqs = 0;          // requests crossing the boundary
    uint64_t checked = 0;       // AddrType::Global — subject to a policy check
    uint64_t bypassed = 0;      // IO / local-mem — carries no header, never gated
    uint64_t allows = 0;
    uint64_t denies = 0;
    uint64_t added_cycles = 0;  // total latency injected across all requests
    uint64_t faulted_reads = 0;   // enforced denies answered with a poison MemRsp
    uint64_t dropped_writes = 0;  // enforced denies dropped (writes are posted)
    uint64_t dcr_claims = 0;      // buffer claims committed over the DCR path
    uint64_t headers_written = 0; // header-store entries those claims installed
    uint64_t epoch_bumps = 0;     // per-owner epoch-table writes (scoped revocations)
    // Claims refused because a granule they cover already belongs to another
    // owner. Granule exclusivity is what lets one writer id per cache sector
    // be sufficient (install_claim(), playground_2626/PROJECT.md §2.3); a non-zero count here means
    // a setup would have put two owners in one granule and was fail-closed.
    uint64_t claims_rejected = 0;
    // Granules overwritten by their *existing* owner (re-grant). Distinguishes
    // a clean setup from a clobbered one: cross-owner overwrite is impossible
    // by construction now, so this counts only legitimate re-claims.
    uint64_t headers_reclaimed = 0;
    // Committed claims whose base or size was not granule-aligned. Diagnostic
    // only — legal and harmless under a single owner, but it is the condition
    // that makes outward rounding able to reach a neighbour's granule.
    uint64_t claims_unaligned = 0;
    // Claims refused because a granule they cover maps onto a header-store
    // entry already held by a *different* buffer. The store is direct-mapped
    // and tagged: entry index is (buffer_id mod entries) and the tag is the
    // buffer_id, so two buffers whose ids collide modulo the store size want
    // the same entry. Installing both would silently give one buffer the
    // other's policy, so the second claim is refused whole (fail closed) and
    // counted here. Non-zero means the store is too small for the granularity
    // in use — a capacity result worth reporting, not a bug to route around.
    uint64_t claims_aliased = 0;
    // Claims refused because the staged owner was not the issuer: a tenant
    // tried to claim (or re-claim, or re-grant) for someone else (spec D2).
    uint64_t claims_foreign = 0;
    // Labeled lines. Requests the port passed because a labeled cache issued
    // them (fills judged at delivery, writebacks authorized on entry), and
    // the denies the caches made at delivery.
    uint64_t labeled_passed = 0;
    uint64_t label_read_denies = 0;
    uint64_t label_write_denies = 0;
    // Confinement by taint. taint_raises: reads that added a contributor to
    // a core's taint. taint_denies: writes the permissions allowed but the
    // covering rule refused (owners do not cover the writer's taint).
    // leaves / leaves_refused: BUF_LEAVE commands applied or refused.
    uint64_t taint_raises = 0;
    uint64_t taint_denies = 0;
    uint64_t leaves = 0;
    uint64_t leaves_refused = 0;
    // Stack-slice rule (T12): accesses to a core's stack slice by anyone but
    // that core, and fetches from it.
    uint64_t stack_denies = 0;
    // The command processor's device path (D7): lines its DMA and event
    // commands moved, judged for the queue that issued them. Kept apart from
    // the port counters above, which the kernel's thread owns.
    uint64_t cp_lines = 0;
    uint64_t cp_bypassed = 0;
    uint64_t cp_allows = 0;
    uint64_t cp_denies = 0;
    uint64_t cp_faulted_reads = 0;
    uint64_t cp_dropped_writes = 0;
    uint64_t cp_taint_denies = 0;
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

  // Phase 3 step 4: the who's-who setup path. Handles DCR_CHECKER_BASE..END;
  // returns 0. Setup writes are configuration, not data-plane traffic — they
  // take effect immediately and cost no modelled cycles (the attested channel
  // is pre-launch setup, not on the measured path). `issuer` is the
  // command-processor queue (tenant) the write arrived on: staging is per
  // issuer, a claim or leave must name the issuer, and EPOCH advances the
  // issuer's own epoch.
  int dcr_write(uint32_t addr, uint32_t value, uint32_t issuer);

  // Phase 4 revocation, scoped to one owner: bumping owner_eid's epoch-table
  // entry invalidates only *that owner's* grants whose grant_epoch has
  // fallen behind. No per-access write to any header, and no effect on any
  // other owner's grants. owner_eid == OWNER_ANY is a no-op (OWNER_ANY
  // headers are never epoch-gated in the first place — see check()). Writes
  // that would not strictly increase the owner's epoch are ignored, so
  // revocation cannot be undone by replaying an earlier (or equal) value.
  void set_epoch(uint32_t owner_eid, uint64_t epoch);

  // The command processor's device path (D7). Judges one device line a CP
  // command moves (upload, download, copy, event) for `issuer`, the queue
  // (= tenant) whose command it is, with the predicate the ports use. A queue
  // whose index names no core owns nothing: it gets OWNER_ANY's perms or the
  // grant. With confinement on, `taint` carries what the line read brings
  // along (a copy's write must be covered by it), and a line leaving for the
  // host (`to_host`) is refused if it would carry any: data confined to its
  // owners never leaves the device through the CP. Returns whether the
  // access proceeds: a deny under enforcement stops it (the caller poisons a
  // read and drops a write); without enforcement it is only counted.
  bool cp_authorize(uint64_t addr, bool is_write, uint32_t issuer,
                    uint32_t* taint, bool to_host);

  const PerfStats& perf_stats() const;
  const FaultStatus& fault_status() const;

  void dump(std::ostream& os) const;

  // Config is read from the environment so a sweep can vary granularity and
  // lookup latency without a rebuild. Returns enabled=false when
  // VX_CHECKER is unset, in which case the checker is not constructed at all
  // and the l3→dram binding stays exactly as upstream leaves it.
  static bool env_config(Config* out);

  // LabelAuthority: what a labeled cache consults (sec/label.h).
  MemLabel resolve_label(uint64_t addr) const override;
  bool authorize(const MemLabel& label, uint32_t hart_id, bool is_write,
                 bool is_fetch, uint64_t addr) const override;
  bool enforcing() const override;
  std::shared_ptr<mem_block_t> poison() const override;
  void count_label_deny(bool is_write) override;

protected:
  void on_reset();
  void on_tick();

private:
  class Impl;
  Impl* impl_;

  friend class SimObject<MemChecker>;
};

}
