// Data-plane access checker — inline module on the LLC→DRAM wire. See mem_checker.h.

#include "mem_checker.h"
#include "mem/mem_block_pool.h"

#include <cmd_processor.h>   // CommandProcessor::DCR_PRIV_* (see static_assert below)

#include <cstdlib>
#include <cstring>
#include <ostream>
#include <algorithm>
#include <array>
#include <deque>
#include <atomic>

using namespace vortex;

// The Command Processor refuses DCR writes into the checker's configuration
// window when they arrive from a device-resident (tenant-writable) command
// bundle — see DCR_PRIV_BEGIN in sim/common/cmd_processor.h. That filter has
// to duplicate the range as literals, because sim/common must not depend on
// the simx-only checker. These are the compile-time link between the two: if
// the checker's register window ever moves, the CP's filter moves with it or
// the build stops, rather than silently reopening the control-plane bypass.
static_assert(CommandProcessor::DCR_PRIV_BEGIN == DCR_CHECKER_BASE,
              "CP privileged-DCR window must start at DCR_CHECKER_BASE");
static_assert(CommandProcessor::DCR_PRIV_END == DCR_CHECKER_END,
              "CP privileged-DCR window must end at DCR_CHECKER_END");

// Third consumer of the same window: the host runtime's auto-claim path
// (sw/runtime/common/buffer.cpp) issues these registers from outside the
// simulator, so the numbers now also live in VX_types.toml, from which both
// sw/VX_types.h and hw/VX_types.vh are generated. The RTL checker's decoder
// will read the same generated header. Bind the simx-private constants to the
// generated ones here, so a window that moves in one place stops the build
// instead of leaving the runtime claiming registers the checker does not
// implement — which would look like a successful setup and protect nothing.
static_assert(DCR_CHECKER_BUF_BASE     == VX_DCR_CHECKER_BUF_BASE,     "BUF_BASE drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_SIZE     == VX_DCR_CHECKER_BUF_SIZE,     "BUF_SIZE drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_OWNER    == VX_DCR_CHECKER_BUF_OWNER,    "BUF_OWNER drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_PERMS    == VX_DCR_CHECKER_BUF_PERMS,    "BUF_PERMS drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_EPOCH    == VX_DCR_CHECKER_BUF_EPOCH,    "BUF_EPOCH drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_COMMIT   == VX_DCR_CHECKER_BUF_COMMIT,   "BUF_COMMIT drifted from VX_types.toml");
static_assert(DCR_CHECKER_EPOCH        == VX_DCR_CHECKER_EPOCH,        "EPOCH drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_SHARED   == VX_DCR_CHECKER_BUF_SHARED,   "BUF_SHARED drifted from VX_types.toml");
static_assert(DCR_CHECKER_REVOKE_OWNER == VX_DCR_CHECKER_REVOKE_OWNER, "REVOKE_OWNER drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_JOINT    == VX_DCR_CHECKER_BUF_JOINT,    "BUF_JOINT drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_CONFINED == VX_DCR_CHECKER_BUF_CONFINED, "BUF_CONFINED drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_LEAVE    == VX_DCR_CHECKER_BUF_LEAVE,    "BUF_LEAVE drifted from VX_types.toml");
static_assert(DCR_CHECKER_BASE         == VX_DCR_CHECKER_STATE_BEGIN,  "window start drifted from VX_types.toml");
static_assert(DCR_CHECKER_END          == VX_DCR_CHECKER_STATE_END,    "window end drifted from VX_types.toml");
static_assert(PERM_R    == VX_CHECKER_PERM_R,    "PERM_R drifted from VX_types.toml");
static_assert(PERM_W    == VX_CHECKER_PERM_W,    "PERM_W drifted from VX_types.toml");
static_assert(PERM_X    == VX_CHECKER_PERM_X,    "PERM_X drifted from VX_types.toml");
static_assert(DCR_CHECKER_BUF_GRANTEE == VX_DCR_CHECKER_BUF_GRANTEE, "BUF_GRANTEE drifted from VX_types.toml");
static_assert(VX_CFG_CHECKER_TENANTS <= 32, "owner sets are 32-bit masks");
static_assert(OWNER_ANY == VX_CHECKER_OWNER_ANY, "OWNER_ANY drifted from VX_types.toml");

namespace {

uint32_t env_u32(const char* name, uint32_t fallback) {
  const char* raw = std::getenv(name);
  if (raw == nullptr || raw[0] == '\0')
    return fallback;
  return uint32_t(std::strtoul(raw, nullptr, 0));
}

bool env_flag(const char* name, bool fallback) {
  const char* raw = std::getenv(name);
  if (raw == nullptr || raw[0] == '\0')
    return fallback;
  return raw[0] != '0';
}

// Bound the modelled isolated store so a fine-granularity sweep can't try to
// allocate a header per cache line across the whole 32-bit space. At the
// granularities this study cares about (>=4 KB on a 32-bit space) the cap is
// never reached and every buffer gets its own entry. Below that the store can
// no longer cover the address space, and buffers whose ids collide in it
// contend for one entry — which the tag turns into a refused claim
// (claims_aliased) rather than into two buffers sharing one policy.
constexpr uint32_t MAX_HEADER_ENTRIES = 1u << 20;

// Bound growth of the per-owner epoch table the same way — owner ids are
// core ids in this design (a handful at most), so this cap is never reached
// in practice; it just stops a bogus REVOKE_OWNER value from resizing the
// table unboundedly.
constexpr uint32_t MAX_OWNERS = 1u << 12;

// Owner sets and taints are bitmasks by eid, so confinement covers eids
// below 32. Eids are core ids in this prototype; 32 is far above any
// configuration the evaluation runs.
constexpr uint32_t MAX_TAINT_EIDS = 32;

inline uint32_t eid_bit(uint32_t eid) {
  return (eid < MAX_TAINT_EIDS) ? (1u << eid) : 0u;
}

}

class MemChecker::Impl {
private:
  // A synthesized response for a denied read, waiting for a free slot on the
  // response bus. `delay` carries the check latency it was charged.
  struct PendingFault {
    MemRsp   rsp;
    uint64_t delay;
  };

  MemChecker*  simobject_;
  Config       config_;
  // mutable: the predicate is const (a labeled cache only reads policy), but
  // with confinement on it also raises the requesting core's taint and counts.
  mutable PerfStats perf_stats_;
  FaultStatus  fault_;

  // Confinement by taint (kernel_identity_oct16.md). One taint per core: the
  // set of owners whose confined data the kernel on that core has read. In
  // this proof of concept the taint lives here rather than at the socket
  // boundary, so it is raised when a read is *judged* at the delivery edge
  // and read when a write is *judged*. Both are no earlier than the RTL
  // design's points (stamp when a request leaves the L1, snoop when a
  // response enters it), so the model can only over-restrict, never leak.
  // Kept across launches; cleared at a clean boundary (note_clean_boundary).
  mutable std::vector<uint32_t> taint_;

  // The launching tenant (tenant_from_launch). Written on the CP's thread
  // between launches, read on the kernel's.
  std::atomic<uint32_t> launch_tenant_{0};

  // Scrub boundaries (take_scrub_boundary): a clean boundary requested since
  // the last launch, whether any kernel has run, and the last one's tenant.
  std::atomic<bool> clean_pending_{false};
  bool     ran_ = false;
  uint32_t last_tenant_ = 0;

  // One shared poison block backs every fault response. The cache does
  // copy-on-write on shared fill data, so handing out the same block is safe.
  std::shared_ptr<mem_block_t> poison_;
  std::vector<std::deque<PendingFault>> fault_q_;
  std::vector<SimChannel<MemRsp>*> rsp_ports_;

  // The isolated metadata region. Writable only through this object — no
  // MemReq path reaches it, which is the simulator's stand-in for "checker-
  // writable only" (thesis §6: integrity by construction, no crypto).
  //
  // Direct-mapped and tagged: entry (id & header_mask_) holds the header for
  // buffer `tag`, and only for that buffer. An entry whose tag does not match
  // the buffer being looked up is not a header for it — the buffer is
  // unclaimed and falls to default_header_. Without the tag, two buffer ids
  // colliding modulo the store size would silently share one header, so a
  // claim on one would rewrite the other's policy and a check on one would be
  // answered from the other's owner (playground_2626/PROJECT.md §10, item #5).
  //
  // The tag is what makes the fail-closed rule in install_claim() expressible,
  // and the fail-closed rule is in turn what makes the permissive default on a
  // tag miss sound: an installed header is never displaced — a colliding claim
  // is refused instead — so "tag does not match" always means "never claimed",
  // never "claimed and evicted".
  struct StoreEntry {
    BufferHeader header;
    uint64_t     tag = 0;
    bool         valid = false;
  };
  std::vector<StoreEntry> header_store_;
  uint32_t header_mask_;

  // Policy for granules with no installed header: the empty owner set with
  // Config::default_perms (D9). Holding it in one place
  // rather than pre-filling every entry is what lets an entry's valid bit mean
  // "claimed" — the property the tag check depends on.
  BufferHeader default_header_;

  // Per-owner epoch table (fix for the global-revocation bug: owner A
  // revoking its grant to B must not also expire owner C's unrelated grant
  // to D). Indexed by tenant: the *granting* owner, not
  // the grantee — since that is what the check in check() compares against.
  // Sized on demand; an owner with no entry yet reads as epoch 0, matching
  // the pre-revocation default every owner started at.
  std::vector<uint64_t> epoch_table_;

  uint32_t last_revoked_owner_ = OWNER_ANY;

  // Staged DCR claim (Phase 3 step 4). Persists across commits so a re-grant
  // can rewrite one register and commit again.
  struct Claim {
    uint32_t base = 0;
    uint32_t size = 0;
    uint32_t owner = 0;
    uint32_t perms = 0;
    uint32_t shared = 0;
    uint32_t epoch = 0xFFFFFFFFu;
    uint32_t joint = 0;
    uint32_t confined = 0;
    uint32_t grantee = 0;
  };
  // One staging set per issuer (spec D3). With shared staging, another queue's
  // BUF_BASE/SIZE written between a tenant's staging and its COMMIT would
  // retarget that tenant's claim.
  std::array<Claim, VX_CFG_CHECKER_TENANTS> claims_;

public:
  Impl(MemChecker* simobject, const Config& config)
    : simobject_(simobject)
    , config_(config) {
    // Size the store to cover the device address space at this granularity,
    // unless the harness pins a capacity to model a store that cannot.
    uint64_t entries;
    if (config_.header_entries != 0) {
      entries = 1ull << log2ceil(config_.header_entries);
    } else {
      entries = 1ull << (VX_CFG_MEM_ADDR_WIDTH - std::min<uint32_t>(config_.buffer_log2, VX_CFG_MEM_ADDR_WIDTH));
    }
    entries = std::min<uint64_t>(entries, MAX_HEADER_ENTRIES);
    if (entries == 0)
      entries = 1;
    header_store_.resize(entries);
    header_mask_ = uint32_t(entries - 1);
    config_.header_entries = uint32_t(entries);

    // Unclaimed memory: no owners, the default perms, no grant.
    default_header_.owners = 0;
    default_header_.perms = config_.default_perms & (PERM_R | PERM_W | PERM_X);
    default_header_.grant_perms = 0;
    default_header_.grant_epoch = UINT64_MAX;

    poison_ = make_mem_block();
    std::memset(poison_->data(), 0xDD, poison_->size());
    fault_q_.resize(config_.num_ports);
    rsp_ports_.resize(config_.num_ports, nullptr);
    taint_.assign(MAX_TAINT_EIDS, 0);
  }

  void attach_rsp_port(uint32_t port, SimChannel<MemRsp>* chan) {
    rsp_ports_.at(port) = chan;
  }

  ~Impl() {}

  // The policy governing `buffer_id`: its own header if it has one installed,
  // otherwise the default. The tag comparison is the whole aliasing fix.
  const BufferHeader& header_for(uint64_t buffer_id) const {
    const StoreEntry& entry = header_store_[buffer_id & header_mask_];
    return (entry.valid && entry.tag == buffer_id) ? entry.header
                                                   : default_header_;
  }

  uint64_t epoch_for(uint32_t owner) const {
    return (owner < epoch_table_.size()) ? epoch_table_[owner] : 0;
  }

  void set_epoch(uint32_t owner, uint64_t epoch) {
    // Owners are tenants; the issuer always is one, so this only guards the
    // table against a bogus index.
    if (owner >= MAX_OWNERS)
      return;
    if (owner >= epoch_table_.size())
      epoch_table_.resize(owner + 1, 0);
    // Monotonicity guard: revocation must not be reversible. A write that
    // would move the owner's epoch backward (or hold it steady) is silently
    // ignored rather than un-revoking already-expired grants.
    if (epoch <= epoch_table_[owner])
      return;
    epoch_table_[owner] = epoch;
    ++perf_stats_.epoch_bumps;
    last_revoked_owner_ = owner;
  }

  // The who's-who setup path. Configuration writes take effect immediately:
  // every check reads header_store_ directly, so nothing needs invalidating
  // for a claim to become visible.
  //
  // `issuer` is the command-processor queue the write came from, i.e. the
  // tenant (spec D1/D2). Staging is per issuer, claims and leaves are judged
  // against it, and a revocation advances the issuer's own epoch.
  int dcr_write(uint32_t addr, uint32_t value, uint32_t issuer) {
    if (issuer >= claims_.size()) {
      ++perf_stats_.claims_foreign;
      return 0;
    }
    Claim& c = claims_[issuer];
    switch (addr) {
    case DCR_CHECKER_BUF_BASE:   c.base  = value; break;
    case DCR_CHECKER_BUF_SIZE:   c.size  = value; break;
    case DCR_CHECKER_BUF_OWNER:  c.owner = value; break;
    case DCR_CHECKER_BUF_PERMS:  c.perms = value; break;
    case DCR_CHECKER_BUF_EPOCH:  c.epoch = value; break;
    case DCR_CHECKER_BUF_SHARED: c.shared = value; break;
    case DCR_CHECKER_BUF_JOINT:    c.joint = value; break;
    case DCR_CHECKER_BUF_CONFINED: c.confined = value; break;
    case DCR_CHECKER_BUF_GRANTEE:  c.grantee = value; break;
    case DCR_CHECKER_BUF_LEAVE:
      this->leave(c, value, issuer);
      break;
    case DCR_CHECKER_BUF_COMMIT:
      this->install_claim(c, issuer);
      break;
    case DCR_CHECKER_REVOKE_OWNER:
      // Retired (spec D3): a revocation advances the issuer's own epoch, so
      // no one can expire another owner's grants. Kept as a no-op address so
      // an old host image does not fault.
      break;
    case DCR_CHECKER_EPOCH:
      this->set_epoch(issuer, value);
      break;
    default:
      break;  // reserved registers in the checker range: ignore
    }
    return 0;
  }

  const PerfStats& perf_stats() const {
    return perf_stats_;
  }

  const FaultStatus& fault_status() const {
    return fault_;
  }

  void reset() {
    for (auto& q : fault_q_) {
      q.clear();
    }
    fault_ = FaultStatus{};
    // The taint is NOT cleared here (T8, option 3): the next kernel of the
    // same tenant inherits it. It clears at a clean boundary
    // (note_clean_boundary) the tenant requests. The taint is kept per
    // tenant, not per core, so a tenant also keeps it across another
    // tenant's kernels, where the RTL's scrub at the tenant change would
    // clear it: SimX can only over-restrict there.
  }

  void tick() {
    for (uint32_t i = 0; i < config_.num_ports; ++i) {
      // Inject pending fault responses into free response-bus slots. DRAM
      // responses arrive on the same channel via the untouched direct binding
      // and hold their slots first; try_send failing just means the bus is
      // busy this cycle — retry next tick.
      auto& faults = fault_q_.at(i);
      while (!faults.empty()) {
        if (!rsp_ports_.at(i)->try_send(faults.front().rsp, faults.front().delay))
          break;
        faults.pop_front();
      }

      if (req_in(i).empty())
        continue;
      // Respect downstream backpressure so the checker cannot make the DRAM
      // queue deeper than it is in the baseline.
      if (req_out(i).full())
        continue;
      auto& req = req_in(i).peek();
      bool allowed = true;
      uint64_t added = this->check(req, &allowed);
      if (allowed || !config_.enforce) {
        req_out(i).send(req, 1 + added);
      } else {
        this->deliver_fault(i, req, added);
      }
      req_in(i).pop();
    }
  }

  void dump(std::ostream& os) const {
    os << "CHECKER: reqs=" << perf_stats_.reqs
       << ", checked=" << perf_stats_.checked
       << ", bypassed=" << perf_stats_.bypassed
       << ", allow=" << perf_stats_.allows
       << ", deny=" << perf_stats_.denies
       << std::endl;
    os << "CHECKER: added_cycles=" << perf_stats_.added_cycles
       << ", per_req=" << (perf_stats_.reqs ? (double(perf_stats_.added_cycles) / double(perf_stats_.reqs)) : 0.0)
       << " cyc"
       << std::endl;
    os << "CHECKER: config: buffer=" << (1ull << config_.buffer_log2) << "B"
       << ", header_entries=" << config_.header_entries
       << ", lookup_lat=" << config_.lookup_latency
       << ", enforce=" << (config_.enforce ? 1 : 0)
       << std::endl;
    if (config_.enforce) {
      os << "CHECKER: enforce: faulted_reads=" << perf_stats_.faulted_reads
         << ", dropped_writes=" << perf_stats_.dropped_writes
         << std::endl;
    }
    if (perf_stats_.labeled_passed != 0 || perf_stats_.label_read_denies != 0
     || perf_stats_.label_write_denies != 0) {
      os << "CHECKER: labels: port_passed=" << perf_stats_.labeled_passed
         << ", deliver_read_deny=" << perf_stats_.label_read_denies
         << ", deliver_write_deny=" << perf_stats_.label_write_denies
         << std::endl;
    }
    if (perf_stats_.stack_denies != 0) {
      os << "CHECKER: stack: denies=" << perf_stats_.stack_denies << std::endl;
    }
    if (perf_stats_.scrubs != 0) {
      os << "CHECKER: scrubs=" << perf_stats_.scrubs << std::endl;
    }
    if (config_.taint) {
      os << "CHECKER: taint: clean_boundaries=" << perf_stats_.clean_boundaries << std::endl;
      os << "CHECKER: taint: raises=" << perf_stats_.taint_raises
         << ", write_denies=" << perf_stats_.taint_denies
         << ", leaves=" << perf_stats_.leaves
         << ", leaves_refused=" << perf_stats_.leaves_refused
         << std::endl;
    }
    if (perf_stats_.dcr_claims != 0 || perf_stats_.epoch_bumps != 0) {
      os << "CHECKER: setup: dcr_claims=" << perf_stats_.dcr_claims
         << ", headers_written=" << perf_stats_.headers_written
         << ", epoch_bumps=" << perf_stats_.epoch_bumps;
      if (perf_stats_.epoch_bumps != 0) {
        os << ", last_revoked_owner=" << last_revoked_owner_
           << ", epoch=" << this->epoch_for(last_revoked_owner_);
      }
      os << std::endl;
      os << "CHECKER: claims: rejected=" << perf_stats_.claims_rejected
         << ", aliased=" << perf_stats_.claims_aliased
         << ", reclaimed=" << perf_stats_.headers_reclaimed
         << ", unaligned=" << perf_stats_.claims_unaligned
         << ", foreign=" << perf_stats_.claims_foreign
         << std::endl;
    }
    if (perf_stats_.cp_lines != 0) {
      os << "CHECKER: cp: lines=" << perf_stats_.cp_lines
         << ", cp_bypassed=" << perf_stats_.cp_bypassed
         << ", cp_allow=" << perf_stats_.cp_allows
         << ", cp_deny=" << perf_stats_.cp_denies
         << ", cp_faulted_reads=" << perf_stats_.cp_faulted_reads
         << ", cp_dropped_writes=" << perf_stats_.cp_dropped_writes
         << ", cp_taint_denies=" << perf_stats_.cp_taint_denies
         << std::endl;
    }
    if (fault_.valid) {
      os << "CHECKER: first_fault: addr=0x" << std::hex << fault_.addr << std::dec
         << ", hart_id=" << fault_.hart_id
         << ", op=" << (fault_.is_write ? "write" : "read")
         << ", total=" << fault_.count
         << std::endl;
    }
  }

private:
  SimChannel<MemReq>& req_in(uint32_t i)  { return simobject_->req_in.at(i); }
  SimChannel<MemReq>& req_out(uint32_t i) { return simobject_->req_out.at(i); }

  // Maps a request to the entity whose policy governs it: one tenant per
  // core. hart_id is packed (core, warp, thread) by make_hart_id(), so the
  // owner is the core field shifted back out — no new MemReq field. Every
  // single-core configuration resolves to eid 0, so all Phase 2 results stay
  // reproducible by construction. Writeback attribution under this mapping:
  // sec/README.md §2. (An earlier note argued writebacks should be *exempt*
  // from the owner check and filed --cores=2 --l3cache as post-PoC work; that
  // is the configuration which then failed with 992 errors and forced the
  // opposite design. It is archived, not live — see playground_2626/PROJECT.md §17.)
public:
  // A header's label: the header minus the store's bookkeeping.
  static MemLabel label_of(const BufferHeader& header) {
    MemLabel label;
    label.valid       = true;
    label.owners      = header.owners;
    label.perms       = header.perms;
    label.grantee     = header.grantee;
    label.grant_perms = header.grant_perms;
    label.grant_epoch = header.grant_epoch;
    label.confined    = header.confined;
    return label;
  }

  MemLabel resolve_label(uint64_t addr) const {
    if (get_addr_type(addr) != AddrType::Global)
      return MemLabel{};
    return label_of(this->header_for(addr >> config_.buffer_log2));
  }

  // THE predicate (header v2, kernel_identity_oct16.md "The predicate").
  // check() applies it to a header at the memory port; a labeled cache to
  // the label it stored with the line; the CP path to every line it moves.
  // One function, so the placements cannot drift apart.
  //
  //   unclaimed (owners == {}):  need in perms (the default perms)
  //   eid an owner:              need in perms, never epoch-gated
  //   otherwise:                 eid == grantee, need in grant_perms, and
  //                              epoch(the owner) <= grant_epoch
  //
  // A grant exists only on a single-owner granule (S4, install_claim), so
  // "the owner" whose epoch gates it is the one bit of `owners`. Revoking
  // advances that owner's epoch, without writing any header, and expires
  // every cached copy of the grant at once.
  //
  // `contrib` is what an allowed read adds to the reader's taint: the other
  // owners of a joint granule, or the owners behind a confined grant.
  bool judge(const MemLabel& label, uint32_t eid, uint32_t need,
             uint32_t* contrib) const {
    const uint32_t me = eid_bit(eid);
    bool ok;
    *contrib = 0;
    if (label.owners == 0) {
      ok = (label.perms & need) != 0;
    } else if ((label.owners & me) != 0) {
      ok = (label.perms & need) != 0;
      *contrib = label.owners & ~me;
    } else {
      ok = (eid == label.grantee)
        && ((label.grant_perms & need) != 0)
        && (this->epoch_for(sole_owner(label.owners)) <= label.grant_epoch);
      *contrib = label.confined ? label.owners : 0u;
    }
    if (config_.test_deny == 1 || (config_.test_deny == 2 && need == PERM_W))
      ok = false;
    return ok;
  }

  static uint32_t need_of(bool is_write, bool is_fetch) {
    return is_write ? PERM_W : (is_fetch ? PERM_X : PERM_R);
  }

  // The lowest owner: the owner, on the single-owner granules grants exist on.
  static uint32_t sole_owner(uint32_t owners) {
    uint32_t i = 0;
    while (i < 31 && ((owners >> i) & 1u) == 0)
      ++i;
    return i;
  }

  // The stack slices (spec T12): a fixed hardware rule, no claims. Hart h's
  // stack is the 2^VX_MEM_STACK_LOG2_SIZE bytes below
  // VX_MEM_STACK_BASE_ADDR - h * that (sw/kernel/src/vx_start.S), so the
  // owning core of a stack address is arithmetic. Inside the region only the
  // slice's own core may read or write, never fetch; the covering check does
  // not apply and nothing taints. Everyone else is denied, including the
  // command processor (D7).
  static constexpr uint64_t STACK_TOP   = VX_MEM_STACK_BASE_ADDR;
  static constexpr uint32_t STACK_LOG2  = VX_MEM_STACK_LOG2_SIZE;
  static constexpr uint64_t STACK_HARTS = uint64_t(VX_CFG_NUM_CLUSTERS) * VX_CFG_NUM_CORES
                                        * VX_CFG_NUM_WARPS * VX_CFG_NUM_THREADS;
  static bool in_stack(uint64_t addr) {
    return addr < STACK_TOP && addr >= STACK_TOP - (STACK_HARTS << STACK_LOG2);
  }
  static uint32_t stack_core(uint64_t addr) {
    constexpr uint32_t LOG_WARPS   = log2ceil(VX_CFG_NUM_WARPS);
    constexpr uint32_t LOG_THREADS = log2ceil(VX_CFG_NUM_THREADS);
    const uint64_t hart = (STACK_TOP - 1 - addr) >> STACK_LOG2;
    return uint32_t(hart >> (LOG_WARPS + LOG_THREADS));
  }

  bool authorize(const MemLabel& label, uint32_t hart_id, bool is_write,
                 bool is_fetch, uint64_t addr) const {
    if (!label.valid)
      return true;   // no policy: IO / local memory
    if (in_stack(addr)) {
      bool ok = !is_fetch && (stack_core(addr) == this->core_of(hart_id));
      if (config_.test_deny == 1 || (config_.test_deny == 2 && is_write))
        ok = false;
      if (!ok)
        ++perf_stats_.stack_denies;
      return ok;
    }
    const uint32_t eid  = this->tenant_of(hart_id);
    const uint32_t need = need_of(is_write, is_fetch);
    uint32_t contrib;
    const bool ok = this->judge(label, eid, need, &contrib);
    if (!config_.taint || !ok || eid >= MAX_TAINT_EIDS)
      return ok;
    return this->apply_taint(label, eid, is_write, contrib);
  }

  // Confinement (kernel_identity_oct16.md). An allowed read raises the
  // reader's taint by its contributors; an allowed write must land in a
  // granule whose owners cover the writer's taint. Unclaimed memory covers
  // only an empty taint.
  bool apply_taint(const MemLabel& label, uint32_t eid, bool is_write,
                   uint32_t contrib) const {
    uint32_t& taint = taint_[eid];
    if (is_write) {
      if ((taint & ~label.owners) != 0) {
        ++perf_stats_.taint_denies;
        return false;
      }
    } else if ((contrib & ~taint) != 0) {
      taint |= contrib;
      ++perf_stats_.taint_raises;
    }
    return true;
  }

  // D7: one device line the command processor moves for queue `issuer`, the
  // tenant. Runs on the CP's thread while a kernel may be running on another,
  // so it reads policy (headers, epochs) and writes only its own cp_*
  // counters. Every queue is a tenant (header v2 indexes owners by tenant,
  // not by core); one that has claimed nothing simply owns nothing.
  bool cp_authorize(uint64_t addr, bool is_write, uint32_t issuer,
                    uint32_t* taint, bool to_host) {
    ++perf_stats_.cp_lines;
    if (get_addr_type(addr) != AddrType::Global) {
      ++perf_stats_.cp_bypassed;
      return true;
    }
    const MemLabel label = label_of(this->header_for(addr >> config_.buffer_log2));
    uint32_t contrib = 0;
    // T12: no queue reaches a core's stack slice.
    bool ok = !in_stack(addr)
           && this->judge(label, issuer, need_of(is_write, false), &contrib);
    if (ok && config_.taint && taint) {
      if (is_write) {
        if ((*taint & ~label.owners) != 0) {
          ok = false;
          ++perf_stats_.cp_taint_denies;
        }
      } else {
        *taint |= contrib;
        // S6: a download leaves the device. Joint data and confined grants
        // never leave that way.
        if (to_host && *taint != 0) {
          ok = false;
          ++perf_stats_.cp_taint_denies;
        }
      }
    }
    if (ok) {
      ++perf_stats_.cp_allows;
      return true;
    }
    ++perf_stats_.cp_denies;
    if (!config_.enforce)
      return true;
    if (is_write) ++perf_stats_.cp_dropped_writes;
    else          ++perf_stats_.cp_faulted_reads;
    return false;
  }

  bool enforcing() const { return config_.enforce; }

  // The issuer of a KMU launch-register write. The CP replays a launch's
  // registers from the launching queue's shadow, each write carrying that
  // queue, so the latest one before the launch starts names its tenant.
  void note_launch_issuer(uint32_t issuer) {
    launch_tenant_.store(issuer);
  }

  // A clean boundary (T8): the launch runs the full scrub on every core it
  // uses (take_scrub_boundary) and starts with an empty taint.
  void note_clean_boundary() {
    std::fill(taint_.begin(), taint_.end(), 0u);
    clean_pending_.store(true);
    ++perf_stats_.clean_boundaries;
  }

  // Called as a launch starts: does it cross a scrub boundary (T8)? Yes at a
  // clean boundary or a change of launching tenant; the first kernel is not
  // one (nothing ran before it), as in the RTL socket. One kernel runs at a
  // time, so a launch is every core's kernel change.
  bool take_scrub_boundary() {
    const uint32_t tenant = config_.tenant_from_launch ? launch_tenant_.load() : 0u;
    const bool scrub = ran_ && (clean_pending_.load() || tenant != last_tenant_);
    ran_ = true;
    last_tenant_ = tenant;
    clean_pending_.store(false);
    if (scrub)
      ++perf_stats_.scrubs;
    return scrub;
  }

  std::shared_ptr<mem_block_t> poison() const { return poison_; }

  void count_label_deny(bool is_write) {
    if (is_write) ++perf_stats_.label_write_denies;
    else          ++perf_stats_.label_read_denies;
  }

private:
  // The tenant a request runs as (spec T3): with tenant_from_launch, the CP
  // queue that launched the kernel (one kernel at a time on the device);
  // otherwise, in test mode, the core.
  uint32_t tenant_of(uint32_t hart_id) const {
    return config_.tenant_from_launch ? launch_tenant_.load() : this->core_of(hart_id);
  }

  uint32_t core_of(uint32_t hart_id) const {
    constexpr uint32_t LOG_WARPS   = log2ceil(VX_CFG_NUM_WARPS);
    constexpr uint32_t LOG_THREADS = log2ceil(VX_CFG_NUM_THREADS);
    return hart_id >> (LOG_WARPS + LOG_THREADS);
  }

  // Installs the staged claim over every granule overlapping
  // [base, base+size). Indexing matches check()'s (id & header_mask_), so the
  // claim lands on exactly the entries the data path will consult. All or
  // nothing: a refused claim leaves the store exactly as it was.
  //
  // The setup rules (kernel_identity_oct16.md S1, S4; spec T6), with the
  // issuer from the queue (D2):
  //   - the staged owner must be the issuer (authorship); the owner set is
  //     {issuer} plus the staged co-owners (BUF_JOINT);
  //   - S1 claim: any unclaimed granule;
  //   - S4 re-grant: a granule whose owner set is exactly {issuer}, with the
  //     owner set unchanged, may change its perms and its grant;
  //   - a grant (non-zero BUF_SHARED) only with a single owner, for a tenant;
  //   - nothing else. No re-claim changes an owner set (T6): owner sets grow
  //     only at claim time and shrink only by BUF_LEAVE.
  //
  // Granule exclusivity is what the write-back-cache identity fix depends on:
  // one writer id per cache sector is sufficient only because two claims can
  // never share a granule (playground_2626/PROJECT.md §2.3). Alignment is
  // counted, not enforced: a single-owner claim may sit unaligned and overlap
  // unclaimed code or stack granules harmlessly (vecadd_claimed relies on it).
  void install_claim(const Claim& c, uint32_t issuer) {
    if (c.size == 0)
      return;
    // Authorship (spec D2): a tenant claims for itself only. Counted apart
    // from rejected/aliased: it is an attempt, not a conflict or a capacity
    // limit.
    if (c.owner != issuer || issuer >= VX_CFG_CHECKER_TENANTS) {
      ++perf_stats_.claims_foreign;
      return;
    }
    const uint32_t tenants = (1u << VX_CFG_CHECKER_TENANTS) - 1;
    const uint32_t self    = eid_bit(issuer);
    const uint32_t owners  = self | (c.joint & tenants);
    const uint32_t grant   = c.shared & (PERM_R | PERM_W | PERM_X);
    // S4: a grant names one tenant, and only a sole owner grants.
    if (grant != 0 && (owners != self || c.grantee >= VX_CFG_CHECKER_TENANTS)) {
      ++perf_stats_.claims_rejected;
      return;
    }
    uint64_t first = uint64_t(c.base) >> config_.buffer_log2;
    uint64_t last  = (uint64_t(c.base) + c.size - 1) >> config_.buffer_log2;

    // Diagnostic: does this claim rely on the padding convention the
    // multi-tenant tests follow? Counted, never rejected.
    uint64_t granule_mask = (1ull << config_.buffer_log2) - 1;
    if ((uint64_t(c.base) & granule_mask) != 0
     || (uint64_t(c.size) & granule_mask) != 0)
      ++perf_stats_.claims_unaligned;

    // Pre-pass: refuse before mutating anything.
    for (uint64_t id = first; id <= last; ++id) {
      const StoreEntry& entry = header_store_[id & header_mask_];
      if (entry.valid && entry.tag != id) {
        // The entry this granule indexes belongs to a different buffer.
        // Installing here would hand that buffer this claim's policy (the
        // reason the store needs a tag at all, PROJECT.md §10 item #5).
        ++perf_stats_.claims_aliased;
        return;
      }
      const uint32_t cur = entry.valid ? entry.header.owners : 0u;
      if (cur != 0 && !(cur == self && owners == self)) {
        ++perf_stats_.claims_rejected;
        return;
      }
    }

    for (uint64_t id = first; id <= last; ++id) {
      StoreEntry& entry = header_store_[id & header_mask_];
      // A re-grant by the sole owner is legal and counted, so "no claim ever
      // replaced another" is a measured zero rather than an assumption.
      if (entry.valid && entry.header.owners != 0)
        ++perf_stats_.headers_reclaimed;
      entry.valid = true;
      entry.tag = id;
      entry.header.owners      = owners;
      entry.header.perms       = c.perms & (PERM_R | PERM_W | PERM_X);
      entry.header.grantee     = (grant != 0) ? c.grantee : 0u;
      entry.header.grant_perms = grant;
      entry.header.grant_epoch = (c.epoch == 0xFFFFFFFFu) ? UINT64_MAX
                                                          : uint64_t(c.epoch);
      entry.header.confined    = (grant != 0) && (c.confined != 0);
      ++perf_stats_.headers_written;
    }
    ++perf_stats_.dcr_claims;
  }

  // Release (S2): owner `eid` leaves every granule of the issuer's staged
  // range. All or nothing, like a claim: refused if any granule is
  // unclaimed, does not list `eid` as an owner, or would be left with no
  // owner. Only an owner removes itself: `eid` must be the issuer (spec D2).
  // A joint granule carries no grant, so the remaining set inherits none.
  void leave(const Claim& c, uint32_t eid, uint32_t issuer) {
    const uint32_t me = eid_bit(eid);
    if (c.size == 0 || me == 0 || eid != issuer) {
      ++perf_stats_.leaves_refused;
      return;
    }
    uint64_t first = uint64_t(c.base) >> config_.buffer_log2;
    uint64_t last  = (uint64_t(c.base) + c.size - 1) >> config_.buffer_log2;
    for (uint64_t id = first; id <= last; ++id) {
      const StoreEntry& entry = header_store_[id & header_mask_];
      if (!entry.valid || entry.tag != id) {
        ++perf_stats_.leaves_refused;
        return;
      }
      const uint32_t owners = entry.header.owners;
      if ((owners & me) == 0 || owners == me) {
        ++perf_stats_.leaves_refused;
        return;
      }
    }
    for (uint64_t id = first; id <= last; ++id)
      header_store_[id & header_mask_].header.owners &= ~me;
    ++perf_stats_.leaves;
  }

  // A denied request under enforcement never reaches DRAM. Reads get a poison
  // response after the check latency (fast-fail: the requester is unblocked
  // without paying a DRAM round-trip); writes are posted at this boundary and
  // are simply dropped, which also stops the functional RAM write that the
  // DRAM model would have applied.
  void deliver_fault(uint32_t port, const MemReq& req, uint64_t added) {
    if (!fault_.valid) {
      fault_.valid = true;
      fault_.is_write = req.is_write();
      fault_.addr = req.addr;
      fault_.hart_id = req.hart_id;
    }
    ++fault_.count;

    if (req.is_write()) {
      ++perf_stats_.dropped_writes;
      return;
    }
    ++perf_stats_.faulted_reads;
    MemRsp rsp{req.tag, req.hart_id, req.uuid};
    rsp.data = poison_;
    fault_q_.at(port).push_back({rsp, 1 + added});
  }

  // Returns the cycles of latency this request must absorb before it may be
  // forwarded to DRAM, and reports the policy decision through `allowed`.
  uint64_t check(const MemReq& req, bool* allowed) {
    ++perf_stats_.reqs;

    // Only global device memory carries a buffer header; IO and local-mem
    // traffic is structurally outside the policy and passes untouched.
    if (req.addr_type() != AddrType::Global) {
      ++perf_stats_.bypassed;
      return 0;
    }
    ++perf_stats_.checked;

    // Labeled lines: a labeled cache's fill is judged where its data is
    // delivered (the cache stores the label this port resolves for it), and
    // its writeback carries data that was authorized when it entered the
    // cache. Judging either here would be wrong twice over: a denied fill
    // would install poison in a shared cache that the owner then reads, and a
    // writeback names the evictor, not the writer. The header is still looked
    // up, because that lookup is what resolves the fill's label.
    uint64_t buffer_id = req.addr >> config_.buffer_log2;
    if (req.flags.labeled) {
      uint64_t added = config_.lookup_latency;
      ++perf_stats_.labeled_passed;
      ++perf_stats_.allows;
      *allowed = true;
      perf_stats_.added_cycles += added;
      return added;
    }
    uint64_t added = config_.lookup_latency;

    bool ok = this->authorize(label_of(this->header_for(buffer_id)),
                              req.hart_id, req.is_write(), req.flags.fetch, req.addr);

    if (ok) {
      ++perf_stats_.allows;
    } else {
      ++perf_stats_.denies;
    }
    *allowed = ok;

    perf_stats_.added_cycles += added;
    return added;
  }
};

///////////////////////////////////////////////////////////////////////////////

MemChecker::MemChecker(const SimContext& ctx, const char* name, const Config& config)
  : SimObject<MemChecker>(ctx, name)
  , req_in(config.num_ports, this)
  , req_out(config.num_ports, this)
  , impl_(new Impl(this, config))
{}

void MemChecker::attach_rsp_port(uint32_t port, SimChannel<MemRsp>* chan) {
  impl_->attach_rsp_port(port, chan);
}

MemChecker::~MemChecker() {
  delete impl_;
}

void MemChecker::on_reset() {
  impl_->reset();
}

void MemChecker::on_tick() {
  impl_->tick();
}


void MemChecker::set_epoch(uint32_t owner_eid, uint64_t epoch) {
  impl_->set_epoch(owner_eid, epoch);
}

int MemChecker::dcr_write(uint32_t addr, uint32_t value, uint32_t issuer) {
  return impl_->dcr_write(addr, value, issuer);
}

void MemChecker::note_launch_issuer(uint32_t issuer) {
  impl_->note_launch_issuer(issuer);
}

void MemChecker::note_clean_boundary() {
  impl_->note_clean_boundary();
}

bool MemChecker::take_scrub_boundary() {
  return impl_->take_scrub_boundary();
}

bool MemChecker::cp_authorize(uint64_t addr, bool is_write, uint32_t issuer,
                              uint32_t* taint, bool to_host) {
  return impl_->cp_authorize(addr, is_write, issuer, taint, to_host);
}

const MemChecker::PerfStats& MemChecker::perf_stats() const {
  return impl_->perf_stats();
}

const MemChecker::FaultStatus& MemChecker::fault_status() const {
  return impl_->fault_status();
}

void MemChecker::dump(std::ostream& os) const {
  impl_->dump(os);
}

MemLabel MemChecker::resolve_label(uint64_t addr) const {
  return impl_->resolve_label(addr);
}

bool MemChecker::authorize(const MemLabel& label, uint32_t hart_id, bool is_write,
                           bool is_fetch, uint64_t addr) const {
  return impl_->authorize(label, hart_id, is_write, is_fetch, addr);
}

bool MemChecker::enforcing() const {
  return impl_->enforcing();
}

std::shared_ptr<mem_block_t> MemChecker::poison() const {
  return impl_->poison();
}

void MemChecker::count_label_deny(bool is_write) {
  impl_->count_label_deny(is_write);
}

bool MemChecker::env_config(Config* out) {
  if (!env_flag("VX_CHECKER", false))
    return false;
  out->buffer_log2    = env_u32("VX_CHECKER_BUF_LOG2", 20);
  out->header_entries = env_u32("VX_CHECKER_HEADER_ENTRIES", 0);
  out->lookup_latency = env_u32("VX_CHECKER_LOOKUP_LAT", 0);
  out->enforce        = env_flag("VX_CHECKER_ENFORCE", false);
  out->test_deny      = env_u32("VX_CHECKER_TEST_DENY", 0);
  out->taint          = env_flag("VX_CHECKER_TAINT", false);
  out->default_perms  = env_u32("VX_CHECKER_DEFAULT_PERMS", VX_CFG_CHECKER_DEFAULT_PERMS);
  out->tenant_from_launch = env_flag("VX_CHECKER_TENANT_FROM_LAUNCH", false);
  return true;
}
