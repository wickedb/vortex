// Data-plane access checker — inline module on the LLC→DRAM wire. See mem_checker.h.

#include "mem_checker.h"
#include "mem/mem_block_pool.h"

#include <cmd_processor.h>   // CommandProcessor::DCR_PRIV_* (see static_assert below)

#include <cstdlib>
#include <cstring>
#include <ostream>
#include <algorithm>
#include <deque>

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
  // Cleared on reset(), which every launch performs: one kernel at a time on
  // the device, so a launch boundary is every core's kernel change.
  mutable std::vector<uint32_t> taint_;

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

  // Policy for granules with no installed header. install_single_owner() sets
  // it; the boot default is OWNER_ANY + R|W, i.e. unclaimed memory (kernel
  // code, stacks, launch args) is system/shared. Holding it in one place
  // rather than pre-filling every entry is what lets an entry's valid bit mean
  // "claimed" — the property the tag check depends on.
  BufferHeader default_header_;

  // Per-owner epoch table (fix for the global-revocation bug: owner A
  // revoking its grant to B must not also expire owner C's unrelated grant
  // to D). Indexed by BufferHeader::owner_eid — the *granting* owner, not
  // the grantee — since that is what the check in check() compares against.
  // Sized on demand; an owner with no entry yet reads as epoch 0, matching
  // the pre-revocation default every owner started at.
  std::vector<uint64_t> epoch_table_;

  // Staged target for the next DCR_CHECKER_EPOCH write (see
  // DCR_CHECKER_REVOKE_OWNER in mem_checker.h). OWNER_ANY means "nothing
  // staged" — a bare EPOCH write with no owner staged is a no-op.
  uint32_t revoke_owner_ = OWNER_ANY;
  uint32_t last_revoked_owner_ = OWNER_ANY;

  // Staged DCR claim (Phase 3 step 4). Persists across commits so a re-grant
  // can rewrite one register and commit again.
  struct {
    uint32_t base = 0;
    uint32_t size = 0;
    uint32_t owner = 0;
    uint32_t perms = 0;
    uint32_t shared = 0;
    uint32_t epoch = 0xFFFFFFFFu;
    uint32_t joint = 0;
    uint32_t confined = 0;
  } claim_;

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

    // Boot default: unclaimed memory is system/shared. Overwritten by
    // install_single_owner() at construction (see processor.cpp).
    default_header_.owner_eid = OWNER_ANY;
    default_header_.perms = PERM_R | PERM_W;
    default_header_.shared_perms = 0;
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

  // Installs one owner over all of global memory by moving the *default* —
  // the policy every granule with no claim of its own falls to. Equivalent to
  // the old blanket pre-fill of every entry, minus the part that made every
  // entry look claimed, which is what the tag check needs to distinguish.
  void install_single_owner(uint32_t owner_eid, uint32_t perms) {
    default_header_.owner_eid = owner_eid;
    default_header_.perms = perms;
    default_header_.shared_perms = 0;
    default_header_.grant_epoch = UINT64_MAX;
  }

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
    // OWNER_ANY headers are never epoch-gated (see check()), so scoping a
    // revocation to OWNER_ANY — staged or explicit — would be a no-op host
    // mistake, not a real grant to expire. Also covers the "nothing staged"
    // sentinel from a bare DCR_CHECKER_EPOCH write.
    if (owner == OWNER_ANY || owner >= MAX_OWNERS)
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
  int dcr_write(uint32_t addr, uint32_t value) {
    switch (addr) {
    case DCR_CHECKER_BUF_BASE:   claim_.base  = value; break;
    case DCR_CHECKER_BUF_SIZE:   claim_.size  = value; break;
    case DCR_CHECKER_BUF_OWNER:  claim_.owner = value; break;
    case DCR_CHECKER_BUF_PERMS:  claim_.perms = value; break;
    case DCR_CHECKER_BUF_EPOCH:  claim_.epoch = value; break;
    case DCR_CHECKER_BUF_SHARED: claim_.shared = value; break;
    case DCR_CHECKER_BUF_JOINT:    claim_.joint = value; break;
    case DCR_CHECKER_BUF_CONFINED: claim_.confined = value; break;
    case DCR_CHECKER_BUF_LEAVE:
      this->leave(value);
      break;
    case DCR_CHECKER_BUF_COMMIT:
      this->install_claim();
      break;
    case DCR_CHECKER_REVOKE_OWNER:
      revoke_owner_ = value;
      break;
    case DCR_CHECKER_EPOCH:
      this->set_epoch(revoke_owner_, value);
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
    // A launch starts every core on a new kernel with an empty taint. The
    // residue scrub (registers, local memory) that makes this sound is not
    // modelled yet; see the proposal's SimX section.
    std::fill(taint_.begin(), taint_.end(), 0u);
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
    if (config_.taint) {
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
    label.valid        = true;
    label.owner        = header.owner_eid;
    label.perms        = header.perms;
    label.shared_perms = header.shared_perms;
    label.grant_epoch  = header.grant_epoch;
    label.joint        = header.joint;
    label.confined     = header.confined;
    return label;
  }

  MemLabel resolve_label(uint64_t addr) const {
    if (get_addr_type(addr) != AddrType::Global)
      return MemLabel{};
    return label_of(this->header_for(addr >> config_.buffer_log2));
  }

  // THE predicate. check() applies it to a header at the memory port; a
  // labeled cache applies it to the label it stored with the line. One
  // function, so the placements cannot drift apart.
  //
  // Owner (and system/shared OWNER_ANY) access is not epoch-gated:
  // revocation expires grants to *others*, it does not evict the owner.
  // Non-owner access rides the shared grant, which the *granting* owner's
  // epoch-table entry gates — bumped via DCR_CHECKER_REVOKE_OWNER +
  // DCR_CHECKER_EPOCH, without writing any header (thesis §6). Scoped per
  // owner: revoking owner A's grants never advances owner C's entry, so
  // C's unrelated grant to D is untouched. The epoch is read live, which is
  // what lets one bump expire every cached copy of a grant at once.
  bool authorize(const MemLabel& label, uint32_t hart_id, bool is_write) const {
    if (!label.valid)
      return true;   // no policy: IO / local memory
    uint32_t owner = this->owner_of(hart_id);
    uint32_t need = is_write ? PERM_W : PERM_R;
    if (config_.taint)
      return this->authorize_taint(label, owner, need, is_write);
    bool ok;
    if (label.owner == OWNER_ANY || label.owner == owner) {
      ok = (label.perms & need) != 0;
    } else {
      ok = ((label.shared_perms & need) != 0)
        && (this->epoch_for(label.owner) <= label.grant_epoch);
    }
    if (config_.test_deny == 1 || (config_.test_deny == 2 && is_write))
      ok = false;
    return ok;
  }

  // The predicate with confinement (kernel_identity_oct16.md, "The
  // predicate"). The owner set is {owner} plus the joint co-owners; the
  // unclaimed default (OWNER_ANY) has an empty owner set. Every owner gets the
  // owner permissions, unchanged; a non-owner rides the shared grant, gated by
  // the granting owner's epoch, unchanged. Two additions:
  //   - an allowed read raises the reader's taint by its contributors: the
  //     other owners of a joint granule, or the owners behind a confined grant;
  //   - an allowed write must land in a granule whose owners cover the
  //     writer's taint. Unclaimed memory covers only an empty taint.
  bool authorize_taint(const MemLabel& label, uint32_t eid, uint32_t need,
                       bool is_write) const {
    const bool     unclaimed = (label.owner == OWNER_ANY);
    const uint32_t owners    = unclaimed ? 0u : (eid_bit(label.owner) | label.joint);
    const uint32_t me        = eid_bit(eid);
    const bool     is_owner  = unclaimed || (owners & me) != 0;
    bool ok;
    uint32_t contrib = 0;
    if (is_owner) {
      ok = (label.perms & need) != 0;
      contrib = owners & ~me;
    } else {
      ok = ((label.shared_perms & need) != 0)
        && (this->epoch_for(label.owner) <= label.grant_epoch);
      contrib = label.confined ? owners : 0u;
    }
    if (config_.test_deny == 1 || (config_.test_deny == 2 && is_write))
      ok = false;
    if (!ok || eid >= MAX_TAINT_EIDS)
      return ok;
    uint32_t& taint = taint_[eid];
    if (is_write) {
      if ((taint & ~owners) != 0) {
        ++perf_stats_.taint_denies;
        return false;
      }
    } else if ((contrib & ~taint) != 0) {
      taint |= contrib;
      ++perf_stats_.taint_raises;
    }
    return true;
  }

  bool enforcing() const { return config_.enforce; }

  std::shared_ptr<mem_block_t> poison() const { return poison_; }

  void count_label_deny(bool is_write) {
    if (is_write) ++perf_stats_.label_write_denies;
    else          ++perf_stats_.label_read_denies;
  }

private:
  uint32_t owner_of(uint32_t hart_id) const {
    constexpr uint32_t LOG_WARPS   = log2ceil(VX_CFG_NUM_WARPS);
    constexpr uint32_t LOG_THREADS = log2ceil(VX_CFG_NUM_THREADS);
    return hart_id >> (LOG_WARPS + LOG_THREADS);
  }

  // Installs the staged claim: every granule overlapping [base, base+size)
  // gets the staged owner/perms/epoch. Indexing matches check()'s
  // (id & header_mask_), so the claim lands on exactly the entries the
  // data path will consult.
  //
  // Granule exclusivity (fail-closed). A claim is rejected outright if any
  // granule it would cover already belongs to a *different* non-OWNER_ANY
  // owner. This is the invariant the write-back-cache identity fix depends
  // on: one writer id is stamped per cache sector, but the sector's dirty
  // mask accumulates bytes from every writer, so if two owners could share a
  // granule they could share a sector, and the last writer's identity would
  // authorize the other owner's bytes on the merged writeback (playground_2626/PROJECT.md §2.3).
  // Enforcing exclusivity here means two owners can never reach the same
  // sector, which is what makes one writer id per sector sufficient.
  //
  // Note this is deliberately *not* a blanket "base must be granule-aligned"
  // rule. Alignment is neither necessary nor sufficient: a single-owner claim
  // may sit unaligned and overlap code/stack granules harmlessly (all traffic
  // is one eid — tests/regression/vecadd_claimed relies on this to stay
  // cycle-identical to vecadd), while two *aligned* claims can still collide
  // through outward rounding when a size spills past a granule boundary.
  // Cross-owner conflict is the condition that actually matters, so that is
  // the one enforced; misalignment is counted for diagnostics instead.
  void install_claim() {
    if (claim_.size == 0)
      return;
    uint64_t first = uint64_t(claim_.base) >> config_.buffer_log2;
    uint64_t last  = (uint64_t(claim_.base) + claim_.size - 1) >> config_.buffer_log2;

    // Diagnostic: does this claim rely on the padding convention the
    // multi-tenant tests follow? Counted, never rejected.
    uint64_t granule_mask = (1ull << config_.buffer_log2) - 1;
    if ((uint64_t(claim_.base) & granule_mask) != 0
     || (uint64_t(claim_.size) & granule_mask) != 0)
      ++perf_stats_.claims_unaligned;

    // Pre-pass: reject before mutating anything, so a rejected claim leaves
    // the header store exactly as it was. Two independent reasons to refuse,
    // both fail-closed, counted separately because they say different things
    // about the setup — one is a policy conflict, the other a capacity limit.
    for (uint64_t id = first; id <= last; ++id) {
      const StoreEntry& entry = header_store_[id & header_mask_];
      if (entry.valid && entry.tag != id) {
        // The entry this granule indexes belongs to a different buffer.
        // Installing here would hand that buffer this claim's policy while
        // leaving it addressable under its own id — silent cross-buffer
        // corruption, and the reason the store needs a tag at all
        // (playground_2626/PROJECT.md §10, item #5). Refuse whole, whoever owns the occupant:
        // two buffers is the
        // problem, not two owners.
        ++perf_stats_.claims_aliased;
        return;
      }
      // Granule exclusivity, as before. An unclaimed granule is governed by
      // the default, so that is what a cross-owner conflict is measured
      // against when no header is installed yet.
      const BufferHeader& header = entry.valid ? entry.header : default_header_;
      if (header.owner_eid != OWNER_ANY && header.owner_eid != claim_.owner) {
        ++perf_stats_.claims_rejected;
        return;
      }
      // A re-claim may add co-owners but never drop one: only a co-owner
      // removes itself (BUF_LEAVE). Otherwise the owner could release joint
      // data to itself by re-claiming without its co-owners.
      if (entry.valid && (header.joint & ~this->staged_joint()) != 0) {
        ++perf_stats_.claims_rejected;
        return;
      }
    }

    for (uint64_t id = first; id <= last; ++id) {
      StoreEntry& entry = header_store_[id & header_mask_];
      // Re-claim by the same owner (e.g. a Phase 4 re-grant) is allowed and
      // counted, so "no owner ever silently replaced another" is a measured
      // zero rather than an assumption. Only an installed header can be
      // re-claimed; first claim over an unclaimed granule is not a re-claim,
      // which is why the valid bit is part of the test.
      if (entry.valid && entry.header.owner_eid == claim_.owner)
        ++perf_stats_.headers_reclaimed;
      entry.valid = true;
      entry.tag = id;
      entry.header.owner_eid = claim_.owner;
      entry.header.perms = claim_.perms;
      entry.header.shared_perms = claim_.shared;
      entry.header.grant_epoch = (claim_.epoch == 0xFFFFFFFFu) ? UINT64_MAX
                                                               : uint64_t(claim_.epoch);
      entry.header.joint    = this->staged_joint();
      entry.header.confined = (claim_.confined != 0);
      ++perf_stats_.headers_written;
    }
    ++perf_stats_.dcr_claims;
  }

  // The staged co-owner mask, minus the owner itself; empty for an OWNER_ANY
  // claim, which has no owners to add to.
  uint32_t staged_joint() const {
    if (claim_.owner == OWNER_ANY)
      return 0;
    return claim_.joint & ~eid_bit(claim_.owner);
  }

  // Release (S2): owner `eid` leaves every granule of the staged range. All
  // or nothing, like a claim: refused if any granule is unclaimed, does not
  // list `eid` as an owner, or would be left with no owner. When the leaving
  // owner is owner_eid, the lowest remaining co-owner takes its place, so the
  // owner set is exactly the old one minus `eid`.
  void leave(uint32_t eid) {
    const uint32_t me = eid_bit(eid);
    if (claim_.size == 0 || me == 0) {
      ++perf_stats_.leaves_refused;
      return;
    }
    uint64_t first = uint64_t(claim_.base) >> config_.buffer_log2;
    uint64_t last  = (uint64_t(claim_.base) + claim_.size - 1) >> config_.buffer_log2;
    for (uint64_t id = first; id <= last; ++id) {
      const StoreEntry& entry = header_store_[id & header_mask_];
      if (!entry.valid || entry.tag != id || entry.header.owner_eid == OWNER_ANY) {
        ++perf_stats_.leaves_refused;
        return;
      }
      uint32_t owners = eid_bit(entry.header.owner_eid) | entry.header.joint;
      if ((owners & me) == 0 || owners == me) {
        ++perf_stats_.leaves_refused;
        return;
      }
    }
    for (uint64_t id = first; id <= last; ++id) {
      BufferHeader& header = header_store_[id & header_mask_].header;
      if (header.owner_eid == eid) {
        uint32_t next = 0;
        while (((header.joint >> next) & 1u) == 0)
          ++next;
        header.owner_eid = next;
        header.joint &= ~eid_bit(next);
      } else {
        header.joint &= ~me;
      }
    }
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
                              req.hart_id, req.is_write());

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

void MemChecker::install_single_owner(uint32_t owner_eid, uint32_t perms) {
  impl_->install_single_owner(owner_eid, perms);
}

void MemChecker::set_epoch(uint32_t owner_eid, uint64_t epoch) {
  impl_->set_epoch(owner_eid, epoch);
}

int MemChecker::dcr_write(uint32_t addr, uint32_t value) {
  return impl_->dcr_write(addr, value);
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

bool MemChecker::authorize(const MemLabel& label, uint32_t hart_id, bool is_write) const {
  return impl_->authorize(label, hart_id, is_write);
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
  return true;
}
