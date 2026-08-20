// Data-plane access checker — inline module on the LLC→DRAM wire. See mem_checker.h.

#include "mem_checker.h"
#include "mem/mem_block_pool.h"

#include <cstdlib>
#include <cstring>
#include <ostream>
#include <algorithm>
#include <deque>

using namespace vortex;

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
// allocate a header per cache line across the whole 32-bit space. Buffers
// beyond the cap wrap; at the granularities this study cares about (>=64 KB)
// the cap is never reached.
constexpr uint32_t MAX_HEADER_ENTRIES = 1u << 20;

// Bound growth of the per-owner epoch table the same way — owner ids are
// core ids in this design (a handful at most), so this cap is never reached
// in practice; it just stops a bogus REVOKE_OWNER value from resizing the
// table unboundedly.
constexpr uint32_t MAX_OWNERS = 1u << 12;

}

class MemChecker::Impl {
private:
  struct HCacheEntry {
    uint64_t tag = 0;
    bool     valid = false;
    uint64_t lru = 0;
  };

  // A synthesized response for a denied read, waiting for a free slot on the
  // response bus. `delay` carries the check latency it was charged.
  struct PendingFault {
    MemRsp   rsp;
    uint64_t delay;
  };

  MemChecker*  simobject_;
  Config       config_;
  PerfStats    perf_stats_;
  FaultStatus  fault_;

  // One shared poison block backs every fault response. The cache does
  // copy-on-write on shared fill data, so handing out the same block is safe.
  std::shared_ptr<mem_block_t> poison_;
  std::vector<std::deque<PendingFault>> fault_q_;
  std::vector<SimChannel<MemRsp>*> rsp_ports_;

  // The isolated metadata region. Writable only through this object — no
  // MemReq path reaches it, which is the simulator's stand-in for "checker-
  // writable only" (thesis §6: integrity by construction, no crypto).
  std::vector<BufferHeader> header_store_;
  uint32_t header_mask_;

  std::vector<HCacheEntry> hcache_;
  uint32_t hc_sets_;
  uint64_t hc_clock_;

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
  } claim_;

public:
  Impl(MemChecker* simobject, const Config& config)
    : simobject_(simobject)
    , config_(config)
    , hc_clock_(0) {
    // Size the store to cover the device address space at this granularity.
    uint64_t entries = 1ull << (VX_CFG_MEM_ADDR_WIDTH - std::min<uint32_t>(config_.buffer_log2, VX_CFG_MEM_ADDR_WIDTH));
    entries = std::min<uint64_t>(entries, MAX_HEADER_ENTRIES);
    if (entries == 0)
      entries = 1;
    header_store_.resize(entries);
    header_mask_ = uint32_t(entries - 1);

    if (config_.hcache_entries != 0) {
      uint32_t assoc = std::max<uint32_t>(1, std::min(config_.hcache_assoc, config_.hcache_entries));
      hc_sets_ = std::max<uint32_t>(1, config_.hcache_entries / assoc);
      config_.hcache_assoc = assoc;
      hcache_.resize(size_t(hc_sets_) * assoc);
    } else {
      hc_sets_ = 0;
    }

    poison_ = make_mem_block();
    std::memset(poison_->data(), 0xDD, poison_->size());
    fault_q_.resize(config_.num_ports);
    rsp_ports_.resize(config_.num_ports, nullptr);
  }

  void attach_rsp_port(uint32_t port, SimChannel<MemRsp>* chan) {
    rsp_ports_.at(port) = chan;
  }

  ~Impl() {}

  void install_single_owner(uint32_t owner_eid, uint32_t perms) {
    for (auto& header : header_store_) {
      header.owner_eid = owner_eid;
      header.perms = perms;
      header.shared_perms = 0;
      header.grant_epoch = UINT64_MAX;
    }
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
    epoch_table_[owner] = epoch;
    ++perf_stats_.epoch_bumps;
    last_revoked_owner_ = owner;
  }

  // The who's-who setup path. Configuration writes take effect immediately:
  // the header cache only models lookup *timing* (presence tags — the policy
  // check always reads header_store_ directly), so no invalidation is needed
  // for a claim to become visible.
  int dcr_write(uint32_t addr, uint32_t value) {
    switch (addr) {
    case DCR_CHECKER_BUF_BASE:   claim_.base  = value; break;
    case DCR_CHECKER_BUF_SIZE:   claim_.size  = value; break;
    case DCR_CHECKER_BUF_OWNER:  claim_.owner = value; break;
    case DCR_CHECKER_BUF_PERMS:  claim_.perms = value; break;
    case DCR_CHECKER_BUF_EPOCH:  claim_.epoch = value; break;
    case DCR_CHECKER_BUF_SHARED: claim_.shared = value; break;
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
    for (auto& entry : hcache_) {
      entry.valid = false;
    }
    hc_clock_ = 0;
    for (auto& q : fault_q_) {
      q.clear();
    }
    fault_ = FaultStatus{};
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
    uint64_t lookups = perf_stats_.hc_hits + perf_stats_.hc_misses;
    os << "CHECKER: reqs=" << perf_stats_.reqs
       << ", checked=" << perf_stats_.checked
       << ", bypassed=" << perf_stats_.bypassed
       << ", allow=" << perf_stats_.allows
       << ", deny=" << perf_stats_.denies
       << std::endl;
    os << "CHECKER: hcache: hits=" << perf_stats_.hc_hits
       << ", misses=" << perf_stats_.hc_misses
       << ", hit_rate=" << (lookups ? (100.0 * double(perf_stats_.hc_hits) / double(lookups)) : 0.0) << "%"
       << std::endl;
    os << "CHECKER: added_cycles=" << perf_stats_.added_cycles
       << ", per_req=" << (perf_stats_.reqs ? (double(perf_stats_.added_cycles) / double(perf_stats_.reqs)) : 0.0)
       << " cyc"
       << std::endl;
    os << "CHECKER: config: buffer=" << (1ull << config_.buffer_log2) << "B"
       << ", hcache_entries=" << config_.hcache_entries
       << ", assoc=" << config_.hcache_assoc
       << ", hit_lat=" << config_.hit_latency
       << ", miss_lat=" << config_.miss_latency
       << ", enforce=" << (config_.enforce ? 1 : 0)
       << std::endl;
    if (config_.enforce) {
      os << "CHECKER: enforce: faulted_reads=" << perf_stats_.faulted_reads
         << ", dropped_writes=" << perf_stats_.dropped_writes
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
  // phase3/writeback_attribution.md.
  uint32_t owner_of(uint32_t hart_id) const {
    constexpr uint32_t LOG_WARPS   = log2ceil(VX_CFG_NUM_WARPS);
    constexpr uint32_t LOG_THREADS = log2ceil(VX_CFG_NUM_THREADS);
    return hart_id >> (LOG_WARPS + LOG_THREADS);
  }

  // Installs the staged claim: every granule overlapping [base, base+size)
  // gets the staged owner/perms/epoch. Indexing matches check()'s
  // (id & header_mask_), so the claim lands on exactly the entries the
  // data path will consult.
  void install_claim() {
    if (claim_.size == 0)
      return;
    uint64_t first = uint64_t(claim_.base) >> config_.buffer_log2;
    uint64_t last  = (uint64_t(claim_.base) + claim_.size - 1) >> config_.buffer_log2;
    for (uint64_t id = first; id <= last; ++id) {
      auto& header = header_store_[id & header_mask_];
      header.owner_eid = claim_.owner;
      header.perms = claim_.perms;
      header.shared_perms = claim_.shared;
      header.grant_epoch = (claim_.epoch == 0xFFFFFFFFu) ? UINT64_MAX
                                                         : uint64_t(claim_.epoch);
      ++perf_stats_.headers_written;
    }
    ++perf_stats_.dcr_claims;
  }

  bool hcache_lookup(uint64_t buffer_id) {
    if (hcache_.empty())
      return false;   // no cache: every check pays the store fetch

    uint32_t set = uint32_t(buffer_id % hc_sets_);
    uint64_t tag = buffer_id / hc_sets_;
    size_t base = size_t(set) * config_.hcache_assoc;
    ++hc_clock_;

    for (uint32_t w = 0; w < config_.hcache_assoc; ++w) {
      auto& entry = hcache_[base + w];
      if (entry.valid && entry.tag == tag) {
        entry.lru = hc_clock_;
        return true;
      }
    }

    // Miss: install, evicting the least-recently-used way.
    size_t victim = base;
    for (uint32_t w = 0; w < config_.hcache_assoc; ++w) {
      auto& entry = hcache_[base + w];
      if (!entry.valid) { victim = base + w; break; }
      if (entry.lru < hcache_[victim].lru) victim = base + w;
    }
    hcache_[victim].valid = true;
    hcache_[victim].tag = tag;
    hcache_[victim].lru = hc_clock_;
    return false;
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

    uint64_t buffer_id = req.addr >> config_.buffer_log2;
    bool hit = this->hcache_lookup(buffer_id);
    if (hit) {
      ++perf_stats_.hc_hits;
    } else {
      ++perf_stats_.hc_misses;
    }
    uint64_t added = hit ? config_.hit_latency : config_.miss_latency;

    const BufferHeader& header = header_store_[buffer_id & header_mask_];
    uint32_t owner = this->owner_of(req.hart_id);
    uint32_t need = req.is_write() ? PERM_W : PERM_R;

    // Owner (and system/shared OWNER_ANY) access is not epoch-gated:
    // revocation expires grants to *others*, it does not evict the owner.
    // Non-owner access rides the shared grant, which the *granting* owner's
    // epoch-table entry gates — bumped via DCR_CHECKER_REVOKE_OWNER +
    // DCR_CHECKER_EPOCH, without writing any header (thesis §6). Scoped per
    // owner: revoking owner A's grants never advances owner C's entry, so
    // C's unrelated grant to D is untouched.
    bool ok;
    if (header.owner_eid == OWNER_ANY || header.owner_eid == owner) {
      ok = (header.perms & need) != 0;
    } else {
      ok = ((header.shared_perms & need) != 0)
        && (this->epoch_for(header.owner_eid) <= header.grant_epoch);
    }
    if (config_.test_deny == 1 || (config_.test_deny == 2 && req.is_write()))
      ok = false;

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

bool MemChecker::env_config(Config* out) {
  if (!env_flag("VX_CHECKER", false))
    return false;
  out->buffer_log2    = env_u32("VX_CHECKER_BUF_LOG2", 20);
  out->hcache_entries = env_u32("VX_CHECKER_HCACHE_ENTRIES", 16);
  out->hcache_assoc   = env_u32("VX_CHECKER_HCACHE_ASSOC", 4);
  out->hit_latency    = env_u32("VX_CHECKER_HIT_LAT", 0);
  out->miss_latency   = env_u32("VX_CHECKER_MISS_LAT", 4);
  out->enforce        = env_flag("VX_CHECKER_ENFORCE", false);
  out->test_deny      = env_u32("VX_CHECKER_TEST_DENY", 0);
  return true;
}
