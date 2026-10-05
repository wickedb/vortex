// Labeled lines — the data-plane checker's policy carried with the data.
//
// The memory-port checker resolves a granule's policy header where the lookup
// is already overlapped with a DRAM access, and attaches the result (a
// MemLabel, types.h) to the fill. Every shared cache stores the label with the
// line and, when it delivers the line, evaluates the *same* predicate the
// checker evaluates on a miss. So a hit in a cache shared between tenants is
// authorized like a miss is, without a header lookup inside the hierarchy.
//
// Revocation stays an epoch bump: the predicate reads the live per-owner epoch
// table, so every cached copy of a revoked grant loses its authority at once
// without being touched (the TTL in the networking analogy).
//
// Staleness. A cached label can only be stale conservatively within a launch:
// claims and grants are installed over the command ring, which waits for the
// launch to finish, and every launch ends with a device-wide cache flush that
// clears every line. Dropping that flush for shared levels (refresh-on-deny,
// non-epoch narrowing walks) is a later stage; see
// playground_2626/R6b_alternatives.md §3.2 and §7.4.

#pragma once

#include <cstdint>
#include <memory>
#include "types.h"

namespace vortex {

class LabelAuthority {
public:
  virtual ~LabelAuthority() = default;

  // The label for the granule containing `addr`, as the memory-port checker
  // would resolve it now. Non-global addresses get an invalid label, which
  // authorize() always allows: they carry no policy.
  virtual MemLabel resolve_label(uint64_t addr) const = 0;

  // The checker's predicate, applied to a label at the point of delivery.
  // `hart_id` identifies the requester (owner = core, as at the port).
  virtual bool authorize(const MemLabel& label, uint32_t hart_id, bool is_write) const = 0;

  // The block a denied read is answered with (shared with the port checker).
  virtual std::shared_ptr<mem_block_t> poison() const = 0;

  // Delivery-side counters, kept with the checker's so one dump covers both.
  virtual void count_label_deny(bool is_write) = 0;
};

}
