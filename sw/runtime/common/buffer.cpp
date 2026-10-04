// Copyright © 2019-2023
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

#include "vortex2_internal.h"

#include <cstdio>
#include <cstdlib>

namespace vx {

namespace {

// ---------------------------------------------------------------------------
// Checker auto-claim (data-centric TEE prototype — playground_2626/PROJECT.md).
//
// The in-tree OpenCL suite (bfs, kmeans, hotspot, lud, backprop, ...) allocates
// through the runtime rather than a hand-written main, so its buffers cannot be
// claimed the way tests/regression/{twotenant,revoke,revoke_scope} do — those
// issue the DCR writes themselves. Env-gating the claim here makes the whole
// suite runnable unmodified, which is what the Tier-1 overhead table needs
// (PROJECT.md §12, "The one prerequisite": one patch unblocks ~10 workloads).
//
// It lives in the driver-agnostic runtime on purpose: libvortex.so is built
// once from sw/runtime/common, so simx, rtlsim, opae, xrt and aved all inherit
// this without a second implementation. vx_mem_alloc funnels through
// vx_buffer_create, so hooking Buffer::create covers the legacy API too.
//
// Scope is deliberately SINGLE-OWNER. Tier 1 measures single-owner overhead on
// recognizable workloads, and one owner also sidesteps granule rounding:
// exclusivity rejects only CROSS-owner conflicts, so the up-to-two granules of
// outward slack a claim carries (PROJECT.md §10 m4) overlap a neighbour
// harmlessly when every claim names the same owner. A multi-tenant auto-claim
// would need twotenant's `used_size + 2*granule` padding hoisted in here —
// a different patch, and not what Tier 1 asks for.
//
// This is itself a datapoint for the "setup logic centralizes" claim
// (PROJECT.md §4): one place claims for every application, and no application
// changed to get it.
struct AutoClaimConfig {
  bool     enabled = false;
  bool     verbose = false;   // VX_CHECKER_AUTOCLAIM=2 logs every claim
  uint32_t owner   = 0;
};

const AutoClaimConfig& autoclaim_config() {
  static const AutoClaimConfig cfg = []() {
    AutoClaimConfig c;
    if (const char* s = std::getenv("VX_CHECKER_AUTOCLAIM")) {
      unsigned long v = std::strtoul(s, nullptr, 0);
      c.enabled = (v != 0);
      c.verbose = (v > 1);
    }
    if (const char* s = std::getenv("VX_CHECKER_AUTOCLAIM_OWNER")) {
      c.owner = (uint32_t)std::strtoul(s, nullptr, 0);
    }
    return c;
  }();
  return cfg;
}

// Installs one claim over [dev_addr, dev_addr + size).
//
// Six staged writes plus the commit, inside a CP batch so the ring takes one
// doorbell and one seqnum poll instead of seven round trips. The writes ride
// the command ring (cp_submit_*), which is what preserves the launch-boundary
// ordering PROJECT.md §2.2 Bound 1 rests on — a queued DCR write cannot
// overtake a running kernel.
//
// A failed claim is reported but never fails the allocation. A refused claim
// leaves the buffer *unprotected*, not unusable, and the checker's own
// claims_rejected / claims_aliased counters are the authority on whether a
// setup can be trusted (PROJECT.md §8.4). Turning a policy problem into an
// application crash would make the sweep harder to debug, not safer — but a
// silent failure would let a run look protected when it is not, so it prints.
void autoclaim_buffer(Device* dev, uint64_t dev_addr, uint64_t size) {
  const auto& cfg = autoclaim_config();
  if (!cfg.enabled || dev == nullptr || size == 0)
    return;

  // The DCR data bus is 32 bits and the checker stages base/size as uint32_t,
  // so a claim outside the low 4 GB cannot be expressed. Truncating would
  // install policy over the WRONG range — strictly worse than not claiming —
  // so refuse loudly instead and let the checker's counters stay honest.
  if ((dev_addr + size) > 0xFFFFFFFFull) {
    std::fprintf(stderr,
        "[VXDRV] checker autoclaim SKIPPED: [0x%llx, +%llu) exceeds the 32-bit "
        "DCR claim range; buffer is UNPROTECTED\n",
        (unsigned long long)dev_addr, (unsigned long long)size);
    return;
  }

  dev->cp_batch_begin();
  vx_result_t r = VX_SUCCESS;
  auto w = [&](uint32_t addr, uint32_t value) {
    if (r == VX_SUCCESS)
      r = dev->cp_submit_dcr_write(addr, value);
  };
  w(VX_DCR_CHECKER_BUF_BASE,   (uint32_t)dev_addr);
  w(VX_DCR_CHECKER_BUF_SIZE,   (uint32_t)size);
  w(VX_DCR_CHECKER_BUF_OWNER,  cfg.owner);
  w(VX_DCR_CHECKER_BUF_PERMS,  VX_CHECKER_PERM_R | VX_CHECKER_PERM_W);
  w(VX_DCR_CHECKER_BUF_SHARED, 0);  // no grant to non-owners under Tier 1
  w(VX_DCR_CHECKER_BUF_EPOCH,  VX_CHECKER_GRANT_NO_EXPIRY);
  w(VX_DCR_CHECKER_BUF_COMMIT, 1);  // installs the staged claim
  // cp_batch_end is always paired with cp_batch_begin, even on a mid-batch
  // error, or the ring lock is never released.
  auto batch_r = dev->cp_batch_end();
  if (r == VX_SUCCESS)
    r = batch_r;

  if (r != VX_SUCCESS) {
    std::fprintf(stderr,
        "[VXDRV] checker autoclaim FAILED for 0x%llx (%llu bytes), err=%d; "
        "buffer is UNPROTECTED\n",
        (unsigned long long)dev_addr, (unsigned long long)size, (int)r);
  } else if (cfg.verbose) {
    std::fprintf(stderr,
        "[VXDRV] checker autoclaim: addr=0x%llx size=%llu owner=%u\n",
        (unsigned long long)dev_addr, (unsigned long long)size, cfg.owner);
  }
}

} // namespace

Buffer::Buffer(Device* dev, uint64_t dev_addr, uint64_t size, uint32_t flags)
    : device_(dev), dev_addr_(dev_addr), size_(size), flags_(flags) {
    device_->retain();
    device_->register_buffer(this);
}

Buffer::~Buffer() {
    if (mapped_ && host_mirror_) {
        std::free(host_mirror_);
        host_mirror_ = nullptr;
    }
    if (device_) {
        // Best-effort free on the device. Ignore errors at destruction.
        device_->mem_free(dev_addr_);
        device_->unregister_buffer(this);
        device_->release();
    }
}

vx_result_t Buffer::create(Device* dev, uint64_t size, uint32_t flags,
                           Buffer** out) {
    if (!dev || !out || size == 0) return VX_ERR_INVALID_VALUE;
    uint64_t dev_addr = 0;
    auto r = dev->mem_alloc(size, flags, &dev_addr);
    if (r != VX_SUCCESS) return r;
    *out = new Buffer(dev, dev_addr, size, flags);
    autoclaim_buffer(dev, dev_addr, size);
    return VX_SUCCESS;
}

vx_result_t Buffer::reserve(Device* dev, uint64_t address, uint64_t size,
                            uint32_t flags, Buffer** out) {
    if (!dev || !out || size == 0) return VX_ERR_INVALID_VALUE;
    auto r = dev->mem_reserve(address, size, flags);
    if (r != VX_SUCCESS) return r;
    *out = new Buffer(dev, address, size, flags);
    autoclaim_buffer(dev, address, size);
    return VX_SUCCESS;
}

vx_result_t Buffer::access(uint64_t off, uint64_t size, uint32_t /*flags*/) {
    if (off + size > size_) return VX_ERR_INVALID_VALUE;
    // Access permissions are not tracked by the transport HAL — the CP is
    // the sole memory engine and the common-core allocator owns the map.
    return VX_SUCCESS;
}

vx_result_t Buffer::map_reserve(uint64_t off, uint64_t size, uint32_t flags,
                                void** out) {
    if (!out)                return VX_ERR_INVALID_VALUE;
    if (off + size > size_)  return VX_ERR_INVALID_VALUE;

    std::lock_guard<std::mutex> g(map_mu_);
    if (mapped_) return VX_ERR_NOT_SUPPORTED;   // single mapping at a time

    // Allocate a host mirror. map_commit prefills it from the device for
    // READ maps; unmap uploads it back for WRITE maps. Correct (no
    // use-after-free) but loses the zero-copy benefit pinned memory
    // would provide on real hardware.
    host_mirror_ = std::malloc(size);
    if (!host_mirror_) return VX_ERR_OUT_OF_HOST_MEMORY;

    mapped_off_   = off;
    mapped_size_  = size;
    mapped_flags_ = flags;
    mapped_       = true;
    *out = host_mirror_;
    return VX_SUCCESS;
}

vx_result_t Buffer::map_commit() {
    std::lock_guard<std::mutex> g(map_mu_);
    if (!mapped_) return VX_ERR_INVALID_VALUE;
    if ((mapped_flags_ & VX_MEM_READ) && mapped_size_ != 0) {
        return device_->dev_read(host_mirror_, dev_addr_ + mapped_off_,
                                 mapped_size_);
    }
    return VX_SUCCESS;
}

void Buffer::map_cancel() {
    std::lock_guard<std::mutex> g(map_mu_);
    if (mapped_) {
        std::free(host_mirror_);
        host_mirror_ = nullptr;
        mapped_      = false;
    }
}

vx_result_t Buffer::map(uint64_t off, uint64_t size, uint32_t flags,
                        void** out) {
    auto r = this->map_reserve(off, size, flags, out);
    if (r != VX_SUCCESS) return r;
    r = this->map_commit();
    if (r != VX_SUCCESS) this->map_cancel();
    return r;
}

vx_result_t Buffer::unmap(void* host_ptr) {
    std::lock_guard<std::mutex> g(map_mu_);
    if (!mapped_ || host_ptr != host_mirror_)
        return VX_ERR_INVALID_VALUE;
    vx_result_t r = VX_SUCCESS;
    if (mapped_flags_ & VX_MEM_WRITE) {
        r = device_->dev_write(dev_addr_ + mapped_off_, host_mirror_,
                               mapped_size_);
    }
    std::free(host_mirror_);
    host_mirror_ = nullptr;
    mapped_      = false;
    return r;
}

} // namespace vx

// ============================================================================
// C entry points
// ============================================================================

using namespace vx;

extern "C" vx_result_t vx_buffer_create(vx_device_h dev, uint64_t size,
                                        uint32_t flags, vx_buffer_h* out) {
    VX_C_ENTRY_TRY
    if (!dev || !out) return VX_ERR_INVALID_VALUE;
    Buffer* b = nullptr;
    auto r = Buffer::create(to_device(dev), size, flags, &b);
    if (r != VX_SUCCESS) return r;
    *out = to_handle(b);
    return VX_SUCCESS;
    VX_C_ENTRY_CATCH
}

extern "C" vx_result_t vx_buffer_reserve(vx_device_h dev, uint64_t address,
                                         uint64_t size, uint32_t flags,
                                         vx_buffer_h* out) {
    VX_C_ENTRY_TRY
    if (!dev || !out) return VX_ERR_INVALID_VALUE;
    Buffer* b = nullptr;
    auto r = Buffer::reserve(to_device(dev), address, size, flags, &b);
    if (r != VX_SUCCESS) return r;
    *out = to_handle(b);
    return VX_SUCCESS;
    VX_C_ENTRY_CATCH
}

extern "C" vx_result_t vx_buffer_retain(vx_buffer_h buf) {
    if (!buf) return VX_ERR_INVALID_HANDLE;
    to_buffer(buf)->retain();
    return VX_SUCCESS;
}

extern "C" vx_result_t vx_buffer_release(vx_buffer_h buf) {
    if (!buf) return VX_ERR_INVALID_HANDLE;
    to_buffer(buf)->release();
    return VX_SUCCESS;
}

extern "C" vx_result_t vx_buffer_address(vx_buffer_h buf, uint64_t* out) {
    if (!buf) return VX_ERR_INVALID_HANDLE;
    if (!out) return VX_ERR_INVALID_VALUE;
    *out = to_buffer(buf)->dev_address();
    return VX_SUCCESS;
}

extern "C" vx_result_t vx_buffer_access(vx_buffer_h buf, uint64_t offset,
                                        uint64_t size, uint32_t flags) {
    if (!buf) return VX_ERR_INVALID_HANDLE;
    return to_buffer(buf)->access(offset, size, flags);
}

extern "C" vx_result_t vx_buffer_map(vx_buffer_h buf, uint64_t offset,
                                     uint64_t size, uint32_t flags,
                                     void** out_host_ptr) {
    VX_C_ENTRY_TRY
    if (!buf)          return VX_ERR_INVALID_HANDLE;
    if (!out_host_ptr) return VX_ERR_INVALID_VALUE;
    return to_buffer(buf)->map(offset, size, flags, out_host_ptr);
    VX_C_ENTRY_CATCH
}

extern "C" vx_result_t vx_buffer_unmap(vx_buffer_h buf, void* host_ptr) {
    if (!buf) return VX_ERR_INVALID_HANDLE;
    return to_buffer(buf)->unmap(host_ptr);
}
