// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

#include "cmd_processor.h"

#include <VX_config.h>     // VX_CFG_* device configuration
#include <VX_types.h>      // VX_ISA_IMPL_ID

#include <cstring>
#include <cassert>
#include <vector>

namespace vortex {

// ============================================================================
// Static GPU capability words
//
// GPU_DEV_CAPS / GPU_ISA_CAPS register values exposed as read-only MMIO.
// sw/runtime/common/vx_caps.h is the matching decoder.
// ============================================================================
namespace {
constexpr unsigned cp_clog2(uint64_t n) {
    unsigned r = 0;
    while ((uint64_t(1) << r) < n) ++r;
    return r;
}
uint64_t gpu_dev_caps() {
    const unsigned cluster_size = VX_CFG_NUM_CORES / VX_CFG_SOCKET_SIZE;
    static_assert(VX_CFG_NUM_WARPS < 128 && VX_CFG_NUM_CLUSTERS < 128
               && VX_CFG_NUM_CORES / VX_CFG_SOCKET_SIZE < 256,
                  "GPU_DEV_CAPS exact-count fields overflow");
    const unsigned bank_addr_w  = VX_CFG_PLATFORM_MEMORY_ADDR_WIDTH
                                - cp_clog2(VX_CFG_PLATFORM_MEMORY_NUM_BANKS);
    return  (uint64_t(VX_ISA_IMPL_ID) & 0xFF)
         | ((uint64_t(cp_clog2(VX_CFG_NUM_THREADS))  & 0x7)  << 8)
         | ((uint64_t(cp_clog2(VX_CFG_NUM_WARPS))    & 0x7)  << 11)
         | ((uint64_t(cp_clog2(VX_CFG_SOCKET_SIZE))  & 0x7)  << 14)
         | ((uint64_t(cp_clog2(cluster_size))        & 0x7)  << 17)
         | ((uint64_t(cp_clog2(VX_CFG_NUM_CLUSTERS)) & 0x7)  << 20)
         | ((uint64_t(cp_clog2(VX_CFG_ISSUE_WIDTH))  & 0x7)  << 23)
         | ((uint64_t(VX_CFG_LMEM_ENABLED ? VX_CFG_LMEM_LOG_SIZE : 0) & 0xFF) << 26)
         | ((uint64_t(cp_clog2(VX_CFG_PLATFORM_MEMORY_NUM_BANKS)) & 0x7) << 34)
         | ((uint64_t(bank_addr_w - 20) & 0x1F) << 37)
         | ((uint64_t(VX_CFG_NUM_WARPS)    & 0x7F) << 42)
         | ((uint64_t(cluster_size)        & 0xFF) << 49)
         | ((uint64_t(VX_CFG_NUM_CLUSTERS) & 0x7F) << 57);
}
uint64_t gpu_isa_caps() {
    return  (uint64_t(VX_CFG_MISA_EXT) << 32)
         | ((uint64_t(cp_clog2(VX_CFG_XLEN) - 4) & 0x3) << 30)
         |  uint64_t(VX_CFG_MISA_STD);
}
} // namespace

static_assert(CommandProcessor::NUM_QUEUES >= 1 && CommandProcessor::NUM_QUEUES <= 64,
              "queue q's registers live at 0x100 + q*0x40 below the 0x1000 MMIO window");

CommandProcessor::CommandProcessor(const Hooks& hooks)
    : hooks_(hooks) {
    for (auto& q : qs_) {
        for (uint32_t i = 0; i < NUM_SHADOW; ++i)
            q.shadow[i] = shadow_reset_value_(shadow_addr_(int(i)));
    }
}

bool CommandProcessor::queue_enabled_(uint32_t qi) const {
    return (cp_ctrl_ & 0x1) && (qs_[qi].regs.control & 0x1);
}

bool CommandProcessor::enabled() const {
    for (uint32_t qi = 0; qi < NUM_QUEUES; ++qi) {
        if (queue_enabled_(qi))
            return true;
    }
    return false;
}

bool CommandProcessor::busy() const {
    if (launch_state_ != LaunchState::Idle)
        return true;
    for (uint32_t qi = 0; qi < NUM_QUEUES; ++qi) {
        const QState& q = qs_[qi];
        if (queue_enabled_(qi)
         && (q.regs.head < q.regs.tail || q.cl_loaded || q.eng_state != EngState::Idle))
            return true;
    }
    return false;
}

// ============================================================================
// Launch shadow (D4)
// ============================================================================

int CommandProcessor::shadow_index_(uint32_t addr) {
    if (addr >= SHADOW_KMU_BEGIN && addr < SHADOW_KMU_END)
        return int(addr - SHADOW_KMU_BEGIN);
#ifdef VX_CFG_VM_ENABLE
    if (addr == VX_DCR_MMU_SATP_LO) return int(NUM_SHADOW_KMU);
    if (addr == VX_DCR_MMU_SATP_HI) return int(NUM_SHADOW_KMU + 1);
#endif
    return -1;
}

uint32_t CommandProcessor::shadow_addr_(int index) {
#ifdef VX_CFG_VM_ENABLE
    if (uint32_t(index) == NUM_SHADOW_KMU)     return VX_DCR_MMU_SATP_LO;
    if (uint32_t(index) == NUM_SHADOW_KMU + 1) return VX_DCR_MMU_SATP_HI;
#endif
    return SHADOW_KMU_BEGIN + uint32_t(index);
}

uint32_t CommandProcessor::shadow_reset_value_(uint32_t addr) {
    switch (addr) {
    case VX_DCR_KMU_BLOCK_DIM_X:   case VX_DCR_KMU_BLOCK_DIM_Y:   case VX_DCR_KMU_BLOCK_DIM_Z:
    case VX_DCR_KMU_GRID_DIM_X:    case VX_DCR_KMU_GRID_DIM_Y:    case VX_DCR_KMU_GRID_DIM_Z:
    case VX_DCR_KMU_CLUSTER_DIM_X: case VX_DCR_KMU_CLUSTER_DIM_Y: case VX_DCR_KMU_CLUSTER_DIM_Z:
    case VX_DCR_KMU_WARP_STEP_X:   case VX_DCR_KMU_WARP_STEP_Y:   case VX_DCR_KMU_WARP_STEP_Z:
        return 1;
    default:
        return 0;
    }
}

// The launch takes the KMU, then the queue's shadow is written through,
// tagged with the queue, before start. The KMU stays with the queue until its
// kernel drains, so no other queue's launch registers reach the GPU in between.
bool CommandProcessor::try_begin_launch_(uint32_t qi) {
    if (launch_state_ != LaunchState::Idle)
        return false;
    launch_owner_ = qi;
    if (hooks_.vortex_dcr_write) {
        const QState& q = qs_[qi];
        for (uint32_t i = 0; i < NUM_SHADOW; ++i)
            hooks_.vortex_dcr_write(shadow_addr_(int(i)), q.shadow[i], qi);
    }
    launch_state_ = LaunchState::PulseStart;
    return true;
}

// ============================================================================
// DCR access on behalf of a queue (D2, D4, D5)
// ============================================================================

// A device-resident command bundle (QMD, OP_DRAW step list) is tenant-
// rewritable (see DCR_PRIV_BEGIN in cmd_processor.h), so the checker's
// configuration window is unreachable from it: a forged {BUF_OWNER, self} /
// {BUF_COMMIT, 1} pair must not become a privileged claim on a victim's
// buffer. Dropped silently and counted rather than raising Q_ERROR — a refused
// write is a policy decision on a per-pair basis, not a malformed command, and
// stalling the queue would turn the attempt into a denial of service against
// the legitimate launch that carries the rest of the bundle. Q_DCR_BLOCKED
// (0x134) makes the attempt observable.
bool CommandProcessor::dcr_write_(uint32_t qi, uint32_t addr, uint32_t value,
                                  bool indirect) {
    QState& q = qs_[qi];
    if (indirect && addr >= DCR_PRIV_BEGIN && addr < DCR_PRIV_END) {
        if (q.dcr_blocked != 0xFFFFFFFFu)   // saturate rather than wrap
            ++q.dcr_blocked;
        return false;
    }
    const int si = shadow_index_(addr);
    if (si >= 0) {
        q.shadow[si] = value;
        return true;
    }
    if (hooks_.vortex_dcr_write)
        hooks_.vortex_dcr_write(addr, value, qi);
    return true;
}

uint32_t CommandProcessor::dcr_read_(uint32_t qi, uint32_t addr, uint32_t tag) {
#if VX_CFG_CHECKER_DEBUG_READS == 0
    if (addr >= DCR_PRIV_BEGIN && addr < DCR_PRIV_END) {
        QState& q = qs_[qi];
        if (q.dcr_blocked != 0xFFFFFFFFu)
            ++q.dcr_blocked;
        return 0;
    }
#endif
    // A queue reads back its own launch registers, not whichever queue's
    // the GPU last saw.
    const int si = shadow_index_(addr);
    if (si >= 0)
        return qs_[qi].shadow[si];
    return hooks_.vortex_dcr_read ? hooks_.vortex_dcr_read(addr, tag) : 0;
}

// ============================================================================
// MMIO surface
// ============================================================================

void CommandProcessor::mmio_write(uint32_t off, uint32_t value) {
    // Globals
    switch (off) {
        case 0x000: cp_ctrl_ = value; return;
        // CP_SATP — page-table root for the CP DMA's MMU.
        case 0x028: satp_ = (satp_ & 0xFFFFFFFF00000000ULL) |  uint64_t(value);         return;
        case 0x02C: satp_ = (satp_ & 0x00000000FFFFFFFFULL) | (uint64_t(value) << 32);  return;
        // STATUS / DEV_CAPS / CYCLE / GPU caps are RO; ignore writes.
        case 0x004: case 0x008: case 0x010: case 0x014:
        case 0x018: case 0x01C: case 0x020: case 0x024: return;
    }
    // Queue q: offsets 0x100 + q*0x40 .. +0x3F
    if (off >= 0x100 && off < 0x100 + NUM_QUEUES * 0x40) {
        Queue& r = qs_[(off - 0x100) / 0x40].regs;
        switch ((off - 0x100) % 0x40) {
            case 0x00: r.ring_base   = (r.ring_base & 0xFFFFFFFF00000000ULL) | uint64_t(value);            return;
            case 0x04: r.ring_base   = (r.ring_base & 0x00000000FFFFFFFFULL) | (uint64_t(value) << 32);   return;
            case 0x08: r.head_addr   = (r.head_addr & 0xFFFFFFFF00000000ULL) | uint64_t(value);           return;
            case 0x0C: r.head_addr   = (r.head_addr & 0x00000000FFFFFFFFULL) | (uint64_t(value) << 32);   return;
            case 0x10: r.cmpl_addr   = (r.cmpl_addr & 0xFFFFFFFF00000000ULL) | uint64_t(value);           return;
            case 0x14: r.cmpl_addr   = (r.cmpl_addr & 0x00000000FFFFFFFFULL) | (uint64_t(value) << 32);   return;
            case 0x18: r.ring_log2   = uint8_t(value & 0xFF);                                                 return;
            case 0x1C: r.control     = value;                                                                 return;
            case 0x20: r.tail_lo_staging = value;                                                             return;
            case 0x24: {
                // Atomic tail commit: writing the HI word completes the 64-bit update.
                r.tail = (uint64_t(value) << 32) | uint64_t(r.tail_lo_staging);
                return;
            }
            // SEQNUM / ERROR are RO; ignore.
            case 0x28: case 0x2C: return;
        }
    }
    // Unknown offset — silently ignored.
}

uint32_t CommandProcessor::mmio_read(uint32_t off) const {
    switch (off) {
        case 0x000: return cp_ctrl_;
        case 0x004: return uint32_t(busy() ? 1 : 0);    // CP_STATUS bit0
        case 0x008: {
            // CP_DEV_CAPS: {SUPPORTS_QMD:1 @bit26 | SUPPORTS_DRAW:1 @bit25 |
            // VM_ENABLED:1 @bit24 | AXI_TID_W:8 | RING_LOG2:8 | NUM_QUEUES:8}.
            // Defaults: TID=6, RING_LOG2=16. VM_ENABLED reflects the
            // build-config so the config-agnostic libvortex.so can discover VM
            // at open. SUPPORTS_DRAW / SUPPORTS_QMD = 1: this (Emulation) CP
            // decodes CMD_DRAW (OP_DRAW) and CMD_LAUNCH_QMD; the RTL CP
            // advertises 0 until its mirrors are synth-validated, so the
            // runtime falls back to plain ring commands there.
            uint32_t vm_enabled = 0;
#ifdef VX_CFG_VM_ENABLE
            vm_enabled = 1u << 24;
#endif
            const uint32_t supports_draw = 1u << 25;
            const uint32_t supports_qmd  = 1u << 26;
            const uint32_t fault_report  = hooks_.mmu_fault_report ? (1u << 27) : 0;
            return supports_qmd | supports_draw | vm_enabled | fault_report
                 | (uint32_t(6) << 16) | (uint32_t(16) << 8) | uint32_t(NUM_QUEUES);
        }
        case 0x010: return uint32_t(cycle_counter_ & 0xFFFFFFFF);
        case 0x014: return uint32_t(cycle_counter_ >> 32);
        case 0x018: return uint32_t(gpu_dev_caps() & 0xFFFFFFFF);
        case 0x01C: return uint32_t(gpu_dev_caps() >> 32);
        case 0x020: return uint32_t(gpu_isa_caps() & 0xFFFFFFFF);
        case 0x024: return uint32_t(gpu_isa_caps() >> 32);
        case 0x028: return uint32_t(satp_ & 0xFFFFFFFF);
        case 0x02C: return uint32_t(satp_ >> 32);
    }
    if (off >= 0x100 && off < 0x100 + NUM_QUEUES * 0x40) {
        const QState& q = qs_[(off - 0x100) / 0x40];
        const Queue& r = q.regs;
        switch ((off - 0x100) % 0x40) {
            case 0x00: return uint32_t(r.ring_base & 0xFFFFFFFF);
            case 0x04: return uint32_t(r.ring_base >> 32);
            case 0x08: return uint32_t(r.head_addr & 0xFFFFFFFF);
            case 0x0C: return uint32_t(r.head_addr >> 32);
            case 0x10: return uint32_t(r.cmpl_addr & 0xFFFFFFFF);
            case 0x14: return uint32_t(r.cmpl_addr >> 32);
            case 0x18: return uint32_t(r.ring_log2);
            case 0x1C: return r.control;
            case 0x20: return r.tail_lo_staging;
            case 0x24: return uint32_t(r.tail >> 32);
            case 0x28: return uint32_t(r.seqnum & 0xFFFFFFFF);
            case 0x2C: return r.error;
            case 0x30: return q.last_dcr_rsp;  // last CMD_DCR_READ response
            case 0x34: return q.dcr_blocked;   // privileged-window refusals
        }
    }
    return 0xDEADBEEF;
}

// ============================================================================
// VM — page-table walk (the CP DMA is an MMU-aware copy engine)
// ============================================================================

uint64_t CommandProcessor::cp_translate(uint64_t vaddr, bool physical) const {
#ifdef VX_CFG_VM_ENABLE
    if (physical || satp_ == 0)
        return vaddr;
    SATP_t satp(satp_);
    if (satp.get_mode() == BARE)
        return vaddr;
    // Sv32/Sv39 walk — mirrors VMManager::page_table_walk so the CP DMA and
    // the host driver resolve addresses identically.
    int i = VX_VM_PT_LEVEL - 1;
    vAddr_t va(vaddr);
    uint64_t cur_base_ppn = satp.get_base_ppn();
    for (;;) {
        uint64_t pte_addr  = cur_base_ppn * VX_VM_PT_SIZE
                           + va.vpn[i] * VX_VM_PTE_SIZE;
        uint64_t pte_bytes = 0;
        if (hooks_.dram_read)
            hooks_.dram_read(pte_addr, &pte_bytes, VX_VM_PTE_SIZE);
        PTE_t pte(pte_bytes);
        if (pte.v == 0)
            return vaddr;            // unmapped — pass through (defensive)
        if (pte.r == 0 && pte.w == 0 && pte.x == 0) {
            if (--i < 0)
                return vaddr;        // no leaf — pass through
            cur_base_ppn = pte.ppn;
            continue;
        }
        cur_base_ppn = pte.ppn;      // leaf found at level i
        break;
    }
    // Reconstruct the physical address. For a leaf found at level i > 0 (a
    // mega/gigapage) the low VX_VM_PAGE_LOG2_SIZE + i*VPN_BITS address bits
    // are the offset *within* the superpage and must come from the VA, not
    // from the (superpage-aligned) leaf PPN. For a 4 KB leaf (i == 0) this
    // reduces to the ordinary ppn<<12 | page-offset.
    constexpr unsigned VPN_BITS = cp_clog2(VX_VM_PT_SIZE / VX_VM_PTE_SIZE);
    const uint64_t off_mask =
        (uint64_t(1) << (VX_VM_PAGE_LOG2_SIZE + i * VPN_BITS)) - 1;
    return ((cur_base_ppn << VX_VM_PAGE_LOG2_SIZE) & ~off_mask)
         | (vaddr & off_mask);
#else
    (void)physical;
    return vaddr;
#endif
}

// ============================================================================
// Fetch + unpack
// ============================================================================

void CommandProcessor::fetch_if_needed(QState& q) {
    if (q.cl_loaded) return;
    if (q.regs.head >= q.regs.tail) return;
    const uint64_t mask = (uint64_t(1) << q.regs.ring_log2) - 1;
    const uint64_t off  = q.regs.head & mask;
    if (!hooks_.dram_read) return;
    hooks_.dram_read(q.regs.ring_base + off, q.cl_buf.data(), CL_BYTES);
    q.cl_loaded   = true;
    q.cl_cmd_slot = 0;
    unpack_cl(q);
}

int CommandProcessor::decode_cmd(const QState& q, int off, Cmd& out) const {
    return decode_cmd_bytes(q.cl_buf.data(), int(CL_BYTES), off, out);
}

int CommandProcessor::decode_cmd_bytes(const uint8_t* buf, int len,
                                       int off, Cmd& out) {
    auto rd8 = [&](int o) -> uint8_t {
        return (o >= 0 && o < len) ? buf[o] : 0;
    };
    auto rd64 = [&](int o) -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= uint64_t(rd8(o + i)) << (8 * i);
        return v;
    };
    out.opcode   = rd8(off + 0);
    out.flags    = rd8(off + 1);
    out.reserved = uint16_t(rd8(off + 2)) | (uint16_t(rd8(off + 3)) << 8);
    out.arg0     = rd64(off + 4);
    out.arg1     = rd64(off + 12);
    out.arg2     = rd64(off + 20);
    // Command size in bytes by opcode.
    switch (out.opcode) {
        case OP_NOP:        return 4;
        case OP_LAUNCH:     return 12;
        case OP_LAUNCH_QMD: return 12;   // arg0 = QMD descriptor address
        case OP_DRAW:       return 12;   // arg0 = draw descriptor address
        case OP_FENCE:      return 8;
        case OP_CACHE_FLUSH: return 12;
        case OP_DCR_WRITE:  return 20;
        case OP_DCR_READ:   return 20;
        case OP_EVENT_SIG:  return 20;
        case OP_EVENT_WAIT: return 28;
        case OP_MEM_WRITE:
        case OP_MEM_READ:
        case OP_MEM_COPY:   return 28;
        default:            return 4;
    }
}

void CommandProcessor::unpack_cl(QState& q) {
    q.cl_cmd_count = 0;
    q.cl_cmd_slot  = 0;
    int offset = 0;
    for (int slot = 0; slot < MAX_CMDS_PER_CL; ++slot) {
        if (offset + 4 > int(CL_BYTES)) break;
        const uint8_t opcode = q.cl_buf[offset];
        const uint8_t flags  = q.cl_buf[offset + 1];
        // Zero header = padding sentinel; stop.
        if (opcode == 0 && flags == 0) break;
        Cmd c;
        const int sz = decode_cmd(q, offset, c);
        if (offset + sz > int(CL_BYTES)) break;
        ++q.cl_cmd_count;
        offset += sz;
    }
}

// ============================================================================
// Engine FSM
// ============================================================================

void CommandProcessor::publish_completion(const QState& q) {
    if (!hooks_.dram_write || q.regs.cmpl_addr == 0) return;
    uint64_t seq = q.regs.seqnum;
    hooks_.dram_write(q.regs.cmpl_addr, &seq, sizeof(seq));
}

// ----- The checker on the CP's device path (D7) -----
//
// Every device line a command moves is judged for the queue that issued the
// command, which is the tenant: the same identity the setup path uses. The
// RTL judges the same beats with a dedicated VX_mem_checker between the CP's
// device bridge and the memory fabric (VX_afu_wrap.sv). Ring fetches and
// completion writes are host memory and are not judged here or there.
static constexpr uint64_t DEV_LINE = 64;
static constexpr uint8_t  DEV_POISON = 0xDD;   // VX_checker_fault / MemChecker

void CommandProcessor::dev_read_(uint32_t qi, uint64_t addr, void* dst, std::size_t bytes) {
    if (!hooks_.dram_read) return;
    hooks_.dram_read(addr, dst, bytes);
    if (!hooks_.dev_authorize) return;
    auto* out = static_cast<uint8_t*>(dst);
    for (uint64_t off = 0; off < bytes; ) {
        uint64_t n = DEV_LINE - ((addr + off) % DEV_LINE);
        if (n > bytes - off) n = bytes - off;
        if (!hooks_.dev_authorize(addr + off, false, qi, nullptr, false))
            std::memset(out + off, DEV_POISON, std::size_t(n));
        off += n;
    }
}

void CommandProcessor::dev_write_(uint32_t qi, uint64_t addr, const void* src, std::size_t bytes) {
    if (!hooks_.dram_write) return;
    if (!hooks_.dev_authorize) {
        hooks_.dram_write(addr, src, bytes);
        return;
    }
    auto* in = static_cast<const uint8_t*>(src);
    for (uint64_t off = 0; off < bytes; ) {
        uint64_t n = DEV_LINE - ((addr + off) % DEV_LINE);
        if (n > bytes - off) n = bytes - off;
        if (hooks_.dev_authorize(addr + off, true, qi, nullptr, false))
            hooks_.dram_write(addr + off, in + off, std::size_t(n));
        off += n;
    }
}

// A transfer moves in pieces that straddle no line of either device operand,
// so each piece is one read line and one write line. A copy's write is judged
// with the taint its own read line brought along; a download's read is judged
// as leaving for the host.
void CommandProcessor::dev_transfer_(uint32_t qi, uint64_t dst, bool dst_dev,
                                     uint64_t src, bool src_dev, uint64_t total) {
    constexpr uint64_t CHUNK = 64 * 1024;
    std::vector<uint8_t> buf(std::size_t(total < CHUNK ? total : CHUNK));
    for (uint64_t done = 0; done < total; ) {
        uint64_t n = total - done;
        if (n > CHUNK) n = CHUNK;
        hooks_.dram_read(src + done, buf.data(), n);
        if (!hooks_.dev_authorize) {
            hooks_.dram_write(dst + done, buf.data(), n);
            done += n;
            continue;
        }
        for (uint64_t off = 0; off < n; ) {
            const uint64_t s = src + done + off, d = dst + done + off;
            uint64_t p = n - off;
            if (src_dev && DEV_LINE - (s % DEV_LINE) < p) p = DEV_LINE - (s % DEV_LINE);
            if (dst_dev && DEV_LINE - (d % DEV_LINE) < p) p = DEV_LINE - (d % DEV_LINE);
            uint32_t taint = 0;
            if (src_dev && !hooks_.dev_authorize(s, false, qi, &taint, !dst_dev))
                std::memset(buf.data() + off, DEV_POISON, std::size_t(p));
            if (!dst_dev || hooks_.dev_authorize(d, true, qi, &taint, false))
                hooks_.dram_write(d, buf.data() + off, std::size_t(p));
            off += p;
        }
        done += n;
    }
}

// wait_op_e encoded in arg2[1:0].
bool CommandProcessor::event_wait_satisfied_(uint32_t qi, const Cmd& c) {
    if (!hooks_.dram_read) return true;   // no DRAM hook -> retire as NOP
    uint64_t cur = 0;
    dev_read_(qi, c.arg0, &cur, sizeof(cur));
    const uint64_t target = c.arg1;
    const uint32_t op = uint32_t(c.arg2) & 0x3;
    switch (op) {
        case 0: return cur == target;   // WAIT_OP_EQ
        case 1: return cur >= target;   // WAIT_OP_GE
        case 2: return cur >  target;   // WAIT_OP_GT
        case 3: return cur != target;   // WAIT_OP_NE
        default: return true;
    }
}

// CMD_LAUNCH_QMD: read the KMU descriptor from device memory and apply it as
// the queue's launch registers. The descriptor is a {uint32 count, then count ×
// (uint32 dcr_addr, uint32 value)} list the host staged before submit (like a
// kernel-args blob). cp_translate matches the address the host's CMD_MEM_WRITE
// staged it at (VM walk when active, passthrough otherwise).
void CommandProcessor::apply_qmd_(uint32_t qi, uint64_t qmd_addr) {
    if (!hooks_.dram_read) return;
    uint64_t addr = cp_translate(qmd_addr, /*physical=*/false);
    uint32_t count = 0;
    dev_read_(qi, addr, &count, sizeof(count));
    addr += sizeof(count);
    constexpr uint32_t MAX_QMD_DCRS = 64;   // backstop against a corrupt count
    if (count > MAX_QMD_DCRS) count = MAX_QMD_DCRS;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t pair[2] = {0, 0};          // {dcr_addr, value}
        dev_read_(qi, addr, pair, sizeof(pair));
        addr += sizeof(pair);
        // VX_DCR_ADDR_BITS=12. Filtered: the blob is in tenant-writable memory.
        dcr_write_(qi, pair[0] & 0xFFF, pair[1], /*indirect=*/true);
    }
}

// Execute one draw-bundle step. Inline ops (DCR_WRITE/DCR_READ/CACHE_FLUSH)
// complete immediately and return false; a launch step (LAUNCH/LAUNCH_QMD)
// returns true so the caller takes the KMU and waits for the drain (the
// inter-stage barrier). Mirrors the per-opcode logic of the ring Bid path.
bool CommandProcessor::exec_inline_cmd_(uint32_t qi, const Cmd& c, bool indirect) {
    switch (c.opcode) {
        case OP_LAUNCH:
        case OP_LAUNCH_QMD:
            return true;
        case OP_DCR_WRITE:
            // A step decoded out of a device-resident descriptor is subject to
            // the privileged-window filter; a ring command is not.
            dcr_write_(qi, uint32_t(c.arg0 & 0xFFF), uint32_t(c.arg1 & 0xFFFFFFFF), indirect);
            return false;
        case OP_DCR_READ:
            qs_[qi].last_dcr_rsp = dcr_read_(qi, uint32_t(c.arg0 & 0xFFF),
                                             uint32_t(c.arg1 & 0xFFFFFFFF));
            return false;
        case OP_CACHE_FLUSH:
            if (hooks_.vortex_dcr_read) {
                uint32_t n = uint32_t(c.arg0 & 0xFFFFFFFF);
                for (uint32_t cid = 0; cid < n; ++cid)
                    (void)hooks_.vortex_dcr_read(VX_DCR_BASE_CACHE_FLUSH, cid);
            }
            return false;
        default:
            // NOP / FENCE / unknown step — no-op (draws don't use MEM_*/EVENT_*).
            return false;
    }
}

// Read q.draw_step's 28-byte cmd record from the descriptor into q.draw_cmd.
void CommandProcessor::draw_load_step_(QState& q) {
    q.draw_cmd = Cmd{};
    if (!hooks_.dram_read) return;
    uint8_t buf[DRAW_STEP_BYTES] = {0};
    const uint64_t at = q.draw_phys + 4
                      + uint64_t(q.draw_step) * DRAW_STEP_BYTES;
    dev_read_(uint32_t(&q - qs_.data()), at, buf, DRAW_STEP_BYTES);
    decode_cmd_bytes(buf, DRAW_STEP_BYTES, 0, q.draw_cmd);
}

void CommandProcessor::tick_launch() {
    switch (launch_state_) {
        case LaunchState::Idle:        return;
        case LaunchState::PulseStart:
            if (hooks_.vortex_start) hooks_.vortex_start();
            launch_state_ = LaunchState::WaitBusy;
            return;
        case LaunchState::WaitBusy:
            // Wait for Vortex to actually start.
            if (hooks_.vortex_busy && hooks_.vortex_busy())
                launch_state_ = LaunchState::WaitDrain;
            return;
        case LaunchState::WaitDrain:
            if (!hooks_.vortex_busy || !hooks_.vortex_busy())
                launch_state_ = LaunchState::Idle;
            return;
    }
}

void CommandProcessor::tick_engine(uint32_t qi) {
    QState& q = qs_[qi];

    // Decode a single cmd at the current slot and walk it through the FSM.
    auto load_next_cmd = [this, &q]() -> bool {
        if (!q.cl_loaded) return false;
        if (q.cl_cmd_slot >= q.cl_cmd_count) {
            // All commands in this CL consumed (or it was pure padding);
            // advance head and drop the CL.
            q.regs.head += CL_BYTES;
            q.cl_loaded = false;
            return false;
        }
        int off = 0;
        for (int s = 0; s < q.cl_cmd_slot; ++s) {
            Cmd skip;
            off += decode_cmd(q, off, skip);
        }
        decode_cmd(q, off, q.cur_cmd);
        q.cur_is_launch = (q.cur_cmd.opcode == OP_LAUNCH ||
                           q.cur_cmd.opcode == OP_LAUNCH_QMD);
        switch (q.cur_cmd.opcode) {
            case OP_NOP: case OP_FENCE:
                // No resource bid for these opcodes; retire as NOP.
                q.cur_is_no_resource = true;
                break;
            default:
                // LAUNCH, DCR_*, MEM_*, EVENT_SIG, EVENT_WAIT all bid a
                // resource.
                q.cur_is_no_resource = false;
                break;
        }
        return true;
    };

    const Cmd& c = q.cur_cmd;
    switch (q.eng_state) {
        case EngState::Idle:
            fetch_if_needed(q);
            if (load_next_cmd())
                q.eng_state = EngState::Decode;
            return;

        case EngState::Decode:
            q.eng_state = q.cur_is_no_resource ? EngState::Retire : EngState::Bid;
            return;

        case EngState::Bid:
            // Dispatch to the resource. Only the KMU is contended: DCR, DMA
            // and event commands complete within the tick, so they never
            // interleave with another queue's command mid-way.
            if (q.cur_is_launch) {
                // QMD launch: the KMU descriptor lives in memory as a
                // {count, (dcr_addr,value)...} list (NVIDIA QMD model). Apply
                // it to the queue's launch registers, then launch exactly like
                // a plain CMD_LAUNCH — collapsing ~18 ring DCR writes to one.
                // Applied only once the KMU is ours, so a retried bid does not
                // re-read the descriptor.
                if (launch_state_ != LaunchState::Idle)
                    return;   // another queue's kernel holds the KMU
                if (c.opcode == OP_LAUNCH_QMD)
                    apply_qmd_(qi, c.arg0);
                (void)try_begin_launch_(qi);
                q.eng_state = EngState::WaitDone;
            } else if (c.opcode == OP_DRAW) {
                // Device-orchestrated draw: arg0 → resident draw descriptor
                // {uint32 num_steps, steps[28 B]...}. Walk the embedded command
                // bundle (DrawStep), retiring the one OP_DRAW when drained.
                q.draw_phys = cp_translate(c.arg0, /*physical=*/false);
                q.draw_num_steps = 0;
                dev_read_(qi, q.draw_phys, &q.draw_num_steps,
                          sizeof(q.draw_num_steps));
                if (q.draw_num_steps > MAX_DRAW_STEPS)
                    q.draw_num_steps = MAX_DRAW_STEPS;
                q.draw_step = 0;
                q.eng_state = EngState::DrawStep;
            } else if (c.opcode == OP_DCR_WRITE) {
                // A ring command: the privileged window is reachable, and the
                // write is attributed to this queue.
                dcr_write_(qi, uint32_t(c.arg0 & 0xFFF), uint32_t(c.arg1 & 0xFFFFFFFF),
                           /*indirect=*/false);   // VX_DCR_ADDR_BITS=12
                q.eng_state = EngState::Retire;
            } else if (c.opcode == OP_DCR_READ) {
                // Issue the DCR read; latch the response into the regfile
                // slot so the host can grab it after polling Q_SEQNUM.
                q.last_dcr_rsp = dcr_read_(qi, uint32_t(c.arg0 & 0xFFF),
                                           uint32_t(c.arg1 & 0xFFFFFFFF));
                q.eng_state = EngState::Retire;
            } else if (c.opcode == OP_CACHE_FLUSH) {
                // Sweep a per-core DCR-read of VX_DCR_BASE_CACHE_FLUSH across
                // [0, num_cores). arg0 carries num_cores; dcr_read routes each
                // call to flush_caches() (drains dcache/L2/L3 to memsim).
                if (hooks_.vortex_dcr_read) {
                    uint32_t n = uint32_t(c.arg0 & 0xFFFFFFFF);
                    for (uint32_t cid = 0; cid < n; ++cid) {
                        (void)hooks_.vortex_dcr_read(VX_DCR_BASE_CACHE_FLUSH, cid);
                    }
                }
                q.eng_state = EngState::Retire;
            } else if (c.opcode == OP_EVENT_SIG) {
                // CMD_EVENT_SIGNAL: write arg1 (8-byte value) to arg0
                // (device counter slot).
                uint64_t v = c.arg1;
                dev_write_(qi, c.arg0, &v, sizeof(v));
                q.eng_state = EngState::Retire;
            } else if (c.opcode == OP_EVENT_WAIT) {
                // CMD_EVENT_WAIT: poll arg0 until it satisfies the wait_op
                // (arg2[1:0]) comparison against arg1; retry each tick.
                if (event_wait_satisfied_(qi, c)) {
                    q.eng_state = EngState::Retire;
                } else {
                    // Spin in Bid (no state change); re-checked each tick.
                }
            } else if (c.opcode == OP_MEM_WRITE ||
                       c.opcode == OP_MEM_READ  ||
                       c.opcode == OP_MEM_COPY) {
                // CMD_MEM_*: copy arg2 bytes from src (arg1) to dst (arg0).
                // The CP DMA is an MMU-aware copy engine: the device-side
                // operand is a virtual address, translated here by a
                // page-table walk. MEM_WRITE -> arg0 is the device dst;
                // MEM_READ -> arg1 is the device src; MEM_COPY -> both.
                // Host-side operands and physical-flagged commands pass
                // through untranslated. A buffer is one contiguous PA
                // allocation, so translating the base covers the transfer.
                if (hooks_.dram_read && hooks_.dram_write
                 && c.arg2 != 0) {
                    const bool physical =
                        (c.flags & MEM_FLAG_PHYSICAL) != 0;
                    uint64_t dst = c.arg0;
                    uint64_t src = c.arg1;
                    if (c.opcode == OP_MEM_WRITE) {
                        dst = cp_translate(dst, physical);
                    } else if (c.opcode == OP_MEM_READ) {
                        src = cp_translate(src, physical);
                    } else { // OP_MEM_COPY — both operands are device
                        dst = cp_translate(dst, physical);
                        src = cp_translate(src, physical);
                    }
                    dev_transfer_(qi, dst, c.opcode != OP_MEM_READ,
                                  src, c.opcode != OP_MEM_WRITE, c.arg2);
                }
                q.eng_state = EngState::Retire;
            } else {
                // Unknown opcode — retire as NOP.
                q.eng_state = EngState::Retire;
            }
            return;

        case EngState::WaitDone:
            // For LAUNCH: wait until this queue's kernel has drained.
            if (q.cur_is_launch && launch_state_ != LaunchState::Idle)
                return;
            q.eng_state = EngState::Retire;
            return;

        case EngState::DrawStep:
            // Walk the draw descriptor one step per tick. Inline ops apply now;
            // a launch step takes the KMU and waits in DrawLaunchWait until its
            // kernel drains (the inter-stage barrier).
            if (q.draw_step >= q.draw_num_steps) {
                q.eng_state = EngState::Retire;
                return;
            }
            draw_load_step_(q);
            if (exec_inline_cmd_(qi, q.draw_cmd, /*indirect=*/true)) {
                if (launch_state_ != LaunchState::Idle)
                    return;   // KMU busy: re-read and retry this step next tick
                if (q.draw_cmd.opcode == OP_LAUNCH_QMD)
                    apply_qmd_(qi, q.draw_cmd.arg0);
                (void)try_begin_launch_(qi);
                q.eng_state = EngState::DrawLaunchWait;
            } else {
                ++q.draw_step;
            }
            return;

        case EngState::DrawLaunchWait:
            // tick_launch advances launch_state_; resume the walk on drain.
            if (launch_state_ != LaunchState::Idle)
                return;
            ++q.draw_step;
            q.eng_state = EngState::DrawStep;
            return;

        case EngState::Retire:
            q.regs.seqnum += 1;
            publish_completion(q);
            ++q.cl_cmd_slot;
            q.eng_state = EngState::Idle;
            return;
    }
}

void CommandProcessor::tick() {
    ++cycle_counter_;
    // Each enabled queue advances one engine step per tick, starting from a
    // rotating queue so no queue always wins the KMU when two bid together
    // (the RTL arbiter is round-robin too).
    bool any = false;
    for (uint32_t k = 0; k < NUM_QUEUES; ++k) {
        const uint32_t qi = (rr_next_ + k) % NUM_QUEUES;
        if (!queue_enabled_(qi))
            continue;
        any = true;
        tick_engine(qi);
    }
    rr_next_ = (rr_next_ + 1) % NUM_QUEUES;
    if (any || launch_state_ != LaunchState::Idle)
        tick_launch();
}

} // namespace vortex
