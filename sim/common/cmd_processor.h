// Copyright © 2019-2023
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ============================================================================
// cmd_processor.h — functional C++ model of the Command Processor.
// Shared by simx and rtlsim; presents the same cp_mmio_* MMIO surface to
// the runtime.
//
// Implements a `tick()`-per-cycle state machine that reads commands from a
// host-pinned ring in DRAM, dispatches them to the right resource (DCR proxy,
// launch, DMA), and publishes the retired sequence number back to a
// host-pinned completion slot.
//
// Address map (CP-internal, 0-based):
//   Globals (CP-internal offsets 0x000..0x0FF)
//     0x000 CP_CTRL       bit0=enable_global, bit1=reset_all
//     0x004 CP_STATUS     bit0=busy, bit1=error
//     0x008 CP_DEV_CAPS   {AXI_TID_W:8 | RING_LOG2:8 | NUM_QUEUES:8}
//     0x010 CP_CYCLE_LO
//     0x014 CP_CYCLE_HI
//     0x018 GPU_DEV_CAPS_LO  device-config caps, low 32 bits   (RO)
//     0x01C GPU_DEV_CAPS_HI  device-config caps, high 32 bits  (RO)
//     0x020 GPU_ISA_CAPS_LO  ISA caps, low 32 bits             (RO)
//     0x024 GPU_ISA_CAPS_HI  ISA caps, high 32 bits            (RO)
//   Per queue q (CP-internal offsets 0x100 + q*0x40 .. +0x3F; NUM_QUEUES queues)
//     0x100/04 Q_RING_BASE_LO/HI
//     0x108/0C Q_HEAD_ADDR_LO/HI   (where the CP publishes head)
//     0x110/14 Q_CMPL_ADDR_LO/HI   (where the CP publishes seqnum)
//     0x118    Q_RING_SIZE_LOG2
//     0x11C    Q_CONTROL          bit0=enable, bit1=reset
//     0x120    Q_TAIL_LO          (staging)
//     0x124    Q_TAIL_HI          (atomic commit)
//     0x128    Q_SEQNUM           (RO mirror)
//     0x12C    Q_ERROR
//     0x130    Q_LAST_DCR_RSP     (RO — latest CMD_DCR_READ response)
//     0x134    Q_DCR_BLOCKED      (RO — DCR accesses refused by the
//                                 privileged-window filter; see
//                                 DCR_PRIV_BEGIN below)
//
// Queues and tenants (P1_and_taint_specv2.md D1-D5). Queue q is tenant q.
//   - Every DCR write a queue's command causes carries the queue as its
//     *issuer*, so the checker can attribute claims and revocations to the
//     tenant that sent them rather than to a value the writer chose.
//   - The launch registers (KMU 0x010-0x023, and the MMU root under VM) are
//     captured per queue instead of being written through, and replayed into
//     the GPU when that queue's launch takes the KMU. Another queue's writes in
//     between therefore cannot change what a launch runs.
//   - DCR reads of the checker window are refused unless the build sets
//     VX_CFG_CHECKER_DEBUG_READS.
//   Queues run independently; the KMU is the one shared resource, held by one
//   queue from the shadow replay until its kernel drains, as in the RTL
//   (VX_cp_launch).
//
// CMD_DRAW (OP_DRAW, opcode 0x0C) — device-orchestrated draw.
//   A single ring command whose arg0 points at a resident *draw descriptor*:
//     uint32_t num_steps;                       // at offset 0
//     cmd_step  steps[num_steps];               // at offset 4, 28 B stride
//   Each step is a 28-byte cmd record (same byte layout decode_cmd reads):
//   {opcode:u8, flags:u8, reserved:u16, arg0:u64, arg1:u64, arg2:u64}. The CP
//   walks the steps in order, executing each through the same per-opcode logic
//   as the ring (CMD_LAUNCH_QMD drains its kernel via the launch sub-FSM — the
//   inter-stage barrier; CMD_DCR_WRITE / CMD_CACHE_FLUSH apply inline), then
//   retires the one OP_DRAW. The whole VS→setup→bin→FF-config→FS sequence runs
//   from one host doorbell with no host round-trip — the "true GPU" draw. The
//   descriptor is an indirect command bundle, so the executed sequence is
//   byte-identical to streaming the same commands through the ring.
// ============================================================================

#ifndef VORTEX_COMMAND_PROCESSOR_H
#define VORTEX_COMMAND_PROCESSOR_H

#include <cstdint>
#include <functional>
#include <array>
#include <vm_types.h>   // SATP_t / PTE_t / vAddr_t (VM page-table walk)
#include <VX_config.h>  // VX_CFG_CHECKER_TENANTS, VX_CFG_VM_ENABLE
#include <VX_types.h>   // VX_DCR_KMU_*, VX_DCR_MMU_*

namespace vortex {

class CommandProcessor {
public:
    struct Hooks {
        // Read `bytes` bytes from device DRAM at `addr` into `dst`.
        // Used for ring-buffer fetches (one cache line at a time).
        std::function<void(uint64_t addr, void* dst, std::size_t bytes)> dram_read;

        // Write `bytes` bytes from `src` into device DRAM at `addr`.
        // Used for completion-slot writebacks (8 B seqnum).
        std::function<void(uint64_t addr, const void* src, std::size_t bytes)> dram_write;

        // Issue a single DCR write to Vortex (for CMD_DCR_WRITE). `issuer` is
        // the queue (= tenant) whose command caused it; the checker's setup
        // path attributes claims and revocations to it.
        std::function<void(uint32_t addr, uint32_t value, uint32_t issuer)> vortex_dcr_write;

        // Issue a single DCR read to Vortex (for CMD_DCR_READ). `tag` is
        // placed on the DCR data bus and addresses things like per-core
        // CACHE_FLUSH. The backend must block until the response is
        // available before returning.
        std::function<uint32_t(uint32_t addr, uint32_t tag)> vortex_dcr_read;

        // The checker on the CP's device path (D7). Judges one device line
        // (64 B, never straddled) that queue `issuer`'s command reads or
        // writes; false stops it: a read line becomes poison, a write line is
        // dropped. `taint` carries what a read brings along into a copy's
        // write; `to_host` marks a read whose data leaves for the host. Unset
        // (rtlsim, which has no C++ checker) means every access proceeds.
        std::function<bool(uint64_t addr, bool is_write, uint32_t issuer,
                           uint32_t* taint, bool to_host)> dev_authorize;

        // Pulse Vortex's start signal (for CMD_LAUNCH). The launch FSM
        // calls this once when transitioning into the "started" state.
        std::function<void()> vortex_start;

        // Query Vortex's busy state. The launch FSM waits for this to
        // rise (kernel actually executing) then fall (kernel done)
        // before retiring the CMD_LAUNCH.
        std::function<bool()> vortex_busy;

        // Backend decodes the MMU fault-report DCRs. Published in DEV_CAPS
        // so the runtime does not read them on a target that would leave
        // the DCR bus waiting for a response.
        bool mmu_fault_report = false;
    };

    // ----- Privileged DCR window (control/data separation) -----
    //
    // DCR addresses in [DCR_PRIV_BEGIN, DCR_PRIV_END) are the memory
    // checker's configuration interface — buffer ownership, permissions and
    // the per-owner revocation epoch (sim/simx/sec/mem_checker.h holds the
    // authoritative per-register names, DCR_CHECKER_BASE..DCR_CHECKER_END).
    // They are the mechanism's *control plane*, and the threat model treats
    // the host ring as the attested channel that owns it.
    //
    // Indirect command bundles do not qualify. A QMD descriptor
    // (CMD_LAUNCH_QMD) and an OP_DRAW step list are read out of device
    // memory at execution time, and the checker's boot policy leaves
    // unclaimed memory OWNER_ANY | R|W — world-writable. A tenant kernel can
    // therefore rewrite a bundle after the host staged it and before the CP
    // reads it (TOCTOU) and have its own {addr,value} pairs replayed with
    // full privilege: {BUF_OWNER, self} + {BUF_COMMIT, 1} claims a victim's
    // buffer, {EPOCH, 0} attempts to undo a revocation. Because the CP reads
    // the bundle functionally, no such write ever crosses the LLC→DRAM
    // enforcement point, so the checker cannot see the attack itself.
    //
    // Real hardware puts the privileged register window out of reach of an
    // unprivileged command buffer; this range is that rule. Writes to it from
    // an indirect bundle are dropped and counted in Q_DCR_BLOCKED (0x134).
    // Nothing legitimate is lost: the runtime only ever packs KMU registers
    // (VX_DCR_KMU_*, 0x010..0x023) into a QMD — see cmd_stage_qmds() in
    // sw/runtime/common/queue.cpp.
    //
    // Duplicated as literals rather than included, because sim/common must
    // not depend on the simx-only checker. mem_checker.cpp static_asserts
    // that the two definitions agree.
    static constexpr uint32_t DCR_PRIV_BEGIN = 0x300;
    static constexpr uint32_t DCR_PRIV_END   = 0x340;

    // One queue per tenant.
    static constexpr uint32_t NUM_QUEUES = VX_CFG_CHECKER_TENANTS;

    explicit CommandProcessor(const Hooks& hooks);

    // ----- Host-facing MMIO surface -----
    // Offsets match VX_cp_axil_regfile (CP-internal, 0-based).
    // Backends doing MMIO at byte offset 0x1000+ should subtract 0x1000
    // on their side before calling these.
    void     mmio_write(uint32_t off, uint32_t value);
    uint32_t mmio_read (uint32_t off) const;

    // ----- Sim integration -----
    // Advance the CP one functional cycle. Called by the simulator's
    // per-cycle loop. Cheap: a small FSM step (single-digit branches).
    void tick();

    // True iff CP_CTRL.enable_global && Q_CONTROL.enable. The simulator
    // can use this to skip tick() when the host hasn't enabled the CP.
    bool enabled() const;

    // True iff the engine has commands in flight OR ring has pending
    // entries. Lets the host's wait loop break early when the CP is idle.
    bool busy() const;

private:
    // Engine FSM states. DrawStep / DrawLaunchWait walk an OP_DRAW bundle.
    enum class EngState { Idle, Decode, Bid, WaitDone, Retire,
                          DrawStep, DrawLaunchWait };

    // KMU launch sub-FSM.
    enum class LaunchState { Idle, PulseStart, WaitBusy, WaitDrain };

    // Command opcodes: low 8 bits of the on-wire command header.
    enum : uint8_t {
        OP_NOP        = 0x00,
        OP_MEM_WRITE  = 0x01,
        OP_MEM_READ   = 0x02,
        OP_MEM_COPY   = 0x03,
        OP_DCR_WRITE  = 0x04,
        OP_DCR_READ   = 0x05,
        OP_LAUNCH     = 0x06,
        OP_FENCE      = 0x07,
        OP_EVENT_SIG  = 0x08,
        OP_EVENT_WAIT = 0x09,
        OP_CACHE_FLUSH = 0x0A,
        OP_LAUNCH_QMD = 0x0B,  // atomic launch: KMU descriptor read from memory
        OP_DRAW       = 0x0C,  // device-orchestrated draw: arg0 = draw descriptor addr
    };

    // Fixed per-step stride inside a draw descriptor: the 28-byte cmd-record
    // prefix (opcode/flags/reserved + arg0/arg1/arg2). A uniform stride keeps
    // the descriptor walk (and the RTL CP mirror) simple.
    static constexpr int DRAW_STEP_BYTES = 28;
    static constexpr uint32_t MAX_DRAW_STEPS = 256;  // corrupt-count backstop

    // CMD_MEM_* header flag (cmd_t.flags bit2 = F_MEM_PHYSICAL): the device
    // operand is a physical address — the MMU-aware CP DMA skips translation.
    // Used for page-table bootstrap writes and the PT region itself. A
    // dedicated bit, distinct from flags bit0 (F_PROFILE) — the addressing
    // mode is its own descriptor field (modern-GPU convention).
    static constexpr uint8_t MEM_FLAG_PHYSICAL = 0x04;

    // Decoded cmd record (matches cmd_t struct layout on-wire).
    struct Cmd {
        uint8_t  opcode;
        uint8_t  flags;
        uint16_t reserved;
        uint64_t arg0;
        uint64_t arg1;
        uint64_t arg2;
    };

    // ----- Per-queue programmable state (q_state_t mirror) -----
    struct Queue {
        uint64_t ring_base   = 0;
        uint64_t head_addr   = 0;
        uint64_t cmpl_addr   = 0;
        uint8_t  ring_log2   = 16;     // 64 KiB default
        uint32_t control     = 0;      // bit0=enable, bits3:2=prio
        uint64_t tail        = 0;
        uint32_t tail_lo_staging = 0;
        // CP-tracked state (not host-writable):
        uint64_t head        = 0;      // bytes consumed
        uint64_t seqnum      = 0;      // commands retired
        uint32_t error       = 0;
    };

    // ----- Launch shadow -----
    // The KMU launch registers, and the MMU root under VM, captured per queue
    // and replayed at that queue's launch (D4). Initialised to the KMU's own
    // reset values (sim/simx/kmu/kmu.cpp): dims, cluster dims and warp steps 1,
    // everything else 0, so a queue that never writes one launches as the
    // device would from reset.
    static constexpr uint32_t SHADOW_KMU_BEGIN = VX_DCR_KMU_STATE_BEGIN;
    static constexpr uint32_t SHADOW_KMU_END   = VX_DCR_KMU_STATE_END;
    static constexpr uint32_t NUM_SHADOW_KMU   = SHADOW_KMU_END - SHADOW_KMU_BEGIN;
#ifdef VX_CFG_VM_ENABLE
    static constexpr uint32_t NUM_SHADOW = NUM_SHADOW_KMU + 2;  // + SATP_LO/HI
#else
    static constexpr uint32_t NUM_SHADOW = NUM_SHADOW_KMU;
#endif
    static uint32_t shadow_reset_value_(uint32_t addr);
    // Index of `addr` in a queue's shadow, or -1 if it is not shadowed.
    static int shadow_index_(uint32_t addr);
    static uint32_t shadow_addr_(int index);

    // ----- Fetch geometry -----
    // The simulator fetches one cache line at a time when head < tail,
    // then walks the CL extracting decoded cmds before fetching the next.
    static constexpr std::size_t CL_BYTES = 64;
    static constexpr int MAX_CMDS_PER_CL = 5;

    // ----- Per-queue state: programmable registers, fetch, engine, draw -----
    struct QState {
        Queue    regs;
        uint32_t last_dcr_rsp = 0;    // Q_LAST_DCR_RSP slot (0x130)
        uint32_t dcr_blocked  = 0;    // Q_DCR_BLOCKED slot (0x134): DCR accesses
                                      // refused by the privileged-window filter
        // Engine.
        EngState eng_state = EngState::Idle;
        Cmd      cur_cmd{};
        bool     cur_is_launch = false;
        bool     cur_is_no_resource = false;
        // Draw-bundle walk (OP_DRAW).
        uint64_t draw_phys      = 0;  // descriptor base (translated)
        uint32_t draw_num_steps = 0;
        uint32_t draw_step      = 0;
        Cmd      draw_cmd{};          // decoded current step
        // Fetch.
        std::array<uint8_t, CL_BYTES> cl_buf{};
        int      cl_cmd_count = 0;
        int      cl_cmd_slot  = 0;
        bool     cl_loaded    = false;
        // Launch shadow.
        std::array<uint32_t, NUM_SHADOW> shadow{};
    };

    // ----- Globals -----
    uint32_t cp_ctrl_ = 0;           // bit0=enable_global
    uint64_t satp_ = 0;              // CP_SATP — page-table root for the CP DMA's MMU
    uint64_t cycle_counter_ = 0;
    std::array<QState, NUM_QUEUES> qs_;
    Hooks    hooks_;

    // ----- The KMU: one launch at a time, owned by one queue -----
    LaunchState launch_state_ = LaunchState::Idle;
    uint32_t    launch_owner_ = 0;     // queue holding the KMU (valid unless Idle)
    uint32_t    rr_next_      = 0;     // round-robin start for the next tick

    bool queue_enabled_(uint32_t q) const;
    // Walk `q.cl_buf` and count the commands it holds.
    void unpack_cl(QState& q);
    // Decode a single header at byte offset `off` into a Cmd record;
    // returns the size in bytes of the command (so caller can advance).
    int  decode_cmd(const QState& q, int off, Cmd& out) const;
    // Decode a cmd record from an arbitrary byte buffer (shared by the ring
    // unpacker and the OP_DRAW step walk).
    static int decode_cmd_bytes(const uint8_t* buf, int len, int off, Cmd& out);
    // Execute one DCR_WRITE / DCR_READ / CACHE_FLUSH step of a draw bundle
    // against `c`, for queue `qi`. Steps are always `indirect`: decoded out of
    // a device-memory command bundle, so the privileged DCR window is gated.
    // Returns true if `c` is a launch (the caller must take the KMU and wait
    // for the drain).
    bool exec_inline_cmd_(uint32_t qi, const Cmd& c, bool indirect);
    // Every DCR write a command causes goes through here. A write into the
    // privileged window from an indirect bundle is dropped and counted; a
    // launch register is captured in the queue's shadow; anything else goes
    // to the GPU tagged with the issuing queue. Returns true unless dropped.
    bool dcr_write_(uint32_t qi, uint32_t addr, uint32_t value, bool indirect);
    // A DCR read on behalf of queue `qi`. Reads of the privileged window are
    // refused (counted, answered with 0) unless VX_CFG_CHECKER_DEBUG_READS.
    uint32_t dcr_read_(uint32_t qi, uint32_t addr, uint32_t tag);
    // Take the KMU for queue `qi` if it is free: replay the queue's launch
    // shadow into the GPU, then start. False if another queue holds it.
    bool try_begin_launch_(uint32_t qi);
    // Read the next OP_DRAW step from the descriptor into q.draw_cmd.
    void draw_load_step_(QState& q);
    // Write the queue's seqnum to its cmpl_addr.
    void publish_completion(const QState& q);
    // CMD_EVENT_WAIT compare helper — reads cmd.arg0 from DRAM and compares to
    // cmd.arg1 under the wait_op encoded in arg2[1:0].
    bool event_wait_satisfied_(uint32_t qi, const Cmd& c);
    // Device memory as queue `qi`'s command sees it (D7): every line judged
    // by hooks_.dev_authorize. A denied read line reads as poison, a denied
    // write line does not land.
    void dev_read_(uint32_t qi, uint64_t addr, void* dst, std::size_t bytes);
    void dev_write_(uint32_t qi, uint64_t addr, const void* src, std::size_t bytes);
    // CMD_MEM_*: one transfer, judged line by line on each device operand.
    void dev_transfer_(uint32_t qi, uint64_t dst, bool dst_dev,
                       uint64_t src, bool src_dev, uint64_t total);
    // CMD_LAUNCH_QMD: read the in-memory KMU descriptor at `qmd_addr` and
    // apply its {dcr_addr,value} pairs as indirect writes of queue `qi`.
    void apply_qmd_(uint32_t qi, uint64_t qmd_addr);
    // Advance the launch FSM one step.
    void tick_launch();
    // Advance queue `qi`'s engine FSM one step.
    void tick_engine(uint32_t qi);
    // Fetch one CL from queue `qi`'s ring if needed.
    void fetch_if_needed(QState& q);
    // VM: translate a device virtual address to physical via a page-table
    // walk. A no-op when VM is disabled, SATP is unset/BARE, or physical.
    uint64_t cp_translate(uint64_t vaddr, bool physical) const;
};

} // namespace vortex

#endif // VORTEX_COMMAND_PROCESSOR_H
