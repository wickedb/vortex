// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

// ============================================================================
// Verilator integration test for VX_cp_core (full CP).
//
// Wires the three CP interfaces against synthetic models:
//   - AXI-Lite slave host: drives W/AW + AR transactions for control.
//   - AXI4 master upstream: 16 KiB byte-addressed memory model (host
//     pinned ring + completion slot live here).
//   - gpu_if (Vortex side): tiny FSM that responds to gpu.start by
//     pulsing gpu.busy for a few cycles.
//
// End-to-end happy-path sequence:
//   1. Seed memory at ring_base with a single CMD_NOP+F_PROFILE so the
//      walker doesn't treat it as the padding sentinel.
//   2. Program regs:
//        Q_RING_BASE_LO/HI = ring_base
//        Q_CMPL_ADDR_LO/HI = cmpl_slot
//        Q_RING_SIZE_LOG2  = 12 (4 KiB)
//        Q_CONTROL.enable  = 1, Q_CONTROL.profile = 1
//        CP_CTRL.enable_global = 1
//   3. Ring the doorbell: write Q_TAIL_LO = 64, then Q_TAIL_HI = 0.
//   4. Watch:
//        - AXI AR at ring_base from CP fetch
//        - AXI W to cmpl_slot with value 1 (first retired seqnum)
//   5. Verify memory[cmpl_slot] == 1.
//
// NOP retires without bidding for any resource, so this exercises the
// regfile → fetch → unpack → engine → completion path without touching
// the launch or DMA paths.
//
// Then authorship across two queues (P1_and_taint_specv2.md D1-D5), each
// queue with its own ring:
//   A. Both queues post DCR writes at once. Every write reaches the GPU
//      exactly once, tagged with its own queue as issuer. (A resource that
//      granted a second queue while busy used to retire that queue's command
//      without executing it.)
//   B. Queue 1 writes a launch register; queue 0 writes the same register and
//      launches. Queue 1's write never reaches the GPU; queue 0's launch
//      replays queue 0's value (issuer 0) before start; queue 1's later launch
//      replays queue 1's value (issuer 1).
//   C. Queue 1 reads the checker window: refused (no GPU request, response 0,
//      Q_DCR_BLOCKED = 1). Queue 0 reads a normal DCR: the GPU answers, and
//      each queue keeps its own Q_LAST_DCR_RSP.
// ============================================================================

#include "vl_simulator.h"
#include "util.h"
#include "VVX_cp_core_top.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#ifndef TRACE_START_TIME
#define TRACE_START_TIME 0ull
#endif
#ifndef TRACE_STOP_TIME
#define TRACE_STOP_TIME -1ull
#endif

static uint64_t timestamp = 0;
static bool     trace_en  = false;
double sc_time_stamp() { return timestamp; }
bool   sim_trace_enabled() { return trace_en; }
void   sim_trace_enable(bool e) { trace_en = e; }

#define EXPECT(cond, msg) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
        std::exit(1); \
    } \
} while (0)

// ---- cmd_t pack (header at MSB word, profile_slot at LSB words) ----
static constexpr int F_PROFILE_BIT = 0;
static void emit_nop_profiled(uint8_t* cl, uint64_t profile_slot) {
    std::memset(cl, 0, 64);
    cl[0] = 0x00;                // opcode = NOP
    cl[1] = 1u << F_PROFILE_BIT; // flags  = F_PROFILE (so it's not padding)
    // NOP profiled size = 12 B; profile_slot at tail (offset 4..11)
    for (int i = 0; i < 8; ++i) cl[4 + i] = (uint8_t)(profile_slot >> (8*i));
}

// ============================================================================
// Synthetic AXI4 slave (memory model).
// ============================================================================
struct AxiSlave {
    static constexpr uint64_t MEM_BASE = 0x1000;
    static constexpr int      MEM_SIZE = 16 * 1024;
    uint8_t mem[MEM_SIZE] = {0};

    bool         r_inflight = false;
    uint64_t     r_addr     = 0;
    uint8_t      r_id       = 0;

    bool         aw_taken   = false;
    uint64_t     aw_addr    = 0;
    uint8_t      aw_id      = 0;
    bool         b_pending  = false;
    uint8_t      b_id       = 0;

    void mem_write_cl(uint64_t addr, const uint8_t* src) {
        for (int i = 0; i < 64; ++i) {
            int64_t a = (int64_t)addr - (int64_t)MEM_BASE + i;
            if (a >= 0 && a < MEM_SIZE) mem[a] = src[i];
        }
    }
    void mem_read_cl(uint64_t addr, uint32_t* dst) const {
        for (int w = 0; w < 16; ++w) {
            uint32_t v = 0;
            for (int b = 0; b < 4; ++b) {
                int64_t a = (int64_t)addr - (int64_t)MEM_BASE + w*4 + b;
                if (a >= 0 && a < MEM_SIZE) v |= (uint32_t)mem[a] << (8 * b);
            }
            dst[w] = v;
        }
    }
    uint64_t mem_read64(uint64_t addr) const {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            int64_t a = (int64_t)addr - (int64_t)MEM_BASE + i;
            if (a >= 0 && a < MEM_SIZE) v |= (uint64_t)mem[a] << (8 * i);
        }
        return v;
    }

    template <typename T>
    void comb_drive(T* top) {
        top->m_arready = !r_inflight;
        top->m_rvalid = r_inflight;
        top->m_rid    = r_id;
        top->m_rlast  = 1;
        top->m_rresp  = 0;
        if (r_inflight) {
            mem_read_cl(r_addr, vortex::VDataCast<uint32_t*, sizeof(top->m_rdata)>::get(top->m_rdata));
        }

        top->m_awready = !aw_taken;
        top->m_wready  = aw_taken && !b_pending;
        top->m_bvalid  = b_pending;
        top->m_bid     = b_id;
        top->m_bresp   = 0;
    }
    template <typename T>
    void posedge_update(T* top) {
        if (top->m_arvalid && top->m_arready) {
            r_inflight = true; r_addr = top->m_araddr; r_id = top->m_arid;
        } else if (r_inflight && top->m_rvalid && top->m_rready) {
            r_inflight = false;
        }
        if (top->m_awvalid && top->m_awready) {
            aw_taken = true; aw_addr = top->m_awaddr; aw_id = top->m_awid;
        }
        if (aw_taken && top->m_wvalid && top->m_wready) {
            // Write low 64 b of wdata at aw_addr.
            uint64_t v = ((uint64_t)top->m_wdata[1] << 32) | top->m_wdata[0];
            for (int i = 0; i < 8; ++i) {
                int64_t a = (int64_t)aw_addr - (int64_t)MEM_BASE + i;
                if (a >= 0 && a < MEM_SIZE) mem[a] = (uint8_t)(v >> (8 * i));
            }
            aw_taken = false; b_pending = true; b_id = aw_id;
        }
        if (b_pending && top->m_bvalid && top->m_bready) b_pending = false;
    }
};

// ============================================================================
// Synthetic device-memory slave (d_*): accepts single-beat writes, answers B
// with the request's ID, and records every AW ID it accepts. Reads are not
// modelled (no scenario issues one).
// ============================================================================
struct DevSlave {
    std::vector<uint32_t> aw_ids;
    bool    aw_taken  = false;
    uint8_t aw_id     = 0;
    bool    b_pending = false;
    uint8_t b_id      = 0;
    template <typename T>
    void comb_drive(T* top) {
        top->d_awready = !aw_taken;
        top->d_wready  = aw_taken && !b_pending;
        top->d_bvalid  = b_pending;
        top->d_bid     = b_id;
        top->d_bresp   = 0;
        top->d_arready = 0;
        top->d_rvalid  = 0;
    }
    template <typename T>
    void posedge_update(T* top) {
        if (top->d_awvalid && top->d_awready) {
            aw_taken = true; aw_id = top->d_awid; aw_ids.push_back(top->d_awid);
        }
        if (aw_taken && top->d_wvalid && top->d_wready) {
            aw_taken = false; b_pending = true; b_id = aw_id;
        }
        if (b_pending && top->d_bvalid && top->d_bready) b_pending = false;
    }
};
static DevSlave g_dev;

// ============================================================================
// Synthetic gpu_if model. Always ready; records every DCR request it accepts
// (and every start, in the same log, as addr 0xFFF); answers a read one cycle
// later with 0x1000 + addr; pulses busy for a few cycles after start.
// ============================================================================
struct GpuModel {
    struct Req { bool rw; uint32_t addr, data, issuer; };
    std::vector<Req> log;
    int  busy_cnt  = 0;
    bool rsp_pend  = false;
    uint32_t rsp_data = 0;
    template <typename T>
    void comb_drive(T* top) {
        top->gpu_dcr_req_ready = 1;
        top->gpu_dcr_rsp_valid = rsp_pend;
        top->gpu_dcr_rsp_data  = rsp_data;
        top->gpu_busy = (busy_cnt > 0);
    }
    template <typename T>
    void posedge_update(T* top) {
        rsp_pend = false;
        if (top->gpu_dcr_req_valid && top->gpu_dcr_req_ready) {
            log.push_back({bool(top->gpu_dcr_req_rw), uint32_t(top->gpu_dcr_req_addr),
                           uint32_t(top->gpu_dcr_req_data), uint32_t(top->gpu_dcr_req_issuer)});
            if (!top->gpu_dcr_req_rw) { rsp_pend = true; rsp_data = 0x1000u + top->gpu_dcr_req_addr; }
        }
        if (top->gpu_start) { busy_cnt = 4; log.push_back({true, 0xFFF, 0, 0}); }
        else if (busy_cnt > 0) busy_cnt--;
    }
};

template <typename T>
static void cycle(vl_simulator<T>& sim, AxiSlave& slave, GpuModel& gpu,
                  uint64_t& tick) {
    auto* top = sim.operator->();
    slave.comb_drive(top);
    gpu.comb_drive(top);
    g_dev.comb_drive(top);
    top->eval();
    slave.comb_drive(top);
    gpu.comb_drive(top);
    g_dev.comb_drive(top);
    top->eval();
    slave.posedge_update(top);
    gpu.posedge_update(top);
    g_dev.posedge_update(top);
    tick = sim.step(tick, 2);
    slave.comb_drive(top);
    gpu.comb_drive(top);
    g_dev.comb_drive(top);
    top->eval();
}

// ---- AXI-Lite W and R helpers (drive the host control plane) ----
template <typename T>
static void axil_write(vl_simulator<T>& sim, AxiSlave& slave, GpuModel& gpu,
                       uint64_t& tick, uint16_t addr, uint32_t data) {
    // Drive AW + W + bready continuously; sample bvalid each cycle.
    sim->s_awvalid = 1; sim->s_awaddr = addr;
    sim->s_wvalid  = 1; sim->s_wdata = data; sim->s_wstrb = 0xF;
    sim->s_bready  = 1;
    bool aw_done = false, w_done = false;
    for (int g = 0; g < 32; ++g) {
        cycle(sim, slave, gpu, tick);
        if (!aw_done && sim->s_awready) { aw_done = true; sim->s_awvalid = 0; }
        if (!w_done  && sim->s_wready)  { w_done  = true; sim->s_wvalid  = 0; }
        if (aw_done && w_done && sim->s_bvalid) {
            sim->s_bready = 0;
            return;
        }
    }
    EXPECT(false, "axil_write: B never asserted within 32 cycles");
}

template <typename T>
static uint32_t axil_read(vl_simulator<T>& sim, AxiSlave& slave, GpuModel& gpu,
                          uint64_t& tick, uint16_t addr) {
    // Drive AR and rready continuously; sample rvalid each cycle. When
    // rvalid + rready handshake, capture rdata and clear both.
    sim->s_arvalid = 1; sim->s_araddr = addr;
    sim->s_rready  = 1;
    bool ar_done = false;
    uint32_t captured = 0;
    for (int g = 0; g < 32; ++g) {
        cycle(sim, slave, gpu, tick);
        if (!ar_done && sim->s_arready) {
            ar_done = true;
            sim->s_arvalid = 0;
        }
        if (sim->s_rvalid) {
            captured = sim->s_rdata;
            sim->s_rready = 0;
            return captured;
        }
    }
    EXPECT(false, "axil_read: R never asserted");
    return 0;
}

// Register offsets matching VX_cp_axil_regfile.
static constexpr uint16_t CP_CTRL          = 0x000;
static constexpr uint16_t CP_DEV_CAPS      = 0x008;
static constexpr uint16_t Q0_BASE          = 0x100;
static constexpr uint16_t Q_RING_BASE_LO   = 0x00;
static constexpr uint16_t Q_RING_BASE_HI   = 0x04;
static constexpr uint16_t Q_CMPL_ADDR_LO   = 0x10;
static constexpr uint16_t Q_CMPL_ADDR_HI   = 0x14;
static constexpr uint16_t Q_RING_SIZE_LOG2 = 0x18;
static constexpr uint16_t Q_CONTROL        = 0x1C;
static constexpr uint16_t Q_TAIL_LO        = 0x20;
static constexpr uint16_t Q_TAIL_HI        = 0x24;
static constexpr uint16_t Q_SEQNUM         = 0x28;
static constexpr uint16_t Q_HEAD_LO        = 0x2C;

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    vl_simulator<VVX_cp_core_top> sim;
    uint64_t tick = 0;
    AxiSlave slave;
    GpuModel gpu;

    // Idle inputs before reset.
    sim->s_awvalid = sim->s_wvalid = sim->s_bready = 0;
    sim->s_arvalid = sim->s_rready = 0;
    tick = sim.reset(tick);

    // Sanity: CP_DEV_CAPS readable.
    {
        uint32_t v = axil_read(sim, slave, gpu, tick, CP_DEV_CAPS);
        EXPECT((v & 0xff) == 2, "DEV_CAPS NUM_QUEUES");
    }

    // ----- Seed memory: a single NOP+F_PROFILE at ring_base -----
    constexpr uint64_t RING_BASE = AxiSlave::MEM_BASE;
    constexpr uint64_t CMPL_ADDR = AxiSlave::MEM_BASE + 0x200;
    {
        uint8_t cl[64];
        emit_nop_profiled(cl, /*profile_slot=*/0xCAFEBABEull);
        slave.mem_write_cl(RING_BASE, cl);
        // Seed the cmpl slot with 0xFF...FF so we can detect a write of
        // seqnum=0 (the first retired command writes 0; the increment
        // happens at the retire posedge so retire_seqnum is the pre-
        // increment value).
        for (int i = 0; i < 8; ++i)
            slave.mem[CMPL_ADDR - AxiSlave::MEM_BASE + i] = 0xFF;
    }

    // ----- Program the queue regs -----
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_RING_BASE_LO,
               (uint32_t)(RING_BASE & 0xffffffffu));
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_RING_BASE_HI,
               (uint32_t)(RING_BASE >> 32));
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_CMPL_ADDR_LO,
               (uint32_t)(CMPL_ADDR & 0xffffffffu));
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_CMPL_ADDR_HI,
               (uint32_t)(CMPL_ADDR >> 32));
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_RING_SIZE_LOG2, 12);
    // Q_CONTROL: enable=1, profile_en=1, prio=2.
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_CONTROL,
               1u | (2u << 2) | (1u << 4));
    // CP_CTRL.enable_global = 1
    axil_write(sim, slave, gpu, tick, CP_CTRL, 1);

    // ----- Ring the doorbell: Q_TAIL_LO=64, then Q_TAIL_HI=0 (commit). -----
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_TAIL_LO, 64);
    axil_write(sim, slave, gpu, tick, Q0_BASE + Q_TAIL_HI, 0);

    // Verify the registers were programmed before waiting.
    {
        uint32_t rb_lo = axil_read(sim, slave, gpu, tick, Q0_BASE + Q_RING_BASE_LO);
        uint32_t ctrl  = axil_read(sim, slave, gpu, tick, Q0_BASE + Q_CONTROL);
        uint32_t cp    = axil_read(sim, slave, gpu, tick, CP_CTRL);
        std::fprintf(stderr, "[verify] ring_base_lo=0x%x q_ctrl=0x%x cp_ctrl=0x%x dbg_enabled=%d dbg_tail=0x%lx\n",
                     rb_lo, ctrl, cp, sim->dbg_q0_enabled, (unsigned long)sim->dbg_q0_tail);
    }

    // ----- Wait for completion writeback at CMPL_ADDR -----
    // First retired seqnum is 0 (engine pre-increments at posedge, so the
    // retire_seqnum payload is the post-retire count, matching Q_SEQNUM). We
    // pre-seeded
    // CMPL_ADDR with 0xFF...FF so any new write changes it.
    bool got = false;
    for (int g = 0; g < 500 && !got; ++g) {
        cycle(sim, slave, gpu, tick);
        if (slave.mem_read64(CMPL_ADDR) != 0xFFFFFFFFFFFFFFFFull) got = true;
    }
    EXPECT(got, "completion never wrote seqnum to cmpl_addr within 500 cycles");
    uint64_t seq = slave.mem_read64(CMPL_ADDR);
    // One command retired => the line reads 1, exactly what Q_SEQNUM reads.
    // The old expectation here was 0 -- this test verified the off-by-one.
    EXPECT(seq == 1, "completion wrote wrong seqnum");

    // ----- Q_CONTROL.reset actually clears the queue -----
    //
    // The counters used to survive everything: q_reset_pulse was decoded in
    // the regfile and discarded in VX_cp_core, so Q_CONTROL.reset was a no-op
    // and a fresh process inherited the previous one's seqnum. The fetch gate
    // is `head < tail` on absolute byte counts, so an inherited head meant the
    // new queue silently never ran.
    {
        // The command above retired, so the queue has advanced.
        uint32_t seq_before = axil_read(sim, slave, gpu, tick, Q0_BASE + Q_SEQNUM);
        EXPECT(seq_before != 0, "queue should have advanced before the reset");

        // Pulse Q_CONTROL.reset (bit 1). The hardware latches it and applies
        // the clear once the CPE has drained to idle, so give it time.
        axil_write(sim, slave, gpu, tick, Q0_BASE + Q_CONTROL, 0x2);
        for (int i = 0; i < 200; ++i) cycle(sim, slave, gpu, tick);

        uint32_t seq_after  = axil_read(sim, slave, gpu, tick, Q0_BASE + Q_SEQNUM);
        uint32_t head_after = axil_read(sim, slave, gpu, tick, Q0_BASE + Q_HEAD_LO);
        uint32_t tail_after = axil_read(sim, slave, gpu, tick, Q0_BASE + Q_TAIL_LO);
        uint32_t ctrl_after = axil_read(sim, slave, gpu, tick, Q0_BASE + Q_CONTROL);

        std::fprintf(stderr,
            "[reset] seqnum %u -> %u, head=0x%x tail=0x%x ctrl=0x%x\n",
            seq_before, seq_after, head_after, tail_after, ctrl_after);

        EXPECT(seq_after == 0, "Q_CONTROL.reset did not clear Q_SEQNUM");
        EXPECT(head_after == 0, "Q_CONTROL.reset did not clear the head pointer");
        // Tail and enable must clear with the head, or `head < tail` is
        // immediately true again and the queue refetches the whole ring.
        EXPECT(tail_after == 0, "Q_CONTROL.reset did not clear Q_TAIL");
        EXPECT((ctrl_after & 1) == 0, "Q_CONTROL.reset did not clear enable");
    }

    // ======================================================================
    // Authorship across two queues.
    // ======================================================================
    constexpr uint64_t RING[2] = {AxiSlave::MEM_BASE + 0x0000, AxiSlave::MEM_BASE + 0x1000};
    constexpr uint64_t CMPL[2] = {AxiSlave::MEM_BASE + 0x3000, AxiSlave::MEM_BASE + 0x3100};
    uint64_t tail[2] = {0, 0};
    auto qreg = [](int q, uint16_t off) { return uint16_t(Q0_BASE + q * 0x40 + off); };
    for (int q = 0; q < 2; ++q) {
        axil_write(sim, slave, gpu, tick, qreg(q, Q_RING_BASE_LO), uint32_t(RING[q]));
        axil_write(sim, slave, gpu, tick, qreg(q, Q_RING_BASE_HI), uint32_t(RING[q] >> 32));
        axil_write(sim, slave, gpu, tick, qreg(q, Q_CMPL_ADDR_LO), uint32_t(CMPL[q]));
        axil_write(sim, slave, gpu, tick, qreg(q, Q_CMPL_ADDR_HI), uint32_t(CMPL[q] >> 32));
        axil_write(sim, slave, gpu, tick, qreg(q, Q_RING_SIZE_LOG2), 12);
        axil_write(sim, slave, gpu, tick, qreg(q, Q_CONTROL), 1u | (2u << 2));
    }

    // One ring cache line holding up to four commands; returns how many.
    struct Cmd { uint8_t op; uint64_t a0, a1; };
    auto put_cl = [&](int q, std::vector<Cmd> cmds) {
        uint8_t cl[64];
        std::memset(cl, 0, sizeof(cl));
        int off = 0;
        for (auto& c : cmds) {
            const int sz = (c.op == 0x06) ? 12 : 20;   // LAUNCH : DCR_WRITE/READ
            cl[off] = c.op;
            for (int i = 0; i < 8; ++i) cl[off + 4 + i]  = uint8_t(c.a0 >> (8 * i));
            if (sz == 20)
                for (int i = 0; i < 8; ++i) cl[off + 12 + i] = uint8_t(c.a1 >> (8 * i));
            off += sz;
        }
        EXPECT(off <= 64, "test bug: too many commands for one line");
        slave.mem_write_cl(RING[q] + tail[q], cl);
        tail[q] += 64;
    };
    auto doorbell = [&](int q) {
        axil_write(sim, slave, gpu, tick, qreg(q, Q_TAIL_LO), uint32_t(tail[q]));
        axil_write(sim, slave, gpu, tick, qreg(q, Q_TAIL_HI), uint32_t(tail[q] >> 32));
    };
    auto wait_seq = [&](int q, uint32_t target) {
        for (int g = 0; g < 4000; ++g) {
            if (axil_read(sim, slave, gpu, tick, qreg(q, Q_SEQNUM)) >= target) return;
            for (int i = 0; i < 4; ++i) cycle(sim, slave, gpu, tick);
        }
        EXPECT(false, "queue did not retire its commands");
    };
    constexpr uint8_t OP_WR = 0x04, OP_RD = 0x05, OP_LAUNCH = 0x06;
    constexpr uint32_t ARG0 = 0x014;   // VX_DCR_KMU_STARTUP_ARG0 (a launch register)

    // ----- A. concurrent DCR writes from both queues -----
    gpu.log.clear();
    put_cl(0, {{OP_WR, 0x120, 0xA0}, {OP_WR, 0x121, 0xA1}, {OP_WR, 0x122, 0xA2}});
    put_cl(1, {{OP_WR, 0x130, 0xB0}, {OP_WR, 0x131, 0xB1}, {OP_WR, 0x132, 0xB2}});
    // Release both queues with one write, so they fetch, decode and bid for
    // the DCR proxy in the same cycles.
    axil_write(sim, slave, gpu, tick, CP_CTRL, 0);
    doorbell(0);
    doorbell(1);
    axil_write(sim, slave, gpu, tick, CP_CTRL, 1);
    wait_seq(0, 3);
    wait_seq(1, 3);
    {
        int seen[2][3] = {{0}};
        for (auto& r : gpu.log) {
            EXPECT(r.rw, "A: unexpected read");
            const int q = (r.addr >= 0x130) ? 1 : 0;
            const int i = int(r.addr - (q ? 0x130 : 0x120));
            EXPECT(i >= 0 && i < 3, "A: unexpected address");
            EXPECT(r.data == uint32_t((q ? 0xB0 : 0xA0) + i), "A: wrong data");
            EXPECT(r.issuer == uint32_t(q), "A: write tagged with the wrong issuer");
            ++seen[q][i];
        }
        for (int q = 0; q < 2; ++q)
            for (int i = 0; i < 3; ++i)
                EXPECT(seen[q][i] == 1, "A: a write was lost or duplicated");
    }

    // ----- B. launch registers are per queue -----
    gpu.log.clear();
    put_cl(1, {{OP_WR, ARG0, 0xBAD0BAD0}});
    doorbell(1);
    wait_seq(1, 4);
    put_cl(0, {{OP_WR, ARG0, 0x600D600D}, {OP_LAUNCH, 0, 0}});
    doorbell(0);
    wait_seq(0, 5);
    {
        int start_at = -1;
        for (size_t k = 0; k < gpu.log.size(); ++k)
            if (gpu.log[k].addr == 0xFFF) { start_at = int(k); break; }
        EXPECT(start_at > 0, "B: queue 0's launch never started");
        bool replayed = false;
        for (int k = 0; k < start_at; ++k) {
            const auto& r = gpu.log[k];
            EXPECT(r.data != 0xBAD0BAD0, "B: queue 1's launch register reached the GPU");
            if (r.addr == ARG0) {
                EXPECT(r.data == 0x600D600D, "B: queue 0's launch ran on another value");
                EXPECT(r.issuer == 0, "B: replay not tagged with the launching queue");
                replayed = true;
            }
        }
        EXPECT(replayed, "B: queue 0's launch registers were not replayed before start");
    }
    gpu.log.clear();
    put_cl(1, {{OP_LAUNCH, 0, 0}});
    doorbell(1);
    wait_seq(1, 5);
    {
        bool replayed = false;
        for (auto& r : gpu.log) {
            if (r.addr == 0xFFF) break;
            if (r.addr == ARG0) {
                EXPECT(r.data == 0xBAD0BAD0, "B: queue 1's launch did not run on its own value");
                EXPECT(r.issuer == 1, "B: replay not tagged with queue 1");
                replayed = true;
            }
        }
        EXPECT(replayed, "B: queue 1's launch registers were not replayed");
    }

    // ----- C. checker-window reads refused; responses per queue -----
    gpu.log.clear();
    put_cl(1, {{OP_RD, 0x306, 0}});            // VX_DCR_CHECKER_EPOCH
    doorbell(1);
    wait_seq(1, 6);
    put_cl(0, {{OP_RD, 0x0A0, 0}});
    doorbell(0);
    wait_seq(0, 6);
    {
        bool saw_checker = false, saw_a0 = false;
        for (auto& r : gpu.log) {
            if (r.addr == 0x306) saw_checker = true;
            if (r.addr == 0x0A0 && !r.rw) saw_a0 = true;
        }
        EXPECT(!saw_checker, "C: the checker-window read reached the GPU");
        EXPECT(saw_a0, "C: queue 0's read never reached the GPU");
        EXPECT(axil_read(sim, slave, gpu, tick, qreg(1, 0x34)) == 1, "C: queue 1's Q_DCR_BLOCKED");
        EXPECT(axil_read(sim, slave, gpu, tick, qreg(0, 0x34)) == 0, "C: queue 0's Q_DCR_BLOCKED");
        EXPECT(axil_read(sim, slave, gpu, tick, qreg(1, 0x30)) == 0, "C: refused read must answer 0");
        EXPECT(axil_read(sim, slave, gpu, tick, qreg(0, 0x30)) == 0x10A0, "C: queue 0's response");
    }

    // ----- D. device-side beats carry their queue (D7) -----
    // Both queues signal an event in the same cycles. Every device AW must
    // carry its issuing queue in the low ID bits, which is what the checker
    // on the CP's device path reads as the requester.
    constexpr uint8_t OP_SIGNAL = 0x08;
    g_dev.aw_ids.clear();
    put_cl(0, {{OP_SIGNAL, 0x80000000ull, 0x11}});
    put_cl(1, {{OP_SIGNAL, 0x80000040ull, 0x22}});
    axil_write(sim, slave, gpu, tick, CP_CTRL, 0);
    doorbell(0);
    doorbell(1);
    axil_write(sim, slave, gpu, tick, CP_CTRL, 1);
    wait_seq(0, 7);
    wait_seq(1, 7);
    {
        EXPECT(g_dev.aw_ids.size() == 2, "D: expected one device write per queue");
        int seen[2] = {0, 0};
        for (uint32_t id : g_dev.aw_ids) {
            const uint32_t q = id & 0x1Fu;   // below the xbar's source bit
            EXPECT(q < 2, "D: device AW ID names no queue");
            if (q < 2) ++seen[q];
        }
        EXPECT(seen[0] == 1 && seen[1] == 1, "D: device beats not stamped with their queue");
    }

    // ----- E. a clean-boundary request is one-shot (T8) -----
    // Queue 1 asks for a clean boundary, then launches twice: the first
    // launch replays CLEAN = 1, the second CLEAN = 0.
    {
        constexpr uint32_t CLEAN = 0x024;   // VX_DCR_KMU_CLEAN
        auto replayed_clean = [&]() -> int {
            int v = -1;
            for (auto& r : gpu.log) {
                if (r.addr == 0xFFF) break;
                if (r.rw && r.addr == CLEAN) v = int(r.data);
            }
            return v;
        };
        gpu.log.clear();
        put_cl(1, {{OP_WR, CLEAN, 1}, {OP_LAUNCH, 0, 0}});
        doorbell(1);
        wait_seq(1, 9);
        EXPECT(replayed_clean() == 1, "E: the requested launch did not replay CLEAN = 1");
        gpu.log.clear();
        put_cl(1, {{OP_LAUNCH, 0, 0}});
        doorbell(1);
        wait_seq(1, 10);
        EXPECT(replayed_clean() == 0, "E: the clean request outlived its launch");
    }

    std::printf("PASSED — CP end-to-end: NOP retired, seqnum written to "
                "cmpl_addr, Q_CONTROL.reset clears the queue; two queues: "
                "issuer tagging, no lost commands, per-queue launch registers, "
                "checker-window reads refused, device beats stamped with their queue, "
                "clean boundary one-shot\n");
    return 0;
}
