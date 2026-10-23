// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

// ============================================================================
// Verilator unit test for VX_cp_launch.
//
// FSM under test:
//   IDLE         grant → REPLAY (latch the granted queue)
//   REPLAY       write the queue's NUM_SHADOW launch registers onto the DCR
//                bus, one per accepted cycle (dcr_req_ready) → SETTLE
//   SETTLE       a few cycles with no start, so the last write reaches the
//                GPU first → PULSE_START
//   PULSE_START  one-cycle `start` pulse → WAIT_BUSY
//   WAIT_BUSY    gpu_busy ↑ → WAIT_DRAIN
//   WAIT_DRAIN   gpu_busy ↓ → done pulse → IDLE
//
// Coverage:
//   1. Reset → IDLE, idle high, no spurious start/done/request.
//   2. Long idle while grant=0 → no transition.
//   3. A full launch for each of several queues: the replay presents every
//      shadow slot exactly once, in order, at the right address, with that
//      queue's value (the C++ shadow model) and launch_q == the granted queue;
//      start only after the last write and the settle; idle low throughout.
//   4. Back-pressure: dcr_req_ready held low stalls the replay on the same
//      slot (no skipped or repeated writes).
//   5. WAIT_BUSY waits indefinitely for busy; start and done are one cycle.
// ============================================================================

#include "vl_simulator.h"
#include "VVX_cp_launch_top.h"
#include <cstdio>
#include <cstdlib>

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

// The shadow store the core would hold: a distinct value per (queue, slot).
static uint32_t shadow_value(uint32_t q, uint32_t idx) {
    return 0x51000000u | (q << 16) | idx;
}

// Drive the shadow read port from the DUT's (launch_q, shadow_idx), then
// sample. Combinational, as the core's array read is.
template <typename T>
static void settle_inputs(vl_simulator<T>& sim) {
    sim->eval();
    sim->shadow_rd_data = shadow_value(sim->launch_q, sim->shadow_idx);
    sim->eval();
}

template <typename T>
static void cycle(vl_simulator<T>& sim, uint64_t& tick) {
    settle_inputs(sim);
    tick = sim.step(tick, 2);
}

// One full launch for queue `q`. `stall_at` (or -1) is a replay slot at which
// dcr_req_ready is held low for `stall_len` cycles.
template <typename T>
static void launch(vl_simulator<T>& sim, uint64_t& tick, uint32_t q,
                   int busy_hold, int stall_at, int stall_len) {
    const uint32_t n    = sim->num_shadow;
    const uint32_t base = sim->shadow_base;

    // IDLE, granted this cycle.
    sim->grant         = 1;
    sim->grant_q       = q;
    sim->gpu_busy      = 0;
    sim->dcr_req_ready = 1;
    settle_inputs(sim);
    EXPECT(sim->idle == 1, "idle should be high before the grant edge");
    EXPECT(sim->start == 0 && sim->done == 0, "no start/done in IDLE");
    EXPECT(sim->dcr_req_valid == 0, "no DCR request in IDLE");
    cycle(sim, tick);
    sim->grant   = 0;
    sim->grant_q = (q + 1) & 3;   // a later grant_q must not matter

    // REPLAY: every slot once, in order, for queue q.
    uint32_t slot = 0;
    int stalled = 0;
    while (slot < n) {
        const bool stall = (int(slot) == stall_at) && (stalled < stall_len);
        sim->dcr_req_ready = stall ? 0 : 1;
        settle_inputs(sim);
        EXPECT(sim->idle == 0, "idle must be low during the replay");
        EXPECT(sim->replaying == 1, "replaying should be high in REPLAY");
        EXPECT(sim->start == 0, "start must not fire during the replay");
        EXPECT(sim->dcr_req_valid == 1, "replay must present a request every cycle");
        EXPECT(sim->launch_q == q, "launch_q must be the granted queue");
        EXPECT(sim->shadow_idx == slot, "replay skipped or repeated a slot");
        EXPECT(sim->dcr_req_addr == base + slot, "replay address is not the slot's DCR");
        EXPECT(sim->dcr_req_data == shadow_value(q, slot), "replay data is not the queue's shadow");
        cycle(sim, tick);
        if (stall) ++stalled; else ++slot;
    }
    sim->dcr_req_ready = 1;

    // SETTLE then PULSE_START: no request, no start until the settle ends.
    int settle_cycles = 0;
    for (;;) {
        settle_inputs(sim);
        EXPECT(sim->dcr_req_valid == 0, "no request after the replay");
        EXPECT(sim->replaying == 0, "replaying should drop after the last slot");
        if (sim->start) break;
        ++settle_cycles;
        EXPECT(settle_cycles <= 8, "start never fired after the replay");
        cycle(sim, tick);
    }
    EXPECT(settle_cycles >= 3, "start fired before the last write could settle");
    EXPECT(sim->done == 0, "done should be 0 in PULSE_START");
    cycle(sim, tick);

    // WAIT_BUSY: start low, no done while busy has not risen.
    for (int i = 0; i < 2; ++i) {
        settle_inputs(sim);
        EXPECT(sim->start == 0, "start must be exactly one cycle");
        EXPECT(sim->done == 0, "done while busy hasn't risen");
        cycle(sim, tick);
    }
    sim->gpu_busy = 1;
    cycle(sim, tick);
    for (int i = 0; i < busy_hold; ++i) {
        settle_inputs(sim);
        EXPECT(sim->done == 0, "done fired while busy still high");
        EXPECT(sim->idle == 0, "idle must stay low while the kernel runs");
        cycle(sim, tick);
    }
    sim->gpu_busy = 0;
    settle_inputs(sim);
    EXPECT(sim->done == 1, "done should pulse on busy falling edge");
    cycle(sim, tick);
    settle_inputs(sim);
    EXPECT(sim->done == 0, "done should not stick after one cycle");
    EXPECT(sim->idle == 1, "idle should return after the drain");
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    vl_simulator<VVX_cp_launch_top> sim;
    uint64_t tick = 0;

    sim->grant         = 0;
    sim->grant_q       = 0;
    sim->gpu_busy      = 0;
    sim->dcr_req_ready = 1;
    tick = sim.reset(tick);

    EXPECT(sim->num_shadow > 0, "shadow geometry not exported");

    for (int i = 0; i < 5; ++i) {
        settle_inputs(sim);
        EXPECT(sim->idle == 1, "idle should be high after reset");
        EXPECT(sim->start == 0 && sim->done == 0, "no start/done during idle");
        EXPECT(sim->dcr_req_valid == 0, "no DCR request during idle");
        cycle(sim, tick);
    }

    launch(sim, tick, /*q=*/0, /*busy_hold=*/1, /*stall_at=*/-1, 0);
    launch(sim, tick, /*q=*/2, /*busy_hold=*/3, /*stall_at=*/0, 2);
    launch(sim, tick, /*q=*/3, /*busy_hold=*/0, /*stall_at=*/int(sim->num_shadow) - 1, 3);
    launch(sim, tick, /*q=*/1, /*busy_hold=*/2, /*stall_at=*/5, 1);

    std::printf("PASSED (%u shadow slots per launch)\n", unsigned(sim->num_shadow));
    return 0;
}
