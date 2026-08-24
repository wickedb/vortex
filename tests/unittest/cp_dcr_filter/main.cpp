// ============================================================================
// cp_dcr_filter — regression for the control-plane bypass (todo.md §3 / M1).
//
// CommandProcessor::apply_qmd_ replays {dcr_addr, value} pairs read out of
// device memory. The QMD blob is staged in unclaimed memory, which the memory
// checker's boot policy leaves OWNER_ANY | R|W — writable by every tenant. A
// tenant kernel can therefore rewrite a staged QMD between submit and the CP's
// read (TOCTOU) and get its own pairs replayed with full privilege. Because
// the CP reads the blob functionally (memcpy out of RAM, never a MemReq), the
// forged write never crosses the LLC→DRAM enforcement point, so the checker
// cannot see the attack at all — the data plane is simply told to hand over
// the buffer.
//
// The forged claim is two pairs:
//     {DCR_CHECKER_BUF_OWNER  (0x302), attacker_eid}
//     {DCR_CHECKER_BUF_COMMIT (0x305), 1}
// which re-owns whatever range the staged BUF_BASE/BUF_SIZE cover, and
//     {DCR_CHECKER_EPOCH      (0x306), 0}
// which attempts to walk a revocation back.
//
// The fix is CommandProcessor::DCR_PRIV_BEGIN/END: the checker's register
// window is unreachable from a device-resident command bundle. This test
// drives the *real* model through its public MMIO surface — ring programming,
// doorbell, tick loop — so it exercises the shipped path rather than a mock,
// and asserts:
//
//   1. every legitimate KMU pair in the same QMD is still applied, in order;
//   2. no pair in [0x300, 0x340) reaches the DCR bus;
//   3. Q_DCR_BLOCKED (0x134) counts exactly the attempts, so a forged claim is
//      an observable event rather than a silent drop;
//   4. the same filter covers an OP_DRAW step list (the other device-resident
//      command bundle);
//   5. the host ring itself is unaffected — CMD_DCR_WRITE from the ring still
//      programs the checker, because the ring is the attested setup channel
//      the threat model actually trusts.
// ============================================================================

#include <cmd_processor.h>
#include <VX_types.h>

#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdint>

namespace {

int g_failures = 0;

#define CHECK(_cond)                                                    \
   do {                                                                 \
     if (!(_cond)) {                                                    \
       printf("*** FAILED %s:%d: %s\n", __FILE__, __LINE__, #_cond);    \
       ++g_failures;                                                    \
     }                                                                  \
   } while (false)

// Checker configuration window (sim/simx/sec/mem_checker.h). Duplicated here
// for the same reason the CP duplicates the range: a host-side test must not
// pull in the simx-only checker. mem_checker.cpp static_asserts the CP copy
// against the originals, and this test asserts against the CP's copy below.
constexpr uint32_t DCR_CHECKER_BUF_BASE   = 0x300;
constexpr uint32_t DCR_CHECKER_BUF_SIZE   = 0x301;
constexpr uint32_t DCR_CHECKER_BUF_OWNER  = 0x302;
constexpr uint32_t DCR_CHECKER_BUF_COMMIT = 0x305;
constexpr uint32_t DCR_CHECKER_EPOCH      = 0x306;

// CP MMIO offsets (cmd_processor.h address map).
constexpr uint32_t CP_CTRL           = 0x000;
constexpr uint32_t Q_RING_BASE_LO    = 0x100;
constexpr uint32_t Q_RING_BASE_HI    = 0x104;
constexpr uint32_t Q_HEAD_ADDR_LO    = 0x108;
constexpr uint32_t Q_CMPL_ADDR_LO    = 0x110;
constexpr uint32_t Q_RING_SIZE_LOG2  = 0x118;
constexpr uint32_t Q_CONTROL         = 0x11C;
constexpr uint32_t Q_TAIL_LO         = 0x120;
constexpr uint32_t Q_TAIL_HI         = 0x124;
constexpr uint32_t Q_DCR_BLOCKED     = 0x134;

constexpr uint8_t OP_DCR_WRITE  = 0x04;
constexpr uint8_t OP_LAUNCH_QMD = 0x0B;
constexpr uint8_t OP_DRAW       = 0x0C;

// Device-memory layout for the harness. Addresses are arbitrary but distinct;
// the ring must be cache-line aligned because the CP fetches a CL at a time.
constexpr uint64_t DRAM_BYTES = 1 << 20;
constexpr uint64_t RING_BASE  = 0x1000;
constexpr uint64_t HEAD_ADDR  = 0x0800;
constexpr uint64_t CMPL_ADDR  = 0x0840;
constexpr uint64_t QMD_ADDR   = 0x4000;
constexpr uint64_t DRAW_ADDR  = 0x8000;

// ----------------------------------------------------------------------------
// Harness: a CommandProcessor over a flat byte array, with the DCR bus
// recorded. vortex_busy models a kernel that runs for a few cycles so the
// launch sub-FSM completes rather than hanging.
// ----------------------------------------------------------------------------
struct Harness {
    std::vector<uint8_t> dram = std::vector<uint8_t>(DRAM_BYTES, 0);
    std::vector<std::pair<uint32_t, uint32_t>> dcr_writes;
    int busy_left = 0;

    vortex::CommandProcessor cp;

    Harness() : cp(make_hooks()) {
        cp.mmio_write(Q_RING_BASE_LO,   uint32_t(RING_BASE));
        cp.mmio_write(Q_RING_BASE_HI,   0);
        cp.mmio_write(Q_HEAD_ADDR_LO,   uint32_t(HEAD_ADDR));
        cp.mmio_write(Q_CMPL_ADDR_LO,   uint32_t(CMPL_ADDR));
        cp.mmio_write(Q_RING_SIZE_LOG2, 12);        // 4 KiB ring
        cp.mmio_write(Q_CONTROL,        1);         // enable
        cp.mmio_write(CP_CTRL,          1);         // enable_global
    }

    vortex::CommandProcessor::Hooks make_hooks() {
        vortex::CommandProcessor::Hooks h;
        h.dram_read = [this](uint64_t addr, void* dst, std::size_t bytes) {
            if (addr + bytes > dram.size()) { std::memset(dst, 0, bytes); return; }
            std::memcpy(dst, dram.data() + addr, bytes);
        };
        h.dram_write = [this](uint64_t addr, const void* src, std::size_t bytes) {
            if (addr + bytes > dram.size()) return;
            std::memcpy(dram.data() + addr, src, bytes);
        };
        h.vortex_dcr_write = [this](uint32_t addr, uint32_t value) {
            dcr_writes.emplace_back(addr, value);
        };
        h.vortex_dcr_read = [](uint32_t, uint32_t) -> uint32_t { return 0; };
        h.vortex_start = [this]() { busy_left = 3; };
        h.vortex_busy  = [this]() -> bool {
            if (busy_left > 0) { --busy_left; return true; }
            return false;
        };
        return h;
    }

    // Write a QMD blob: [uint32 count, count x (uint32 addr, uint32 value)].
    void write_qmd(uint64_t at, const std::vector<std::pair<uint32_t,uint32_t>>& pairs) {
        uint32_t count = uint32_t(pairs.size());
        std::memcpy(dram.data() + at, &count, sizeof(count));
        uint64_t off = at + sizeof(count);
        for (auto& p : pairs) {
            uint32_t w[2] = {p.first, p.second};
            std::memcpy(dram.data() + off, w, sizeof(w));
            off += sizeof(w);
        }
    }

    // Encode one 28-byte cmd record {opcode,flags,rsvd,arg0,arg1,arg2}.
    static void encode_cmd(uint8_t* buf, uint8_t opcode,
                           uint64_t a0, uint64_t a1 = 0, uint64_t a2 = 0) {
        std::memset(buf, 0, 28);
        buf[0] = opcode;
        std::memcpy(buf + 4,  &a0, 8);
        std::memcpy(buf + 12, &a1, 8);
        std::memcpy(buf + 20, &a2, 8);
    }

    // Write an OP_DRAW descriptor: [uint32 num_steps, steps[28 B]...].
    void write_draw(uint64_t at, const std::vector<std::vector<uint8_t>>& steps) {
        uint32_t n = uint32_t(steps.size());
        std::memcpy(dram.data() + at, &n, sizeof(n));
        uint64_t off = at + sizeof(n);
        for (auto& s : steps) {
            std::memcpy(dram.data() + off, s.data(), s.size());
            off += 28;
        }
    }

    // Push one command into the ring at byte offset `tail` and ring the
    // doorbell. Each command gets its own cache line so the CL unpacker sees
    // exactly one command (a zero header is the padding sentinel).
    void submit(uint8_t opcode, uint64_t arg0, uint64_t arg1 = 0) {
        uint8_t cl[64] = {0};
        encode_cmd(cl, opcode, arg0, arg1);
        std::memcpy(dram.data() + RING_BASE + tail_, cl, sizeof(cl));
        tail_ += 64;
        cp.mmio_write(Q_TAIL_LO, uint32_t(tail_));
        cp.mmio_write(Q_TAIL_HI, uint32_t(tail_ >> 32));
    }

    // Run until the CP goes idle, with a bound so a hang fails the test rather
    // than spinning forever.
    bool drain(int max_cycles = 100000) {
        for (int i = 0; i < max_cycles; ++i) {
            if (!cp.busy()) return true;
            cp.tick();
        }
        return false;
    }

    uint32_t blocked() const { return cp.mmio_read(Q_DCR_BLOCKED); }

    bool saw(uint32_t addr) const {
        for (auto& w : dcr_writes) if (w.first == addr) return true;
        return false;
    }

  private:
    uint64_t tail_ = 0;
};

// ----------------------------------------------------------------------------
// 1-3: forged claim inside a QMD is refused; the legitimate pairs still apply.
// ----------------------------------------------------------------------------
int test_qmd_forged_claim() {
    Harness h;
    // What the host staged, interleaved with what a tenant kernel overwrote it
    // with. Interleaved deliberately: the filter must be per-pair, not a
    // "reject the whole blob" rule that would let one forged pair deny service
    // to the launch carrying it.
    h.write_qmd(QMD_ADDR, {
        {VX_DCR_KMU_KERNEL_ENTRY0, 0xdeadbeef},
        {DCR_CHECKER_BUF_BASE,     0x10000000},   // forged: retarget the claim
        {VX_DCR_KMU_BLOCK_DIM_X,   64},
        {DCR_CHECKER_BUF_SIZE,     0x1000},       // forged
        {DCR_CHECKER_BUF_OWNER,    1},            // forged: "this is mine"
        {VX_DCR_KMU_GRID_DIM_X,    8},
        {DCR_CHECKER_BUF_COMMIT,   1},            // forged: install it
        {DCR_CHECKER_EPOCH,        0},            // forged: undo a revocation
        {VX_DCR_KMU_LMEM_SIZE,     0},
    });
    h.submit(OP_LAUNCH_QMD, QMD_ADDR);
    CHECK(h.drain());

    // (1) every legitimate KMU pair applied, in order, values intact.
    const std::vector<std::pair<uint32_t,uint32_t>> expect = {
        {VX_DCR_KMU_KERNEL_ENTRY0, 0xdeadbeef},
        {VX_DCR_KMU_BLOCK_DIM_X,   64},
        {VX_DCR_KMU_GRID_DIM_X,    8},
        {VX_DCR_KMU_LMEM_SIZE,     0},
    };
    CHECK(h.dcr_writes == expect);

    // (2) nothing in the checker window reached the DCR bus.
    for (auto& w : h.dcr_writes) {
        CHECK(!(w.first >= vortex::CommandProcessor::DCR_PRIV_BEGIN &&
                w.first <  vortex::CommandProcessor::DCR_PRIV_END));
    }

    // (3) the attempt is counted, not silently dropped.
    CHECK(h.blocked() == 5);
    return 0;
}

// ----------------------------------------------------------------------------
// 2 (boundary): the window is half-open [BEGIN, END). The register just below
// and the one at END are ordinary DCRs and must still pass, so the filter
// cannot quietly swallow unrelated traffic.
// ----------------------------------------------------------------------------
int test_qmd_window_boundaries() {
    Harness h;
    const uint32_t begin = vortex::CommandProcessor::DCR_PRIV_BEGIN;
    const uint32_t end   = vortex::CommandProcessor::DCR_PRIV_END;
    h.write_qmd(QMD_ADDR, {
        {begin - 1, 0xA},   // outside, below     -> applied
        {begin,     0xB},   // first protected    -> blocked
        {end - 1,   0xC},   // last protected     -> blocked
        {end,       0xD},   // outside, above     -> applied
    });
    h.submit(OP_LAUNCH_QMD, QMD_ADDR);
    CHECK(h.drain());

    const std::vector<std::pair<uint32_t,uint32_t>> expect = {
        {begin - 1, 0xA}, {end, 0xD},
    };
    CHECK(h.dcr_writes == expect);
    CHECK(h.blocked() == 2);
    return 0;
}

// ----------------------------------------------------------------------------
// 4: the other device-resident command bundle. An OP_DRAW step list is read
// out of the same world-writable memory, so a CMD_DCR_WRITE step is exactly as
// forgeable as a QMD pair and gets the same treatment. Its embedded
// CMD_LAUNCH_QMD is filtered too, since it runs apply_qmd_.
// ----------------------------------------------------------------------------
int test_draw_bundle_forged_claim() {
    Harness h;
    h.write_qmd(QMD_ADDR, {
        {VX_DCR_KMU_BLOCK_DIM_X, 32},
        {DCR_CHECKER_BUF_OWNER,  1},    // forged, inside the nested QMD
    });

    std::vector<std::vector<uint8_t>> steps;
    auto step = [&](uint8_t op, uint64_t a0, uint64_t a1 = 0) {
        std::vector<uint8_t> b(28);
        Harness::encode_cmd(b.data(), op, a0, a1);
        steps.push_back(std::move(b));
    };
    step(OP_DCR_WRITE, VX_DCR_KMU_GRID_DIM_X,   4);   // legitimate
    step(OP_DCR_WRITE, DCR_CHECKER_BUF_OWNER,   1);   // forged
    step(OP_DCR_WRITE, DCR_CHECKER_BUF_COMMIT,  1);   // forged
    step(OP_LAUNCH_QMD, QMD_ADDR);
    h.write_draw(DRAW_ADDR, steps);

    h.submit(OP_DRAW, DRAW_ADDR);
    CHECK(h.drain());

    const std::vector<std::pair<uint32_t,uint32_t>> expect = {
        {VX_DCR_KMU_GRID_DIM_X,  4},
        {VX_DCR_KMU_BLOCK_DIM_X, 32},
    };
    CHECK(h.dcr_writes == expect);
    CHECK(!h.saw(DCR_CHECKER_BUF_OWNER));
    CHECK(!h.saw(DCR_CHECKER_BUF_COMMIT));
    CHECK(h.blocked() == 3);            // 2 draw steps + 1 nested QMD pair
    return 0;
}

// ----------------------------------------------------------------------------
// 5: the setup channel still works. Every existing checker demo programs its
// policy with vx_enqueue_dcr_write, which becomes a CMD_DCR_WRITE in the host
// ring. The ring is the attested channel; filtering it would break the
// mechanism instead of protecting it.
// ----------------------------------------------------------------------------
int test_ring_dcr_write_still_privileged() {
    Harness h;
    h.submit(OP_DCR_WRITE, DCR_CHECKER_BUF_BASE,  0x20000000);
    h.submit(OP_DCR_WRITE, DCR_CHECKER_BUF_OWNER, 0);
    h.submit(OP_DCR_WRITE, DCR_CHECKER_BUF_COMMIT, 1);
    CHECK(h.drain());

    const std::vector<std::pair<uint32_t,uint32_t>> expect = {
        {DCR_CHECKER_BUF_BASE,   0x20000000},
        {DCR_CHECKER_BUF_OWNER,  0},
        {DCR_CHECKER_BUF_COMMIT, 1},
    };
    CHECK(h.dcr_writes == expect);
    CHECK(h.blocked() == 0);
    return 0;
}

} // namespace

int main() {
    test_qmd_forged_claim();
    test_qmd_window_boundaries();
    test_draw_bundle_forged_claim();
    test_ring_dcr_write_still_privileged();

    if (g_failures != 0) {
        printf("Found %d errors!\n", g_failures);
        return 1;
    }
    printf("PASSED!\n");
    return 0;
}
