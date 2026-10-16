// confine — SimX proof of concept for confinement by taint
// (docs/proposals/kernel_identity_oct16.md, hospital walk-through).
//
// Setup over the checker's DCR path:
//   images  owner H, perms RW, shared R, CONFINED   (H's data, granted to M)
//   mown    owner M, perms RW                       (M's own buffer)
//   pub     unclaimed                               (anyone's memory)
//   out     owner M, co-owner H, perms RW           (the agreed output)
//   origin  owner M, co-owner H, perms RW           (bookkeeping)
//   stack   owner M, co-owner H, perms RW           (the fixed stack granule)
// Then three launches on two cores, core 0 = H and core 1 = M:
//   0 TRAIN         M reads images, writes out = image ^ KEY, and tries to
//                   copy the raw images into mown and into pub.
//   1 EXPORT_EARLY  M copies out into its own buffer: H still co-owns it.
//   -- H leaves the output's owner set (the release) --
//   2 EXPORT_LATE   the same copy, now that out belongs to M alone.
// Expected with VX_CHECKER_TAINT=1: the training output lands, both
// laundering writes and the early export are refused, the late export lands.
// Expected without it (the control): the laundering lands and the test fails.
//
// Host copies are functional and not judged by the checker (review issue 2),
// so the host reads everything back directly to verify.

#include <vortex2.h>
#include "common.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <vector>

#define CHECK(expr) do { \
    vx_result_t _r = (expr); \
    if (_r != VX_SUCCESS) { \
        std::fprintf(stderr, "FAIL %s:%d: '%s' returned %s\n", \
                     __FILE__, __LINE__, #expr, vx_result_string(_r)); \
        std::exit(1); \
    } \
} while (0)

namespace {
const char* kernel_file = "kernel.vxbin";
uint32_t    size        = 32;
bool        claim_stack = true;

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:k:Sh")) != -1) {
        switch (c) {
            case 'n': size        = std::atoi(optarg); break;
            case 'k': kernel_file = optarg;            break;
            case 'S': claim_stack = false;             break;
            default:
                std::cout << "Usage: [-k kernel] [-n words] [-S (leave the stack unclaimed)] [-h]" << std::endl;
                std::exit(c == 'h' ? 0 : -1);
        }
    }
}

void dcr(vx_queue_h q, uint32_t addr, uint32_t value) {
    CHECK(vx_enqueue_dcr_write(q, addr, value, 0, nullptr, nullptr));
}

// Every staged register is written on every claim: staged values persist
// across commits, so a claim that skipped BUF_JOINT would inherit the last one.
void enqueue_claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner,
                   uint32_t joint, uint32_t perms, uint32_t shared, uint32_t confined) {
    dcr(q, DCR_CHECKER_BUF_BASE,     (uint32_t)base);
    dcr(q, DCR_CHECKER_BUF_SIZE,     (uint32_t)bytes);
    dcr(q, DCR_CHECKER_BUF_OWNER,    owner);
    dcr(q, DCR_CHECKER_BUF_PERMS,    perms);
    dcr(q, DCR_CHECKER_BUF_SHARED,   shared);
    dcr(q, DCR_CHECKER_BUF_EPOCH,    GRANT_NO_EXPIRY);
    dcr(q, DCR_CHECKER_BUF_JOINT,    joint);
    dcr(q, DCR_CHECKER_BUF_CONFINED, confined);
    dcr(q, DCR_CHECKER_BUF_COMMIT,   1);
}

struct Padded {
    vx_buffer_h buf = nullptr;
    uint64_t    base = 0;   // granule-aligned device address the claim covers
    uint64_t    off = 0;    // base - allocation start
};

Padded make_padded(vx_device_h dev, uint64_t bytes, uint64_t granule) {
    Padded p;
    CHECK(vx_buffer_create(dev, bytes + 2*granule, VX_MEM_READ_WRITE, &p.buf));
    uint64_t dev_addr = 0;
    CHECK(vx_buffer_address(p.buf, &dev_addr));
    p.base = (dev_addr + granule - 1) & ~(granule - 1);
    p.off  = p.base - dev_addr;
    return p;
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);

    const uint32_t n     = size;
    const uint64_t words = n * sizeof(uint32_t);

    uint32_t buf_log2 = 20;
    if (const char* e = std::getenv("VX_CHECKER_BUF_LOG2")) {
        if (*e) buf_log2 = std::strtoul(e, nullptr, 0);
    }
    const uint64_t granule = 1ull << buf_log2;
    const char* taint_env = std::getenv("VX_CHECKER_TAINT");
    const bool taint_on = taint_env && *taint_env && *taint_env != '0';

    std::cout << "confine: n=" << n << " granule=" << granule << "B taint="
              << (taint_on ? "on" : "off (control)") << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    Padded images = make_padded(dev, words, granule);
    Padded mown   = make_padded(dev, NUM_PHASES * words, granule);
    Padded pub    = make_padded(dev, words, granule);
    Padded out    = make_padded(dev, words, granule);
    Padded origin = make_padded(dev, NUM_PHASES * words, granule);

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    std::vector<uint32_t> h_images(n), h_zero(NUM_PHASES * n, 0);
    for (uint32_t i = 0; i < n; ++i)
        h_images[i] = SECRET(i);
    CHECK(vx_enqueue_write(q, images.buf, images.off, h_images.data(), words, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q, mown.buf,   mown.off,   h_zero.data(), NUM_PHASES * words, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q, pub.buf,    pub.off,    h_zero.data(), words, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q, out.buf,    out.off,    h_zero.data(), words, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q, origin.buf, origin.off, h_zero.data(), NUM_PHASES * words, 0, nullptr, nullptr));

    const uint32_t RW = CHECKER_PERM_R | CHECKER_PERM_W;
    const uint32_t H_BIT = 1u << TENANT_H;
    enqueue_claim(q, images.base, words, TENANT_H, 0, RW, CHECKER_PERM_R, 1);
    enqueue_claim(q, mown.base, NUM_PHASES * words, TENANT_M, 0, RW, 0, 0);
    enqueue_claim(q, out.base, words, TENANT_M, H_BIT, RW, 0, 0);
    enqueue_claim(q, origin.base, NUM_PHASES * words, TENANT_M, H_BIT, RW, 0, 0);
    if (claim_stack) {
        // The stacks sit at a fixed address below VX_MEM_STACK_BASE_ADDR
        // (0xFFFF0000 at XLEN=32). A kernel that has read confined data can
        // only spill to memory H co-owns, so the stack granule is joint too.
        const uint64_t stack_top = 0xFFFF0000ull;
        const uint64_t stack_granule = (stack_top - 1) & ~(granule - 1);
        enqueue_claim(q, stack_granule, granule, TENANT_M, H_BIT, RW, 0, 0);
    }

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &n, grid, block));

    kernel_arg_t args[NUM_PHASES];
    vx_event_h launch_ev[NUM_PHASES] = {};
    for (uint32_t phase = 0; phase < NUM_PHASES; ++phase) {
        if (phase == PHASE_EXPORT_LATE) {
            // The release: H leaves the output's owner set.
            dcr(q, DCR_CHECKER_BUF_BASE,  (uint32_t)out.base);
            dcr(q, DCR_CHECKER_BUF_SIZE,  (uint32_t)words);
            dcr(q, DCR_CHECKER_BUF_LEAVE, TENANT_H);
        }
        kernel_arg_t& a = args[phase];
        a = kernel_arg_t{};
        a.num_points  = n;
        a.phase       = phase;
        a.images_addr = images.base;
        a.mown_addr   = mown.base;
        a.pub_addr    = pub.base;
        a.out_addr    = out.base;
        a.origin_addr = origin.base;

        vx_launch_info_t li{};
        li.struct_size = sizeof(li);
        li.kernel      = kern;
        li.args_host   = &a;
        li.args_size   = sizeof(a);
        li.ndim        = 1;
        li.grid_dim[0] = grid[0];
        li.block_dim[0]= block[0];
        CHECK(vx_enqueue_launch(q, &li, phase ? 1 : 0, phase ? &launch_ev[phase-1] : nullptr,
                                &launch_ev[phase]));
    }

    std::vector<uint32_t> r_mown(NUM_PHASES * n), r_pub(n), r_out(n), r_origin(NUM_PHASES * n);
    vx_event_h last = launch_ev[NUM_PHASES - 1], read_ev = nullptr;
    CHECK(vx_enqueue_read(q, r_mown.data(),   mown.buf,   mown.off,   NUM_PHASES * words, 1, &last, nullptr));
    CHECK(vx_enqueue_read(q, r_pub.data(),    pub.buf,    pub.off,    words, 1, &last, nullptr));
    CHECK(vx_enqueue_read(q, r_out.data(),    out.buf,    out.off,    words, 1, &last, nullptr));
    CHECK(vx_enqueue_read(q, r_origin.data(), origin.buf, origin.off, NUM_PHASES * words, 1, &last, &read_ev));
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    // ----- verification, per core-1 (M) task, per phase -----
    int errors = 0;
    uint32_t m_tasks[NUM_PHASES] = {}, h_tasks[NUM_PHASES] = {};
    uint32_t trained = 0, laundered_mown = 0, laundered_pub = 0, early = 0, late = 0;
    auto fail = [&](uint32_t phase, uint32_t i, const char* what, uint32_t exp, uint32_t got) {
        if (errors < 16)
            std::printf("*** phase %u [%u] %s: expected=0x%08x actual=0x%08x\n", phase, i, what, exp, got);
        ++errors;
    };
    for (uint32_t phase = 0; phase < NUM_PHASES; ++phase) {
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t core = r_origin[phase * n + i];
            if (core == TENANT_H) { ++h_tasks[phase]; continue; }
            if (core != TENANT_M) { fail(phase, i, "origin core id", TENANT_M, core); continue; }
            ++m_tasks[phase];
            if (phase == PHASE_TRAIN) {
                if (r_out[i] == (SECRET(i) ^ KEY)) ++trained;
                else fail(phase, i, "training output (joint) must land", SECRET(i) ^ KEY, r_out[i]);
                if (r_mown[i] == SECRET(i)) { ++laundered_mown; fail(phase, i, "launder into M's buffer (leak!)", 0, r_mown[i]); }
                if (r_pub[i] == SECRET(i))  { ++laundered_pub;  fail(phase, i, "launder into unclaimed (leak!)", 0, r_pub[i]); }
            } else if (phase == PHASE_EXPORT_EARLY) {
                uint32_t got = r_mown[phase * n + i];
                if (got != 0 && got == r_out[i]) { ++early; fail(phase, i, "export before release (leak!)", 0, got); }
            } else {
                uint32_t got = r_mown[phase * n + i];
                if (got == r_out[i]) ++late;
                else fail(phase, i, "export after release must land", r_out[i], got);
            }
        }
    }

    std::printf("tasks on M (core 1) per phase: %u %u %u; on H (core 0): %u %u %u\n",
                m_tasks[0], m_tasks[1], m_tasks[2], h_tasks[0], h_tasks[1], h_tasks[2]);
    std::printf("RESULT train_output_landed=%u/%u launder_mown=%u launder_unclaimed=%u "
                "export_before_release=%u export_after_release=%u/%u\n",
                trained, m_tasks[0], laundered_mown, laundered_pub, early, late, m_tasks[2]);

    for (uint32_t phase = 0; phase < NUM_PHASES; ++phase) {
        if (m_tasks[phase] == 0) {
            std::cout << "phase " << phase << ": no task ran on core 1 — run with --cores=2\nFAILED!" << std::endl;
            return 1;
        }
    }

    vx_event_release(read_ev);
    for (auto ev : launch_ev) vx_event_release(ev);
    for (auto* p : {&images, &mown, &pub, &out, &origin}) vx_buffer_release(p->buf);
    vx_kernel_release(kern);
    vx_module_release(mod);
    vx_queue_release(q);
    vx_device_dump_perf(dev, stdout);
    vx_device_release(dev);

    if (errors) {
        std::cout << "Found " << errors << " errors!\nFAILED!" << std::endl;
        return 1;
    }
    std::cout << "PASSED!" << std::endl;
    return 0;
}
