// churn — Tier-3 policy-churn amortization workload (PROJECT.md §12, figure 3).
//
// Owner A (eid 0) holds a dataset in `chunks` buffers. Per epoch, A re-grants B
// (eid 1) read on one chunk, B's kernel reduces it into B-owned output, then A
// revokes. Nine DCR ring writes per epoch — 7 to re-grant at a fresh
// grant_epoch, 2 to revoke — around one launch.
//
// Two modes, and the curve is the difference between them:
//
//   --mode=0  CONTROL. Every chunk claimed once up front with a no-expiry
//             grant; `epochs` launches, zero policy operations in between.
//   --mode=1  CHURN. Same launches, same work, with re-grant + revoke around
//             each one.
//
//   policy overhead = cycles(churn) - cycles(control)
//   per-epoch cost  = that difference / epochs
//   policy share    = that difference / cycles(churn)
//
// Sweeping `--taps` moves work-per-epoch while holding the policy cost per
// epoch fixed, which is what makes the curve an amortization curve. The
// analogue is the Blackwell CC-tax figure (14% at 256 tokens → ~1% at 2048),
// with grant/revoke playing the role of the per-submission tax.
//
// Identity model, stated because it shapes what this measures: owner is core id
// (§10 #6), the grid spans both cores, so the read stream splits — core 0's
// half is A reading its own buffer under owner perms, core 1's half is B
// reading under the grant. The grant is genuinely exercised and the revoke
// genuinely expires it; what is being timed is the policy operations, which are
// scoped to A either way. A correct run has deny=0: the grant is live for the
// whole of every launch, because this measures the cost of policy change, not
// denial. Denial is revoke / revoke_scope's job.
//
// Needs --cores=2 for B to exist at all, and VX_CHECKER=1.
//
// The invalidate is NOT included in these numbers and cannot be: no invalidate
// primitive exists (PROJECT.md §10 #9), and SimX's per-launch reset is stronger
// than anything the design can issue. Per §10 #9 the curve therefore ships with
// the invalidate as a bounded unknown swept 0 → full-flush, applied in
// post-processing by sweep.sh. Check that the conclusion survives the worst end.

#include <vortex2.h>
#include <VX_types.h>   // VX_DCR_CHECKER_* / VX_CHECKER_* — generated, not mirrored
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
uint32_t num_points = 4096;
uint32_t taps       = 8;
uint32_t epochs     = 8;
uint32_t chunks     = 4;
uint32_t mode       = 1;   // 1 = churn, 0 = control

void usage() {
    std::cout << "churn: Tier-3 policy-churn amortization workload\n"
              << "  -n <points>  points per chunk (default 4096)\n"
              << "  -t <taps>    reduction width = work-per-epoch knob (default 8)\n"
              << "  -e <epochs>  grant/launch/revoke cycles (default 8)\n"
              << "  -c <chunks>  dataset chunks A rotates through (default 4)\n"
              << "  -m <0|1>     0 = control (no policy ops), 1 = churn (default 1)\n"
              << "  -k <file>    kernel binary\n"
              << "Run with --cores=2 and VX_CHECKER=1." << std::endl;
}

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:t:e:c:m:k:h")) != -1) {
        switch (c) {
        case 'n': num_points = std::atoi(optarg); break;
        case 't': taps       = std::atoi(optarg); break;
        case 'e': epochs     = std::atoi(optarg); break;
        case 'c': chunks     = std::atoi(optarg); break;
        case 'm': mode       = std::atoi(optarg); break;
        case 'k': kernel_file = optarg; break;
        case 'h': usage(); std::exit(0);
        default:  usage(); std::exit(1);
        }
    }
}

// The 7-write staged claim. Installing a claim and re-granting it are the same
// operation — stage, then commit — which is the point §2.2 makes about headers
// staying read-only in steady state.
void enqueue_claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner,
                   uint32_t perms, uint32_t shared, uint32_t epoch) {
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_BASE,   (uint32_t)base,  0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_SIZE,   (uint32_t)bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_OWNER,  owner,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_PERMS,  perms,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_SHARED, shared,          0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_EPOCH,  epoch,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_COMMIT, 1,               0, nullptr, nullptr));
}

// The 2-write scoped revoke. Stage whose epoch moves, then move it. No header
// is touched, which is the whole reason this is cheap.
void enqueue_revoke(vx_queue_h q, uint32_t owner, uint32_t new_epoch) {
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_REVOKE_OWNER, owner,     0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_EPOCH,        new_epoch, 0, nullptr, nullptr));
}

} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);
    if (chunks == 0 || epochs == 0 || num_points == 0 || taps == 0) {
        std::cout << "chunks, epochs, points and taps must all be non-zero\nFAILED!" << std::endl;
        return 1;
    }

    const uint64_t used_size = uint64_t(num_points) * sizeof(uint32_t);
    const uint32_t buf_log2  = []() -> uint32_t {
        if (const char* s = std::getenv("VX_CHECKER_BUF_LOG2"))
            return (uint32_t)std::strtoul(s, nullptr, 0);
        return 20;
    }();
    const uint64_t granule = 1ull << buf_log2;

    std::cout << "churn: mode=" << (mode ? "churn" : "control")
              << " n=" << num_points << " taps=" << taps
              << " epochs=" << epochs << " chunks=" << chunks
              << " buf=" << used_size << "B granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_h q = nullptr;
    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    CHECK(vx_queue_create(dev, &qi, &q));

    // Each chunk gets its own granule-aligned claim, padded by two granules so
    // outward rounding can never reach a neighbour (the twotenant convention,
    // §10 m4). Without this, two chunks could share a granule and the second
    // claim would be a same-owner re-claim rather than an independent one.
    std::vector<vx_buffer_h> chunk_buf(chunks, nullptr);
    std::vector<uint64_t>    chunk_base(chunks, 0), chunk_off(chunks, 0);
    for (uint32_t c = 0; c < chunks; ++c) {
        CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &chunk_buf[c]));
        uint64_t dev_addr = 0;
        CHECK(vx_buffer_address(chunk_buf[c], &dev_addr));
        chunk_base[c] = (dev_addr + granule - 1) & ~(granule - 1);
        chunk_off[c]  = chunk_base[c] - dev_addr;
    }

    vx_buffer_h out_buf = nullptr;
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &out_buf));
    uint64_t out_dev = 0;
    CHECK(vx_buffer_address(out_buf, &out_dev));
    const uint64_t out_base = (out_dev + granule - 1) & ~(granule - 1);
    const uint64_t out_off  = out_base - out_dev;

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    // Chunk-tagged data, so a read of the wrong chunk is distinguishable from
    // poison and from zero.
    std::vector<std::vector<uint32_t>> h_chunk(chunks);
    for (uint32_t c = 0; c < chunks; ++c) {
        h_chunk[c].resize(num_points);
        for (uint32_t i = 0; i < num_points; ++i)
            h_chunk[c][i] = CHUNK_VAL(c, i);
        CHECK(vx_enqueue_write(q, chunk_buf[c], chunk_off[c], h_chunk[c].data(),
                               used_size, 0, nullptr, nullptr));
    }
    std::vector<uint32_t> h_zero(num_points, 0);
    CHECK(vx_enqueue_write(q, out_buf, out_off, h_zero.data(), used_size, 0, nullptr, nullptr));

    // The output buffer is left UNCLAIMED, i.e. system/shared under the boot
    // default (OWNER_ANY, R|W) — the same convention twotenant uses for its
    // probe/origin result buffers.
    //
    // Claiming it for B instead looks tidier and is wrong here: the grid spans
    // both cores, so under the one-tenant-per-core identity model core 0's
    // tasks are owner A, and A writing into a B-owned buffer with shared_perms=0
    // is correctly denied. The first run of this test did exactly that and
    // reported deny=256. The thing under policy in this experiment is the
    // *input* chunk A grants to B; the output does not need protecting to
    // measure the cost of changing that grant, and protecting it would measure
    // a denial storm instead.
    if (mode == 0) {
        // Control: claim every chunk once, grant never expires, no churn.
        for (uint32_t c = 0; c < chunks; ++c)
            enqueue_claim(q, chunk_base[c], used_size, 0,
                          VX_CHECKER_PERM_R | VX_CHECKER_PERM_W,
                          VX_CHECKER_PERM_R, VX_CHECKER_GRANT_NO_EXPIRY);
    }

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &num_points, grid, block));

    std::vector<kernel_arg_t> args(epochs);
    vx_event_h last_ev = nullptr;

    for (uint32_t e = 0; e < epochs; ++e) {
        const uint32_t c = e % chunks;

        // Re-grant this chunk at a fresh grant_epoch. A's current epoch is e
        // (bumped to e by the previous iteration's revoke), and the grant holds
        // while current_epoch <= grant_epoch — so grant_epoch = e is live now
        // and dies the moment A's epoch reaches e+1.
        if (mode == 1)
            enqueue_claim(q, chunk_base[c], used_size, 0,
                          VX_CHECKER_PERM_R | VX_CHECKER_PERM_W,
                          VX_CHECKER_PERM_R, e);

        args[e] = kernel_arg_t{};
        args[e].num_points = num_points;
        args[e].taps       = taps;
        args[e].chunk      = c;
        args[e].in_addr    = chunk_base[c];
        args[e].out_addr   = out_base;

        vx_launch_info_t li{};
        li.struct_size  = sizeof(li);
        li.kernel       = kern;
        li.args_host    = &args[e];
        li.args_size    = sizeof(args[e]);
        li.ndim         = 1;
        li.grid_dim[0]  = grid[0];
        li.block_dim[0] = block[0];

        if (last_ev) { vx_event_release(last_ev); last_ev = nullptr; }
        CHECK(vx_enqueue_launch(q, &li, 0, nullptr, &last_ev));

        // Revoke. The queue is FIFO and each launch drains before the next
        // command retires, so this lands strictly between launches — which is
        // §2.2 Bound 1 as a property of the interface, not of this protocol.
        if (mode == 1)
            enqueue_revoke(q, 0, e + 1);
    }

    // Wait on the read's own event rather than flushing the queue: the host
    // buffer is only guaranteed populated once the read retires (the pattern
    // revoke_scope uses).
    std::vector<uint32_t> h_out(num_points);
    vx_event_h read_ev = nullptr;
    CHECK(vx_enqueue_read(q, h_out.data(), out_buf, out_off, used_size,
                          last_ev ? 1 : 0, last_ev ? &last_ev : nullptr, &read_ev));
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    // Value-check, never counter-check (§2.3). A grant that failed to install
    // would give B poison, and the sums would be wrong — aggregate deny counts
    // could not tell us that.
    const uint32_t last_chunk = (epochs - 1) % chunks;
    uint32_t errors = 0, poisoned = 0;
    for (uint32_t i = 0; i < num_points; ++i) {
        uint32_t want = 0;
        for (uint32_t k = 0; k < taps; ++k) {
            uint32_t j = i + k;
            if (j >= num_points) j -= num_points;
            want += h_chunk[last_chunk][j];
        }
        if (h_out[i] != want) {
            if (h_out[i] == POISON_WORD || (h_out[i] & 0xFF) == 0xDD)
                ++poisoned;
            if (errors < 8)
                std::cout << "mismatch at " << i << ": got 0x" << std::hex << h_out[i]
                          << " want 0x" << want << std::dec << std::endl;
            ++errors;
        }
    }

    vx_buffer_release(out_buf);
    for (uint32_t c = 0; c < chunks; ++c)
        vx_buffer_release(chunk_buf[c]);
    if (read_ev) vx_event_release(read_ev);
    if (last_ev) vx_event_release(last_ev);
    vx_kernel_release(kern);
    vx_module_release(mod);
    vx_queue_release(q);
    vx_device_dump_perf(dev, stdout);
    vx_device_release(dev);

    if (errors) {
        std::cout << "Found " << errors << " errors";
        if (poisoned)
            std::cout << " (" << poisoned << " look like poison — a grant did not install)";
        std::cout << "!\nFAILED!" << std::endl;
        return 1;
    }
    std::cout << "PASSED!" << std::endl;
    return 0;
}
