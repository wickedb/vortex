// revoke_window — measure the window in which a revocation has no effect.
//
// Application only. No simulator modification, no privileged counter: the
// kernel times its own read loop with vx_rdcycle() and classifies the words it
// gets back. That is exactly the instrumentation a co-resident tenant has.
//
//   claim:    shared buffer -> owner eid 0 (R|W), shared_perms R, grant_epoch 0
//   launch 1: grantee warms the working set, then times `iters` reads of it
//   revoke:   REVOKE_OWNER = 0, EPOCH = 1  (the only revocation the API can
//             express — the ring engine's WaitDone blocks until the launch FSM
//             idles, so it necessarily lands at a launch boundary)
//   launch 2: the identical loop, now after the grant expired
//
// Read the two phases together. In phase 1 at small -w the grantee runs at
// L1-hit latency, which is another way of saying its reads never became
// requests at the checker and no policy was consulted for any of them. In
// phase 2 every read misses — SimX re-enters ProcessorImpl::run() per launch
// and reset() wipes every cache set — so every read meets the checker and is
// denied, at roughly an order of magnitude more cycles per read.
//
// The denial is only ever observed on the miss path. Sweep -w across the L1
// knee (sweep.sh) and phase 1's cycles/read shows where that path stops being
// taken at all.

#include <vortex2.h>
#include "common.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <utility>

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
uint32_t    num_tasks   = 64;
uint32_t    ws_words    = 1024;   // 4 KB — fits the 16 KB L1
uint32_t    iters       = 8192;
// Which phases to run. 1 = the live-grant loop only, 2 = revoke + the
// post-revocation loop only, 3 = both. Isolating phase 1 is what makes the
// enforcement-coverage differential in sweep.sh work: two runs that differ
// only in -i, so the change in the checker's `checked` counter is attributable
// to the extra grantee reads and nothing else.
uint32_t    phases      = 3;

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:w:i:P:k:h")) != -1) {
        switch (c) {
            case 'n': num_tasks   = std::atoi(optarg); break;
            case 'w': ws_words    = std::atoi(optarg); break;
            case 'i': iters       = std::atoi(optarg); break;
            case 'P': phases      = std::atoi(optarg); break;
            case 'k': kernel_file = optarg;            break;
            default:
                std::cout << "Usage: [-k kernel] [-n tasks] [-w words] "
                             "[-i iters] [-P phases:1|2|3] [-h]" << std::endl;
                std::exit(c == 'h' ? 0 : -1);
        }
    }
}

struct phase_result {
    uint64_t reads = 0;
    uint64_t poison = 0;
    uint64_t plain = 0;
    // Least-contended task. A dependent chase measures latency only when it is
    // not queued behind its neighbours, so the minimum is the right statistic
    // for this probe; the maximum measures occupancy, not the cache level.
    uint64_t cycles_min = 0;
    double   cyc_per_read = 0;
};
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);

    if (ws_words == 0) { std::cout << "-w must be > 0\nFAILED!" << std::endl; return 1; }

    const uint64_t ws_bytes = uint64_t(ws_words) * sizeof(uint32_t);

    uint32_t buf_log2 = 20;
    if (const char* e = std::getenv("VX_CHECKER_BUF_LOG2")) {
        if (*e) buf_log2 = std::strtoul(e, nullptr, 0);
    }
    const uint64_t granule = 1ull << buf_log2;

    std::cout << "revoke_window: tasks=" << num_tasks
              << " ws=" << ws_bytes << "B"
              << " lines=" << ((ws_words + 15) / 16)
              << " iters=" << iters
              << " granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));

    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    const uint64_t tbytes = uint64_t(num_tasks) * sizeof(uint32_t);
    vx_buffer_h shared_buf=nullptr;
    vx_buffer_h cyc_buf[2]={nullptr,nullptr}, poi_buf[2]={nullptr,nullptr},
                pla_buf[2]={nullptr,nullptr}, org_buf[2]={nullptr,nullptr};
    CHECK(vx_buffer_create(dev, ws_bytes + 2*granule, VX_MEM_READ_WRITE, &shared_buf));
    for (int p = 0; p < 2; ++p) {
        // Output buffers stay UNCLAIMED (OWNER_ANY), so writing them is never
        // gated and never perturbs what the grantee observes.
        CHECK(vx_buffer_create(dev, tbytes, VX_MEM_READ_WRITE, &cyc_buf[p]));
        CHECK(vx_buffer_create(dev, tbytes, VX_MEM_READ_WRITE, &poi_buf[p]));
        CHECK(vx_buffer_create(dev, tbytes, VX_MEM_READ_WRITE, &pla_buf[p]));
        CHECK(vx_buffer_create(dev, tbytes, VX_MEM_READ_WRITE, &org_buf[p]));
    }

    uint64_t shared_dev=0;
    CHECK(vx_buffer_address(shared_buf, &shared_dev));
    const uint64_t shared_base = (shared_dev + granule - 1) & ~(granule - 1);
    const uint64_t shared_off  = shared_base - shared_dev;

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    // Build the chase: a single cycle visiting one word per 64 B cache line, in
    // a shuffled order so no stride prefetcher (and no reviewer) can claim the
    // latency came from anywhere but the level the line is resident in. Words
    // that are not a line's head keep SECRET(i), so a served load is still
    // recognisable as the owner's data and a denied one as the poison block.
    const uint32_t nlines = (ws_words + WORDS_PER_LINE - 1) / WORDS_PER_LINE;
    std::vector<uint32_t> h_secret(ws_words), h_zero(num_tasks, 0);
    for (uint32_t i = 0; i < ws_words; ++i)
        h_secret[i] = SECRET(i);
    {
        std::vector<uint32_t> order(nlines);
        for (uint32_t i = 0; i < nlines; ++i) order[i] = i;
        // Fixed seed: the chase must be identical across every point of a sweep.
        uint64_t rng = 0x9E3779B97F4A7C15ull;
        for (uint32_t i = nlines; i > 1; --i) {
            rng = rng * 6364136223846793005ull + 1442695040888963407ull;
            uint32_t j = uint32_t((rng >> 33) % i);
            std::swap(order[i - 1], order[j]);
        }
        // order[] is a permutation; link it into one cycle of line heads.
        for (uint32_t i = 0; i < nlines; ++i) {
            uint32_t here = order[i] * WORDS_PER_LINE;
            uint32_t next = order[(i + 1) % nlines] * WORDS_PER_LINE;
            if (here < ws_words) h_secret[here] = next;
        }
    }

    CHECK(vx_enqueue_write(q, shared_buf, shared_off, h_secret.data(), ws_bytes, 0,nullptr,nullptr));
    for (int p = 0; p < 2; ++p) {
        CHECK(vx_enqueue_write(q, cyc_buf[p], 0, h_zero.data(), tbytes, 0,nullptr,nullptr));
        CHECK(vx_enqueue_write(q, poi_buf[p], 0, h_zero.data(), tbytes, 0,nullptr,nullptr));
        CHECK(vx_enqueue_write(q, pla_buf[p], 0, h_zero.data(), tbytes, 0,nullptr,nullptr));
        CHECK(vx_enqueue_write(q, org_buf[p], 0, h_zero.data(), tbytes, 0,nullptr,nullptr));
    }

    // The grant: owner 0 holds R|W; everyone else gets READ through epoch 0.
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_BASE,  (uint32_t)shared_base, 0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SIZE,  (uint32_t)ws_bytes,    0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_OWNER, 0,                     0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_PERMS, CHECKER_PERM_R | CHECKER_PERM_W, 0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SHARED, CHECKER_PERM_R,       0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_EPOCH, 0,                     0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_COMMIT, 1,                    0,nullptr,nullptr));

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &num_tasks, grid, block));

    kernel_arg_t arg[2]{};
    for (int p = 0; p < 2; ++p) {
        arg[p].num_points  = num_tasks;
        arg[p].ws_words    = ws_words;
        arg[p].iters       = iters;
        arg[p].phase       = uint32_t(p + 1);
        arg[p].shared_addr = shared_base;
        CHECK(vx_buffer_address(cyc_buf[p], &arg[p].cycles_addr));
        CHECK(vx_buffer_address(poi_buf[p], &arg[p].poison_addr));
        CHECK(vx_buffer_address(pla_buf[p], &arg[p].plain_addr));
        CHECK(vx_buffer_address(org_buf[p], &arg[p].origin_addr));
    }

    auto make_li = [&](kernel_arg_t* a) {
        vx_launch_info_t li{};
        li.struct_size = sizeof(li);
        li.kernel      = kern;
        li.args_host   = a;
        li.args_size   = sizeof(*a);
        li.ndim        = 1;
        li.grid_dim[0] = grid[0];
        li.block_dim[0]= block[0];
        return li;
    };
    vx_launch_info_t li1 = make_li(&arg[0]), li2 = make_li(&arg[1]);

    const bool run_p1 = (phases & 1) != 0;
    const bool run_p2 = (phases & 2) != 0;
    if (!run_p1 && !run_p2) { std::cout << "-P must select a phase\nFAILED!" << std::endl; return 1; }

    vx_event_h ev2=nullptr, read_ev=nullptr;
    if (run_p1)
        CHECK(vx_enqueue_launch(q, &li1, 0, nullptr, run_p2 ? nullptr : &ev2));
    if (run_p2) {
        // The revocation. Two register writes, no header touched. The queue is
        // FIFO and each launch drains before the next command, which is not a
        // choice this program makes — it is the only ordering the API offers.
        CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_REVOKE_OWNER, 0, 0, nullptr, nullptr));
        CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_EPOCH, 1, 0, nullptr, nullptr));
        CHECK(vx_enqueue_launch(q, &li2, 0, nullptr, &ev2));
    }

    std::vector<uint32_t> h_cyc[2], h_poi[2], h_pla[2], h_org[2];
    for (int p = 0; p < 2; ++p) {
        h_cyc[p].resize(num_tasks); h_poi[p].resize(num_tasks);
        h_pla[p].resize(num_tasks); h_org[p].resize(num_tasks);
    }
    for (int p = 0; p < 2; ++p) {
        vx_event_h* last = (p == 1) ? &read_ev : nullptr;
        CHECK(vx_enqueue_read(q, h_cyc[p].data(), cyc_buf[p], 0, tbytes, 1, &ev2, nullptr));
        CHECK(vx_enqueue_read(q, h_poi[p].data(), poi_buf[p], 0, tbytes, 1, &ev2, nullptr));
        CHECK(vx_enqueue_read(q, h_pla[p].data(), pla_buf[p], 0, tbytes, 1, &ev2, nullptr));
        CHECK(vx_enqueue_read(q, h_org[p].data(), org_buf[p], 0, tbytes, 1, &ev2, last));
    }
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    // ----- results -----
    // Only non-owner tasks are grantees; owner-core reads are the control and
    // are supposed to survive the revocation.
    phase_result gr[2], ow[2];
    uint32_t tasks_owner = 0, tasks_grantee = 0;
    for (int p = 0; p < 2; ++p) {
        for (uint32_t t = 0; t < num_tasks; ++t) {
            if (h_cyc[p][t] == 0) continue;   // not a measurer
            phase_result& r = (h_org[p][t] == 0) ? ow[p] : gr[p];
            if (p == (run_p1 ? 0 : 1))
                (h_org[p][t] == 0) ? ++tasks_owner : ++tasks_grantee;
            r.reads  += iters;
            r.poison += h_poi[p][t];
            r.plain  += h_pla[p][t];
            if (r.cycles_min == 0 || h_cyc[p][t] < r.cycles_min)
                r.cycles_min = h_cyc[p][t];
        }
    }
    // cycles/step is per task: divide the least-contended task's cycle count
    // by that task's own iteration count, not by the group total.
    for (int p = 0; p < 2; ++p) {
        gr[p].cyc_per_read = iters ? double(gr[p].cycles_min) / double(iters) : 0.0;
        ow[p].cyc_per_read = iters ? double(ow[p].cycles_min) / double(iters) : 0.0;
    }

    if (tasks_owner == 0 || tasks_grantee == 0) {
        std::cout << "measuring threads did not span both cores (owner=" << tasks_owner
                  << " grantee=" << tasks_grantee
                  << ") — run with --cores=2 and enough -n to fill two blocks\nFAILED!"
                  << std::endl;
        return 1;
    }

    std::printf("measuring threads: owner=%u grantee=%u\n", tasks_owner, tasks_grantee);
    std::printf("%-28s %12s %12s %12s\n", "", "steps", "served", "cyc/step");
    if (run_p1)
        std::printf("%-28s %12llu %12llu %12.2f\n", "phase1 grantee (grant live)",
                    (unsigned long long)gr[0].reads, (unsigned long long)gr[0].plain,
                    gr[0].cyc_per_read);
    if (run_p2) {
        std::printf("%-28s %12llu %12llu %12.2f\n", "phase2 grantee (revoked)",
                    (unsigned long long)gr[1].reads, (unsigned long long)gr[1].plain,
                    gr[1].cyc_per_read);
        std::printf("%-28s %12llu %12llu %12.2f\n", "phase2 owner   (control)",
                    (unsigned long long)ow[1].reads, (unsigned long long)ow[1].plain,
                    ow[1].cyc_per_read);
    }

    // GRANTEE_READS is the exact number of loads the grantee's timed loop
    // issued while the grant was live. Differencing it, and the checker's own
    // `checked` counter, across two runs that differ only in -i gives the
    // fraction of a grantee's reads that any policy is consulted for at all.
    std::printf("GRANTEE_READS ws=%llu iters=%u phase1=%llu phase2=%llu\n",
                (unsigned long long)ws_bytes, iters,
                (unsigned long long)gr[0].reads, (unsigned long long)gr[1].reads);
    std::printf("SUMMARY ws=%llu cyc_per_step_live=%.2f cyc_per_step_revoked=%.2f "
                "denied_frac=%.4f\n",
                (unsigned long long)ws_bytes, gr[0].cyc_per_read, gr[1].cyc_per_read,
                gr[1].reads ? double(gr[1].poison) / double(gr[1].reads) : 0.0);

    int errors = 0;
    // Phase 1 sanity: under a live grant the grantee must see only plaintext.
    if (run_p1 && gr[0].poison != 0) {
        std::printf("*** phase1 returned %llu poison words under a live grant\n",
                    (unsigned long long)gr[0].poison);
        ++errors;
    }
    // Phase 2: the owner's own access is not epoch-gated and must survive.
    if (run_p2 && ow[1].poison != 0) {
        std::printf("*** phase2 denied %llu owner reads; the owner was not revoked\n",
                    (unsigned long long)ow[1].poison);
        ++errors;
    }
    // Phase 2 grantee: denial is expected here *because* launch 2 starts cold.
    if (run_p2 && gr[1].plain != 0) {
        std::printf("*** phase2 leaked %llu plaintext reads after revocation\n",
                    (unsigned long long)gr[1].plain);
        ++errors;
    }

    vx_event_release(read_ev);
    vx_event_release(ev2);
    for (int p = 0; p < 2; ++p) {
        vx_buffer_release(org_buf[p]); vx_buffer_release(pla_buf[p]);
        vx_buffer_release(poi_buf[p]); vx_buffer_release(cyc_buf[p]);
    }
    vx_buffer_release(shared_buf);
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
