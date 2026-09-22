// header_alias — see common.h for the property under test.

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
uint32_t    size        = 1024;

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:k:h")) != -1) {
        switch (c) {
            case 'n': size        = std::atoi(optarg); break;
            case 'k': kernel_file = optarg;            break;
            default:
                std::cout << "Usage: [-k kernel] [-n words] [-h]" << std::endl;
                std::exit(c == 'h' ? 0 : -1);
        }
    }
}

void enqueue_claim(vx_queue_h q, uint64_t base, uint64_t bytes,
                   uint32_t owner, uint32_t perms, uint32_t shared, uint32_t epoch) {
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_BASE,   (uint32_t)base,  0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SIZE,   (uint32_t)bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_OWNER,  owner,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_PERMS,  perms,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SHARED, shared,          0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_EPOCH,  epoch,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_COMMIT, 1,               0, nullptr, nullptr));
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);

    const uint32_t num_points = size;
    const uint64_t used_size  = num_points * sizeof(uint32_t);

    uint32_t buf_log2 = 20;
    if (const char* e = std::getenv("VX_CHECKER_BUF_LOG2")) {
        if (*e) buf_log2 = std::strtoul(e, nullptr, 0);
    }
    const uint64_t granule = 1ull << buf_log2;

    // The collision this test needs is only guaranteed with a one-entry store.
    // Say so rather than passing vacuously against a store big enough that no
    // two buffers ever contend — the failure mode of a regression like this is
    // to keep passing for the wrong reason.
    const char* entries_env = std::getenv("VX_CHECKER_HEADER_ENTRIES");
    const uint32_t header_entries = (entries_env && *entries_env)
                                  ? (uint32_t)std::strtoul(entries_env, nullptr, 0) : 0;
    if (header_entries != 1) {
        std::cout << "header_alias: needs VX_CHECKER_HEADER_ENTRIES=1 to force the "
                     "store collision (got "
                  << (entries_env && *entries_env ? entries_env : "unset")
                  << ")\nFAILED!" << std::endl;
        return 1;
    }

    std::cout << "header_alias: n=" << num_points << " buf=" << used_size
              << "B granule=" << granule << "B header_entries=1" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));

    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    // Both buffers padded so a granule-aligned claim stays inside them (same
    // pattern as twotenant/revoke_scope), and separately allocated, so they
    // are guaranteed to sit in different granules — which is what makes their
    // contention for one store entry an aliasing case and not a re-claim.
    vx_buffer_h bufA_buf=nullptr, bufB_buf=nullptr, probeA_buf=nullptr,
                probeB_buf=nullptr, origin_buf=nullptr;
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &bufA_buf));
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &bufB_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &probeA_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &probeB_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &origin_buf));

    uint64_t bufA_dev=0, bufB_dev=0;
    CHECK(vx_buffer_address(bufA_buf, &bufA_dev));
    CHECK(vx_buffer_address(bufB_buf, &bufB_dev));
    const uint64_t bufA_base = (bufA_dev + granule - 1) & ~(granule - 1);
    const uint64_t bufB_base = (bufB_dev + granule - 1) & ~(granule - 1);
    const uint64_t bufA_off  = bufA_base - bufA_dev;
    const uint64_t bufB_off  = bufB_base - bufB_dev;

    if ((bufA_base >> buf_log2) == (bufB_base >> buf_log2)) {
        std::cout << "bufA and bufB landed in the same granule — no aliasing to test\n"
                     "FAILED!" << std::endl;
        return 1;
    }

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    std::vector<uint32_t> h_a(num_points), h_b(num_points), h_zero(num_points, 0);
    for (uint32_t i = 0; i < num_points; ++i) {
        h_a[i] = SECRET_A(i);
        h_b[i] = SECRET_B(i);
    }

    CHECK(vx_enqueue_write(q, bufA_buf, bufA_off, h_a.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, bufB_buf, bufB_off, h_b.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, probeA_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, probeB_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, origin_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));

    // One owner, two buffers, differing only in what they grant: bufA grants
    // nothing, bufB grants READ to everyone. Same owner on purpose — granule
    // exclusivity only refuses cross-owner claims, so it cannot catch this
    // pair and the tag is the only thing that does. The second claim collides
    // with the first in a one-entry store and must be refused whole.
    enqueue_claim(q, bufA_base, used_size, 0, CHECKER_PERM_R | CHECKER_PERM_W, 0, GRANT_NO_EXPIRY);
    enqueue_claim(q, bufB_base, used_size, 0, CHECKER_PERM_R | CHECKER_PERM_W, CHECKER_PERM_R, GRANT_NO_EXPIRY);

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &num_points, grid, block));

    kernel_arg_t arg{};
    arg.num_points = num_points;
    arg.bufA_addr  = bufA_base;
    arg.bufB_addr  = bufB_base;
    CHECK(vx_buffer_address(probeA_buf, &arg.probeA_addr));
    CHECK(vx_buffer_address(probeB_buf, &arg.probeB_addr));
    CHECK(vx_buffer_address(origin_buf, &arg.origin_addr));

    vx_launch_info_t li{};
    li.struct_size = sizeof(li);
    li.kernel      = kern;
    li.args_host   = &arg;
    li.args_size   = sizeof(arg);
    li.ndim        = 1;
    li.grid_dim[0] = grid[0];
    li.block_dim[0]= block[0];

    vx_event_h ev=nullptr, read_ev=nullptr;
    CHECK(vx_enqueue_launch(q, &li, 0, nullptr, &ev));

    std::vector<uint32_t> h_probeA(num_points), h_probeB(num_points), h_origin(num_points);
    CHECK(vx_enqueue_read(q, h_probeA.data(), probeA_buf, 0, used_size, 1, &ev, nullptr));
    CHECK(vx_enqueue_read(q, h_probeB.data(), probeB_buf, 0, used_size, 1, &ev, nullptr));
    CHECK(vx_enqueue_read(q, h_origin.data(), origin_buf, 0, used_size, 1, &ev, &read_ev));
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    // ----- verification -----
    uint32_t core0=0, core1=0;
    int errors = 0;
    auto fail = [&](uint32_t i, const char* what, uint32_t exp, uint32_t got) {
        if (errors < 16)
            std::printf("*** [%u] %s: expected=0x%08x actual=0x%08x\n", i, what, exp, got);
        ++errors;
    };
    for (uint32_t i = 0; i < num_points; ++i) {
        if (h_origin[i] == 0) {
            ++core0;
            // bufA's owner, unaffected either way — recorded so a failure on
            // the core-1 line below cannot be dismissed as the buffer simply
            // being unreadable.
            if (h_probeA[i] != SECRET_A(i))
                fail(i, "core0 reads bufA (its own buffer, claim must be intact)", SECRET_A(i), h_probeA[i]);
        } else if (h_origin[i] == 1) {
            ++core1;
            // bufA grants nothing, so a non-owner read must be poison. Under
            // an untagged store claim B's shared_perms=R lands on bufA's
            // entry, manufacturing a grant bufA's owner never issued. See
            // common.h on what the untagged failure actually looks like.
            if (h_probeA[i] != POISON_WORD)
                fail(i, "core1 reads bufA (never granted — leak via store aliasing!)", POISON_WORD, h_probeA[i]);
        } else {
            fail(i, "origin core id", 0, h_origin[i]);
        }
        // bufB's claim was refused, so bufB carries no policy and falls to the
        // boot default (OWNER_ANY, R|W): readable by both cores. Asserted so
        // the refusal's real consequence is recorded, not assumed.
        if (h_probeB[i] != SECRET_B(i))
            fail(i, "reads bufB (claim refused — buffer is unprotected, not locked)", SECRET_B(i), h_probeB[i]);
    }
    std::cout << "tasks: core0=" << core0 << " core1=" << core1 << std::endl;
    if (core0 == 0 || core1 == 0) {
        std::cout << "tasks did not span both cores — run with --cores=2\nFAILED!" << std::endl;
        return 1;
    }

    vx_event_release(read_ev);
    vx_event_release(ev);
    vx_buffer_release(origin_buf);
    vx_buffer_release(probeB_buf);
    vx_buffer_release(probeA_buf);
    vx_buffer_release(bufB_buf);
    vx_buffer_release(bufA_buf);
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
