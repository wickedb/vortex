// twotenant — Phase 3 two-tenant isolation demo (vortex2.h-native).
//
// Host flow: upload tenant 0's secret, program the checker's who's-who over
// the DCR setup path (claim secret→eid0, t1own→eid1; everything else stays
// shared), launch one kernel spanning both cores, then verify both directions:
//   negative — core-1 tasks saw poison, their writes to the secret never
//              landed;
//   positive — core-0 tasks read real data and their writes landed, and
//              core-1 tasks' writes to tenant 1's own buffer landed.
//
// Protected buffers are over-allocated by two checker granules and the
// claimed region is aligned up to a granule boundary, so a claim never
// covers a neighboring allocation regardless of VX_CHECKER_BUF_LOG2.

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

// One staged claim over the DCR setup path: 5 registers + commit, enqueued
// in FIFO order ahead of the launch ("headers populated at launch").
void enqueue_claim(vx_queue_h q, uint64_t base, uint64_t bytes,
                   uint32_t owner, uint32_t perms, uint32_t epoch) {
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_BASE,  (uint32_t)base,  0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SIZE,  (uint32_t)bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_OWNER, owner,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_PERMS, perms,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_EPOCH, epoch,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_COMMIT, 1,              0, nullptr, nullptr));
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);

    const uint32_t num_points = size;
    const uint64_t used_size  = num_points * sizeof(uint32_t);

    // Match the checker's granularity so the claims cover exactly our buffers.
    uint32_t buf_log2 = 20;
    if (const char* e = std::getenv("VX_CHECKER_BUF_LOG2")) {
        if (*e) buf_log2 = std::strtoul(e, nullptr, 0);
    }
    const uint64_t granule = 1ull << buf_log2;

    std::cout << "twotenant: n=" << num_points << " buf=" << used_size
              << "B granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));

    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    // Protected buffers padded so a granule-aligned claim stays inside them.
    vx_buffer_h secret_buf=nullptr, t1_buf=nullptr, probe_buf=nullptr, origin_buf=nullptr;
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &secret_buf));
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &t1_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &probe_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &origin_buf));

    uint64_t secret_dev=0, t1_dev=0;
    CHECK(vx_buffer_address(secret_buf, &secret_dev));
    CHECK(vx_buffer_address(t1_buf, &t1_dev));
    const uint64_t secret_base = (secret_dev + granule - 1) & ~(granule - 1);
    const uint64_t t1_base     = (t1_dev     + granule - 1) & ~(granule - 1);
    const uint64_t secret_off  = secret_base - secret_dev;
    const uint64_t t1_off      = t1_base - t1_dev;

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    kernel_arg_t kernel_arg{};
    kernel_arg.num_points  = num_points;
    kernel_arg.secret_addr = secret_base;
    kernel_arg.t1_addr     = t1_base;
    CHECK(vx_buffer_address(probe_buf,  &kernel_arg.probe_addr));
    CHECK(vx_buffer_address(origin_buf, &kernel_arg.origin_addr));

    std::vector<uint32_t> h_secret(num_points), h_zero(num_points, 0);
    for (uint32_t i = 0; i < num_points; ++i)
        h_secret[i] = SECRET(i);

    // Uploads (host copies are functional and not subject to the checker).
    CHECK(vx_enqueue_write(q, secret_buf, secret_off, h_secret.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, t1_buf, t1_off, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, probe_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, origin_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));

    // The who's-who: secret → tenant 0, t1own → tenant 1. Result buffers,
    // kernel code, stacks and args stay unclaimed (shared).
    enqueue_claim(q, secret_base, used_size, 0, CHECKER_PERM_R | CHECKER_PERM_W, GRANT_NO_EXPIRY);
    enqueue_claim(q, t1_base,     used_size, 1, CHECKER_PERM_R | CHECKER_PERM_W, GRANT_NO_EXPIRY);

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &num_points, grid, block));

    vx_launch_info_t li{};
    li.struct_size = sizeof(li);
    li.kernel      = kern;
    li.args_host   = &kernel_arg;
    li.args_size   = sizeof(kernel_arg);
    li.ndim        = 1;
    li.grid_dim[0] = grid[0];
    li.block_dim[0]= block[0];

    std::vector<uint32_t> h_probe(num_points), h_origin(num_points),
                          h_secret_rb(num_points), h_t1_rb(num_points);

    vx_event_h launch_ev=nullptr, read_ev=nullptr;
    CHECK(vx_enqueue_launch(q, &li, 0, nullptr, &launch_ev));
    CHECK(vx_enqueue_read(q, h_probe.data(), probe_buf, 0, used_size, 1, &launch_ev, nullptr));
    CHECK(vx_enqueue_read(q, h_origin.data(), origin_buf, 0, used_size, 1, &launch_ev, nullptr));
    CHECK(vx_enqueue_read(q, h_secret_rb.data(), secret_buf, secret_off, used_size, 1, &launch_ev, nullptr));
    CHECK(vx_enqueue_read(q, h_t1_rb.data(), t1_buf, t1_off, used_size, 1, &launch_ev, &read_ev));
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    // ----- verification: expectations keyed on where each task actually ran -----
    uint32_t on_core0 = 0, on_core1 = 0;
    int errors = 0;
    auto fail = [&](uint32_t i, const char* what, uint32_t exp, uint32_t got) {
        if (errors < 16)
            std::printf("*** [%u] core=%u %s: expected=0x%08x actual=0x%08x\n",
                        i, h_origin[i], what, exp, got);
        ++errors;
    };
    for (uint32_t i = 0; i < num_points; ++i) {
        if (h_origin[i] == 0) {
            ++on_core0;
            // tenant 0 on its own buffer: real read, landed write
            if (h_probe[i] != SECRET(i))
                fail(i, "own-read", SECRET(i), h_probe[i]);
            if (h_secret_rb[i] != MARK_T0(i))
                fail(i, "own-write", MARK_T0(i), h_secret_rb[i]);
        } else if (h_origin[i] == 1) {
            ++on_core1;
            // cross-tenant read: poison, not the secret
            if (h_probe[i] != POISON_WORD)
                fail(i, "cross-read (leak!)", POISON_WORD, h_probe[i]);
            // cross-tenant write: dropped — the secret's cell is untouched
            if (h_secret_rb[i] != SECRET(i))
                fail(i, "cross-write (landed!)", SECRET(i), h_secret_rb[i]);
            // tenant 1 on its own buffer: landed write
            if (h_t1_rb[i] != MARK_T1(i))
                fail(i, "t1 own-write", MARK_T1(i), h_t1_rb[i]);
        } else {
            fail(i, "origin core id", 0, h_origin[i]);
        }
    }
    std::cout << "tasks: core0=" << on_core0 << " core1=" << on_core1 << std::endl;
    if (on_core0 == 0 || on_core1 == 0) {
        std::cout << "tasks did not span both cores — run with --cores=2\nFAILED!" << std::endl;
        return 1;
    }

    vx_event_release(read_ev);
    vx_event_release(launch_ev);
    vx_buffer_release(origin_buf);
    vx_buffer_release(probe_buf);
    vx_buffer_release(t1_buf);
    vx_buffer_release(secret_buf);
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
