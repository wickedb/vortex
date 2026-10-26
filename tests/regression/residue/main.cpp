// residue — what one kernel leaves on a core does not reach the next kernel
// across a scrub boundary (spec T8). See common.h.

#include <vortex2.h>
#include "common.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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
uint32_t    size        = 256;
bool        no_clean    = false;   // -n
bool        other_tenant = false;  // -t

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:k:Nth")) != -1) {
        switch (c) {
            case 'n': size         = std::atoi(optarg); break;
            case 'k': kernel_file  = optarg;            break;
            case 'N': no_clean     = true;              break;
            case 't': other_tenant = true;              break;
            default:
                std::cout << "Usage: [-k kernel] [-n words] [-N (no clean boundary: residue expected)] "
                             "[-t (B from another tenant)] [-h]" << std::endl;
                std::exit(c == 'h' ? 0 : -1);
        }
    }
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);
    const uint32_t n     = size;
    const uint64_t bytes = uint64_t(n) * sizeof(uint32_t);
    std::printf("residue: n=%u mode=%s\n", n,
                other_tenant ? "other tenant" : (no_clean ? "same tenant, no clean boundary (control)"
                                                          : "same tenant, clean boundary"));

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_info_t qi0 = { sizeof(qi0), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_info_t qi1 = qi0;
    qi1.flags |= VX_QUEUE_FLAG_HW_QUEUE(1);
    vx_queue_h q0 = nullptr, q1 = nullptr;
    CHECK(vx_queue_create(dev, &qi0, &q0));
    CHECK(vx_queue_create(dev, &qi1, &q1));

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    vx_buffer_h lh = nullptr, sh = nullptr;
    kernel_arg_t a{};
    a.num_points = n;
    CHECK(vx_buffer_create(dev, bytes, VX_MEM_READ_WRITE, &lh));
    CHECK(vx_buffer_create(dev, bytes, VX_MEM_READ_WRITE, &sh));
    CHECK(vx_buffer_address(lh, &a.lmem_hits_addr));
    CHECK(vx_buffer_address(sh, &a.stack_hits_addr));
    std::vector<uint32_t> h_zero(n, 0);
    CHECK(vx_enqueue_write(q0, lh, 0, h_zero.data(), bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q0, sh, 0, h_zero.data(), bytes, 0, nullptr, nullptr));
    CHECK(vx_queue_finish(q0, VX_TIMEOUT_INFINITE));

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &n, grid, block));
    vx_launch_info_t li{};
    li.struct_size  = sizeof(li);
    li.kernel       = kern;
    li.args_host    = &a;
    li.args_size    = sizeof(a);
    li.ndim         = 1;
    li.grid_dim[0]  = grid[0];
    li.block_dim[0] = block[0];
    li.lmem_size    = block[0] * sizeof(uint32_t);

    // A: leave the pattern on every core it runs on.
    a.mode = 0;
    CHECK(vx_enqueue_launch(q0, &li, 0, nullptr, nullptr));
    CHECK(vx_queue_finish(q0, VX_TIMEOUT_INFINITE));

    // B: look for it.
    vx_queue_h qb = other_tenant ? q1 : q0;
    if (!other_tenant && !no_clean)
        CHECK(vx_enqueue_clean_boundary(qb, 0, nullptr, nullptr));
    kernel_arg_t b = a;
    b.mode = 1;
    vx_launch_info_t lb = li;
    lb.args_host = &b;
    CHECK(vx_enqueue_launch(qb, &lb, 0, nullptr, nullptr));
    CHECK(vx_queue_finish(qb, VX_TIMEOUT_INFINITE));

    std::vector<uint32_t> rl(n), rs(n);
    CHECK(vx_enqueue_read(q0, rl.data(), lh, 0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, rs.data(), sh, 0, bytes, 0, nullptr, nullptr));
    CHECK(vx_queue_finish(q0, VX_TIMEOUT_INFINITE));
    uint64_t lmem_hits = 0, stack_hits = 0;
    for (uint32_t i = 0; i < n; ++i) { lmem_hits += rl[i]; stack_hits += rs[i]; }
    std::printf("RESULT lmem_residue=%llu stack_residue=%llu (words of A's pattern B could read)\n",
                (unsigned long long)lmem_hits, (unsigned long long)stack_hits);

    vx_buffer_release(sh);
    vx_buffer_release(lh);
    vx_kernel_release(kern);
    vx_module_release(mod);
    vx_queue_release(q1);
    vx_queue_release(q0);
    vx_device_dump_perf(dev, stdout);
    vx_device_release(dev);

    const bool expect_residue = no_clean && !other_tenant;
    if (expect_residue) {
        // The control: without a scrub boundary B sees A's values.
        if (lmem_hits == 0 && stack_hits == 0) {
            std::printf("FAILED! the control saw no residue: the test cannot see any\n");
            return 1;
        }
    } else if (lmem_hits != 0 || stack_hits != 0) {
        std::printf("FAILED! residue crossed a scrub boundary\n");
        return 1;
    }
    std::printf("PASSED!\n");
    return 0;
}
