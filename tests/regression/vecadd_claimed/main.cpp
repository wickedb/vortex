// vecadd_claimed — vecadd with its buffers claimed over the checker's DCR
// setup path. This is fable.md's "positive half": the Phase 2 kernel rerun
// under real per-buffer policy (headers populated at launch over the attested
// channel, owner eid 0, not hard-coded), expecting deny=0 and cycle counts
// bit-identical to plain vecadd.
//
// Everything that affects device state is kept IDENTICAL to
// tests/regression/vecadd/main.cpp — same allocation order, same buffer
// sizes (no alignment padding: under a single tenant a claim granule that
// also covers code/stack is harmless, all traffic is eid 0), and the same
// kernel binary (the Makefile compiles vecadd's kernel.cpp). The only
// additions are host-side vx_enqueue_dcr_write calls, which write the
// command ring and allocate no device memory — so cycles must match vecadd
// exactly, checker on or off.

#include <vortex2.h>
#include "common.h"

#include <cmath>
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
uint32_t    size        = 16;

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

bool float_eq(float a, float b) {
    union fi { float f; int32_t i; };
    fi fa{a}, fb{b};
    return std::abs(fa.i - fb.i) <= 6;
}

// Claim [base, base+bytes) for eid 0, R|W, no sharing, no expiry.
void enqueue_claim(vx_queue_h q, uint64_t base, uint64_t bytes) {
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_BASE,  (uint32_t)base,  0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SIZE,  (uint32_t)bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_OWNER, 0,               0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_PERMS, CHECKER_PERM_R | CHECKER_PERM_W, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SHARED, 0,              0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_EPOCH, GRANT_NO_EXPIRY, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_COMMIT, 1,              0, nullptr, nullptr));
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);
    std::srand(50);

    const uint32_t num_points = size;
    const uint64_t buf_size   = num_points * sizeof(TYPE);
    std::cout << "vecadd_claimed: n=" << num_points
              << " buf=" << buf_size << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));

    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    vx_buffer_h src0_buf=nullptr, src1_buf=nullptr, dst_buf=nullptr;
    CHECK(vx_buffer_create(dev, buf_size, VX_MEM_READ,  &src0_buf));
    CHECK(vx_buffer_create(dev, buf_size, VX_MEM_READ,  &src1_buf));
    CHECK(vx_buffer_create(dev, buf_size, VX_MEM_WRITE, &dst_buf));

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    kernel_arg_t kernel_arg{};
    kernel_arg.num_points = num_points;
    CHECK(vx_buffer_address(src0_buf, &kernel_arg.src0_addr));
    CHECK(vx_buffer_address(src1_buf, &kernel_arg.src1_addr));
    CHECK(vx_buffer_address(dst_buf,  &kernel_arg.dst_addr));

    std::vector<TYPE> h_src0(num_points), h_src1(num_points), h_dst(num_points);
    for (uint32_t i = 0; i < num_points; ++i) {
        h_src0[i] = static_cast<TYPE>(std::rand()) / RAND_MAX;
        h_src1[i] = static_cast<TYPE>(std::rand()) / RAND_MAX;
    }

    CHECK(vx_enqueue_write(q, src0_buf, 0, h_src0.data(), buf_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, src1_buf, 0, h_src1.data(), buf_size, 0,nullptr,nullptr));

    // The addition over plain vecadd: per-buffer claims for eid 0 ride the
    // queue ahead of the launch. Inert when the checker is unarmed.
    enqueue_claim(q, kernel_arg.src0_addr, buf_size);
    enqueue_claim(q, kernel_arg.src1_addr, buf_size);
    enqueue_claim(q, kernel_arg.dst_addr,  buf_size);

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

    vx_event_h launch_ev=nullptr, read_ev=nullptr;
    CHECK(vx_enqueue_launch(q, &li, 0, nullptr, &launch_ev));
    CHECK(vx_enqueue_read(q, h_dst.data(), dst_buf, 0, buf_size,
                          1, &launch_ev, &read_ev));
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    int errors = 0;
    for (uint32_t i = 0; i < num_points; ++i) {
        TYPE ref = h_src0[i] + h_src1[i];
        if (!float_eq(h_dst[i], ref)) {
            if (errors < 16)
                std::printf("*** [%u] expected=%f actual=%f\n", i, ref, h_dst[i]);
            ++errors;
        }
    }

    vx_event_release(read_ev);
    vx_event_release(launch_ev);
    vx_buffer_release(dst_buf);
    vx_buffer_release(src1_buf);
    vx_buffer_release(src0_buf);
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
