// fetchx — the X bit: a fetch from a claimed granule is allowed with X and
// denied without (header v2, spec T9; review issue 6). See common.h.

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
uint32_t    size        = 64;
uint32_t    mode        = 0;

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:k:m:h")) != -1) {
        switch (c) {
            case 'n': size        = std::atoi(optarg); break;
            case 'k': kernel_file = optarg;            break;
            case 'm': mode        = std::atoi(optarg); break;
            default:
                std::cout << "Usage: [-k kernel] [-n words] [-m 0 (R|W|X) | 1 (R|W)] [-h]" << std::endl;
                std::exit(c == 'h' ? 0 : -1);
        }
    }
}

void dcr(vx_queue_h q, uint32_t addr, uint32_t value) {
    CHECK(vx_enqueue_dcr_write(q, addr, value, 0, nullptr, nullptr));
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);
    if (mode > 1) {
        std::cout << "fetchx: unknown mode " << mode << std::endl;
        return -1;
    }

    uint32_t buf_log2 = 20;
    if (const char* e = std::getenv("VX_CHECKER_BUF_LOG2")) {
        if (*e) buf_log2 = std::strtoul(e, nullptr, 0);
    }
    const uint64_t granule = 1ull << buf_log2;

    const uint32_t n     = size;
    const uint64_t bytes = uint64_t(n) * sizeof(uint32_t);

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));
    uint64_t pc = 0;
    CHECK(vx_kernel_address(kern, &pc));
    const uint64_t code_granule = pc & ~(granule - 1);

    vx_buffer_h dst = nullptr;
    kernel_arg_t a{};
    a.num_points = n;
    CHECK(vx_buffer_create(dev, bytes, VX_MEM_READ_WRITE, &dst));
    CHECK(vx_buffer_address(dst, &a.dst_addr));

    // Tenant 0 claims the granule its code is in. Everything else tenant 0
    // touches in that granule (the image's data, possibly the argument blob)
    // is its own, so the owner perms R|W cover it.
    const uint32_t perms = CHECKER_PERM_R | CHECKER_PERM_W | (mode == 0 ? CHECKER_PERM_X : 0);
    std::printf("fetchx: n=%u mode=%u code pc=0x%llx granule=0x%llx perms=%s\n", n, mode,
                (unsigned long long)pc, (unsigned long long)code_granule,
                mode == 0 ? "RWX" : "RW (expect every fetch denied, unenforced)");
    dcr(q, DCR_CHECKER_BUF_BASE,    (uint32_t)code_granule);
    dcr(q, DCR_CHECKER_BUF_SIZE,    (uint32_t)granule);
    dcr(q, DCR_CHECKER_BUF_OWNER,   0);
    dcr(q, DCR_CHECKER_BUF_PERMS,   perms);
    dcr(q, DCR_CHECKER_BUF_SHARED,  0);
    dcr(q, DCR_CHECKER_BUF_GRANTEE, 0);
    dcr(q, DCR_CHECKER_BUF_JOINT,   0);
    dcr(q, DCR_CHECKER_BUF_EPOCH,   GRANT_NO_EXPIRY);
    dcr(q, DCR_CHECKER_BUF_COMMIT,  1);

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
    CHECK(vx_enqueue_launch(q, &li, 0, nullptr, nullptr));

    std::vector<uint32_t> r(n, 0);
    CHECK(vx_enqueue_read(q, r.data(), dst, 0, bytes, 0, nullptr, nullptr));
    CHECK(vx_queue_finish(q, VX_TIMEOUT_INFINITE));

    int errors = 0;
    for (uint32_t i = 0; i < n; ++i) {
        if (r[i] != VALUE(i)) {
            if (errors < 8)
                std::printf("*** [%u] expected=0x%08x actual=0x%08x\n", i, VALUE(i), r[i]);
            ++errors;
        }
    }

    vx_buffer_release(dst);
    vx_kernel_release(kern);
    vx_module_release(mod);
    vx_queue_release(q);
    vx_device_dump_perf(dev, stdout);
    vx_device_release(dev);

    if (errors) {
        std::printf("FAILED! (%d errors)\n", errors);
        return 1;
    }
    std::printf("PASSED!\n");
    return 0;
}
