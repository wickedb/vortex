// sharedhit — concurrent tenants on shared caches (see common.h).
//
// Reports, separately, the two ways a shared cache that answers without the
// checker can fail: confidentiality (tenant 1 observes or plants data in
// tenant 0's buffer) and owner-side corruption (tenant 0 reads poison, or its
// own writes are dropped). A shared-cache build that fails here is a finding
// about where the checker sits, not a regression in the checker itself.

#include <vortex2.h>
#include <VX_config.h>
#include <VX_types.h>
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
uint32_t    size        = 1024;
uint32_t    mode        = 0;

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:m:k:h")) != -1) {
        switch (c) {
            case 'n': size        = std::atoi(optarg); break;
            case 'm': mode        = std::atoi(optarg); break;
            case 'k': kernel_file = optarg;            break;
            default:
                std::cout << "Usage: [-k kernel] [-n words] [-m 0=read|1=write] [-h]" << std::endl;
                std::exit(c == 'h' ? 0 : -1);
        }
    }
}

void enqueue_claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner) {
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_BASE,   (uint32_t)base,  0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_SIZE,   (uint32_t)bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_OWNER,  owner,           0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_PERMS,  VX_CHECKER_PERM_R | VX_CHECKER_PERM_W, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_SHARED, 0,               0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_EPOCH,  VX_CHECKER_GRANT_NO_EXPIRY, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, VX_DCR_CHECKER_BUF_COMMIT, 1,               0, nullptr, nullptr));
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);
    if (mode > 1 || size < 2 * SHARED_WORDS) {
        std::cout << "sharedhit: need -m0|-m1 and -n >= " << 2 * SHARED_WORDS << "\nFAILED!" << std::endl;
        return 1;
    }

    const uint32_t num_points = size;
    const uint64_t used_size  = num_points * sizeof(uint32_t);
    const uint64_t granule    = 1ull << VX_CFG_CHECKER_BUF_LOG2;

    std::cout << "sharedhit: mode=" << (mode ? "write" : "read") << " n=" << num_points
              << " shared_words=" << SHARED_WORDS << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    // Padded by two granules so the granule-aligned claim covers only `secret`.
    vx_buffer_h secret_buf = nullptr, probe_buf = nullptr, origin_buf = nullptr;
    CHECK(vx_buffer_create(dev, used_size + 2 * granule, VX_MEM_READ_WRITE, &secret_buf));
    const uint64_t probe_size = used_size * SHARED_SECTORS;
    CHECK(vx_buffer_create(dev, probe_size, VX_MEM_READ_WRITE, &probe_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &origin_buf));

    uint64_t secret_dev = 0;
    CHECK(vx_buffer_address(secret_buf, &secret_dev));
    const uint64_t secret_base = (secret_dev + granule - 1) & ~(granule - 1);
    const uint64_t secret_off  = secret_base - secret_dev;

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    kernel_arg_t kernel_arg{};
    kernel_arg.num_points  = num_points;
    kernel_arg.mode        = mode;
    kernel_arg.secret_addr = secret_base;
    CHECK(vx_buffer_address(probe_buf,  &kernel_arg.probe_addr));
    CHECK(vx_buffer_address(origin_buf, &kernel_arg.origin_addr));

    std::vector<uint32_t> h_secret(num_points), h_zero(num_points * SHARED_SECTORS, 0);
    for (uint32_t i = 0; i < num_points; ++i)
        h_secret[i] = SECRET(i);
    CHECK(vx_enqueue_write(q, secret_buf, secret_off, h_secret.data(), used_size, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q, probe_buf, 0, h_zero.data(), probe_size, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q, origin_buf, 0, h_zero.data(), used_size, 0, nullptr, nullptr));

    enqueue_claim(q, secret_base, used_size, /*owner*/0);

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

    std::vector<uint32_t> h_probe(num_points * SHARED_SECTORS), h_origin(num_points), h_secret_rb(num_points);
    vx_event_h launch_ev = nullptr, read_ev = nullptr;
    CHECK(vx_enqueue_launch(q, &li, 0, nullptr, &launch_ev));
    CHECK(vx_enqueue_read(q, h_probe.data(), probe_buf, 0, probe_size, 1, &launch_ev, nullptr));
    CHECK(vx_enqueue_read(q, h_origin.data(), origin_buf, 0, used_size, 1, &launch_ev, nullptr));
    CHECK(vx_enqueue_read(q, h_secret_rb.data(), secret_buf, secret_off, used_size, 1, &launch_ev, &read_ev));
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    uint32_t on_core[2] = {0, 0};
    for (uint32_t i = 0; i < num_points; ++i)
        if (h_origin[i] < 2) ++on_core[h_origin[i]];
    std::cout << "tasks: core0=" << on_core[0] << " core1=" << on_core[1] << std::endl;

    // Failure classes, counted separately: a cache that answers without the
    // checker can break confidentiality, the owner's view, or both.
    uint32_t leak = 0, owner_bad = 0, other = 0;
    int printed = 0;
    auto report = [&](const char* what, uint32_t i, uint32_t exp, uint32_t got) {
        if (printed++ < 16)
            std::printf("*** [%u] %s: expected=0x%08x actual=0x%08x\n", i, what, exp, got);
    };

    if (mode == 0) {
        for (uint32_t i = 0; i < num_points; ++i) {
            for (uint32_t s = 0; s < SHARED_SECTORS; ++s) {
                uint32_t w   = s * SECTOR_WORDS + (i % SECTOR_WORDS);
                uint32_t got = h_probe[i * SHARED_SECTORS + s];
                if (h_origin[i] == 0) {
                    if (got != SECRET(w)) { ++owner_bad; report("core0 own read got poison/garbage", i, SECRET(w), got); }
                } else if (h_origin[i] == 1) {
                    if (got != POISON_WORD) { ++leak; report("core1 cross read LEAKED", i, POISON_WORD, got); }
                } else {
                    ++other;
                }
            }
        }
    } else {
        for (uint32_t w = 0; w < num_points; ++w) {
            uint32_t got = h_secret_rb[w];
            if (w < SHARED_WORDS && (w % 2) == 0) {
                if (got != MARK_T0(w)) { ++owner_bad; report("core0 own write lost", w, MARK_T0(w), got); }
            } else if (w < SHARED_WORDS) {
                if (got != SECRET(w)) {
                    if (got == MARK_XT(w)) { ++leak; report("core1 cross write LANDED", w, SECRET(w), got); }
                    else { ++owner_bad; report("secret word corrupted", w, SECRET(w), got); }
                }
            } else if (got != SECRET(w)) {
                ++owner_bad; report("untouched secret word corrupted", w, SECRET(w), got);
            }
        }
    }

    std::cout << "sharedhit: tenant1_breach=" << leak << " tenant0_damage=" << owner_bad
              << " other=" << other << std::endl;

    vx_event_release(read_ev);
    vx_event_release(launch_ev);
    vx_buffer_release(origin_buf);
    vx_buffer_release(probe_buf);
    vx_buffer_release(secret_buf);
    vx_kernel_release(kern);
    vx_module_release(mod);
    vx_queue_release(q);
    vx_device_release(dev);

    if (on_core[0] == 0 || on_core[1] == 0) {
        std::cout << "tasks did not span both cores — run with --cores=2\nFAILED!" << std::endl;
        return 1;
    }
    if (leak || owner_bad || other) {
        std::cout << "Found " << (leak + owner_bad + other) << " errors!\nFAILED!" << std::endl;
        return 1;
    }
    std::cout << "PASSED!" << std::endl;
    return 0;
}
