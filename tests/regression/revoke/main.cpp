// revoke — Phase 4 epoch revocation demo (vortex2.h-native).
//
// The thesis sentence this demonstrates: tenant 0 grants tenant 1 read access
// for epoch 0, the host revokes at epoch 1 with ONE register write (no header
// is touched — on the setup path or any access path), tenant 1 is denied,
// and tenant 0's own access is unaffected.
//
//   claim:    shared buffer → owner eid 0 (R|W), shared_perms R, grant_epoch 0
//   launch 1: both cores read real data (grant active)
//   revoke:   vx_enqueue_dcr_write(CURRENT_EPOCH, 1)   ← the entire revocation
//   launch 2: core 0 reads real data and writes; core 1 reads poison
//
// SimX resets caches at each launch, which models the cache shootdown a real
// revocation requires; the grant state itself lives only in the checker.

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

    std::cout << "revoke: n=" << num_points << " buf=" << used_size
              << "B granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));

    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    vx_buffer_h shared_buf=nullptr, probe1_buf=nullptr, origin1_buf=nullptr,
                probe2_buf=nullptr, origin2_buf=nullptr;
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &shared_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &probe1_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &origin1_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &probe2_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &origin2_buf));

    uint64_t shared_dev=0;
    CHECK(vx_buffer_address(shared_buf, &shared_dev));
    const uint64_t shared_base = (shared_dev + granule - 1) & ~(granule - 1);
    const uint64_t shared_off  = shared_base - shared_dev;

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

    std::vector<uint32_t> h_secret(num_points), h_zero(num_points, 0);
    for (uint32_t i = 0; i < num_points; ++i)
        h_secret[i] = SECRET(i);

    CHECK(vx_enqueue_write(q, shared_buf, shared_off, h_secret.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, probe1_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, origin1_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, probe2_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, origin2_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));

    // The grant: tenant 0 owns the buffer (R|W, no owner expiry); everyone
    // else gets READ, valid through epoch 0.
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_BASE,  (uint32_t)shared_base, 0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SIZE,  (uint32_t)used_size,   0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_OWNER, 0,                     0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_PERMS, CHECKER_PERM_R | CHECKER_PERM_W, 0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_SHARED, CHECKER_PERM_R,       0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_EPOCH, 0,                     0,nullptr,nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_BUF_COMMIT, 1,                    0,nullptr,nullptr));

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &num_points, grid, block));

    kernel_arg_t arg1{}, arg2{};
    arg1.num_points = num_points;
    arg1.phase      = 1;
    arg1.shared_addr = shared_base;
    CHECK(vx_buffer_address(probe1_buf,  &arg1.probe_addr));
    CHECK(vx_buffer_address(origin1_buf, &arg1.origin_addr));
    arg2 = arg1;
    arg2.phase = 2;
    CHECK(vx_buffer_address(probe2_buf,  &arg2.probe_addr));
    CHECK(vx_buffer_address(origin2_buf, &arg2.origin_addr));

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

    // launch 1 (grant active) → revoke (ONE register write) → launch 2.
    // The queue is FIFO and each launch drains before the next command, so
    // the epoch bump lands exactly between the launches.
    vx_launch_info_t li1 = make_li(&arg1), li2 = make_li(&arg2);
    vx_event_h ev2=nullptr, read_ev=nullptr;
    CHECK(vx_enqueue_launch(q, &li1, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_EPOCH, 1, 0, nullptr, nullptr));
    CHECK(vx_enqueue_launch(q, &li2, 0, nullptr, &ev2));

    std::vector<uint32_t> h_probe1(num_points), h_origin1(num_points),
                          h_probe2(num_points), h_origin2(num_points),
                          h_shared_rb(num_points);
    CHECK(vx_enqueue_read(q, h_probe1.data(), probe1_buf, 0, used_size, 1, &ev2, nullptr));
    CHECK(vx_enqueue_read(q, h_origin1.data(), origin1_buf, 0, used_size, 1, &ev2, nullptr));
    CHECK(vx_enqueue_read(q, h_probe2.data(), probe2_buf, 0, used_size, 1, &ev2, nullptr));
    CHECK(vx_enqueue_read(q, h_origin2.data(), origin2_buf, 0, used_size, 1, &ev2, nullptr));
    CHECK(vx_enqueue_read(q, h_shared_rb.data(), shared_buf, shared_off, used_size, 1, &ev2, &read_ev));
    CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

    // ----- verification -----
    uint32_t p1_core0=0, p1_core1=0, p2_core0=0, p2_core1=0;
    int errors = 0;
    auto fail = [&](uint32_t i, const char* what, uint32_t exp, uint32_t got) {
        if (errors < 16)
            std::printf("*** [%u] %s: expected=0x%08x actual=0x%08x\n", i, what, exp, got);
        ++errors;
    };
    for (uint32_t i = 0; i < num_points; ++i) {
        // Launch 1, grant active: every task reads real data, on either core.
        (h_origin1[i] == 0) ? ++p1_core0 : ++p1_core1;
        if (h_probe1[i] != SECRET(i))
            fail(i, "phase1 read under grant", SECRET(i), h_probe1[i]);

        // Launch 2, after revocation: owner unaffected, tenant 1 denied.
        if (h_origin2[i] == 0) {
            ++p2_core0;
            if (h_probe2[i] != SECRET(i))
                fail(i, "phase2 owner read", SECRET(i), h_probe2[i]);
            if (h_shared_rb[i] != MARK_T0(i))
                fail(i, "phase2 owner write", MARK_T0(i), h_shared_rb[i]);
        } else if (h_origin2[i] == 1) {
            ++p2_core1;
            if (h_probe2[i] != POISON_WORD)
                fail(i, "phase2 revoked read (leak!)", POISON_WORD, h_probe2[i]);
            if (h_shared_rb[i] != SECRET(i))
                fail(i, "phase2 shared cell", SECRET(i), h_shared_rb[i]);
        } else {
            fail(i, "phase2 origin core id", 0, h_origin2[i]);
        }
    }
    std::cout << "tasks: phase1 core0=" << p1_core0 << " core1=" << p1_core1
              << " | phase2 core0=" << p2_core0 << " core1=" << p2_core1 << std::endl;
    if (p1_core0 == 0 || p1_core1 == 0 || p2_core0 == 0 || p2_core1 == 0) {
        std::cout << "tasks did not span both cores in both launches — run with --cores=2\nFAILED!" << std::endl;
        return 1;
    }

    vx_event_release(read_ev);
    vx_event_release(ev2);
    vx_buffer_release(origin2_buf);
    vx_buffer_release(probe2_buf);
    vx_buffer_release(origin1_buf);
    vx_buffer_release(probe1_buf);
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
