// revoke_scope — regression for the global-epoch revocation bug.
//
// The property this demonstrates: two owners each grant READ access to a
// buffer. Revoking ONE owner's grant (REVOKE_OWNER = 0, then EPOCH = 1)
// must not affect the OTHER owner's unrelated grant. Before the per-owner
// epoch table, a single global epoch counter meant any revocation expired
// every outstanding grant at once — this test fails under that bug and
// passes under the fix.
//
//   claim A: bufA → owner eid 0 (R|W), shared_perms R, grant_epoch 0
//   claim B: bufB → owner eid 1 (R|W), shared_perms R, grant_epoch 0
//   launch 1: core 1 reads bufA (real, via grant A); core 0 reads bufB (real, via grant B)
//   revoke:   vx_enqueue_dcr_write(REVOKE_OWNER, 0);
//             vx_enqueue_dcr_write(EPOCH, 1)      ← scoped to owner 0 only
//   launch 2: core 1 reads bufA → poison (grant A revoked)
//             core 0 reads bufB → still real data (grant B untouched)

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

    std::cout << "revoke_scope: n=" << num_points << " buf=" << used_size
              << "B granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));

    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));

    // Both protected buffers padded so a granule-aligned claim stays inside
    // them (same pattern as twotenant), so neither claim can spill onto a
    // neighboring allocation regardless of VX_CHECKER_BUF_LOG2.
    vx_buffer_h bufA_buf=nullptr, bufB_buf=nullptr, probe1_buf=nullptr,
                origin1_buf=nullptr, probe2_buf=nullptr, origin2_buf=nullptr;
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &bufA_buf));
    CHECK(vx_buffer_create(dev, used_size + 2*granule, VX_MEM_READ_WRITE, &bufB_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &probe1_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &origin1_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &probe2_buf));
    CHECK(vx_buffer_create(dev, used_size, VX_MEM_READ_WRITE, &origin2_buf));

    uint64_t bufA_dev=0, bufB_dev=0;
    CHECK(vx_buffer_address(bufA_buf, &bufA_dev));
    CHECK(vx_buffer_address(bufB_buf, &bufB_dev));
    const uint64_t bufA_base = (bufA_dev + granule - 1) & ~(granule - 1);
    const uint64_t bufB_base = (bufB_dev + granule - 1) & ~(granule - 1);
    const uint64_t bufA_off  = bufA_base - bufA_dev;
    const uint64_t bufB_off  = bufB_base - bufB_dev;

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
    CHECK(vx_enqueue_write(q, probe1_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, origin1_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, probe2_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));
    CHECK(vx_enqueue_write(q, origin2_buf, 0, h_zero.data(), used_size, 0,nullptr,nullptr));

    // Two independent owners, each granting READ to the other at epoch 0.
    enqueue_claim(q, bufA_base, used_size, 0, CHECKER_PERM_R | CHECKER_PERM_W, CHECKER_PERM_R, 0);
    enqueue_claim(q, bufB_base, used_size, 1, CHECKER_PERM_R | CHECKER_PERM_W, CHECKER_PERM_R, 0);

    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &num_points, grid, block));

    kernel_arg_t arg1{}, arg2{};
    arg1.num_points = num_points;
    arg1.phase      = 1;
    arg1.bufA_addr  = bufA_base;
    arg1.bufB_addr  = bufB_base;
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

    // launch 1 (both grants active) → scoped revoke of owner 0 only → launch 2.
    // The queue is FIFO and each launch drains before the next command, so
    // the revocation lands exactly between the launches.
    vx_launch_info_t li1 = make_li(&arg1), li2 = make_li(&arg2);
    vx_event_h ev2=nullptr, read_ev=nullptr;
    CHECK(vx_enqueue_launch(q, &li1, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_REVOKE_OWNER, 0, 0, nullptr, nullptr));
    CHECK(vx_enqueue_dcr_write(q, DCR_CHECKER_EPOCH, 1, 0, nullptr, nullptr));
    CHECK(vx_enqueue_launch(q, &li2, 0, nullptr, &ev2));

    std::vector<uint32_t> h_probe1(num_points), h_origin1(num_points),
                          h_probe2(num_points), h_origin2(num_points);
    CHECK(vx_enqueue_read(q, h_probe1.data(), probe1_buf, 0, used_size, 1, &ev2, nullptr));
    CHECK(vx_enqueue_read(q, h_origin1.data(), origin1_buf, 0, used_size, 1, &ev2, nullptr));
    CHECK(vx_enqueue_read(q, h_probe2.data(), probe2_buf, 0, used_size, 1, &ev2, nullptr));
    CHECK(vx_enqueue_read(q, h_origin2.data(), origin2_buf, 0, used_size, 1, &ev2, &read_ev));
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
        // Launch 1, both grants active: core 0 reads bufB (real), core 1
        // reads bufA (real).
        if (h_origin1[i] == 0) {
            ++p1_core0;
            if (h_probe1[i] != SECRET_B(i))
                fail(i, "phase1 core0 reads bufB via grant B", SECRET_B(i), h_probe1[i]);
        } else if (h_origin1[i] == 1) {
            ++p1_core1;
            if (h_probe1[i] != SECRET_A(i))
                fail(i, "phase1 core1 reads bufA via grant A", SECRET_A(i), h_probe1[i]);
        } else {
            fail(i, "phase1 origin core id", 0, h_origin1[i]);
        }

        // Launch 2, after revoking owner 0 ONLY: core 0's read of bufB
        // (owner 1's grant) must be unaffected — this is the property under
        // test. Core 1's read of bufA (owner 0's grant) must be poisoned.
        if (h_origin2[i] == 0) {
            ++p2_core0;
            if (h_probe2[i] != SECRET_B(i))
                fail(i, "phase2 core0 reads bufB (unrelated grant, must survive)", SECRET_B(i), h_probe2[i]);
        } else if (h_origin2[i] == 1) {
            ++p2_core1;
            if (h_probe2[i] != POISON_WORD)
                fail(i, "phase2 core1 reads bufA (revoked grant, leak!)", POISON_WORD, h_probe2[i]);
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
