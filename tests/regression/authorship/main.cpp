// authorship — the setup path attributes every command to the queue it
// arrived on (P1_and_taint_specv2.md D1-D4). See common.h for the three
// attacks. Each passes only if tenant 1's commands changed nothing of tenant
// 0's: its policy (-m0, -m1) or what its launch runs (-m2).
//
// Protected buffers are over-allocated by two checker granules and the claimed
// region is aligned up to a granule boundary, so a claim never covers a
// neighbouring allocation regardless of VX_CHECKER_BUF_LOG2.

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
uint32_t    mode        = MODE_FOREIGN;

void parse_args(int argc, char** argv) {
    int c;
    while ((c = getopt(argc, argv, "n:m:k:h")) != -1) {
        switch (c) {
            case 'n': size        = std::atoi(optarg); break;
            case 'm': mode        = std::atoi(optarg); break;
            case 'k': kernel_file = optarg;            break;
            default:
                std::cout << "Usage: [-k kernel] [-n words] [-m mode: 0 foreign "
                             "setup, 1 staging interleave, 2 launch hijack] [-h]"
                          << std::endl;
                std::exit(c == 'h' ? 0 : -1);
        }
    }
}

void dcr(vx_queue_h q, uint32_t addr, uint32_t value) {
    CHECK(vx_enqueue_dcr_write(q, addr, value, 0, nullptr, nullptr));
}

// Stage a claim without committing it.
void stage_claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner,
                 uint32_t perms, uint32_t shared, uint32_t epoch) {
    dcr(q, DCR_CHECKER_BUF_BASE,   (uint32_t)base);
    dcr(q, DCR_CHECKER_BUF_SIZE,   (uint32_t)bytes);
    dcr(q, DCR_CHECKER_BUF_OWNER,  owner);
    dcr(q, DCR_CHECKER_BUF_PERMS,  perms);
    dcr(q, DCR_CHECKER_BUF_SHARED, shared);
    dcr(q, DCR_CHECKER_BUF_EPOCH,  epoch);
}

void claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner,
           uint32_t perms, uint32_t shared, uint32_t epoch) {
    stage_claim(q, base, bytes, owner, perms, shared, epoch);
    dcr(q, DCR_CHECKER_BUF_COMMIT, 1);
}

void finish(vx_queue_h q) {
    CHECK(vx_queue_finish(q, VX_TIMEOUT_INFINITE));
}

// A buffer over-allocated by two granules, with its granule-aligned base.
struct Padded {
    vx_buffer_h buf  = nullptr;
    uint64_t    base = 0;   // granule-aligned device address inside it
    uint64_t    off  = 0;   // base - buffer address
};

Padded make_padded(vx_device_h dev, uint64_t bytes, uint64_t granule) {
    Padded p;
    CHECK(vx_buffer_create(dev, bytes + 2 * granule, VX_MEM_READ_WRITE, &p.buf));
    uint64_t addr = 0;
    CHECK(vx_buffer_address(p.buf, &addr));
    p.base = (addr + granule - 1) & ~(granule - 1);
    p.off  = p.base - addr;
    return p;
}

vx_buffer_h make_plain(vx_device_h dev, uint64_t bytes, uint64_t* addr) {
    vx_buffer_h b = nullptr;
    CHECK(vx_buffer_create(dev, bytes, VX_MEM_READ_WRITE, &b));
    CHECK(vx_buffer_address(b, addr));
    return b;
}
} // namespace

int main(int argc, char** argv) {
    parse_args(argc, argv);
    if (mode > MODE_HIJACK) {
        std::cout << "authorship: unknown mode " << mode << std::endl;
        return -1;
    }

    const uint32_t n     = size;
    const uint64_t bytes = uint64_t(n) * sizeof(uint32_t);

    uint32_t buf_log2 = 20;
    if (const char* e = std::getenv("VX_CHECKER_BUF_LOG2")) {
        if (*e) buf_log2 = std::strtoul(e, nullptr, 0);
    }
    const uint64_t granule = 1ull << buf_log2;

    static const char* names[] = {"foreign setup", "staging interleave", "launch hijack"};
    std::cout << "authorship: n=" << n << " mode=" << mode << " (" << names[mode]
              << ") granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));

    // One command queue per tenant: tenant t submits on hardware queue t.
    vx_queue_info_t qi0 = { sizeof(qi0), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_info_t qi1 = qi0;
    qi1.flags |= VX_QUEUE_FLAG_HW_QUEUE(1);
    vx_queue_h q0 = nullptr, q1 = nullptr;
    CHECK(vx_queue_create(dev, &qi0, &q0));
    CHECK(vx_queue_create(dev, &qi1, &q1));

    Padded secret = make_padded(dev, bytes, granule);
    Padded grant  = make_padded(dev, bytes, granule);
    Padded t1own  = make_padded(dev, bytes, granule);
    kernel_arg_t a{};
    a.num_points  = n;
    a.mode        = mode;
    a.secret_addr = secret.base;
    a.grant_addr  = grant.base;
    a.t1_addr     = t1own.base;
    vx_buffer_h probe  = make_plain(dev, bytes, &a.probe_addr);
    vx_buffer_h probe2 = make_plain(dev, bytes, &a.probe2_addr);
    vx_buffer_h origin = make_plain(dev, bytes, &a.origin_addr);
    vx_buffer_h countA = make_plain(dev, bytes, &a.count_addr);
    uint64_t countB_addr = 0, argsB_addr = 0;
    vx_buffer_h countB = make_plain(dev, bytes, &countB_addr);
    vx_buffer_h argsB  = make_plain(dev, sizeof(kernel_arg_t), &argsB_addr);

    std::vector<uint32_t> h_secret(n), h_granted(n), h_zero(n, 0);
    for (uint32_t i = 0; i < n; ++i) {
        h_secret[i]  = SECRET(i);
        h_granted[i] = GRANTED(i);
    }
    CHECK(vx_enqueue_write(q0, secret.buf, secret.off, h_secret.data(),  bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q0, grant.buf,  grant.off,  h_granted.data(), bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q0, t1own.buf,  t1own.off,  h_zero.data(),    bytes, 0, nullptr, nullptr));
    for (vx_buffer_h b : {probe, probe2, origin, countA, countB})
        CHECK(vx_enqueue_write(q0, b, 0, h_zero.data(), bytes, 0, nullptr, nullptr));
    finish(q0);

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));

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

    const uint32_t RW = CHECKER_PERM_R | CHECKER_PERM_W;

    if (mode == MODE_FOREIGN) {
        // Tenant 0: secret private; grant readable by non-owners at epoch 0.
        claim(q0, secret.base, bytes, 0, RW, 0, GRANT_NO_EXPIRY);
        claim(q0, grant.base,  bytes, 0, RW, CHECKER_PERM_R, 0);
        finish(q0);
        // Tenant 1, attack 1: re-claim the secret as its owner, opening it to
        // every non-owner. Attack 2: revoke tenant 0's grant.
        claim(q1, secret.base, bytes, 0, RW, CHECKER_PERM_R, GRANT_NO_EXPIRY);
        dcr(q1, DCR_CHECKER_REVOKE_OWNER, 0);
        dcr(q1, DCR_CHECKER_EPOCH, 1);
        finish(q1);
    } else if (mode == MODE_INTERLEAVE) {
        // Tenant 0 stages its claim; tenant 1 stages and commits its own in
        // between; then tenant 0 commits.
        stage_claim(q0, secret.base, bytes, 0, RW, 0, GRANT_NO_EXPIRY);
        finish(q0);
        claim(q1, t1own.base, bytes, 1, RW, 0, GRANT_NO_EXPIRY);
        finish(q1);
        dcr(q0, DCR_CHECKER_BUF_COMMIT, 1);
        finish(q0);
    }

    // Launch 1, from tenant 0's queue.
    CHECK(vx_enqueue_launch(q0, &li, 0, nullptr, nullptr));
    finish(q0);

    if (mode == MODE_HIJACK) {
        // Tenant 1 plants an argument block that counts into countB and points
        // the kernel-argument register at it. Then tenant 0 launches again,
        // reusing its kernel and arguments (the legacy escape hatch: no kernel
        // and no argument blob, so the runtime leaves those registers alone).
        kernel_arg_t b = a;
        b.count_addr = countB_addr;
        CHECK(vx_enqueue_write(q1, argsB, 0, &b, sizeof(b), 0, nullptr, nullptr));
        dcr(q1, DCR_KMU_STARTUP_ARG0, uint32_t(argsB_addr & 0xFFFFFFFFu));
        dcr(q1, DCR_KMU_STARTUP_ARG1, uint32_t(argsB_addr >> 32));
        finish(q1);
        vx_launch_info_t li2 = li;
        li2.kernel    = nullptr;
        li2.args_host = nullptr;
        li2.args_size = 0;
        CHECK(vx_enqueue_launch(q0, &li2, 0, nullptr, nullptr));
        finish(q0);
    }

    std::vector<uint32_t> r_probe(n), r_probe2(n), r_origin(n), r_t1(n),
                          r_countA(n), r_countB(n);
    CHECK(vx_enqueue_read(q0, r_probe.data(),  probe,  0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, r_probe2.data(), probe2, 0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, r_origin.data(), origin, 0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, r_t1.data(),     t1own.buf, t1own.off, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, r_countA.data(), countA, 0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, r_countB.data(), countB, 0, bytes, 0, nullptr, nullptr));
    finish(q0);

    // ----- verification, keyed on the core each task ran on -----
    int errors = 0;
    uint32_t on_core[2] = {0, 0};
    auto fail = [&](uint32_t i, const char* what, uint32_t exp, uint32_t got) {
        if (errors < 16)
            std::printf("*** [%u] core=%u %s: expected=0x%08x actual=0x%08x\n",
                        i, r_origin[i], what, exp, got);
        ++errors;
    };
    for (uint32_t i = 0; i < n; ++i) {
        const uint32_t core = r_origin[i];
        if (core < 2) ++on_core[core];
        if (mode == MODE_HIJACK) {
            if (r_countA[i] != 2)
                fail(i, "tenant 0's launches on its own arguments", 2, r_countA[i]);
            if (r_countB[i] != 0)
                fail(i, "launches on tenant 1's planted arguments (hijack!)", 0, r_countB[i]);
            continue;
        }
        if (core == 0) {
            if (r_probe[i] != SECRET(i))
                fail(i, "owner read of the secret", SECRET(i), r_probe[i]);
        } else if (core == 1) {
            if (r_probe[i] != POISON_WORD)
                fail(i, "non-owner read of the secret (leak!)", POISON_WORD, r_probe[i]);
        } else {
            fail(i, "task ran on an unexpected core", 0, core);
            continue;
        }
        if (mode == MODE_FOREIGN) {
            // Both cores may read the grant: tenant 1 could not revoke it.
            if (r_probe2[i] != GRANTED(i))
                fail(i, "read under tenant 0's grant (revoked by tenant 1?)",
                     GRANTED(i), r_probe2[i]);
        } else {
            const uint32_t exp = (core == 1) ? MARK_T1(i) : 0;
            if (r_t1[i] != exp)
                fail(i, core == 1 ? "tenant 1's own write" : "core 0's write to tenant 1's buffer",
                     exp, r_t1[i]);
        }
    }
    if (mode != MODE_HIJACK && (on_core[0] == 0 || on_core[1] == 0)) {
        std::printf("*** tasks ran on core0=%u core1=%u: need both (run with --cores=2)\n",
                    on_core[0], on_core[1]);
        ++errors;
    }

    vx_buffer_release(argsB);
    vx_buffer_release(countB);
    vx_buffer_release(countA);
    vx_buffer_release(origin);
    vx_buffer_release(probe2);
    vx_buffer_release(probe);
    vx_buffer_release(t1own.buf);
    vx_buffer_release(grant.buf);
    vx_buffer_release(secret.buf);
    vx_kernel_release(kern);
    vx_module_release(mod);
    vx_queue_release(q1);
    vx_queue_release(q0);
    vx_device_dump_perf(dev, stdout);
    vx_device_release(dev);

    std::printf("tasks: core0=%u core1=%u\n", on_core[0], on_core[1]);
    if (errors) {
        std::printf("FAILED! (%d errors)\n", errors);
        return 1;
    }
    std::printf("PASSED!\n");
    return 0;
}
