// twolaunch — each tenant's kernel runs as that tenant, on every core it
// uses (spec T3). See common.h.

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

void dcr(vx_queue_h q, uint32_t addr, uint32_t value) {
    CHECK(vx_enqueue_dcr_write(q, addr, value, 0, nullptr, nullptr));
}

void claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner) {
    dcr(q, DCR_CHECKER_BUF_BASE,    (uint32_t)base);
    dcr(q, DCR_CHECKER_BUF_SIZE,    (uint32_t)bytes);
    dcr(q, DCR_CHECKER_BUF_OWNER,   owner);
    dcr(q, DCR_CHECKER_BUF_PERMS,   CHECKER_PERM_R | CHECKER_PERM_W);
    dcr(q, DCR_CHECKER_BUF_SHARED,  0);
    dcr(q, DCR_CHECKER_BUF_GRANTEE, 0);
    dcr(q, DCR_CHECKER_BUF_JOINT,   0);
    dcr(q, DCR_CHECKER_BUF_EPOCH,   GRANT_NO_EXPIRY);
    dcr(q, DCR_CHECKER_BUF_COMMIT,  1);
}

void finish(vx_queue_h q) {
    CHECK(vx_queue_finish(q, VX_TIMEOUT_INFINITE));
}

struct Padded {
    vx_buffer_h buf = nullptr;
    uint64_t    base = 0;
    uint64_t    off = 0;
};

Padded make_padded(vx_device_h dev, uint64_t bytes, uint64_t granule) {
    Padded p;
    CHECK(vx_buffer_create(dev, bytes + 2*granule, VX_MEM_READ_WRITE, &p.buf));
    uint64_t a = 0;
    CHECK(vx_buffer_address(p.buf, &a));
    p.base = (a + granule - 1) & ~(granule - 1);
    p.off  = p.base - a;
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
    const uint32_t n     = size;
    const uint64_t bytes = uint64_t(n) * sizeof(uint32_t);

    uint32_t buf_log2 = 20;
    if (const char* e = std::getenv("VX_CHECKER_BUF_LOG2")) {
        if (*e) buf_log2 = std::strtoul(e, nullptr, 0);
    }
    const uint64_t granule = 1ull << buf_log2;
    std::cout << "twolaunch: n=" << n << " granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_info_t qi0 = { sizeof(qi0), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_info_t qi1 = qi0;
    qi1.flags |= VX_QUEUE_FLAG_HW_QUEUE(1);
    vx_queue_h q0 = nullptr, q1 = nullptr;
    CHECK(vx_queue_create(dev, &qi0, &q0));
    CHECK(vx_queue_create(dev, &qi1, &q1));

    Padded S = make_padded(dev, bytes, granule);
    Padded T = make_padded(dev, bytes, granule);
    uint64_t probeA_a = 0, probeB_a = 0, originA_a = 0, originB_a = 0;
    vx_buffer_h probeA  = make_plain(dev, bytes, &probeA_a);
    vx_buffer_h probeB  = make_plain(dev, bytes, &probeB_a);
    vx_buffer_h originA = make_plain(dev, bytes, &originA_a);
    vx_buffer_h originB = make_plain(dev, bytes, &originB_a);

    std::vector<uint32_t> h_secret(n), h_zero(n, 0);
    for (uint32_t i = 0; i < n; ++i) h_secret[i] = SECRET(i);
    CHECK(vx_enqueue_write(q0, S.buf, S.off, h_secret.data(), bytes, 0, nullptr, nullptr));
    for (vx_buffer_h b : {probeA, probeB, originA, originB})
        CHECK(vx_enqueue_write(q0, b, 0, h_zero.data(), bytes, 0, nullptr, nullptr));
    claim(q0, S.base, bytes, 0);
    finish(q0);
    CHECK(vx_enqueue_write(q1, T.buf, T.off, h_zero.data(), bytes, 0, nullptr, nullptr));
    claim(q1, T.base, bytes, 1);
    finish(q1);

    vx_module_h mod = nullptr;
    vx_kernel_h kern = nullptr;
    CHECK(vx_module_load_file(dev, kernel_file, &mod));
    CHECK(vx_module_get_kernel(mod, "main", &kern));
    uint32_t grid[1], block[1];
    CHECK(vx_device_max_occupancy_grid(dev, 1, &n, grid, block));

    auto launch = [&](vx_queue_h q, uint32_t mode, uint64_t probe, uint64_t origin) {
        kernel_arg_t a{};
        a.num_points  = n;
        a.mode        = mode;
        a.secret_addr = S.base;
        a.t1_addr     = T.base;
        a.probe_addr  = probe;
        a.origin_addr = origin;
        vx_launch_info_t li{};
        li.struct_size  = sizeof(li);
        li.kernel       = kern;
        li.args_host    = &a;
        li.args_size    = sizeof(a);
        li.ndim         = 1;
        li.grid_dim[0]  = grid[0];
        li.block_dim[0] = block[0];
        CHECK(vx_enqueue_launch(q, &li, 0, nullptr, nullptr));
        finish(q);
    };
    launch(q0, 0, probeA_a, originA_a);   // tenant 0's own kernel
    launch(q1, 1, probeB_a, originB_a);   // tenant 1's attack kernel

    std::vector<uint32_t> rS(n), rPA(n), rPB(n), rOA(n), rOB(n), rT(n);
    CHECK(vx_enqueue_read(q0, rS.data(),  S.buf, S.off, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, rPA.data(), probeA,  0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, rPB.data(), probeB,  0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, rOA.data(), originA, 0, bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_read(q0, rOB.data(), originB, 0, bytes, 0, nullptr, nullptr));
    finish(q0);
    CHECK(vx_enqueue_read(q1, rT.data(), T.buf, T.off, bytes, 0, nullptr, nullptr));
    finish(q1);

    int errors = 0;
    uint32_t coresA[2] = {0, 0}, coresB[2] = {0, 0};
    auto fail = [&](uint32_t i, const char* what, uint32_t exp, uint32_t got, uint32_t core) {
        if (errors < 16)
            std::printf("*** [%u] core=%u %s: expected=0x%08x actual=0x%08x\n", i, core, what, exp, got);
        ++errors;
    };
    for (uint32_t i = 0; i < n; ++i) {
        if (rOA[i] < 2) ++coresA[rOA[i]];
        if (rOB[i] < 2) ++coresB[rOB[i]];
        if (rPA[i] != SECRET(i)) fail(i, "tenant 0 reads its secret", SECRET(i), rPA[i], rOA[i]);
        if (rPB[i] != POISON_WORD) fail(i, "tenant 1's kernel read the secret (leak!)", POISON_WORD, rPB[i], rOB[i]);
        if (rS[i] != MARK_A(i)) fail(i, "secret holds tenant 0's write only", MARK_A(i), rS[i], rOB[i]);
        if (rT[i] != MARK_T(i)) fail(i, "tenant 1's write to its own buffer", MARK_T(i), rT[i], rOB[i]);
    }
    std::printf("launch A on cores: %u %u; launch B on cores: %u %u\n",
                coresA[0], coresA[1], coresB[0], coresB[1]);
    if (coresB[0] == 0 || coresB[1] == 0) {
        std::printf("*** launch B did not span both cores (run with --cores=2)\n");
        ++errors;
    }

    for (vx_buffer_h b : {probeA, probeB, originA, originB, S.buf, T.buf}) vx_buffer_release(b);
    vx_kernel_release(kern);
    vx_module_release(mod);
    vx_queue_release(q1);
    vx_queue_release(q0);
    vx_device_dump_perf(dev, stdout);
    vx_device_release(dev);

    if (errors) {
        std::printf("FAILED! (%d errors)\n", errors);
        return 1;
    }
    std::printf("PASSED!\n");
    return 0;
}
