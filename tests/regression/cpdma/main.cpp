// cpdma — the checker on the command processor's device path (D7).
//
// Two tenants, each on its own CP queue (tenant t = hardware queue t = core
// t). Tenant 0 owns a private buffer S and a buffer G it grants read access
// to. Tenant 1 owns T. U is unclaimed. Tenant 1 then attacks S and G with
// host transfers alone, through its own queue:
//
//   download S           -> poison, not the secret
//   upload into S        -> dropped
//   copy S -> T          -> T holds poison
//   copy T -> S          -> dropped
//   copy S -> U          -> U holds poison
//   download G           -> the grant holds: real data
//   upload into G        -> dropped (the grant is read-only)
//   download G after tenant 0 revokes -> poison
//
// and a queue whose index names no core (queue 2 in a 2-core build, whose
// index would truncate onto owner 0) downloads S -> poison, U -> real data.
// Tenant 0 reads S and G back through its own queue each time: intact.
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

void claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner,
           uint32_t perms, uint32_t shared, uint32_t epoch) {
    dcr(q, DCR_CHECKER_BUF_BASE,   (uint32_t)base);
    dcr(q, DCR_CHECKER_BUF_SIZE,   (uint32_t)bytes);
    dcr(q, DCR_CHECKER_BUF_OWNER,  owner);
    dcr(q, DCR_CHECKER_BUF_PERMS,  perms);
    dcr(q, DCR_CHECKER_BUF_SHARED, shared);
    dcr(q, DCR_CHECKER_BUF_EPOCH,  epoch);
    dcr(q, DCR_CHECKER_BUF_COMMIT, 1);
}

void finish(vx_queue_h q) {
    CHECK(vx_queue_finish(q, VX_TIMEOUT_INFINITE));
}

struct Padded {
    vx_buffer_h buf = nullptr;
    uint64_t    base = 0;   // granule-aligned device address the claim covers
    uint64_t    off = 0;    // base - allocation start
};

Padded make_padded(vx_device_h dev, uint64_t bytes, uint64_t granule) {
    Padded p;
    CHECK(vx_buffer_create(dev, bytes + 2*granule, VX_MEM_READ_WRITE, &p.buf));
    uint64_t dev_addr = 0;
    CHECK(vx_buffer_address(p.buf, &dev_addr));
    p.base = (dev_addr + granule - 1) & ~(granule - 1);
    p.off  = p.base - dev_addr;
    return p;
}

vx_queue_h open_queue(vx_device_h dev, uint32_t hw_queue) {
    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    qi.flags |= VX_QUEUE_FLAG_HW_QUEUE(hw_queue);
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));
    return q;
}

int errors = 0;

// Download `p` through `q` and compare every word against `expect(i)`.
template <typename F>
void expect_read(vx_queue_h q, const Padded& p, uint64_t bytes, const char* what, F expect) {
    std::vector<uint32_t> r(bytes / sizeof(uint32_t), 0);
    CHECK(vx_enqueue_read(q, r.data(), p.buf, p.off, bytes, 0, nullptr, nullptr));
    finish(q);
    int bad = 0;
    for (uint32_t i = 0; i < r.size(); ++i) {
        if (r[i] != expect(i)) {
            if (bad < 4)
                std::printf("*** %s [%u]: expected=0x%08x actual=0x%08x\n", what, i, expect(i), r[i]);
            ++bad;
        }
    }
    std::printf("%-46s %s\n", what, bad ? "FAIL" : "ok");
    errors += bad;
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
    std::cout << "cpdma: n=" << n << " granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_h q0 = open_queue(dev, 0);
    vx_queue_h q1 = open_queue(dev, 1);
    vx_queue_h q2 = open_queue(dev, 2);   // names no core in a 2-core build

    Padded S = make_padded(dev, bytes, granule);
    Padded G = make_padded(dev, bytes, granule);
    Padded T = make_padded(dev, bytes, granule);
    Padded U = make_padded(dev, bytes, granule);

    std::vector<uint32_t> h_secret(n), h_granted(n), h_t1(n), h_attack(n), h_zero(n, 0);
    for (uint32_t i = 0; i < n; ++i) {
        h_secret[i]  = SECRET(i);
        h_granted[i] = GRANTED(i);
        h_t1[i]      = T1VAL(i);
        h_attack[i]  = ATTACK(i);
    }

    const uint32_t RW = CHECKER_PERM_R | CHECKER_PERM_W;
    auto secret  = [](uint32_t i) { return SECRET(i); };
    auto granted = [](uint32_t i) { return GRANTED(i); };
    auto poison  = [](uint32_t)   { return POISON_WORD; };
    auto t1val   = [](uint32_t i) { return T1VAL(i); };
    auto zero    = [](uint32_t)   { return 0u; };

    // Each tenant uploads and claims its own buffers on its own queue.
    CHECK(vx_enqueue_write(q0, S.buf, S.off, h_secret.data(),  bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q0, G.buf, G.off, h_granted.data(), bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(q0, U.buf, U.off, h_zero.data(),    bytes, 0, nullptr, nullptr));
    claim(q0, S.base, bytes, 0, RW, 0, GRANT_NO_EXPIRY);
    claim(q0, G.base, bytes, 0, RW, CHECKER_PERM_R, /*grant_epoch*/0);
    finish(q0);
    CHECK(vx_enqueue_write(q1, T.buf, T.off, h_t1.data(), bytes, 0, nullptr, nullptr));
    claim(q1, T.base, bytes, 1, RW, 0, GRANT_NO_EXPIRY);
    finish(q1);

    // Controls: each owner reads its own data back.
    expect_read(q0, S, bytes, "owner 0 downloads S", secret);
    expect_read(q0, G, bytes, "owner 0 downloads G", granted);
    expect_read(q1, T, bytes, "owner 1 downloads T", t1val);

    // Tenant 1 on tenant 0's private buffer.
    expect_read(q1, S, bytes, "tenant 1 downloads S (poison)", poison);
    CHECK(vx_enqueue_write(q1, S.buf, S.off, h_attack.data(), bytes, 0, nullptr, nullptr));
    finish(q1);
    expect_read(q0, S, bytes, "tenant 1's upload into S dropped", secret);
    CHECK(vx_enqueue_copy(q1, T.buf, T.off, S.buf, S.off, bytes, 0, nullptr, nullptr));
    finish(q1);
    expect_read(q1, T, bytes, "tenant 1 copies S -> T (poison)", poison);
    CHECK(vx_enqueue_write(q1, T.buf, T.off, h_attack.data(), bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_copy(q1, S.buf, S.off, T.buf, T.off, bytes, 0, nullptr, nullptr));
    finish(q1);
    expect_read(q0, S, bytes, "tenant 1's copy T -> S dropped", secret);
    CHECK(vx_enqueue_copy(q1, U.buf, U.off, S.buf, S.off, bytes, 0, nullptr, nullptr));
    finish(q1);
    expect_read(q0, U, bytes, "tenant 1 copies S -> U (poison)", poison);

    // The grant: honored on the CP path, read-only, and revocable.
    expect_read(q1, G, bytes, "tenant 1 downloads G under the grant", granted);
    CHECK(vx_enqueue_write(q1, G.buf, G.off, h_attack.data(), bytes, 0, nullptr, nullptr));
    finish(q1);
    expect_read(q0, G, bytes, "tenant 1's upload into G dropped", granted);

    // A queue that names no core owns nothing: its index must not truncate
    // onto owner 0's.
    CHECK(vx_enqueue_write(q0, U.buf, U.off, h_zero.data(), bytes, 0, nullptr, nullptr));
    finish(q0);
    expect_read(q2, S, bytes, "queue 2 (no core) downloads S (poison)", poison);
    expect_read(q2, U, bytes, "queue 2 (no core) downloads U", zero);

    dcr(q0, DCR_CHECKER_EPOCH, 1);
    finish(q0);
    expect_read(q1, G, bytes, "tenant 1 downloads G after revoke (poison)", poison);
    expect_read(q0, G, bytes, "owner 0 downloads G after revoke", granted);

    for (auto* p : {&S, &G, &T, &U}) vx_buffer_release(p->buf);
    vx_queue_release(q2);
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
