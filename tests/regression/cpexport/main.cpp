// cpexport — S6: confined data never leaves the device through the command
// processor (spec S6, D7). See common.h.

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

void claim(vx_queue_h q, uint64_t base, uint64_t bytes, uint32_t owner, uint32_t joint,
           uint32_t shared, uint32_t grantee, uint32_t confined) {
    dcr(q, DCR_CHECKER_BUF_BASE,     (uint32_t)base);
    dcr(q, DCR_CHECKER_BUF_SIZE,     (uint32_t)bytes);
    dcr(q, DCR_CHECKER_BUF_OWNER,    owner);
    dcr(q, DCR_CHECKER_BUF_PERMS,    CHECKER_PERM_R | CHECKER_PERM_W);
    dcr(q, DCR_CHECKER_BUF_SHARED,   shared);
    dcr(q, DCR_CHECKER_BUF_GRANTEE,  grantee);
    dcr(q, DCR_CHECKER_BUF_JOINT,    joint);
    dcr(q, DCR_CHECKER_BUF_CONFINED, confined);
    dcr(q, DCR_CHECKER_BUF_EPOCH,    GRANT_NO_EXPIRY);
    dcr(q, DCR_CHECKER_BUF_COMMIT,   1);
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

vx_queue_h open_queue(vx_device_h dev, uint32_t hw_queue) {
    vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    qi.flags |= VX_QUEUE_FLAG_HW_QUEUE(hw_queue);
    vx_queue_h q = nullptr;
    CHECK(vx_queue_create(dev, &qi, &q));
    return q;
}

int errors = 0;

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
    std::printf("%-48s %s\n", what, bad ? "FAIL" : "ok");
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
    std::cout << "cpexport: n=" << n << " granule=" << granule << "B" << std::endl;

    vx_device_h dev = nullptr;
    CHECK(vx_device_open(0, &dev));
    vx_queue_h qh = open_queue(dev, TENANT_H);
    vx_queue_h qm = open_queue(dev, TENANT_M);

    Padded I    = make_padded(dev, bytes, granule);   // H's images, confined grant to M
    Padded J    = make_padded(dev, bytes, granule);   // M jointly with H
    Padded J2   = make_padded(dev, bytes, granule);   // M jointly with H
    Padded MOWN = make_padded(dev, bytes, granule);   // M alone

    std::vector<uint32_t> h_img(n), h_joint(n), h_zero(n, 0);
    for (uint32_t i = 0; i < n; ++i) { h_img[i] = IMAGE(i); h_joint[i] = JOINT(i); }

    auto image  = [](uint32_t i) { return IMAGE(i); };
    auto joint  = [](uint32_t i) { return JOINT(i); };
    auto poison = [](uint32_t)   { return POISON_WORD; };
    auto zero   = [](uint32_t)   { return 0u; };
    const uint32_t H_BIT = 1u << TENANT_H;

    // Each owner uploads, then claims.
    CHECK(vx_enqueue_write(qh, I.buf, I.off, h_img.data(), bytes, 0, nullptr, nullptr));
    claim(qh, I.base, bytes, TENANT_H, 0, CHECKER_PERM_R, TENANT_M, /*confined*/1);
    finish(qh);
    CHECK(vx_enqueue_write(qm, J.buf,    J.off,    h_joint.data(), bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(qm, J2.buf,   J2.off,   h_zero.data(),  bytes, 0, nullptr, nullptr));
    CHECK(vx_enqueue_write(qm, MOWN.buf, MOWN.off, h_zero.data(),  bytes, 0, nullptr, nullptr));
    claim(qm, J.base,    bytes, TENANT_M, H_BIT, 0, 0, 0);
    claim(qm, J2.base,   bytes, TENANT_M, H_BIT, 0, 0, 0);
    claim(qm, MOWN.base, bytes, TENANT_M, 0,     0, 0, 0);
    finish(qm);

    // Controls: an owner alone reads its own data.
    expect_read(qh, I, bytes, "H downloads its own images", image);
    expect_read(qm, MOWN, bytes, "M downloads its own buffer", zero);

    // S6: a download never carries confined or joint data off the device.
    expect_read(qm, I, bytes, "M downloads the confined images (poison)", poison);
    expect_read(qm, J, bytes, "M downloads joint J (poison)", poison);
    expect_read(qh, J, bytes, "H downloads joint J (poison)", poison);

    // A copy's write must be covered by what it read.
    CHECK(vx_enqueue_copy(qm, MOWN.buf, MOWN.off, J.buf, J.off, bytes, 0, nullptr, nullptr));
    finish(qm);
    expect_read(qm, MOWN, bytes, "M's copy J -> its own buffer dropped", zero);
    CHECK(vx_enqueue_copy(qm, J2.buf, J2.off, J.buf, J.off, bytes, 0, nullptr, nullptr));
    finish(qm);

    // The release: H leaves J2, which is then M's alone and may leave.
    dcr(qh, DCR_CHECKER_BUF_BASE,  (uint32_t)J2.base);
    dcr(qh, DCR_CHECKER_BUF_SIZE,  (uint32_t)bytes);
    dcr(qh, DCR_CHECKER_BUF_LEAVE, TENANT_H);
    finish(qh);
    expect_read(qm, J2, bytes, "after H leaves, M downloads the copy J -> J2", joint);

    for (auto* p : {&I, &J, &J2, &MOWN}) vx_buffer_release(p->buf);
    vx_queue_release(qm);
    vx_queue_release(qh);
    vx_device_dump_perf(dev, stdout);
    vx_device_release(dev);

    if (errors) {
        std::printf("FAILED! (%d errors)\n", errors);
        return 1;
    }
    std::printf("PASSED!\n");
    return 0;
}
