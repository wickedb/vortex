#ifndef _COMMON_H_
#define _COMMON_H_

// header_alias — regression for the direct-mapped header-store aliasing hole
// (PROJECT.md §10, item #5).
//
// The header store is indexed (buffer_id & mask). Two buffers whose granule
// ids collide modulo the store size therefore want the same entry. Before the
// store carried a tag, the second claim simply overwrote the first: one
// buffer's policy silently became another's, with no counter moving and no
// access denied. A soundness hole, not a capacity limit — which is why it is
// tested by value rather than by counter.
//
// Forcing the collision deterministically: VX_CHECKER_HEADER_ENTRIES=1 gives
// the store exactly one entry, so *any* two distinct granules collide. That
// removes all dependence on where the runtime happens to place the buffers.
//
//   claim A: bufA → owner eid 0 (R|W), shared_perms 0  — granted to nobody
//   claim B: bufB → owner eid 0 (R|W), shared_perms R  — READ-granted to all
//
// Both buffers are claimed by the SAME owner, differing only in what they
// grant. That is what makes this the soundness case rather than the
// exclusivity case: granule exclusivity refuses a claim whose granule already
// belongs to a *different* owner, so it never sees this pair. Only the tag
// does. Under a one-entry store the two claims want the same entry, and
// pre-fix the second silently overwrote the first — handing bufA bufB's
// shared_perms and with it a READ grant its owner never issued.
//
// What must be true after the fix (claim B refused, claims_aliased=1):
//   core 0 reads bufA → real data   (its own buffer)
//   core 1 reads bufA → poison      (never granted — the leak this test is for)
//   core 0 reads bufB → real data
//   core 1 reads bufB → real data
//
// The last line is the honest part. A refused claim does not make its buffer
// inaccessible; it means no policy was installed, so bufB falls to the boot
// default (OWNER_ANY, R|W) and is simply unprotected — readable by core 1 for
// that reason rather than by the grant that was refused. Fail-closed here
// means "the claim does not take effect", not "the buffer is locked", so a
// host that ignores claims_aliased ends up with an unprotected buffer it
// believes is protected. Stated in sim/simx/sec/README.md §5.
//
// How to re-verify that this test has teeth. Neuter the tag in
// mem_checker.cpp — make header_for() return entry.header whenever
// entry.valid, and drop the tag branch in install_claim()'s pre-pass — and
// rebuild. The store is then untagged at a pinned capacity, which is the
// pre-fix semantics, and this test fails.
//
// Note what that failure looks like, because it is broader than the leak the
// tag most obviously prevents. With one entry, *every* granule indexes it —
// the probe buffers, stacks and kernel code included — so untagged they all
// pick up whatever policy last claimed it. Core 1's writes are then denied
// against a header it has no business being checked against, the probe
// buffers never get written, and the run comes back zeros rather than either
// secrets or poison. Silent misattribution of policy across unrelated
// buffers is the hole; a cross-tenant read leak is one of its shapes, not the
// only one. (Measured: with the tag neutered, core-0 tasks read 0x00000000
// from bufA where 0x5ec000xx was written.)
//
// Checking the pre-fix *binary* instead does not work and is worth recording
// as a trap: VX_CHECKER_HEADER_ENTRIES did not exist before this fix, so the
// old checker silently sizes the store to cover the whole address space, no
// collision ever happens, and the test passes vacuously.
//
// Run with: VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_HEADER_ENTRIES=1
//           and --cores=2.

// Checker DCR registers — mirror of sim/simx/sec/mem_checker.h.
#define DCR_CHECKER_BUF_BASE     0x300
#define DCR_CHECKER_BUF_SIZE     0x301
#define DCR_CHECKER_BUF_OWNER    0x302
#define DCR_CHECKER_BUF_PERMS    0x303
#define DCR_CHECKER_BUF_EPOCH    0x304
#define DCR_CHECKER_BUF_COMMIT   0x305
#define DCR_CHECKER_EPOCH        0x306
#define DCR_CHECKER_BUF_SHARED   0x307
#define DCR_CHECKER_REVOKE_OWNER 0x308

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu

// The checker's poison fill block is 0xDD bytes (mem_checker.cpp).
#define POISON_WORD 0xDDDDDDDDu

// Distinct value families so a wrong buffer's data is never mistaken for
// poison or for the other owner's secret.
#define SECRET_A(i) (0x5EC00000u | (uint32_t)(i))  // owner 0's buffer (bufA)
#define SECRET_B(i) (0x5EB00000u | (uint32_t)(i))  // owner 1's buffer (bufB)

typedef struct {
  uint32_t num_points;
  uint32_t reserved;
  uint64_t bufA_addr;    // claimed by owner eid 0
  uint64_t bufB_addr;    // claim refused — collides with bufA in the store
  uint64_t probeA_addr;  // what each task read from bufA
  uint64_t probeB_addr;  // what each task read from bufB
  uint64_t origin_addr;  // the core id each task ran on
} kernel_arg_t;

#endif
