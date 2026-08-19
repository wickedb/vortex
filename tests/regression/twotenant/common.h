#ifndef _COMMON_H_
#define _COMMON_H_

// Two-tenant isolation demo (Phase 3). Tenancy model: one tenant per core
// (owner_eid = core id). The host claims `secret` for tenant 0 (core 0) and
// `t1own` for tenant 1 (core 1) over the checker's DCR setup path; the
// `probe`/`origin` result buffers stay unclaimed, i.e. system/shared.
//
// Run with: VX_CHECKER=1 VX_CHECKER_ENFORCE=1 and --cores=2.
// Without the checker armed the cross-tenant accesses succeed and the test
// FAILS — that failure is the control result showing enforcement, not luck,
// produces the isolation.

// Checker DCR registers — mirror of sim/simx/sec/mem_checker.h (range 0x300+,
// reserved per phase0/checker_hook_map.md §2.5).
#define DCR_CHECKER_BUF_BASE   0x300
#define DCR_CHECKER_BUF_SIZE   0x301
#define DCR_CHECKER_BUF_OWNER  0x302
#define DCR_CHECKER_BUF_PERMS  0x303
#define DCR_CHECKER_BUF_EPOCH  0x304
#define DCR_CHECKER_BUF_COMMIT 0x305
#define DCR_CHECKER_EPOCH      0x306

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu

// The checker's poison fill block is 0xDD bytes (mem_checker.cpp).
#define POISON_WORD 0xDDDDDDDDu

// Distinct value families so every observed word identifies its writer.
#define SECRET(i)  (0x5EC00000u | (uint32_t)(i))  // host-uploaded tenant 0 data
#define MARK_T0(i) (0xA0000000u | (uint32_t)(i))  // tenant 0 writing its own buffer
#define MARK_XT(i) (0xB0000000u | (uint32_t)(i))  // cross-tenant write attempt
#define MARK_T1(i) (0xC0000000u | (uint32_t)(i))  // tenant 1 writing its own buffer

typedef struct {
  uint32_t num_points;
  uint64_t secret_addr;  // tenant 0's buffer (claimed for eid 0)
  uint64_t t1_addr;      // tenant 1's buffer (claimed for eid 1)
  uint64_t probe_addr;   // shared: the value each task read from secret[idx]
  uint64_t origin_addr;  // shared: the core id each task ran on
} kernel_arg_t;

#endif
