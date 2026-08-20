#ifndef _COMMON_H_
#define _COMMON_H_

// Scoped-revocation regression (fix for the global-epoch bug: revoking one
// owner's grant must not expire a different owner's unrelated grant).
//
// Two independently owned buffers, each granting READ to the other tenant:
//   bufA: owner eid 0 (core 0), shared_perms R granted to others, epoch 0
//   bufB: owner eid 1 (core 1), shared_perms R granted to others, epoch 0
//
// Launch 1 (both grants active): core 1 reads bufA (via the grant), core 0
// reads bufB (via the grant) — both see real data.
//
// The host then revokes ONLY owner 0: REVOKE_OWNER = 0, EPOCH = 1. This must
// advance owner 0's epoch-table entry alone.
//
// Launch 2: core 1's read of bufA comes back poison (owner 0's grant
// expired). Core 0's read of bufB must STILL be real data — owner 1's grant
// was never touched. Before the per-owner epoch table, bumping the single
// global epoch expired both grants at once and this assertion failed.
//
// Run with: VX_CHECKER=1 VX_CHECKER_ENFORCE=1 and --cores=2.
// Without the checker armed, revocation has no effect and the test FAILS —
// the control result.

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
  uint32_t phase;       // 1 = both grants active, 2 = after scoped revocation
  uint64_t bufA_addr;   // owner eid 0, READ-granted to others at epoch 0
  uint64_t bufB_addr;   // owner eid 1, READ-granted to others at epoch 0
  uint64_t probe_addr;  // per-launch: the value each task read via its grant
  uint64_t origin_addr; // per-launch: the core id each task ran on
} kernel_arg_t;

#endif
