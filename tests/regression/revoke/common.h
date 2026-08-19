#ifndef _COMMON_H_
#define _COMMON_H_

// Epoch revocation demo (Phase 4). Tenant 0 (core 0) owns a buffer and grants
// tenant 1 (core 1) READ access for epoch 0. Launch 1 runs under the grant:
// both cores read real data. The host then revokes with a single DCR write —
// CURRENT_EPOCH = 1 — touching no header. Launch 2: the owner still reads and
// writes its buffer; tenant 1's reads come back poison.
//
// Run with: VX_CHECKER=1 VX_CHECKER_ENFORCE=1 and --cores=2.
// Without the checker armed, revocation has no effect and the test FAILS —
// the control result.

// Checker DCR registers — mirror of sim/simx/sec/mem_checker.h.
#define DCR_CHECKER_BUF_BASE   0x300
#define DCR_CHECKER_BUF_SIZE   0x301
#define DCR_CHECKER_BUF_OWNER  0x302
#define DCR_CHECKER_BUF_PERMS  0x303
#define DCR_CHECKER_BUF_EPOCH  0x304
#define DCR_CHECKER_BUF_COMMIT 0x305
#define DCR_CHECKER_EPOCH      0x306
#define DCR_CHECKER_BUF_SHARED 0x307

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2

// The checker's poison fill block is 0xDD bytes (mem_checker.cpp).
#define POISON_WORD 0xDDDDDDDDu

#define SECRET(i)  (0x5EC00000u | (uint32_t)(i))  // host-uploaded owner data
#define MARK_T0(i) (0xA0000000u | (uint32_t)(i))  // owner write after revocation

typedef struct {
  uint32_t num_points;
  uint32_t phase;        // 1 = under grant, 2 = after revocation
  uint64_t shared_addr;  // tenant 0's buffer, READ-granted to others at epoch 0
  uint64_t probe_addr;   // per-launch: the value each task read
  uint64_t origin_addr;  // per-launch: the core id each task ran on
} kernel_arg_t;

#endif
