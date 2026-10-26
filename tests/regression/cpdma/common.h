#ifndef _COMMON_H_
#define _COMMON_H_

// CP DMA regression (P1_and_taint_specv2.md D7). The checker on the command
// processor's device path judges every line an upload, download or copy moves
// for the queue that issued it, which is the tenant. No kernel runs: every
// attack here is a host transfer through tenant 1's own queue, and every
// check is by value.
//
// Run with: VX_CHECKER=1 VX_CHECKER_ENFORCE=1 (SimX) or --checker-enforce
// (xrtsim), and --cores=2. Tenant 2 (queue 2) has no core in a 2-core build.

// Checker DCR registers: mirror of sim/simx/sec/mem_checker.h.
#define DCR_CHECKER_BUF_BASE   0x300
#define DCR_CHECKER_BUF_SIZE   0x301
#define DCR_CHECKER_BUF_OWNER  0x302
#define DCR_CHECKER_BUF_PERMS  0x303
#define DCR_CHECKER_BUF_EPOCH  0x304
#define DCR_CHECKER_BUF_COMMIT 0x305
#define DCR_CHECKER_EPOCH      0x306
#define DCR_CHECKER_BUF_SHARED 0x307
// Header v2: a grant names the one tenant it is for; in these two-tenant
// tests that is always the other tenant.
#define DCR_CHECKER_BUF_GRANTEE 0x30C

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu

// What a denied read returns (VX_checker_fault / MemChecker::poison()).
#define POISON_WORD 0xDDDDDDDDu

#define SECRET(i)  (0x5ec00000u | (i))
#define GRANTED(i) (0x6a000000u | (i))
#define T1VAL(i)   (0x71000000u | (i))
#define ATTACK(i)  (0xa7000000u | (i))

typedef struct {
	uint32_t unused;
} kernel_arg_t;

#endif
