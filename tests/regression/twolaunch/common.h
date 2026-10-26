#ifndef _COMMON_H_
#define _COMMON_H_

// twolaunch — the tenant a kernel runs as is the queue that launched it
// (spec T3; VX_CFG_CHECKER_TENANT_FROM_LAUNCH in RTL,
// VX_CHECKER_TENANT_FROM_LAUNCH=1 in SimX). Each tenant launches its own
// kernel from its own queue, and each kernel spans every core:
//
//   launch A (queue 0): reads tenant 0's secret and overwrites it: allowed.
//   launch B (queue 1): reads the secret (poison), overwrites it (dropped),
//                       writes tenant 1's own buffer (lands).
//
// Without the option the tenant is the core id, so launch B's tasks on core 0
// run as tenant 0 and the attack succeeds there: the control.

#define DCR_CHECKER_BUF_BASE    0x300
#define DCR_CHECKER_BUF_SIZE    0x301
#define DCR_CHECKER_BUF_OWNER   0x302
#define DCR_CHECKER_BUF_PERMS   0x303
#define DCR_CHECKER_BUF_EPOCH   0x304
#define DCR_CHECKER_BUF_COMMIT  0x305
#define DCR_CHECKER_BUF_SHARED  0x307
#define DCR_CHECKER_BUF_JOINT   0x309
#define DCR_CHECKER_BUF_GRANTEE 0x30C

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu
#define POISON_WORD 0xDDDDDDDDu

#define SECRET(i) (0x5ec00000u | (i))
#define MARK_A(i) (0xa0000000u | (i))
#define MARK_B(i) (0xb0000000u | (i))
#define MARK_T(i) (0x71000000u | (i))

typedef struct {
	uint32_t num_points;
	uint32_t mode;          // 0: launch A (tenant 0), 1: launch B (tenant 1)
	uint64_t secret_addr;
	uint64_t t1_addr;
	uint64_t probe_addr;
	uint64_t origin_addr;
} kernel_arg_t;

#endif
