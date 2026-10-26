#ifndef _COMMON_H_
#define _COMMON_H_

// cpexport — S6 on the command processor's path: confined data never leaves
// the device by DMA. Two tenants, H (queue 0) and M (queue 1). H's images are
// granted to M for confined reading; J and J2 are owned by M jointly with H;
// MOWN is M's alone. With confinement by taint (SimX VX_CHECKER_TAINT=1; RTL
// --checker-taint with a shared cache level):
//   - downloads of the images by M, and of J by either owner: poison;
//   - M's copy J -> MOWN: dropped (MOWN's owners do not cover {H});
//   - M's copy J -> J2: lands (same owners);
//   - after H leaves J2, M downloads J2: J's data.
// Without taint the downloads and the copy into MOWN succeed: the control.
// No kernel runs.

#define DCR_CHECKER_BUF_BASE     0x300
#define DCR_CHECKER_BUF_SIZE     0x301
#define DCR_CHECKER_BUF_OWNER    0x302
#define DCR_CHECKER_BUF_PERMS    0x303
#define DCR_CHECKER_BUF_EPOCH    0x304
#define DCR_CHECKER_BUF_COMMIT   0x305
#define DCR_CHECKER_BUF_SHARED   0x307
#define DCR_CHECKER_BUF_JOINT    0x309
#define DCR_CHECKER_BUF_CONFINED 0x30A
#define DCR_CHECKER_BUF_LEAVE    0x30B
#define DCR_CHECKER_BUF_GRANTEE  0x30C

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu
#define POISON_WORD 0xDDDDDDDDu

#define TENANT_H 0
#define TENANT_M 1

#define IMAGE(i) (0x1a000000u | (i))
#define JOINT(i) (0x10000000u | (i))

typedef struct {
	uint32_t unused;
} kernel_arg_t;

#endif
