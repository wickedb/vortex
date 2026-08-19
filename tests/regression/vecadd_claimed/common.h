#ifndef _COMMON_H_
#define _COMMON_H_

// vecadd_claimed — vecadd with its buffers claimed over the checker's DCR
// setup path (fable.md's "positive half"): the kernel argument struct and
// TYPE must stay byte-identical to tests/regression/vecadd/common.h because
// this app runs vecadd's own kernel.cpp unmodified.

#ifndef TYPE
#define TYPE float
#endif

typedef struct {
  uint32_t num_points;
  uint64_t src0_addr;
  uint64_t src1_addr;
  uint64_t dst_addr;
} kernel_arg_t;

// Checker DCR registers — mirror of sim/simx/sec/mem_checker.h.
#define DCR_CHECKER_BUF_BASE   0x300
#define DCR_CHECKER_BUF_SIZE   0x301
#define DCR_CHECKER_BUF_OWNER  0x302
#define DCR_CHECKER_BUF_PERMS  0x303
#define DCR_CHECKER_BUF_EPOCH  0x304
#define DCR_CHECKER_BUF_COMMIT 0x305
#define DCR_CHECKER_BUF_SHARED 0x307

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu

#endif
