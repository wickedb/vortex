#ifndef _COMMON_H_
#define _COMMON_H_

// fetchx — header v2's X bit (spec T9, review issue 6). The granule holding
// the kernel's code is claimed for tenant 0, the only tenant here (one core):
//
//   -m0  claimed R|W|X: every fetch is allowed; the run passes with no denies.
//   -m1  claimed R|W:   every fetch from it is denied. Run this mode with the
//        checker NOT enforcing: denied fetches are then counted and still
//        delivered, so the kernel completes and the gate checks the deny
//        count. Enforced, the core would execute poison.
//
// A fetch is judged against X, never R: -m1 denies even though the owner
// holds R. Mirror of the checker DCR registers in VX_types.toml.

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
#define CHECKER_PERM_X 0x4
#define GRANT_NO_EXPIRY 0xFFFFFFFFu

#define VALUE(i) (0x0f000000u | ((i) * 3u))

typedef struct {
	uint32_t num_points;
	uint64_t dst_addr;
} kernel_arg_t;

#endif
