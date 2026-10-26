#ifndef _COMMON_H_
#define _COMMON_H_

// Authorship regression (P1_and_taint_specv2.md D1-D4). Two tenants, each
// with its own command-processor queue: tenant t is hardware queue t and runs
// on core t. Each mode stages one attack by tenant 1 on tenant 0 through the
// setup path, and checks by value that it changed nothing:
//
//   -m0  foreign setup: tenant 1 re-claims tenant 0's buffer *as owner 0*
//        with a read grant to every non-owner, and tries to revoke tenant 0's
//        grant on a second buffer. Before authorship both worked: the first
//        is a same-owner re-claim, the second a REVOKE_OWNER/EPOCH pair.
//   -m1  staging interleave: tenant 1 stages and commits its own claim
//        between tenant 0's staging and tenant 0's COMMIT. With shared
//        staging registers tenant 0's COMMIT installed tenant 1's range.
//   -m2  launch hijack: tenant 1 rewrites the kernel-argument register
//        between tenant 0's launches. With global launch registers tenant
//        0's next launch ran on tenant 1's arguments.
//
// Run with: VX_CHECKER=1 VX_CHECKER_ENFORCE=1 and --cores=2.

// Checker DCR registers — mirror of sim/simx/sec/mem_checker.h.
#define DCR_CHECKER_BUF_BASE   0x300
#define DCR_CHECKER_BUF_SIZE   0x301
#define DCR_CHECKER_BUF_OWNER  0x302
#define DCR_CHECKER_BUF_PERMS  0x303
#define DCR_CHECKER_BUF_EPOCH  0x304
#define DCR_CHECKER_BUF_COMMIT 0x305
#define DCR_CHECKER_EPOCH      0x306
#define DCR_CHECKER_BUF_SHARED 0x307
#define DCR_CHECKER_REVOKE_OWNER 0x308
// Header v2: a grant names the one tenant it is for; in these two-tenant
// tests that is always the other tenant.
#define DCR_CHECKER_BUF_GRANTEE 0x30C

// KMU launch registers — mirror of VX_types.toml.
#define DCR_KMU_STARTUP_ARG0   0x014
#define DCR_KMU_STARTUP_ARG1   0x015

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu

// The checker's poison fill block is 0xDD bytes (mem_checker.cpp).
#define POISON_WORD 0xDDDDDDDDu

#define SECRET(i)  (0x5EC00000u | (uint32_t)(i))  // tenant 0's private data
#define GRANTED(i) (0x6A000000u | (uint32_t)(i))  // tenant 0's data shared by grant
#define MARK_T0(i) (0xA0000000u | (uint32_t)(i))  // core 0 writing tenant 1's buffer
#define MARK_T1(i) (0xC0000000u | (uint32_t)(i))  // core 1 writing its own buffer

#define MODE_FOREIGN    0
#define MODE_INTERLEAVE 1
#define MODE_HIJACK     2

typedef struct {
  uint32_t num_points;
  uint32_t mode;
  uint64_t secret_addr;  // tenant 0's private buffer
  uint64_t grant_addr;   // tenant 0's buffer granted R to non-owners (-m0)
  uint64_t t1_addr;      // tenant 1's own buffer (-m1)
  uint64_t probe_addr;   // shared: what each task read from secret[idx]
  uint64_t probe2_addr;  // shared: what each task read from grant[idx]
  uint64_t origin_addr;  // shared: the core id each task ran on
  uint64_t count_addr;   // shared: launches that ran with these arguments (-m2)
} kernel_arg_t;

#endif
