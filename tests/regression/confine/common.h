#ifndef _COMMON_H_
#define _COMMON_H_

// Confinement by taint: SimX proof of concept for
// docs/proposals/kernel_identity_oct16.md (the hospital walk-through).
//
// Tenancy model as in twotenant: one tenant per core. Core 0 is H (the
// hospital, which owns the images); core 1 is M (the model provider). H
// grants M a CONFINED read on the images. M's kernel then trains (reads the
// images, writes a jointly owned output), tries to launder the images into
// buffers H does not co-own, tries to export the joint output before H
// releases it, and exports it again after H leaves the output's owner set.
//
// Run with: VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_TAINT=1, --cores=2.
// Without VX_CHECKER_TAINT the confined bit is ignored, the laundering lands,
// and the test FAILS: that failure is the control result.

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

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2
#define GRANT_NO_EXPIRY 0xFFFFFFFFu

#define TENANT_H 0u   // core 0
#define TENANT_M 1u   // core 1

#define PHASE_TRAIN       0u   // M reads images, writes joint output, tries to launder
#define PHASE_EXPORT_EARLY 1u  // M copies the joint output into its own buffer (before release)
#define PHASE_EXPORT_LATE  2u  // the same, after H has left the output's owner set
#define NUM_PHASES        3u

#define SECRET(i)  (0x5EC00000u | (uint32_t)(i))  // H's images
#define KEY        0x00A5A5A5u                    // "training": out = image ^ KEY

typedef struct {
  uint32_t num_points;
  uint32_t phase;
  uint64_t images_addr;  // H only; confined R grant to M
  uint64_t mown_addr;    // M only: launder target (phase 0), export target (phases 1, 2)
  uint64_t pub_addr;     // unclaimed: second launder target
  uint64_t out_addr;     // owners {M, H}: the agreed output
  uint64_t origin_addr;  // owners {M, H}: the core each task ran on, per phase
} kernel_arg_t;

#endif
