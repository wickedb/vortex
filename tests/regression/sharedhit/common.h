#ifndef _COMMON_H_
#define _COMMON_H_

// sharedhit — does isolation hold for CONCURRENT tenants that share a cache?
//
// The checker sits at the LLC->DRAM boundary, so it sees only what misses the
// last-level cache. twotenant's two cores touch disjoint 64 B sectors, so a
// cross-core cache hit never happens there. Here both cores touch the SAME
// sectors within one launch. Tenancy as twotenant: owner = core id, `secret`
// claimed for tenant 0, everything else unclaimed.
//
//   mode 0 (read):  every task reads one word in each shared sector, so both
//                   tenants read every shared word.
//   mode 1 (write): in the same sectors, core 0 writes the even words and
//                   core 1 the odd ones, so both tenants' stores land in one
//                   sector.
//
// Cross-core ordering within a launch is uncontrolled, and either order is a
// failure if the shared cache answers without the checker, so the test needs
// no synchronisation. With private caches only (no --l2cache/--l3cache) every
// access reaches the checker and both modes must pass: that is the control.
//
// Run with --cores=2 --checker-enforce, with and without --l2cache --l3cache.

#define SECTOR_WORDS   16u  // 64 B sector
#define SHARED_SECTORS 4u
#define SHARED_WORDS   (SECTOR_WORDS * SHARED_SECTORS)

#define POISON_WORD 0xDDDDDDDDu
#define SECRET(i)  (0x5EC00000u | (uint32_t)(i))  // host-uploaded tenant 0 data
#define MARK_T0(i) (0xA0000000u | (uint32_t)(i))  // tenant 0 writing its own buffer
#define MARK_XT(i) (0xB0000000u | (uint32_t)(i))  // cross-tenant write attempt

typedef struct {
  uint32_t num_points;
  uint32_t mode;
  uint64_t secret_addr;  // tenant 0's buffer (claimed for eid 0)
  uint64_t probe_addr;   // shared: what each task read, SHARED_SECTORS per task (mode 0)
  uint64_t origin_addr;  // shared: the core id each task ran on
} kernel_arg_t;

#endif
