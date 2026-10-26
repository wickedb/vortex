#ifndef _COMMON_H_
#define _COMMON_H_

// residue — the kernel-change scrub (spec T8, T12): what one kernel leaves on
// a core (local memory, its stack) must not reach the next kernel across a
// scrub boundary. Kernel A writes a pattern into its local memory and a stack
// array; kernel B reads the same locations without writing them and counts
// words that still hold A's pattern (B's own start-up code may have used its
// stack, so only A's exact values count as residue).
//
//   default  A, then a clean boundary, then B, both from queue 0: B finds none.
//   -n       no clean boundary: B finds A's values (same tenant, no scrub):
//            the control that the test can see residue at all.
//   -t       B is launched by another tenant (queue 1); needs the tenant from
//            the launching queue (RTL --checker-tenant): B finds none.
//
// The register banks are scrubbed too; this test does not reach them.

#define PAT(i) (0xC0FFE000u | ((i) & 0xFFFu))
#define STACK_WORDS 32

typedef struct {
	uint32_t num_points;
	uint32_t mode;           // 0: A (write), 1: B (read)
	uint64_t lmem_hits_addr; // B: per task, local-memory words holding A's pattern
	uint64_t stack_hits_addr;// B: per task, stack words holding A's pattern
} kernel_arg_t;

#endif
