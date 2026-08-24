#ifndef _COMMON_H_
#define _COMMON_H_

// revoke_window — how much of a grantee's read stream ever reaches the
// enforcement point? (thesis M3: "revocation is unenforceable within a launch")
//
// Nothing here touches the simulator. The whole measurement is made by the
// application, with vx_rdcycle() and the values it reads back, because that is
// all a co-resident tenant has — and all a reviewer will accept.
//
// The claim under test. The checker is spliced into the L3 -> DRAM binding, so
// every level above it is a blind spot: 16 KB L1 per core, 1 MB L2 per
// cluster, 2 MB L3 (the granule the policy is written in is 1 MB, so a whole
// granule fits inside the blind spot with room to spare). A read that hits in
// any of those never becomes a MemReq at the checker, so no policy — grant,
// epoch, owner — is consulted for it. Revocation acts on the miss stream and
// only on the miss stream.
//
// What the application can see:
//   phase 1, grant live: a timed read loop over a working set of -w words.
//     cycles/read at small -w is L1-hit latency, which is the same as saying
//     the reads are not reaching the checker.
//   phase 2, after revocation: the same loop. Every read misses (SimX re-enters
//     ProcessorImpl::run() per launch, and reset() wipes every cache set), so
//     every read meets the checker and comes back poison.
//
// The contrast is the finding. Denial is only ever observed on the miss path,
// at ~10x the cycles/read of the resident case. The design has no primitive
// that forces a hit onto the miss path: in this tree Cache::flush_begin()
// early-exits on write-through caches and processFlush() clears `dirty` but
// never `valid` — a flush writes back, it does not invalidate. And there is no
// application-level way to revoke inside a launch at all: vx_dcr_write wraps
// the same queue, and the ring engine's WaitDone state (cmd_processor.cpp:582)
// blocks until the launch FSM idles, so every revocation the API can express
// lands at a launch boundary — i.e. behind exactly the control-plane
// round-trip that §5 and §8 criticise CC for.
//
// Sweep -w across the L1 knee to read the blind window off the curve.

#define DCR_CHECKER_BUF_BASE   0x300
#define DCR_CHECKER_BUF_SIZE   0x301
#define DCR_CHECKER_BUF_OWNER  0x302
#define DCR_CHECKER_BUF_PERMS  0x303
#define DCR_CHECKER_BUF_EPOCH  0x304
#define DCR_CHECKER_BUF_COMMIT 0x305
#define DCR_CHECKER_EPOCH      0x306
#define DCR_CHECKER_BUF_SHARED 0x307
#define DCR_CHECKER_REVOKE_OWNER 0x308

#define CHECKER_PERM_R 0x1
#define CHECKER_PERM_W 0x2

// The checker's poison fill block is 0xDD bytes (mem_checker.cpp).
#define POISON_WORD 0xDDDDDDDDu

#define SECRET(i)  (0x5EC00000u | (uint32_t)(i))

// 64 B line / 4 B word, i.e. VX_CFG_L1_LINE_SIZE / sizeof(uint32_t). The chase
// visits one word per line so every step is a distinct line, and a denied step
// steps forward by one line rather than restarting — otherwise the chase
// collapses onto the single line the poison came back on and every subsequent
// "denial" the application counts is really a cache hit on that one poisoned
// line. That collapse costs the checker exactly one enforcement event for an
// unbounded number of reads, which is the very effect under test; it must not
// be allowed to masquerade as enforcement working.
#define WORDS_PER_LINE 16

typedef struct {
  uint32_t num_points;   // tasks
  uint32_t ws_words;     // grantee working set, in words
  uint32_t iters;        // timed reads per task
  uint32_t phase;        // 1 = grant live, 2 = after revocation
  uint64_t shared_addr;  // owner-0 buffer, READ-granted to others at epoch 0
  uint64_t cycles_addr;  // per task: cycles spent in the timed loop
  uint64_t poison_addr;  // per task: reads that came back poison
  uint64_t plain_addr;   // per task: reads that came back plaintext
  uint64_t origin_addr;  // per task: core id
} kernel_arg_t;

#endif
