// VX_mem_checker directed testbench (RTL_PLAN.md §5, R1).
//
// Each case is one of the properties the SimX prototype had to get right, and
// several of them took more than one attempt there — see PROJECT.md §10's
// closed list. Verifying them here, standalone, is cheaper than discovering a
// divergence during R4 parity against a whole GPU.
//
// What this CANNOT check, and why it is not a gap in R1:
//   * Correct identity attribution through a write-back cache (§2.3). Identity
//     arrives here on a port the TB drives, so the TB can always make it
//     right. The real property — that a WRITEBACK carries the id of whoever
//     dirtied the line, not whoever evicted it — lives in the cache and is
//     R2's. That is also the property whose absence produced 992/1024 errors
//     in SimX *with identical counters to a correct run*, which is why R2's
//     gate is a per-word value check and never a deny count.
//   * Enforcement. R1 reports a deny; poison injection and the response mux
//     are R3.

#include "vl_simulator.h"
#include "VVX_mem_checker_top.h"
#include <VX_types.h>
#include <cstdio>
#include <cstdint>
#include <vector>

#define MAX_TICKS 20000

static uint64_t timestamp = 0;
double sc_time_stamp() { return timestamp; }

using Device = VVX_mem_checker_top;
static vl_simulator<Device> sim;
static int errors = 0;
static int checks = 0;

// Must match VX_CFG_CHECKER_BUF_LOG2 / the generated config.
static constexpr uint32_t BUF_LOG2 = 20;
static constexpr uint64_t GRANULE  = 1ull << BUF_LOG2;

static void expect(bool ok, const char* what) {
  ++checks;
  if (!ok) {
    std::printf("*** FAIL: %s\n", what);
    ++errors;
  }
}

static void tick(uint32_t n = 1) { timestamp = sim.step(timestamp, 2 * n); }

// One DCR write. Held for a cycle, like the real bus (fire-and-forget, no ready).
static void dcr(uint32_t addr, uint32_t data) {
  sim->dcr_wr_valid = 1;
  sim->dcr_wr_addr  = addr;
  sim->dcr_wr_data  = data;
  tick();
  sim->dcr_wr_valid = 0;
  tick();
}

// The 7-write staged claim, exactly as the host issues it.
static void claim(uint64_t base, uint64_t size, uint32_t owner,
                  uint32_t perms, uint32_t shared, uint32_t epoch) {
  dcr(VX_DCR_CHECKER_BUF_BASE,   (uint32_t)base);
  dcr(VX_DCR_CHECKER_BUF_SIZE,   (uint32_t)size);
  dcr(VX_DCR_CHECKER_BUF_OWNER,  owner);
  dcr(VX_DCR_CHECKER_BUF_PERMS,  perms);
  dcr(VX_DCR_CHECKER_BUF_SHARED, shared);
  dcr(VX_DCR_CHECKER_BUF_EPOCH,  epoch);
  dcr(VX_DCR_CHECKER_BUF_COMMIT, 1);
  // The installer walks the granule range over several cycles; let it drain.
  for (int i = 0; i < 64 && sim->req_ready == 0; ++i) tick();
  tick(4);
}

// The 2-write scoped revoke. No header is touched.
static void revoke(uint32_t owner, uint32_t new_epoch) {
  dcr(VX_DCR_CHECKER_REVOKE_OWNER, owner);
  dcr(VX_DCR_CHECKER_EPOCH,        new_epoch);
  tick(2);
}

// Present one request and hold it until the checker accepts it.
static void accept(uint64_t addr, bool is_write, uint32_t owner) {
  sim->req_valid = 1;
  sim->req_rw    = is_write ? 1 : 0;
  sim->req_addr  = (uint32_t)addr;
  sim->req_owner = owner;
  int guard = 0;
  while (!sim->req_ready && guard++ < 128) tick();
  tick();
}

// Wait for the accepted request to retire and return whether it was denied.
// Under enforcement a denied request never reaches out_valid — it is blocked —
// so a denial is observable only as the out_fault pulse. Watch for either.
static bool verdict() {
  int guard = 0;
  bool denied = false;
  while (guard++ < 128) {
    if (sim->out_fault) { denied = true; break; }
    if (sim->out_valid) { denied = (sim->out_deny != 0); break; }
    tick();
  }
  tick();
  return denied;
}

// Drive one request through and return whether it was denied.
static bool access(uint64_t addr, bool is_write, uint32_t owner) {
  sim->out_ready = 1;
  accept(addr, is_write, owner);
  sim->req_valid = 0;
  return verdict();
}

int main(int argc, char** argv) {
  Verilated::commandArgs(argc, argv);
  timestamp = sim.reset(0);
  sim->out_ready = 1;
  tick(4);

  const uint64_t A = 4 * GRANULE;    // owner 0's buffer
  const uint64_t B = 8 * GRANULE;    // owner 1's buffer

  // ---- 1. boot default: unclaimed memory is system/shared (fail-open, §10 m3)
  expect(!access(A, false, 0), "unclaimed read allowed (boot default OWNER_ANY)");
  expect(!access(A, true,  1), "unclaimed write allowed by any owner");

  // ---- 2. owner access, and it is never epoch-gated
  claim(A, GRANULE, /*owner*/0, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W,
        /*shared*/0, VX_CHECKER_GRANT_NO_EXPIRY);
  expect(!access(A, false, 0), "owner read allowed");
  expect(!access(A, true,  0), "owner write allowed");

  // ---- 3. cross-tenant isolation: no grant means no access
  expect(access(A, false, 1), "non-owner read DENIED with no grant");
  expect(access(A, true,  1), "non-owner write DENIED with no grant");

  // ---- 4. the grant, and that shared_perms is honoured per-direction
  claim(A, GRANULE, 0, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W,
        /*shared*/VX_CHECKER_PERM_R, /*grant_epoch*/0);
  expect(!access(A, false, 1), "grantee read allowed under the grant");
  expect(access(A, true, 1),   "grantee write DENIED (grant is read-only)");
  expect(!access(A, true, 0),  "owner write still allowed while granted");

  // ---- 5. revocation expires the grant, and does not evict the owner
  revoke(0, 1);
  expect(access(A, false, 1),  "grantee read DENIED after revoke");
  expect(!access(A, false, 0), "owner read still allowed after revoke");
  expect(!access(A, true,  0), "owner write still allowed after revoke");

  // ---- 6. monotonicity: revocation cannot be reversed (§10 #2)
  // A write that does not strictly increase the epoch must be ignored, or
  // writing an earlier value back would un-revoke.
  revoke(0, 0);
  expect(access(A, false, 1), "revoke is irreversible (epoch 0 write ignored)");

  // ---- 7. scoped revocation: owner 1's grant survives owner 0's revoke (§10 #1)
  // The bug this guards: one global epoch counter meant any revocation expired
  // every outstanding grant at once.
  claim(B, GRANULE, /*owner*/1, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W,
        /*shared*/VX_CHECKER_PERM_R, /*grant_epoch*/0);
  expect(!access(B, false, 0), "owner 1's grant to owner 0 is live");
  revoke(0, 2);                                     // bump owner 0 again
  expect(!access(B, false, 0), "owner 0's revoke did NOT touch owner 1's grant");

  // ---- 8. a bare EPOCH write with nothing staged is a no-op (fails closed)
  dcr(VX_DCR_CHECKER_REVOKE_OWNER, VX_CHECKER_OWNER_ANY);
  dcr(VX_DCR_CHECKER_EPOCH, 99);
  tick(2);
  expect(!access(B, false, 0), "unstaged EPOCH write is a no-op, grant intact");

  // ---- 9. granule exclusivity: a cross-owner claim is refused WHOLE (§10 #4a)
  // This is the invariant the per-sector writer tag depends on: one writer id
  // per sector is sufficient only because two owners can never share a granule.
  uint32_t rej_before = sim->cnt_rejected;
  claim(A, GRANULE, /*owner*/1, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W, 0,
        VX_CHECKER_GRANT_NO_EXPIRY);
  expect(sim->cnt_rejected == rej_before + 1, "cross-owner claim rejected");
  // and the victim's policy must be untouched by the refusal
  expect(!access(A, false, 0), "owner 0 still owns A after the refused claim");
  expect(access(A, false, 1),  "owner 1 gained nothing from the refused claim");

  // ---- 10. re-claim by the same owner is legal and counted, not rejected
  uint32_t rec_before = sim->cnt_reclaimed;
  uint32_t rej2       = sim->cnt_rejected;
  claim(A, GRANULE, 0, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W,
        VX_CHECKER_PERM_R, /*grant_epoch*/5);
  expect(sim->cnt_rejected == rej2, "same-owner re-claim NOT rejected");
  expect(sim->cnt_reclaimed > rec_before, "same-owner re-claim counted");
  // the re-grant is live again because grant_epoch now exceeds owner 0's epoch
  expect(!access(A, false, 1), "re-grant at a fresh epoch is live");

  // ---- 11. IO traffic is bypassed, never gated.
  // Driven by a real IO-aperture ADDRESS, not a flag: the checker decodes the
  // classification itself rather than trusting an attr bit that travelled
  // through the cache hierarchy (a writeback inherits its evictor's attr, and
  // a request misclassified as IO would skip the check entirely).
  const uint64_t IO_ADDR = VX_MEM_IO_BASE_ADDR + 0x40;   // inside [BASE, END)
  uint32_t byp_before = sim->cnt_bypassed;
  expect(!access(IO_ADDR, true, 1), "IO write bypassed, not denied");
  expect(sim->cnt_bypassed == byp_before + 1, "bypass counted");
  // ...and a device-memory address in the same run still goes through the
  // policy path. Asserting on `checked` rather than on a deny: A's re-grant
  // from case 10 is live for owner 1, so the right outcome here is ALLOWED —
  // what matters is that it was classified as checkable, unlike the IO access.
  uint32_t chk_before = sim->cnt_checked;
  (void)access(A, false, 1);
  expect(sim->cnt_checked == chk_before + 1, "device address is checked, not bypassed");

  // ---- 12. a multi-granule claim covers every granule it spans
  const uint64_t C = 16 * GRANULE;
  claim(C, 3 * GRANULE, /*owner*/0, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W, 0,
        VX_CHECKER_GRANT_NO_EXPIRY);
  expect(access(C + 0 * GRANULE, false, 1), "multi-granule claim: granule 0 protected");
  expect(access(C + 1 * GRANULE, false, 1), "multi-granule claim: granule 1 protected");
  expect(access(C + 2 * GRANULE, false, 1), "multi-granule claim: granule 2 protected");

  // ---- 13/14. the verdict belongs to the request in S1, not to the bus.
  // Every case above holds req_addr steady until retirement, which the LLC
  // does not: its request queue moves on while S1 is held. These change the
  // bus address mid-resolution, toward the opposite verdict each time.

  // 13. held by miss latency: a fresh granule forces a header-cache miss, and
  // meanwhile the bus shows B, where owner 1 IS allowed.
  const uint64_t D = 24 * GRANULE;
  claim(D, GRANULE, /*owner*/0, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W, 0,
        VX_CHECKER_GRANT_NO_EXPIRY);
  sim->out_ready = 1;
  uint32_t miss_before = sim->cnt_hc_misses;
  accept(D, false, 1);
  sim->req_valid = 0;
  sim->req_addr  = (uint32_t)B;
  expect(sim->cnt_hc_misses == miss_before + 1, "case 13 takes the miss-latency path");
  expect(verdict(), "verdict held across miss latency: D denied while bus shows B");

  // 14. held by back-pressure: an allowed request waits in S1 while the next
  // request, to a granule owner 1 may NOT read, waits on the bus behind it.
  sim->out_ready = 0;
  accept(B, false, 1);
  sim->req_addr = (uint32_t)C;               // req_valid stays 1: queued behind
  int guard = 0;
  while (!sim->out_valid && !sim->out_fault && guard++ < 128) tick();
  bool held = true;
  for (int i = 0; i < 8; ++i) {
    if (sim->out_fault || !sim->out_valid || sim->out_addr != (uint32_t)B) held = false;
    tick();
  }
  expect(held, "held request keeps its verdict and address under back-pressure");
  expect(sim->out_valid && !sim->out_deny, "held request to B retires ALLOWED");
  sim->out_ready = 1;
  tick();                                    // B retires; C is accepted on the same edge
  sim->req_valid = 0;
  expect(verdict(), "request queued behind it (C) is DENIED");

  // ---- counter sanity: every checked request was either allowed or denied
  expect(sim->cnt_checked == sim->cnt_allows + sim->cnt_denies,
         "checked == allows + denies");
  expect(sim->cnt_reqs == sim->cnt_checked + sim->cnt_bypassed,
         "reqs == checked + bypassed");
  expect(sim->cnt_aliased == 0,
         "no aliased claims at the design point (TAG_W=0, collision impossible)");

  std::printf("\ncounters: reqs=%u checked=%u bypassed=%u allow=%u deny=%u\n",
              (unsigned)sim->cnt_reqs, (unsigned)sim->cnt_checked,
              (unsigned)sim->cnt_bypassed, (unsigned)sim->cnt_allows,
              (unsigned)sim->cnt_denies);
  std::printf("hcache  : hits=%u misses=%u\n",
              (unsigned)sim->cnt_hc_hits, (unsigned)sim->cnt_hc_misses);
  std::printf("setup   : claims=%u written=%u bumps=%u rejected=%u aliased=%u reclaimed=%u\n",
              (unsigned)sim->cnt_claims, (unsigned)sim->cnt_headers_written,
              (unsigned)sim->cnt_epoch_bumps, (unsigned)sim->cnt_rejected,
              (unsigned)sim->cnt_aliased, (unsigned)sim->cnt_reclaimed);

  if (errors) {
    std::printf("\n%d/%d checks FAILED\n", errors, checks);
    return 1;
  }
  std::printf("\nPASSED! (%d checks)\n", checks);
  return 0;
}
