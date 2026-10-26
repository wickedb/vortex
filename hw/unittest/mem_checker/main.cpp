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
#include <VX_config.h>
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

// One DCR write from `issuer`, the command queue (tenant) it came from. Held
// for a cycle, like the real bus (fire-and-forget, no ready).
static void dcr(uint32_t addr, uint32_t data, uint32_t issuer) {
  sim->dcr_wr_valid  = 1;
  sim->dcr_wr_addr   = addr;
  sim->dcr_wr_data   = data;
  sim->dcr_wr_issuer = issuer;
  tick();
  sim->dcr_wr_valid = 0;
  tick();
}

// Stage a claim from `issuer` without committing it. Header v2: a grant names
// its grantee, by default the other of tenants 0 and 1; `joint` adds
// co-owners.
static void stage(uint64_t base, uint64_t size, uint32_t owner, uint32_t perms,
                  uint32_t shared, uint32_t epoch, uint32_t issuer,
                  int grantee = -1, uint32_t joint = 0) {
  dcr(VX_DCR_CHECKER_BUF_BASE,    (uint32_t)base, issuer);
  dcr(VX_DCR_CHECKER_BUF_SIZE,    (uint32_t)size, issuer);
  dcr(VX_DCR_CHECKER_BUF_OWNER,   owner,          issuer);
  dcr(VX_DCR_CHECKER_BUF_PERMS,   perms,          issuer);
  dcr(VX_DCR_CHECKER_BUF_SHARED,  shared,         issuer);
  dcr(VX_DCR_CHECKER_BUF_EPOCH,   epoch,          issuer);
  dcr(VX_DCR_CHECKER_BUF_GRANTEE, (grantee < 0) ? (owner ^ 1u) : uint32_t(grantee), issuer);
  dcr(VX_DCR_CHECKER_BUF_JOINT,   joint,          issuer);
}

static void commit(uint32_t issuer) {
  dcr(VX_DCR_CHECKER_BUF_COMMIT, 1, issuer);
  // The installer walks the granule range over several cycles; let it drain.
  for (int i = 0; i < 64 && sim->req_ready == 0; ++i) tick();
  tick(4);
}

// The 7-write staged claim, exactly as the host issues it, from the owner's
// own queue unless `issuer` says otherwise.
static void claim(uint64_t base, uint64_t size, uint32_t owner,
                  uint32_t perms, uint32_t shared, uint32_t epoch,
                  int issuer = -1, int grantee = -1, uint32_t joint = 0) {
  const uint32_t iss = (issuer < 0) ? owner : uint32_t(issuer);
  stage(base, size, owner, perms, shared, epoch, iss, grantee, joint);
  commit(iss);
}

// Release (S2): `eid` leaves the range, written from queue `issuer`.
static void leave(uint64_t base, uint64_t size, uint32_t eid, int issuer = -1) {
  const uint32_t iss = (issuer < 0) ? eid : uint32_t(issuer);
  dcr(VX_DCR_CHECKER_BUF_BASE,  (uint32_t)base, iss);
  dcr(VX_DCR_CHECKER_BUF_SIZE,  (uint32_t)size, iss);
  dcr(VX_DCR_CHECKER_BUF_LEAVE, eid,            iss);
  for (int i = 0; i < 64 && sim->req_ready == 0; ++i) tick();
  tick(4);
}

// The scoped revoke: one EPOCH write from the owner's queue. No header is
// touched. REVOKE_OWNER is retired; writing it (with any value) is ignored.
static void revoke(uint32_t owner, uint32_t new_epoch, int issuer = -1) {
  const uint32_t iss = (issuer < 0) ? owner : uint32_t(issuer);
  dcr(VX_DCR_CHECKER_REVOKE_OWNER, owner, iss);
  dcr(VX_DCR_CHECKER_EPOCH,        new_epoch, iss);
  tick(2);
}

// Present one request and hold it until the checker accepts it.
static void accept(uint64_t addr, bool is_write, uint32_t owner, bool fetch = false) {
  sim->req_valid = 1;
  sim->req_rw    = is_write ? 1 : 0;
  sim->req_addr  = (uint32_t)addr;
  sim->req_owner = owner;
  sim->req_fetch = fetch ? 1 : 0;
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
static bool access(uint64_t addr, bool is_write, uint32_t owner, bool fetch = false) {
  sim->out_ready = 1;
  accept(addr, is_write, owner, fetch);
  sim->req_valid = 0;
  return verdict();
}

int main(int argc, char** argv) {
  Verilated::commandArgs(argc, argv);
  timestamp = sim.reset(0);
  sim->out_ready = 1;
  // Drain the poison responses: the fault queue holds FAULT_DEPTH of them.
  sim->rsp_ready = 1;
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

  // ---- 8. an EPOCH write from another tenant's queue advances only that
  //      tenant's epoch. REVOKE_OWNER is retired: naming owner 1 there changes
  //      nothing.
  {
    const uint32_t bumps = sim->cnt_epoch_bumps;
    dcr(VX_DCR_CHECKER_REVOKE_OWNER, /*owner*/1, /*issuer*/3);
    dcr(VX_DCR_CHECKER_EPOCH, 99, /*issuer*/3);
    tick(2);
    expect(sim->cnt_epoch_bumps == bumps + 1, "EPOCH from tenant 3 bumps tenant 3's own epoch");
    expect(!access(B, false, 0), "tenant 3's EPOCH leaves owner 1's grant intact");
  }

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

  // 13. held by lookup latency (the Makefile builds this TB with 4 cycles):
  // meanwhile the bus shows B, where owner 1 IS allowed.
  const uint64_t D = 24 * GRANULE;
  claim(D, GRANULE, /*owner*/0, VX_CHECKER_PERM_R | VX_CHECKER_PERM_W, 0,
        VX_CHECKER_GRANT_NO_EXPIRY);
  sim->out_ready = 1;
  accept(D, false, 1);
  sim->req_valid = 0;
  sim->req_addr  = (uint32_t)B;
  expect(verdict(), "verdict held across lookup latency: D denied while bus shows B");

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

  // ---- Authorship (P1_and_taint_specv2.md D1-D3) ----
  // A tenant claims only for itself, stages into its own registers, and
  // revokes only its own grants.
  {
    const uint32_t RW = VX_CHECKER_PERM_R | VX_CHECKER_PERM_W;
    const uint64_t E = 32 * GRANULE;   // owner 0's, private
    const uint64_t F = 36 * GRANULE;   // owner 0's, granted R to non-owners
    const uint64_t G = 40 * GRANULE;
    const uint64_t H = 44 * GRANULE;
    const uint32_t foreign0 = sim->cnt_foreign;

    claim(E, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY);
    expect(access(E, false, 1), "auth: owner 1 denied owner 0's private buffer");

    // A1. Owner 1 re-claims E *as owner 0*, opening it to non-owners.
    claim(E, GRANULE, /*owner*/0, RW, VX_CHECKER_PERM_R, VX_CHECKER_GRANT_NO_EXPIRY, /*issuer*/1);
    expect(sim->cnt_foreign == foreign0 + 1, "auth: a claim naming another owner is counted foreign");
    expect(access(E, false, 1), "auth: the foreign re-grant installed nothing");
    expect(!access(E, false, 0), "auth: owner 0 keeps its access");

    // A2. A claim for OWNER_ANY (everyone) is foreign too.
    claim(G, GRANULE, VX_CHECKER_OWNER_ANY, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, /*issuer*/0);
    expect(sim->cnt_foreign == foreign0 + 2, "auth: an OWNER_ANY claim is foreign");

    // A3. Header v2: tenants are not cores. Tenant 3 (no core in a 2-core
    //     build) claims for itself, and its id does not truncate onto
    //     another owner's.
    {
      const uint64_t G3 = 72 * GRANULE;
      claim(G3, GRANULE, /*owner*/3, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, /*issuer*/3);
      expect(sim->cnt_foreign == foreign0 + 2, "auth: tenant 3's own claim is not foreign");
      expect(!access(G3, false, 3), "auth: tenant 3 reads its own G3");
      expect(access(G3, false, 1),  "auth: tenant 1 denied tenant 3's G3");
      expect(!access(G, false, 1),  "auth: G stayed unclaimed");
    }

    // A4. Staging is per issuer: owner 1 stages and commits H between owner
    //     0's staging of G and owner 0's commit.
    stage(G, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, 0);
    claim(H, GRANULE, 1, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, 1);
    commit(0);
    expect(access(G, false, 1),  "auth: owner 0's interleaved claim landed on G");
    expect(!access(G, false, 0), "auth: G is owner 0's");
    expect(access(H, false, 0),  "auth: H is owner 1's");
    expect(!access(H, false, 1), "auth: owner 1 owns H");

    // A4b. Back-to-back COMMITs from two tenants, two cycles apart, each
    //      followed at once by a staging write that must not alter the claim
    //      it already committed. The DCR bus cannot stall, so the second
    //      COMMIT arrives while the first claim is installing.
    {
      const uint64_t I = 48 * GRANULE, J = 52 * GRANULE, K = 56 * GRANULE;
      stage(I, GRANULE, 1, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, 1);
      stage(J, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, 0);
      dcr(VX_DCR_CHECKER_BUF_COMMIT, 1, 1);
      dcr(VX_DCR_CHECKER_BUF_BASE, (uint32_t)K, 1);   // after its commit: must not move I
      dcr(VX_DCR_CHECKER_BUF_COMMIT, 1, 0);
      dcr(VX_DCR_CHECKER_BUF_BASE, (uint32_t)K, 0);   // likewise for J
      for (int i = 0; i < 256 && sim->req_ready == 0; ++i) tick();
      tick(4);
      expect(access(I, false, 0),  "auth: back-to-back COMMIT: I landed as owner 1's");
      expect(!access(I, false, 1), "auth: back-to-back COMMIT: owner 1 owns I");
      expect(access(J, false, 1),  "auth: back-to-back COMMIT: J landed as owner 0's");
      expect(!access(J, false, 0), "auth: back-to-back COMMIT: owner 0 owns J");
      expect(!access(K, false, 1) && !access(K, false, 0),
             "auth: a staging write after COMMIT did not retarget the claim");
    }

    // A5. Owner 1 cannot revoke owner 0's grant: an EPOCH write advances the
    //     issuer's own epoch, whatever REVOKE_OWNER says.
    claim(F, GRANULE, 0, RW, VX_CHECKER_PERM_R, /*grant_epoch*/100);
    expect(!access(F, false, 1), "auth: owner 0's grant to non-owners is live");
    revoke(/*owner*/0, 200, /*issuer*/1);
    expect(!access(F, false, 1), "auth: owner 1 could not revoke owner 0's grant");
    revoke(0, 200);
    expect(access(F, false, 1),  "auth: owner 0 revokes its own grant");
  }

  // ---- D7: a tenant that has claimed nothing owns nothing ----
  // A CP queue reaches the checker as its tenant id. Tenant 2 has no core in
  // a 2-core build; it must not truncate onto owner 0's id.
  {
    const uint32_t RW = VX_CHECKER_PERM_R | VX_CHECKER_PERM_W;
    const uint64_t L = 60 * GRANULE;   // owner 0's, private
    const uint64_t M = 64 * GRANULE;   // owner 0's, granted R to tenant 1
    const uint64_t N = 68 * GRANULE;   // unclaimed
    claim(L, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY);
    claim(M, GRANULE, 0, RW, VX_CHECKER_PERM_R, VX_CHECKER_GRANT_NO_EXPIRY);
    expect(!access(L, false, 0), "t2: owner 0 reads its own L (control)");
    expect(access(L, false, 2),  "t2: tenant 2 DENIED owner 0's L read");
    expect(access(L, true,  2),  "t2: tenant 2 DENIED owner 0's L write");
    expect(!access(M, false, 1), "t2: tenant 1 holds the grant on M");
    expect(access(M, false, 2),  "t2: the grant names tenant 1, not tenant 2");
    expect(!access(N, false, 2) && !access(N, true, 2),
           "t2: unclaimed memory follows the default perms");
  }

  // ---- Header v2 (T2, T6, T9, S1, S2, S4) ----
  {
    const uint32_t RW  = VX_CHECKER_PERM_R | VX_CHECKER_PERM_W;
    const uint32_t RWX = RW | VX_CHECKER_PERM_X;
    const uint64_t P = 76 * GRANULE;   // owner 0, RW: data, not code
    const uint64_t Q = 80 * GRANULE;   // owner 0, RWX
    const uint64_t J = 84 * GRANULE;   // joint {0, 1}
    const uint64_t K = 88 * GRANULE;   // owner 0 alone
    const uint64_t T = 92 * GRANULE;   // owner 0, R granted to tenant 2

    // V1. X: a fetch needs X. Unclaimed memory is fetchable (default perms).
    claim(P, GRANULE, 0, RW,  0, VX_CHECKER_GRANT_NO_EXPIRY);
    claim(Q, GRANULE, 0, RWX, 0, VX_CHECKER_GRANT_NO_EXPIRY);
    expect(access(P, false, 0, /*fetch*/true),  "v2: owner's fetch from an RW granule DENIED");
    expect(!access(P, false, 0),                "v2: owner's read of the same granule allowed");
    expect(!access(Q, false, 0, /*fetch*/true), "v2: owner's fetch from an RWX granule allowed");
    expect(!access(68 * GRANULE, false, 1, /*fetch*/true), "v2: fetch from unclaimed memory allowed");

    // V2. A joint claim: both owners have the owner perms, nobody else does.
    const uint32_t rej0 = sim->cnt_rejected;
    claim(J, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, -1, -1, /*joint*/0x2);
    expect(!access(J, false, 0) && !access(J, true, 0), "v2: joint owner 0 reads and writes J");
    expect(!access(J, false, 1) && !access(J, true, 1), "v2: joint owner 1 reads and writes J");
    expect(access(J, false, 2), "v2: tenant 2 DENIED the joint granule");

    // V3. S4: a joint claim carries no grant; refused whole.
    claim(96 * GRANULE, GRANULE, 0, RW, VX_CHECKER_PERM_R, VX_CHECKER_GRANT_NO_EXPIRY, -1, 2, 0x2);
    expect(sim->cnt_rejected == rej0 + 1, "v2: a grant on a joint claim is refused");
    expect(!access(96 * GRANULE, true, 2), "v2: ...and the granule stayed unclaimed");

    // V4. T6: no re-claim changes an owner set. Owner 0 re-claiming J alone
    //     would drop owner 1; owner 0 adding owner 1 to K would add one.
    claim(J, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY);
    expect(sim->cnt_rejected == rej0 + 2, "v2: re-claim of a joint granule refused");
    expect(!access(J, false, 1), "v2: owner 1 still co-owns J");
    claim(K, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY);
    claim(K, GRANULE, 0, RW, 0, VX_CHECKER_GRANT_NO_EXPIRY, -1, -1, 0x2);
    expect(sim->cnt_rejected == rej0 + 3, "v2: re-claim adding a co-owner refused");
    expect(access(K, false, 1), "v2: K stayed owner 0's alone");

    // V5. S2: only an owner removes itself, and one owner must remain.
    const uint32_t lv0 = sim->cnt_leaves, lr0 = sim->cnt_leaves_refused;
    leave(J, GRANULE, /*eid*/0, /*issuer*/1);
    expect(sim->cnt_leaves_refused == lr0 + 1, "v2: a leave naming another tenant refused");
    expect(!access(J, false, 0), "v2: ...owner 0 still owns J");
    leave(J, GRANULE, /*eid*/0);
    expect(sim->cnt_leaves == lv0 + 1, "v2: owner 0 leaves J");
    expect(access(J, false, 0),  "v2: after leaving, owner 0 DENIED J");
    expect(!access(J, true, 1),  "v2: owner 1 keeps J");
    leave(J, GRANULE, /*eid*/1);
    expect(sim->cnt_leaves_refused == lr0 + 2, "v2: the last owner cannot leave");
    expect(!access(J, false, 1), "v2: ...owner 1 still owns J");
    leave(K, GRANULE, /*eid*/1);
    expect(sim->cnt_leaves_refused == lr0 + 3, "v2: a non-owner cannot leave");

    // V6. A grant names its grantee.
    claim(T, GRANULE, 0, RW, VX_CHECKER_PERM_R, VX_CHECKER_GRANT_NO_EXPIRY, -1, /*grantee*/2);
    expect(!access(T, false, 2), "v2: grantee 2 reads T");
    expect(access(T, true, 2),   "v2: the grant is read-only");
    expect(access(T, false, 1),  "v2: tenant 1, not the grantee, DENIED");
  }

  // ---- T12: the stack slices, by address ----
  // Hart h's stack is the 8 KB below VX_MEM_STACK_BASE_ADDR - h * 8 KB; core
  // c owns harts [c * WARPS * THREADS, (c+1) * WARPS * THREADS). A claim on
  // the region changes nothing: the slice rule decides by address.
  {
    const uint64_t top   = VX_MEM_STACK_BASE_ADDR;
    const uint64_t slice = uint64_t(1) << VX_MEM_STACK_LOG2_SIZE;
    const uint64_t harts_per_core = uint64_t(VX_CFG_NUM_WARPS) * VX_CFG_NUM_THREADS;
    const uint64_t s0 = top - 1 * slice;                       // hart 0: core 0
    const uint64_t s1 = top - (harts_per_core + 1) * slice;    // core 1's first hart
    expect(!access(s0, false, 0) && !access(s0, true, 0), "t12: core 0 reads and writes its own slice");
    expect(access(s0, false, 1), "t12: core 1 DENIED core 0's slice (read)");
    expect(access(s0, true, 1),  "t12: core 1 DENIED core 0's slice (write)");
    expect(!access(s1, true, 1), "t12: core 1 writes its own slice");
    expect(access(s1, false, 1, /*fetch*/true), "t12: no fetch from a stack slice");
    expect(access(s0, false, 2), "t12: a tenant with no core DENIED every slice");
    const uint64_t below = top - (2 * harts_per_core + 1) * slice;   // outside the region
    expect(!access(below, true, 1), "t12: below the region, the label decides (unclaimed)");
  }

  std::printf("\ncounters: reqs=%u checked=%u bypassed=%u allow=%u deny=%u\n",
              (unsigned)sim->cnt_reqs, (unsigned)sim->cnt_checked,
              (unsigned)sim->cnt_bypassed, (unsigned)sim->cnt_allows,
              (unsigned)sim->cnt_denies);
  std::printf("setup   : claims=%u written=%u bumps=%u rejected=%u aliased=%u reclaimed=%u foreign=%u leaves=%u/%u refused\n",
              (unsigned)sim->cnt_claims, (unsigned)sim->cnt_headers_written,
              (unsigned)sim->cnt_epoch_bumps, (unsigned)sim->cnt_rejected,
              (unsigned)sim->cnt_aliased, (unsigned)sim->cnt_reclaimed,
              (unsigned)sim->cnt_foreign, (unsigned)sim->cnt_leaves,
              (unsigned)sim->cnt_leaves_refused);

  if (errors) {
    std::printf("\n%d/%d checks FAILED\n", errors, checks);
    return 1;
  }
  std::printf("\nPASSED! (%d checks)\n", checks);
  return 0;
}
