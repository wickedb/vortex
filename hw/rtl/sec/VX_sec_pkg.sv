// Data-plane access checker — shared types and derived widths.
//
// Part of the data-centric TEE work; the argument and the SimX measurements are
// in playground_2626/PROJECT.md, the RTL plan in playground_2626/RTL_PLAN.md.
// Kept under sec/ so the thesis work stays separable from upstream in a diff,
// mirroring sim/simx/sec/.
//
// The register numbers and policy constants are NOT redefined here: they come
// from the generated VX_types.vh ([dcr_checker] / [checker_const] in
// VX_types.toml), which is the same source sim/simx/sec/mem_checker.cpp
// static_asserts against and the host runtime's auto-claim path reads. One
// definition, three consumers.

`ifndef VX_SEC_PKG_VH
`define VX_SEC_PKG_VH

`include "VX_define.vh"

package VX_sec_pkg;

    // The owner width is defined once, in VX_gpu_pkg, because mem_bus_attr_t
    // carries it (R2). Importing it here rather than recomputing the same
    // expression means the bus field and the header field cannot drift —
    // the same reasoning that put the DCR window in VX_types.toml.
    import VX_gpu_pkg::MEM_OWNER_WIDTH;
    import VX_gpu_pkg::MEM_RSP_ATTR_WIDTH;

    // ---------------------------------------------------------------------
    // Granularity. One header covers 2^BUF_LOG2 bytes (1 MB by default).
    //
    // Coarse granularity is the performance weapon, not a simplification: one
    // header covers megabytes, so the metadata working set is a handful of
    // entries and the check is an on-chip lookup amortized against a DRAM
    // access that already costs hundreds of cycles.
    // ---------------------------------------------------------------------
    localparam int CHK_BUF_LOG2   = `VX_CFG_CHECKER_BUF_LOG2;

    // A granule id is the address with the in-granule offset shifted out.
    localparam int CHK_BUF_ID_W   = `VX_CFG_MEM_ADDR_WIDTH - CHK_BUF_LOG2;

    // ---------------------------------------------------------------------
    // Header store geometry.
    //
    // CHK_ENTRIES = 0 means "size it to cover the address space at this
    // granularity", which is the design point: every granule gets its own
    // entry, so no two buffers can contend and claims_aliased is zero by
    // construction rather than by luck. A non-zero value models a store too
    // small for the address space, which is what the granularity sweep forces.
    // ---------------------------------------------------------------------
    localparam int CHK_ENTRIES    = (`VX_CFG_CHECKER_HEADER_ENTRIES == 0)
                                  ? (1 << CHK_BUF_ID_W)
                                  : `VX_CFG_CHECKER_HEADER_ENTRIES;
    localparam int CHK_IDX_W      = `CLOG2(CHK_ENTRIES);

    // The tag is what makes a colliding claim distinguishable from a claimed
    // granule, and it costs NOTHING at the design point: when the store covers
    // the address space, the index spans the whole granule id and there is no
    // tag left over. It only becomes real storage in the fine-granularity
    // sweep, where the store can no longer cover the space.
    localparam int CHK_TAG_W      = (CHK_BUF_ID_W > CHK_IDX_W)
                                  ? (CHK_BUF_ID_W - CHK_IDX_W) : 0;

    // ---------------------------------------------------------------------
    // Principal identity. owner_of(hart_id) = hart_id >> (log2 WARPS +
    // log2 THREADS) in SimX, i.e. one tenant per core — so only the core
    // field is load-bearing and the bus carries OWNER_W bits rather than a
    // full hart id. That keeps R2's metadata cost at 1 bit for --cores=2.
    //
    // OWNER_ANY is carried as an explicit flag rather than by reserving an
    // all-ones owner encoding: reserving one would cost a core id at narrow
    // widths, and the wildcard is only ever needed in the boot default and in
    // a "make this shared" claim.
    // ---------------------------------------------------------------------
    // Taken from the bus definition, not recomputed. MEM_OWNER_WIDTH already
    // applies `UP(), which floors it at 1: a single-core build has CLOG2(1) = 0
    // and every [CHK_OWNER_W-1:0] would be an illegal [-1:0] range. One owner
    // still needs one bit to be a value at all, and the field has to exist for
    // the single-core case to resolve to eid 0 the way SimX's owner_of() does.
    localparam int CHK_OWNER_W    = MEM_OWNER_WIDTH;
    // Header v2 (T1): owners are tenants, VX_CFG_CHECKER_TENANTS of them,
    // independent of the core count. The owner set is a bitmask by tenant.
    localparam int CHK_TENANTS    = `VX_CFG_CHECKER_TENANTS;

    // ---------------------------------------------------------------------
    // Epoch width. SimX uses a 64-bit counter, which is absurd in hardware:
    // the monotonicity guard means the width only bounds how many revocations
    // one session can express, and 16 bits is 65k scoped revocations per owner.
    // Parameterised because it is an R5 area input, not a free choice.
    // ---------------------------------------------------------------------
    localparam int CHK_EPOCH_W    = `VX_CFG_CHECKER_EPOCH_WIDTH;

    // Permission bits, from the generated header so SimX / RTL / host agree.
    localparam logic [2:0] CHK_PERM_R = 3'(`VX_CHECKER_PERM_R);
    localparam logic [2:0] CHK_PERM_W = 3'(`VX_CHECKER_PERM_W);
    localparam logic [2:0] CHK_PERM_X = 3'(`VX_CHECKER_PERM_X);
    // Perms of unclaimed memory (D9; VX_CFG_CHECKER_DEFAULT_PERMS). Read by
    // the setup path only; a build that labels caches without instantiating
    // the checker never reads it.
    /* verilator lint_off UNUSEDPARAM */
    localparam logic [2:0] CHK_DEFAULT_PERMS = 3'(`VX_CFG_CHECKER_DEFAULT_PERMS);
    /* verilator lint_on UNUSEDPARAM */

    // ---------------------------------------------------------------------
    // The buffer policy header.
    //
    // Read-only in steady state: revocation advances a per-owner epoch
    // register rather than touching headers, which is what lets the check stay
    // a pure cacheable read that can overlap the DRAM access it gates. Per-
    // access counting would force a read-modify-write on shared metadata for
    // every access, serializing exactly the path the thesis claims is parallel.
    // ---------------------------------------------------------------------
    //
    // Header v2 (T2, kernel_identity_oct16.md): an owner SET, so unclaimed is
    // the empty set and the owner_any wildcard is gone; X; and a grant that
    // names its grantee. A grant exists only on a single-owner granule (S4),
    // whose epoch gates it.
    typedef struct packed {
        logic                      valid;        // a claim is installed here
        logic [`UP(CHK_TAG_W)-1:0] tag;          // which buffer (degenerate at the design point)
        logic [CHK_TENANTS-1:0]    owners;       // owner set; empty = unclaimed
        logic [2:0]                perms;        // R W X for every owner — NEVER epoch-gated
        logic [CHK_OWNER_W-1:0]    grantee;      // the one tenant the grant is for
        logic [2:0]                grant_perms;  // R W X for the grantee
        logic                      confined;     // the grant taints its reader
        logic [CHK_EPOCH_W-1:0]    grant_epoch;  // grant holds while epoch(owner) <= this
    } chk_header_t;

    // Used by the header store only; a build that labels caches without
    // instantiating the checker (the cache unit-test top) never reads it.
    /* verilator lint_off UNUSEDPARAM */
    localparam int CHK_HEADER_W = $bits(chk_header_t);
    /* verilator lint_on UNUSEDPARAM */

    // ---------------------------------------------------------------------
    // The policy LABEL: a header minus the store's bookkeeping (valid, tag).
    //
    // Labeled lines: the checker resolves a granule's header where the lookup
    // is overlapped with DRAM and attaches the label to the fill response
    // (mem_bus rsp_data.attr). Every shared cache stores it with the line and
    // evaluates the SAME predicate at the point of delivery, so a hit in a
    // cache shared between tenants is authorized like a miss. A label is exact
    // per line: a line never straddles a granule (static-asserted where used).
    // Revocation stays an epoch bump -- the predicate reads the live epoch, so
    // every cached copy of a grant expires at once without being touched.
    // ---------------------------------------------------------------------
    typedef struct packed {
        logic [CHK_TENANTS-1:0]    owners;
        logic [2:0]                perms;
        logic [CHK_OWNER_W-1:0]    grantee;
        logic [2:0]                grant_perms;
        logic                      confined;
        logic [CHK_EPOCH_W-1:0]    grant_epoch;
    } chk_label_t;

    /* verilator lint_off UNUSEDPARAM */
    localparam int CHK_LABEL_W = $bits(chk_label_t);
    /* verilator lint_on UNUSEDPARAM */

    /* verilator lint_off UNUSEDSIGNAL */
    // A label is the header's POLICY: `valid` and `tag` are store residency,
    // resolved before a header reaches here, and deliberately dropped.
    function automatic chk_label_t chk_label_of(input chk_header_t hdr);
        chk_label_t l;
        l.owners       = hdr.owners;
        l.perms        = hdr.perms;
        l.grantee      = hdr.grantee;
        l.grant_perms  = hdr.grant_perms;
        l.confined     = hdr.confined;
        l.grant_epoch  = hdr.grant_epoch;
        return l;
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

    // ---------------------------------------------------------------------
    // The authorization predicate (header v2), as functions so the TB, the
    // port checker and every labeled cache cannot drift. Mirrors
    // MemChecker::judge() (sim/simx/sec/mem_checker.cpp).
    //
    //   need = W for a write, X for a fetch, R otherwise
    //   unclaimed (owners == {}):  need in perms (the default perms)
    //   requester an owner:        need in perms, never epoch-gated
    //   otherwise:                 requester == grantee, need in grant_perms,
    //                              and epoch(the owner) <= grant_epoch
    //
    // The epoch that gates a grant is the GRANTING owner's, so revocation is
    // scoped per owner. Grants exist only on single-owner granules, so the
    // owner's epoch is a one-hot mux on `owners` (chk_owner_epoch): no
    // encoder, and no deeper than v1's binary-indexed mux.
    // ---------------------------------------------------------------------
    function automatic logic [2:0] chk_need(input logic is_write, input logic is_fetch);
        return is_write ? CHK_PERM_W : (is_fetch ? CHK_PERM_X : CHK_PERM_R);
    endfunction

    function automatic logic [CHK_EPOCH_W-1:0] chk_owner_epoch(
        input logic [CHK_TENANTS-1:0]             owners,
        input logic [CHK_TENANTS*CHK_EPOCH_W-1:0] epochs
    );
        logic [CHK_EPOCH_W-1:0] e;
        e = '0;
        for (int t = 0; t < CHK_TENANTS; ++t) begin
            if (owners[t])
                e = e | epochs[t * CHK_EPOCH_W +: CHK_EPOCH_W];
        end
        return e;
    endfunction

    // THE predicate, on a label: the checker applies it to the header it just
    // read, a labeled cache to the label it stored with the line. `confined`
    // is the taint plumbing's (step 4); the predicate itself does not read it.
    /* verilator lint_off UNUSEDSIGNAL */
    function automatic logic chk_authorize_label(
        input chk_label_t             lbl,
        input logic [CHK_OWNER_W-1:0] requester,
        input logic                   is_write,
        input logic                   is_fetch,
        input logic [CHK_EPOCH_W-1:0] owner_epoch
    );
        logic [2:0] need;
        logic       is_owner;
        need = chk_need(is_write, is_fetch);
        is_owner = |(lbl.owners & (CHK_TENANTS'(1) << requester));
        if ((lbl.owners == '0) || is_owner) begin
            return |(lbl.perms & need);
        end else begin
            return (requester == lbl.grantee)
                && (|(lbl.grant_perms & need))
                && (owner_epoch <= lbl.grant_epoch);
        end
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

    // ---------------------------------------------------------------------
    // The stack slices (spec T12): a fixed hardware rule, no claims.
    //
    // Hart h's stack is the 2^VX_MEM_STACK_LOG2_SIZE bytes below
    // VX_MEM_STACK_BASE_ADDR - h * that (sw/kernel/src/vx_start.S), so the
    // owning core of a stack address is arithmetic. Inside the region only
    // the slice's own core may read or write, never fetch; the covering
    // check does not apply and nothing taints. It decides by address, in
    // parallel with the label predicate, which it overrides there. Until
    // per-core tenant registers (T3) the requester id is the core id.
    // ---------------------------------------------------------------------
    localparam int          CHK_STACK_LOG2  = `VX_MEM_STACK_LOG2_SIZE;
    localparam int          CHK_STACK_HARTS = `VX_CFG_NUM_CLUSTERS * `VX_CFG_NUM_CORES
                                            * `VX_CFG_NUM_WARPS * `VX_CFG_NUM_THREADS;
    localparam logic [63:0] CHK_STACK_TOP   = 64'(`VX_MEM_STACK_BASE_ADDR);
    localparam logic [63:0] CHK_STACK_BOT   = CHK_STACK_TOP - (64'(CHK_STACK_HARTS) << CHK_STACK_LOG2);
    localparam int          CHK_HART_CORE_SHIFT = `CLOG2(`VX_CFG_NUM_WARPS) + `CLOG2(`VX_CFG_NUM_THREADS);

    function automatic logic chk_in_stack(input logic [63:0] addr);
        return (addr < CHK_STACK_TOP) && (addr >= CHK_STACK_BOT);
    endfunction

    /* verilator lint_off UNUSEDSIGNAL */
    // The slice's core may read and write it; nobody fetches from it.
    // `requester_core` is the requesting core (attr.core), not the tenant.
    function automatic logic chk_stack_allow(
        input logic [63:0] addr,
        input logic [31:0] requester_core,
        input logic        is_fetch
    );
        logic [63:0] core;
        core = ((CHK_STACK_TOP - 64'd1 - addr) >> CHK_STACK_LOG2) >> CHK_HART_CORE_SHIFT;
        return !is_fetch && (core == 64'(requester_core));
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

    // ---------------------------------------------------------------------
    // Confinement by taint (kernel_identity_oct16.md "Updating the taint").
    //
    // chk_contrib: what an allowed read adds to the reader's taint. The other
    // owners of a joint granule, or the owners behind a confined grant;
    // nothing from unclaimed memory or a trusting grant. A denied read
    // contributes nothing (the caller masks it).
    //
    // chk_covers: a write must land in a granule whose owners cover the
    // writer's taint. Unclaimed memory covers only an empty taint.
    // ---------------------------------------------------------------------
    /* verilator lint_off UNUSEDSIGNAL */
    function automatic logic [CHK_TENANTS-1:0] chk_contrib(
        input chk_label_t             lbl,
        input logic [CHK_OWNER_W-1:0] requester
    );
        logic [CHK_TENANTS-1:0] self;
        self = CHK_TENANTS'(1) << requester;
        if ((lbl.owners & self) != '0)
            return lbl.owners & ~self;
        else
            return lbl.confined ? lbl.owners : '0;
    endfunction

    function automatic logic chk_covers(
        input chk_label_t             lbl,
        input logic [CHK_TENANTS-1:0] taint
    );
        return ((taint & ~lbl.owners) == '0);
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

    /* verilator lint_off UNUSEDSIGNAL */
    // `valid` and `tag` are resolved by the store before it hands a header
    // here — by this point the header is either the installed one or the boot
    // default, and the predicate is about policy, not about residency.
    function automatic logic chk_authorize(
        input chk_header_t            hdr,
        input logic [CHK_OWNER_W-1:0] requester,
        input logic                   is_write,
        input logic                   is_fetch,
        input logic [CHK_EPOCH_W-1:0] owner_epoch
    );
        return chk_authorize_label(chk_label_of(hdr), requester, is_write, is_fetch, owner_epoch);
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

endpackage

`endif // VX_SEC_PKG_VH
