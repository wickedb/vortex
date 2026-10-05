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

    // ---------------------------------------------------------------------
    // Epoch width. SimX uses a 64-bit counter, which is absurd in hardware:
    // the monotonicity guard means the width only bounds how many revocations
    // one session can express, and 16 bits is 65k scoped revocations per owner.
    // Parameterised because it is an R5 area input, not a free choice.
    // ---------------------------------------------------------------------
    localparam int CHK_EPOCH_W    = `VX_CFG_CHECKER_EPOCH_WIDTH;

    // Permission bits, from the generated header so SimX / RTL / host agree.
    localparam logic [1:0] CHK_PERM_R = 2'(`VX_CHECKER_PERM_R);
    localparam logic [1:0] CHK_PERM_W = 2'(`VX_CHECKER_PERM_W);

    // ---------------------------------------------------------------------
    // The buffer policy header.
    //
    // Read-only in steady state: revocation advances a per-owner epoch
    // register rather than touching headers, which is what lets the check stay
    // a pure cacheable read that can overlap the DRAM access it gates. Per-
    // access counting would force a read-modify-write on shared metadata for
    // every access, serializing exactly the path the thesis claims is parallel.
    // ---------------------------------------------------------------------
    typedef struct packed {
        logic                      valid;        // a claim is installed here
        logic [`UP(CHK_TAG_W)-1:0] tag;          // which buffer (degenerate at the design point)
        logic                      owner_any;    // wildcard: any tenant, subject to perms
        logic [CHK_OWNER_W-1:0]    owner;        // owning principal
        logic [1:0]                perms;        // owner access — NEVER epoch-gated
        logic [1:0]                shared_perms; // non-owner access: the grant
        logic [CHK_EPOCH_W-1:0]    grant_epoch;  // grant holds while epoch(owner) <= this
    } chk_header_t;

    localparam int CHK_HEADER_W = $bits(chk_header_t);

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
        logic                      owner_any;
        logic [CHK_OWNER_W-1:0]    owner;
        logic [1:0]                perms;
        logic [1:0]                shared_perms;
        logic [CHK_EPOCH_W-1:0]    grant_epoch;
    } chk_label_t;

    localparam int CHK_LABEL_W = $bits(chk_label_t);

    /* verilator lint_off UNUSEDSIGNAL */
    // A label is the header's POLICY: `valid` and `tag` are store residency,
    // resolved before a header reaches here, and deliberately dropped.
    function automatic chk_label_t chk_label_of(input chk_header_t hdr);
        chk_label_t l;
        l.owner_any    = hdr.owner_any;
        l.owner        = hdr.owner;
        l.perms        = hdr.perms;
        l.shared_perms = hdr.shared_perms;
        l.grant_epoch  = hdr.grant_epoch;
        return l;
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

    // ---------------------------------------------------------------------
    // The authorization predicate, as a function so the TB and the datapath
    // cannot drift. Mirrors MemChecker::check() (sim/simx/sec/mem_checker.cpp).
    //
    //   Authorize(r,b,op) <=> ( r = Owner(b)   & op in OwnerPerms(b) )
    //                       | ( r = Grantee(b) & op in GrantPerms(b)
    //                                          & CurrentEpoch(Owner(b)) <= GrantEpoch(b) )
    //
    // Two asymmetries, both deliberate: the owner (and OWNER_ANY) is never
    // epoch-gated — revocation expires grants to *others*, it does not evict
    // the owner — and the epoch that gates a grant is the GRANTING owner's,
    // which is what makes revocation scoped per owner.
    // ---------------------------------------------------------------------
    // THE predicate, on a label: the checker applies it to the header it just
    // read, a labeled cache to the label it stored with the line.
    function automatic logic chk_authorize_label(
        input chk_label_t             lbl,
        input logic [CHK_OWNER_W-1:0] requester,
        input logic                   is_write,
        input logic [CHK_EPOCH_W-1:0] owner_epoch
    );
        logic [1:0] need;
        need = is_write ? CHK_PERM_W : CHK_PERM_R;
        if (lbl.owner_any || (lbl.owner == requester)) begin
            return |(lbl.perms & need);
        end else begin
            return (|(lbl.shared_perms & need)) && (owner_epoch <= lbl.grant_epoch);
        end
    endfunction

    /* verilator lint_off UNUSEDSIGNAL */
    // `valid` and `tag` are resolved by the store before it hands a header
    // here — by this point the header is either the installed one or the boot
    // default, and the predicate is about policy, not about residency.
    function automatic logic chk_authorize(
        input chk_header_t            hdr,
        input logic [CHK_OWNER_W-1:0] requester,
        input logic                   is_write,
        input logic [CHK_EPOCH_W-1:0] owner_epoch
    );
        return chk_authorize_label(chk_label_of(hdr), requester, is_write, owner_epoch);
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

endpackage

`endif // VX_SEC_PKG_VH
