// The checker's control surface: staged claims, the per-owner epoch table, and
// the fail-closed claim installer. Non-checker DCR traffic passes through
// untouched, on the VX_mmu_dcr pattern.
//
// A claim is STAGED across BUF_* registers and installed by a write to
// BUF_COMMIT; the staged values persist across commits, so a later re-grant
// rewrites one register and commits again. Revocation stages the target owner
// (REVOKE_OWNER) then advances that owner's epoch (EPOCH) — two writes, and no
// header is touched by either, which is the whole reason policy change is
// cheap (PROJECT.md §2.2, measured zero in `churn.md`).
//
// Authorship: every write arrives with its issuer, the command-processor
// queue it came from (dcr_issuer, beside the bus). A tenant stages into its
// own registers, claims only for itself (a staged BUF_OWNER naming anyone
// else, OWNER_ANY included, makes the COMMIT install nothing, counted in
// cnt_foreign), and an EPOCH write advances only the issuer's own epoch. So an
// owner re-claiming its buffer and a tenant trying to steal one are now
// different requests, decided by where they came from rather than by a value
// the writer chose (P1_and_taint_specv2.md D1-D3).
//
// Reachability, as distinct from authorship, is closed elsewhere: the whole
// 0x300-0x340 window is refused when it arrives from a device-resident,
// tenant-writable command bundle. In SimX that filter lives in
// sim/common/cmd_processor.cpp; the RTL command processor has no QMD decoder
// yet, so there is nothing to filter there. If it ever gains one, the filter
// must land in the same change (RTL_PLAN.md §5 R3).

`include "VX_define.vh"

module VX_checker_dcr import VX_gpu_pkg::*, VX_sec_pkg::*; #(
    parameter `STRING INSTANCE_ID = ""
) (
    input  wire clk,
    input  wire reset,

    VX_dcr_bus_if.slave  dcr_bus_if,      // from the device DCR input
    VX_dcr_bus_if.master dcr_bus_out_if,  // onward to the cluster DCR arb
    // The command-processor queue (tenant) the current DCR write came from.
    // It travels beside the bus, valid with req_valid; the checker is its only
    // consumer.
    input  wire [VX_DCR_ISSUER_WIDTH-1:0] dcr_issuer,

    // Boot default for granules with no claim of their own.
    output chk_header_t              default_header,

    // Installer <-> store. The probe port feeds the fail-closed pre-pass; the
    // write port lands the claim only once the whole range has passed it.
    output wire                      probe_en,
    output wire [CHK_BUF_ID_W-1:0]   probe_buf_id,
    input  chk_header_t              probe_header,
    input  wire                      probe_claimed,
    input  wire                      probe_occupied,

    output wire                      wr_en,
    output wire [CHK_BUF_ID_W-1:0]   wr_buf_id,
    output chk_header_t              wr_header,

    // Held high while a claim is being installed: the check path must stall
    // rather than observe a half-installed range. Claims arrive at launch
    // boundaries with the pipe drained (§2.2 Bound 1), so this costs nothing
    // real — but it has to be stated and tested, not assumed.
    output wire                      install_busy,

    // Per-owner epoch table, read by the check path.
    output wire [CHK_EPOCH_W-1:0]    epoch_table [1 << CHK_OWNER_W],

    // Counters, mirroring MemChecker::PerfStats so R4 parity can compare like
    // for like. `rejected` is a cross-owner policy conflict and `aliased` is a
    // store-capacity collision: counted apart because they mean different
    // things, and EITHER non-zero means a buffer the host believes it claimed
    // is unprotected (§8.4).
    output wire [31:0]               cnt_claims,
    output wire [31:0]               cnt_headers_written,
    output wire [31:0]               cnt_epoch_bumps,
    output wire [31:0]               cnt_rejected,
    output wire [31:0]               cnt_aliased,
    output wire [31:0]               cnt_reclaimed,
    // Claims refused because they named an owner other than their issuer.
    output wire [31:0]               cnt_foreign,
    // Release (S2): BUF_LEAVE applied, and refused.
    output wire [31:0]               cnt_leaves,
    output wire [31:0]               cnt_leaves_refused
);
    `UNUSED_SPARAM (INSTANCE_ID)

    localparam NUM_OWNERS = 1 << CHK_OWNER_W;

    wire        dcr_wr    = dcr_bus_if.req_valid && dcr_bus_if.req_data.rw;
    wire [31:0] dcr_wdata = 32'(dcr_bus_if.req_data.data);
    wire [11:0] dcr_addr  = 12'(dcr_bus_if.req_data.addr);

    wire is_base   = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_BASE);
    wire is_size   = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_SIZE);
    wire is_owner  = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_OWNER);
    wire is_perms  = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_PERMS);
    wire is_epoch  = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_EPOCH);
    wire is_shared = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_SHARED);
    wire is_commit = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_COMMIT);
    wire is_bump   = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_EPOCH);
    wire is_joint    = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_JOINT);
    wire is_confined = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_CONFINED);
    wire is_grantee  = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_GRANTEE);
    wire is_leave    = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_BUF_LEAVE);
    // VX_DCR_CHECKER_REVOKE_OWNER is retired (authorship): it let any writer
    // pick whose epoch the next EPOCH write advanced. Writes to it are ignored.

    // ---------------------------------------------------------------------
    // Authorship (P1_and_taint_specv2.md D1-D3). Every setup write carries its
    // issuer, the queue it arrived on, which is the tenant. A tenant stages
    // into its own registers, may claim only for itself, and revokes only its
    // own grants. Issuers are tenants (header v2), so every queue is one.
    // ---------------------------------------------------------------------
    localparam NUM_ISSUERS = `VX_CFG_CHECKER_TENANTS;
    wire [`UP(`CLOG2(NUM_ISSUERS))-1:0] iss = `UP(`CLOG2(NUM_ISSUERS))'(dcr_issuer);
    wire iss_is_owner = (32'(dcr_issuer) < 32'(CHK_TENANTS));
    wire [CHK_TENANTS-1:0] iss_bit = CHK_TENANTS'(1) << dcr_issuer;

    // ---------------------------------------------------------------------
    // Staged claims, one set per issuer, so another queue's writes between a
    // tenant's staging and its COMMIT cannot retarget its claim. Persist
    // across commits by design. The staged owner is kept only as "did the
    // issuer name itself": that is all a commit needs.
    // ---------------------------------------------------------------------
    reg [NUM_ISSUERS-1:0][31:0] stg_base, stg_size, stg_epoch;
    reg [NUM_ISSUERS-1:0][2:0]  stg_perms, stg_shared;
    reg [NUM_ISSUERS-1:0]       stg_owner_self;
    // Header v2: co-owners (owners = {issuer} | joint), the grantee, and
    // whether the grant is confined.
    reg [NUM_ISSUERS-1:0][CHK_TENANTS-1:0] stg_joint;
    reg [NUM_ISSUERS-1:0][CHK_OWNER_W-1:0] stg_grantee;
    reg [NUM_ISSUERS-1:0]                  stg_confined;

    always @(posedge clk) begin
        if (reset) begin
            for (int i = 0; i < NUM_ISSUERS; ++i) begin
                stg_base[i]   <= '0;
                stg_size[i]   <= '0;
                stg_perms[i]  <= '0;
                stg_shared[i] <= '0;
                stg_epoch[i]  <= 32'hFFFFFFFF;
                stg_joint[i]    <= '0;
                stg_grantee[i]  <= '0;
                stg_confined[i] <= 1'b0;
                // An unwritten BUF_OWNER reads as owner 0, as in SimX.
                stg_owner_self[i] <= (i == 0);
            end
        end else begin
            if (is_base)   stg_base[iss]   <= dcr_wdata;
            if (is_size)   stg_size[iss]   <= dcr_wdata;
            if (is_owner)  stg_owner_self[iss] <= (dcr_wdata == 32'(dcr_issuer));
            if (is_perms)  stg_perms[iss]  <= dcr_wdata[2:0];
            if (is_shared) stg_shared[iss] <= dcr_wdata[2:0];
            if (is_epoch)  stg_epoch[iss]  <= dcr_wdata;
            if (is_joint)    stg_joint[iss]    <= dcr_wdata[CHK_TENANTS-1:0];
            if (is_grantee)  stg_grantee[iss]  <= dcr_wdata[CHK_OWNER_W-1:0];
            if (is_confined) stg_confined[iss] <= dcr_wdata[0];
        end
    end

    // The operation being installed, latched from the pending FIFO: a claim
    // (owner set {issuer} | joint) or a leave by the issuer (ins_leave).
    reg                   ins_leave;
    reg [CHK_TENANTS-1:0] ins_self, ins_owners;
    reg [2:0]             ins_perms, ins_shared;
    reg [31:0]            ins_epoch;
    reg [CHK_OWNER_W-1:0] ins_grantee;
    reg                   ins_confined;
    // A COMMIT whose issuer named someone else (or names no owner) installs
    // nothing and is counted, apart from rejected/aliased.
    wire commit_self = stg_owner_self[iss] && iss_is_owner;

    // A claim reads only the occupant's owner set; a leave rewrites the
    // occupant's header with the leaver removed, so it reads all of it.

    // ---------------------------------------------------------------------
    // Per-owner epoch table. Indexed by the GRANTING owner, which is what
    // makes revocation scoped: revoking owner A never advances owner C's
    // entry, so C's unrelated grant to D is untouched.
    //
    // Monotonic: a write that does not strictly increase the owner's epoch is
    // ignored, so revocation cannot be reversed by writing an earlier value
    // back. That guard is why CHK_EPOCH_W can be 16 bits instead of 64.
    // ---------------------------------------------------------------------
    reg [CHK_EPOCH_W-1:0] epoch_r [NUM_OWNERS];
    reg [31:0] bumps_r;

    // The issuer's own entry: an owner revokes only its own grants.
    wire [CHK_OWNER_W-1:0] revoke_idx = CHK_OWNER_W'(dcr_issuer);
    wire [CHK_EPOCH_W-1:0] bump_value = dcr_wdata[CHK_EPOCH_W-1:0];
    wire do_bump = is_bump && iss_is_owner
                && (bump_value > epoch_r[revoke_idx]);

    always @(posedge clk) begin
        if (reset) begin
            for (int i = 0; i < NUM_OWNERS; ++i)
                epoch_r[i] <= '0;
            bumps_r <= '0;
        end else if (do_bump) begin
            epoch_r[revoke_idx] <= bump_value;
            bumps_r <= bumps_r + 1;
        end
    end

    for (genvar i = 0; i < NUM_OWNERS; ++i) begin : g_epoch_out
        assign epoch_table[i] = epoch_r[i];
    end

    // ---------------------------------------------------------------------
    // The claim installer: a two-pass FSM over the granule range.
    //
    // PASS 1 (SCAN) walks every granule the claim would cover and refuses the
    // WHOLE claim if any of them fails either test, before mutating anything.
    // A rejected claim must leave the store exactly as it was.
    //
    //   aliased  — the entry this granule indexes is held by a DIFFERENT
    //              buffer. Installing here would hand that buffer this policy
    //              while leaving it addressable under its own id.
    //   rejected — the granule already belongs to a different non-OWNER_ANY
    //              owner. This is the invariant the per-sector writer tag
    //              depends on (§2.3): one writer id per sector is sufficient
    //              only because two owners can never share a granule, and a
    //              granule is orders of magnitude larger than a sector.
    //
    // Deliberately NOT a blanket alignment rule. Alignment is neither
    // necessary nor sufficient — a single-owner claim may sit unaligned and
    // overlap code or stack harmlessly, while two aligned claims can still
    // collide through outward rounding. Cross-owner conflict is the condition
    // that matters; misalignment is a diagnostic counted on the host side.
    //
    // PASS 2 (WRITE) lands one entry per cycle, so a claim spanning N granules
    // costs ~2N cycles. install_busy is held across both passes.
    // ---------------------------------------------------------------------
    typedef enum logic [1:0] { ST_IDLE, ST_SCAN, ST_WRITE, ST_DONE } state_e;
    state_e state, state_n;

    reg [CHK_BUF_ID_W-1:0] first_id, last_id, cur_id;
    reg refuse_alias, refuse_owner;

    // granule id = address >> BUF_LOG2, from the committing issuer's staging
    wire [31:0] claim_end = stg_base[iss] + stg_size[iss] - 1;
    wire [CHK_BUF_ID_W-1:0] first_of = CHK_BUF_ID_W'(stg_base[iss] >> CHK_BUF_LOG2);
    wire [CHK_BUF_ID_W-1:0] last_of  = CHK_BUF_ID_W'(claim_end >> CHK_BUF_LOG2);
    wire refuse_foreign = is_commit && (stg_size[iss] != 0) && !commit_self;

    // A leave names the leaver, which must be the issuer: only an owner
    // removes itself (S2). Anything else is refused before it is queued.
    wire leave_self    = iss_is_owner && (dcr_wdata == 32'(dcr_issuer));
    wire leave_accept  = is_leave && (stg_size[iss] != 0) && leave_self;
    wire refuse_leave  = is_leave && !((stg_size[iss] != 0) && leave_self);

    // ---------------------------------------------------------------------
    // Pending operations. The DCR bus has no back-pressure and an install
    // takes ~2N cycles, so a COMMIT can arrive while another claim is
    // installing -- with several queues, routinely. Each accepted COMMIT or
    // LEAVE is snapshotted here and the installer drains them in order. The
    // snapshot is what makes a later staging write by the same tenant unable
    // to alter an operation it has already issued.
    // ---------------------------------------------------------------------
    localparam PEND_DEPTH = 2 * NUM_ISSUERS;
    localparam PEND_W     = 1 + 2 * CHK_TENANTS + 2 * CHK_BUF_ID_W + 3 + 3 + 32
                          + CHK_OWNER_W + 1;
    wire              pend_empty, pend_full, pend_pop;
    wire [PEND_W-1:0] pend_out;
    wire commit_accept = is_commit && (stg_size[iss] != 0) && commit_self;
    wire op_accept     = commit_accept || leave_accept;
    wire pend_push     = op_accept && !pend_full;
    wire pend_drop     = op_accept && pend_full;

    VX_fifo_queue #(
        .DATAW (PEND_W),
        .DEPTH (PEND_DEPTH)
    ) pending (
        .clk      (clk),
        .reset    (reset),
        .push     (pend_push),
        .pop      (pend_pop),
        .data_in  ({leave_accept, iss_bit, iss_bit | stg_joint[iss], first_of, last_of,
                    stg_perms[iss], stg_shared[iss], stg_epoch[iss],
                    stg_grantee[iss], stg_confined[iss]}),
        .data_out (pend_out),
        .empty    (pend_empty),
        `UNUSED_PIN (alm_empty),
        .full     (pend_full),
        `UNUSED_PIN (alm_full),
        `UNUSED_PIN (size)
    );

    wire                    p_leave;
    wire [CHK_TENANTS-1:0]  p_self, p_owners;
    wire [CHK_BUF_ID_W-1:0] p_first, p_last;
    wire [2:0]              p_perms, p_shared;
    wire [31:0]             p_epoch;
    wire [CHK_OWNER_W-1:0]  p_grantee;
    wire                    p_confined;
    assign {p_leave, p_self, p_owners, p_first, p_last, p_perms, p_shared, p_epoch,
            p_grantee, p_confined} = pend_out;
    wire start_install = !pend_empty;

    // S4, decided once per claim: a grant names one tenant, and only a sole
    // owner grants. A joint claim carrying a grant is refused whole.
    wire grant_refused = !ins_leave && (ins_shared != '0)
                      && ((ins_owners != ins_self)
                       || (32'(ins_grantee) >= 32'(CHK_TENANTS)));

    // ALIAS: the entry this granule indexes is occupied by a DIFFERENT buffer.
    // Refuse whoever owns the occupant — two buffers is the problem, not two
    // owners. Unreachable at the design point (TAG_W == 0 means the index
    // spans the whole granule id), which is why `header_alias` has to pin the
    // store capacity to reach it at all.
    wire scan_alias_conflict = probe_occupied && !probe_claimed;

    // The setup rules per granule (kernel_identity_oct16.md S1, S2, S4; T6):
    //   claim: the granule is unclaimed (S1), or its owner set is exactly
    //          {issuer} and stays so (S4: a perms or grant change). No
    //          re-claim changes an owner set (T6), and granule exclusivity
    //          is what one writer id per sector depends on (§2.3).
    //   leave: the granule is claimed, lists the issuer, and keeps another
    //          owner (S2).
    wire scan_claim_conflict = probe_claimed
                            && !((probe_header.owners == ins_self)
                              && (ins_owners == ins_self));
    wire scan_leave_conflict = !probe_claimed
                            || ((probe_header.owners & ins_self) == '0)
                            || (probe_header.owners == ins_self);
    wire scan_owner_conflict = grant_refused
                            || (ins_leave ? scan_leave_conflict : scan_claim_conflict);

    // RE-CLAIM by the sole owner (a re-grant). Legal and counted, so "no claim
    // ever replaced another" stays a measured zero rather than an assumption.
    wire scan_is_reclaim = !ins_leave && probe_claimed;

    wire at_last = (cur_id == last_id);

    always @(*) begin
        state_n = state;
        case (state)
            ST_IDLE:  if (start_install)                  state_n = ST_SCAN;   // pops one
            // The combinational conflict signals MUST be in this condition, not
            // just the registered flags. refuse_* only updates at the clock
            // edge, so on the cycle a conflict is detected they still read 0 —
            // and for a single-granule claim at_last is true on that very first
            // SCAN cycle, so the FSM would fall through to ST_WRITE and install
            // the claim it had just decided to refuse. Caught by the TB's
            // "owner 0 still owns A after the refused claim" case; a deny-count
            // check would have passed it.
            ST_SCAN:  if (refuse_alias || refuse_owner
                       || scan_alias_conflict || scan_owner_conflict)
                                                        state_n = ST_DONE;
                      else if (at_last)                 state_n = ST_WRITE;
            ST_WRITE: if (at_last)                      state_n = ST_DONE;
            ST_DONE:                                    state_n = ST_IDLE;
            default:                                    state_n = ST_IDLE;
        endcase
    end

    reg [31:0] claims_r, written_r, rejected_r, aliased_r, reclaimed_r, foreign_r;
    reg [31:0] leaves_r, leaves_refused_r;
    reg [31:0] reclaim_acc;

    always @(posedge clk) begin
        if (reset) begin
            state        <= ST_IDLE;
            first_id     <= '0;
            last_id      <= '0;
            cur_id       <= '0;
            refuse_alias <= 1'b0;
            refuse_owner <= 1'b0;
            claims_r     <= '0;
            written_r    <= '0;
            rejected_r   <= '0;
            aliased_r    <= '0;
            reclaimed_r  <= '0;
            reclaim_acc  <= '0;
            foreign_r    <= '0;
            leaves_r     <= '0;
            leaves_refused_r <= '0;
            ins_leave    <= 1'b0;
            ins_self     <= '0;
            ins_owners   <= '0;
            ins_perms    <= '0;
            ins_shared   <= '0;
            ins_epoch    <= '0;
            ins_grantee  <= '0;
            ins_confined <= 1'b0;
        end else begin
            state <= state_n;
            if (refuse_foreign)
                foreign_r <= foreign_r + 1;
            // A leave refused before it was queued (not the issuer, or no
            // range staged); one refused per granule rule is counted at DONE.
            if (refuse_leave)
                leaves_refused_r <= leaves_refused_r + 1;
            case (state)
                ST_IDLE: begin
                    if (start_install) begin
                        first_id     <= p_first;
                        last_id      <= p_last;
                        cur_id       <= p_first;
                        refuse_alias <= 1'b0;
                        refuse_owner <= 1'b0;
                        reclaim_acc  <= '0;
                        ins_leave    <= p_leave;
                        ins_self     <= p_self;
                        ins_owners   <= p_owners;
                        ins_perms    <= p_perms;
                        ins_shared   <= p_shared;
                        ins_epoch    <= p_epoch;
                        ins_grantee  <= p_grantee;
                        ins_confined <= p_confined;
                    end
                end
                ST_SCAN: begin
                    if (scan_alias_conflict)
                        refuse_alias <= 1'b1;
                    if (scan_owner_conflict)
                        refuse_owner <= 1'b1;
                    if (scan_is_reclaim)
                        reclaim_acc <= reclaim_acc + 1;
                    if (at_last)
                        cur_id <= first_id;   // rewind for the write pass
                    else
                        cur_id <= cur_id + 1;
                end
                ST_WRITE: begin
                    written_r <= written_r + 1;
                    if (!at_last)
                        cur_id <= cur_id + 1;
                end
                ST_DONE: begin
                    if (ins_leave) begin
                        if (refuse_owner || refuse_alias)
                            leaves_refused_r <= leaves_refused_r + 1;
                        else
                            leaves_r <= leaves_r + 1;
                    end else if (refuse_owner) begin
                        rejected_r  <= rejected_r + 1;
                    end else if (refuse_alias) begin
                        aliased_r   <= aliased_r + 1;
                    end else begin
                        claims_r    <= claims_r + 1;
                        reclaimed_r <= reclaimed_r + reclaim_acc;
                    end
                end
                default: ;
            endcase
        end
    end

    // The probe also reads during the write pass: a leave rewrites each
    // granule's own header (the store's probe port reads asynchronously).
    assign probe_en     = (state == ST_SCAN) || (state == ST_WRITE);
    assign probe_buf_id = cur_id;

    assign wr_en     = (state == ST_WRITE);
    assign wr_buf_id = cur_id;

    always @(*) begin
        if (ins_leave) begin
            // S2: the granule's header with the leaver removed. A joint
            // granule carries no grant, so the remaining set inherits none.
            wr_header        = probe_header;
            wr_header.owners = probe_header.owners & ~ins_self;
        end else begin
            wr_header             = '0;
            wr_header.owners      = ins_owners;
            wr_header.perms       = ins_perms;
            wr_header.grantee     = (ins_shared != '0) ? ins_grantee : '0;
            wr_header.grant_perms = ins_shared;
            wr_header.confined    = (ins_shared != '0) && ins_confined;
            // 0xFFFFFFFF means "no expiry": saturate rather than truncate, or
            // a never-expiring grant would silently become one that expires
            // at epoch 0xFFFF's wrap.
            wr_header.grant_epoch = (ins_epoch == 32'hFFFFFFFF)
                                  ? {CHK_EPOCH_W{1'b1}}
                                  : ins_epoch[CHK_EPOCH_W-1:0];
        end
        wr_header.valid = 1'b1;
    end

    assign pend_pop = (state == ST_IDLE) && start_install;

    // The check path stalls while a claim installs or waits to.
    assign install_busy = (state != ST_IDLE) || !pend_empty;

    // ---------------------------------------------------------------------
    // Unclaimed memory: the empty owner set with the default perms (D9,
    // VX_CFG_CHECKER_DEFAULT_PERMS). Kept identical to SimX's default so the
    // two tiers measure the same policy.
    // ---------------------------------------------------------------------
    always @(*) begin
        default_header             = '0;
        default_header.valid       = 1'b0;
        default_header.owners      = '0;
        default_header.perms       = CHK_DEFAULT_PERMS;
        default_header.grant_perms = '0;
        default_header.grant_epoch = {CHK_EPOCH_W{1'b1}};
    end

    assign cnt_claims          = claims_r;
    assign cnt_headers_written = written_r;
    assign cnt_epoch_bumps     = bumps_r;
    assign cnt_rejected        = rejected_r;
    assign cnt_aliased         = aliased_r;
    assign cnt_reclaimed       = reclaimed_r;
    assign cnt_foreign         = foreign_r;
    assign cnt_leaves          = leaves_r;
    assign cnt_leaves_refused  = leaves_refused_r;

`ifdef SIMULATION
    // PEND_DEPTH covers two outstanding COMMITs per tenant. More than that
    // before the installer catches up would lose a claim; say so loudly.
    `RUNTIME_ASSERT (reset || !pend_drop, ("%t: %s COMMIT from issuer %0d dropped: %0d claims already pending", $time, INSTANCE_ID, dcr_issuer, PEND_DEPTH))
`endif

    // Checker registers are consumed here; everything else fans onward
    // unchanged. Reads are not answered yet — the counter/fault read-back path
    // is R3, which also owns the response mux.
    assign dcr_bus_out_if.req_valid = dcr_bus_if.req_valid;
    assign dcr_bus_out_if.req_data  = dcr_bus_if.req_data;
    assign dcr_bus_if.rsp_valid     = dcr_bus_out_if.rsp_valid;
    assign dcr_bus_if.rsp_data      = dcr_bus_out_if.rsp_data;

endmodule
