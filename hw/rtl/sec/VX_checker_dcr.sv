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
// WHAT THIS MODULE CANNOT DO, stated because it is the top open item: it
// enforces policy without authenticating its author. A DCR write is
// {addr, value} with no requester identity, so it cannot distinguish an owner
// re-claiming its own buffer from a tenant trying to steal one (PROJECT.md
// §10 #4b). BUF_OWNER is a value the writer *selects*. Deriving the owner from
// the originating command queue instead is what would make the principal
// unforgeable at the interface rather than trusted by convention — and that is
// a second-queue change in the command processor, not something this module
// can fix on its own.
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
    output wire [31:0]               cnt_reclaimed
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
    wire is_revown = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_REVOKE_OWNER);
    wire is_bump   = dcr_wr && (dcr_addr == `VX_DCR_CHECKER_EPOCH);

    // ---------------------------------------------------------------------
    // Staged claim. Persists across commits by design.
    // ---------------------------------------------------------------------
    reg [31:0] stg_base, stg_size;
    reg [31:0] stg_owner;      // full width: OWNER_ANY is 32'hFFFFFFFF
    reg [1:0]  stg_perms, stg_shared;
    reg [31:0] stg_epoch;

    // Staged revoke target. OWNER_ANY means "nothing staged", and a bare EPOCH
    // write with nothing staged is a NO-OP: the checker fails closed rather
    // than falling back to a device-wide revocation.
    reg [31:0] stg_revoke_owner;

    always @(posedge clk) begin
        if (reset) begin
            stg_base         <= '0;
            stg_size         <= '0;
            stg_owner        <= '0;
            stg_perms        <= '0;
            stg_shared       <= '0;
            stg_epoch        <= 32'hFFFFFFFF;
            stg_revoke_owner <= `VX_CHECKER_OWNER_ANY;
        end else begin
            if (is_base)   stg_base   <= dcr_wdata;
            if (is_size)   stg_size   <= dcr_wdata;
            if (is_owner)  stg_owner  <= dcr_wdata;
            if (is_perms)  stg_perms  <= dcr_wdata[1:0];
            if (is_shared) stg_shared <= dcr_wdata[1:0];
            if (is_epoch)  stg_epoch  <= dcr_wdata;
            if (is_revown) stg_revoke_owner <= dcr_wdata;
        end
    end

    wire stg_owner_any = (stg_owner == `VX_CHECKER_OWNER_ANY);

    // The installer reads only the occupant's owner and owner_any: valid and
    // tag are resolved by the store, and perms/epoch belong to the occupant's
    // policy, which a refusal must leave untouched rather than inspect.
    `UNUSED_VAR (probe_header)

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

    wire revoke_targets_any = (stg_revoke_owner == `VX_CHECKER_OWNER_ANY);
    wire [CHK_OWNER_W-1:0] revoke_idx = stg_revoke_owner[CHK_OWNER_W-1:0];
    wire revoke_in_range = !revoke_targets_any
                        && (stg_revoke_owner < 32'(NUM_OWNERS));
    wire [CHK_EPOCH_W-1:0] bump_value = dcr_wdata[CHK_EPOCH_W-1:0];
    // OWNER_ANY headers are never epoch-gated, so scoping a revoke to
    // OWNER_ANY would be a host mistake rather than a real grant to expire.
    wire do_bump = is_bump && revoke_in_range
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

    // granule id = address >> BUF_LOG2
    wire [31:0] claim_end = stg_base + stg_size - 1;
    wire [CHK_BUF_ID_W-1:0] first_of = CHK_BUF_ID_W'(stg_base  >> CHK_BUF_LOG2);
    wire [CHK_BUF_ID_W-1:0] last_of  = CHK_BUF_ID_W'(claim_end >> CHK_BUF_LOG2);

    // ALIAS: the entry this granule indexes is occupied by a DIFFERENT buffer.
    // Refuse whoever owns the occupant — two buffers is the problem, not two
    // owners. Unreachable at the design point (TAG_W == 0 means the index
    // spans the whole granule id), which is why `header_alias` has to pin the
    // store capacity to reach it at all.
    wire scan_alias_conflict = probe_occupied && !probe_claimed;

    // CROSS-OWNER: this granule already belongs to a different non-OWNER_ANY
    // owner. The invariant the per-sector writer tag depends on (§2.3).
    wire scan_owner_conflict = probe_claimed
                            && !probe_header.owner_any
                            && !stg_owner_any
                            && (probe_header.owner != stg_owner[CHK_OWNER_W-1:0]);

    // RE-CLAIM by the same owner (e.g. a re-grant). Legal and counted, so
    // "no owner ever silently replaced another" stays a measured zero rather
    // than an assumption. Only an installed header can be re-claimed.
    wire scan_is_reclaim = probe_claimed
                        && (probe_header.owner == stg_owner[CHK_OWNER_W-1:0]);

    wire at_last = (cur_id == last_id);

    always @(*) begin
        state_n = state;
        case (state)
            ST_IDLE:  if (is_commit && (stg_size != 0)) state_n = ST_SCAN;
            // The combinational conflict signals MUST be in this condition, not
            // just the registered flags. refuse_* only updates at the clock
            // edge, so on the cycle a conflict is detected they still read 0 —
            // and for a single-granule claim at_last is true on that very first
            // SCAN cycle, so the FSM would fall through to ST_WRITE and install
            // the claim it had just decided to refuse. It would then count
            // `rejected` as well, so the counter said fail-closed while the
            // store said otherwise. Caught by the TB's "owner 0 still owns A
            // after the refused claim" case; a deny-count check would have
            // passed it.
            ST_SCAN:  if (refuse_alias || refuse_owner
                       || scan_alias_conflict || scan_owner_conflict)
                                                        state_n = ST_DONE;
                      else if (at_last)                 state_n = ST_WRITE;
            ST_WRITE: if (at_last)                      state_n = ST_DONE;
            ST_DONE:                                    state_n = ST_IDLE;
            default:                                    state_n = ST_IDLE;
        endcase
    end

    reg [31:0] claims_r, written_r, rejected_r, aliased_r, reclaimed_r;
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
        end else begin
            state <= state_n;
            case (state)
                ST_IDLE: begin
                    if (is_commit && (stg_size != 0)) begin
                        first_id     <= first_of;
                        last_id      <= last_of;
                        cur_id       <= first_of;
                        refuse_alias <= 1'b0;
                        refuse_owner <= 1'b0;
                        reclaim_acc  <= '0;
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
                    if (refuse_owner)      rejected_r  <= rejected_r + 1;
                    else if (refuse_alias) aliased_r   <= aliased_r + 1;
                    else begin
                        claims_r    <= claims_r + 1;
                        reclaimed_r <= reclaimed_r + reclaim_acc;
                    end
                end
                default: ;
            endcase
        end
    end

    assign probe_en     = (state == ST_SCAN);
    assign probe_buf_id = cur_id;

    assign wr_en     = (state == ST_WRITE);
    assign wr_buf_id = cur_id;

    always @(*) begin
        wr_header              = '0;
        wr_header.valid        = 1'b1;
        wr_header.owner_any    = stg_owner_any;
        wr_header.owner        = stg_owner[CHK_OWNER_W-1:0];
        wr_header.perms        = stg_perms;
        wr_header.shared_perms = stg_shared;
        // 0xFFFFFFFF means "no expiry": saturate rather than truncate, or a
        // never-expiring grant would silently become one that expires at
        // epoch 0xFFFF's wrap.
        wr_header.grant_epoch  = (stg_epoch == 32'hFFFFFFFF)
                               ? {CHK_EPOCH_W{1'b1}}
                               : stg_epoch[CHK_EPOCH_W-1:0];
    end

    assign install_busy = (state != ST_IDLE);

    // ---------------------------------------------------------------------
    // Boot default: unclaimed memory is system/shared, so kernel code, stacks
    // and launch args are reachable before any claim is installed. This is
    // FAIL-OPEN and it is a known open item (§10 m3) — after the control-plane
    // filter, the command ring is the surviving trusted-but-unprotected
    // surface. Kept identical to SimX rather than quietly hardened, so the
    // two tiers measure the same policy.
    // ---------------------------------------------------------------------
    always @(*) begin
        default_header              = '0;
        default_header.valid        = 1'b0;
        default_header.owner_any    = 1'b1;
        default_header.perms        = CHK_PERM_R | CHK_PERM_W;
        default_header.shared_perms = '0;
        default_header.grant_epoch  = {CHK_EPOCH_W{1'b1}};
    end

    assign cnt_claims          = claims_r;
    assign cnt_headers_written = written_r;
    assign cnt_epoch_bumps     = bumps_r;
    assign cnt_rejected        = rejected_r;
    assign cnt_aliased         = aliased_r;
    assign cnt_reclaimed       = reclaimed_r;

    // Checker registers are consumed here; everything else fans onward
    // unchanged. Reads are not answered yet — the counter/fault read-back path
    // is R3, which also owns the response mux.
    assign dcr_bus_out_if.req_valid = dcr_bus_if.req_valid;
    assign dcr_bus_out_if.req_data  = dcr_bus_if.req_data;
    assign dcr_bus_if.rsp_valid     = dcr_bus_out_if.rsp_valid;
    assign dcr_bus_if.rsp_data      = dcr_bus_out_if.rsp_data;

endmodule
