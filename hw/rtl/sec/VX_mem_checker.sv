// VX_mem_checker — the data-plane access checker, one instance per memory port.
//
// Spliced between the LLC and DRAM: in Vortex.sv, between l3cache's
// mem_bus_if[L3_MEM_PORTS] and the top-level port assignment loop. That is the
// off-chip boundary in EVERY cache configuration, because the L3 module is
// instantiated with PASSTHRU when L3 is disabled and acts as a transparent
// arbiter — so the splice point does not move when a sweep changes cache
// config. Same property the SimX splice relies on.
//
// R1 SCOPE, and the boundaries matter:
//
//   * Identity arrives on a SEPARATE PORT (`req_owner`), not on the memory
//     bus. VX_mem_bus_if carries no requester identity — the only hart id
//     anywhere near it is amo_req_t.hart_id, for AMO reservations. Putting
//     owner identity on the bus is R2, together with the per-sector writer tag
//     that makes a WRITEBACK carry the id of whoever dirtied the line rather
//     than whoever evicted it (PROJECT.md §2.3). Until R2 lands, this module
//     is testable standalone but cannot be meaningfully wired into Vortex:
//     there is nothing to authorize on.
//
//   * A deny is REPORTED, not enforced. `rsp_deny` fires and the request is
//     still forwarded. Poison-response injection, the response-channel mux and
//     its back-pressure are R3 — the subtlest new logic in the design and the
//     likeliest source of a bring-up hang, so it is deliberately not smuggled
//     in here.
//
//   * Latency is injected as stall cycles. The header store is on chip and
//     every check reads it; R5 closed that read at 300 MHz with slack, so
//     LOOKUP_LATENCY = 0 is the design point. There is no header cache: one
//     held only granule ids to choose a modelled hit or miss stall, never a
//     label or a verdict, and fronted a store that is already on chip.
//
// Throughput: one request in flight. With LOOKUP_LATENCY=0 it accepts one
// request per cycle. That is enough for R4's deny-count parity and for R5's
// area and timing, and the pipelined/multi-outstanding version belongs with
// R3's arbiter work rather than ahead of the first testbench.

`include "VX_define.vh"

module VX_mem_checker import VX_gpu_pkg::*, VX_sec_pkg::*; #(
    parameter `STRING INSTANCE_ID = "",
    parameter LOOKUP_LATENCY = `VX_CFG_CHECKER_LOOKUP_LATENCY,
    parameter ENFORCE      = `VX_CFG_CHECKER_ENFORCE,
    parameter DATA_SIZE    = 64,
    parameter TAG_WIDTH    = 1,
    // Denied reads in flight are bounded by the LLC's MSHR -- see
    // VX_checker_fault for the argument. Sized so the queue cannot fill, which
    // keeps a stall off the request path R5 measures.
    parameter FAULT_DEPTH  = 16,
    // Labeled lines. The shared caches above are labeled and the LLC is a
    // labeled write-back cache, so every request here is a fill (judged where
    // its data is delivered) or a writeback of bytes authorized on entry. The
    // checker then never denies: it resolves each fill's header -- the lookup
    // it always did, overlapped with DRAM -- and attaches the label to the
    // response (rsp_label). Without it the checker judges every request.
    parameter LABEL_MODE   = 0,
    // Low tag bits that name an outstanding labeled fill (VX_gpu_pkg
    // LABEL_FILL_ID_W): the label table has 2^LABEL_IDX_W entries.
    parameter LABEL_IDX_W  = TAG_WIDTH - UUID_WIDTH,
    // The requester is a command-processor queue, not a core (D7): it owns
    // no stack slice, so every stack access is denied (T12).
    parameter STACK_DENY_ALL = 0,
    // The S6 rules on the CP's device path, with confinement by taint: a
    // download's read (req_export) is refused if its line would contribute
    // to a taint, and a copy's write (req_copy) must be covered by what the
    // copy's current chunk read. One DMA command runs at a time.
    parameter S6_ENABLE = 0
) (
    input  wire clk,
    input  wire reset,

    // DCR control surface (staged claims, epoch table, installer).
    VX_dcr_bus_if.slave  dcr_bus_if,
    VX_dcr_bus_if.master dcr_bus_out_if,
    // The queue (tenant) the current DCR write came from; see VX_checker_dcr.
    input  wire [VX_DCR_ISSUER_WIDTH-1:0] dcr_issuer,

    // Request in (LLC side).
    input  wire                      req_valid,
    input  wire                      req_rw,
    input  wire [`VX_CFG_MEM_ADDR_WIDTH-1:0] req_addr,
    input  wire [CHK_OWNER_W-1:0]    req_owner,   // the requesting tenant
    // The requesting core: the stack-slice rule (T12) decides by core.
    input  wire [31:0]               req_core,
    // An instruction fetch: judged against X rather than R (header v2, T9).
    input  wire                      req_fetch,
    // S6 (CP path only; see S6_ENABLE).
    input  wire                      req_export,
    input  wire                      req_copy,
    // Payload the checker does not inspect but MUST carry: it pipelines the
    // request through S1, so emitting these straight from the bus input would
    // pair one request's address with the next request's data. That corrupts
    // every write and fill, and the symptom is a wild address far downstream.
    input  wire [DATA_SIZE*8-1:0]    req_data,
    input  wire [DATA_SIZE-1:0]      req_byteen,
    output wire                      req_ready,

    // Request out (DRAM side), plus the policy verdict for this beat.
    output wire                      out_valid,
    output wire                      out_rw,
    output wire [`VX_CFG_MEM_ADDR_WIDTH-1:0] out_addr,
    output wire [DATA_SIZE*8-1:0]    out_data,
    output wire [DATA_SIZE-1:0]      out_byteen,
    output wire [TAG_WIDTH-1:0]      out_tag,
    output wire                      out_deny,
    // Pulses for one cycle when a BLOCKED request retires. Under enforcement a
    // denied request never appears on out_valid (that is the point), so this is
    // the only observable retirement for it — needed by the testbench and by
    // anything counting denials downstream.
    output wire                      out_fault,
    input  wire                      out_ready,

    // Response channel. Passes through untouched unless a poison response is
    // being injected for a denied read (R3).
    input  wire                      dram_rsp_valid,
    input  wire [DATA_SIZE*8-1:0]    dram_rsp_data,
    input  wire [TAG_WIDTH-1:0]      dram_rsp_tag,
    output wire                      dram_rsp_ready,
    output wire                      rsp_valid,
    output wire [DATA_SIZE*8-1:0]    rsp_data,
    output wire [TAG_WIDTH-1:0]      rsp_tag,
    // The policy label of the line this response fills (labeled lines).
    output wire [`UP(MEM_RSP_ATTR_WIDTH)-1:0] rsp_label,
    input  wire                      rsp_ready,

    // The live per-owner epoch table, flattened, for the labeled caches.
    output wire [LABEL_EPOCHS_W-1:0] epochs_out,

    // The denied request's tag, captured so its injected response quotes it.
    input  wire [TAG_WIDTH-1:0]      req_tag,

    output wire                      fault_overflow,

    // Counters, mirroring MemChecker::PerfStats.
    output wire [31:0] cnt_reqs,
    output wire [31:0] cnt_checked,
    output wire [31:0] cnt_bypassed,
    output wire [31:0] cnt_allows,
    output wire [31:0] cnt_denies,
    // The deny split, mirroring SimX's `enforce:` line. A single deny count
    // cannot distinguish "the write was never denied" from "it was denied and
    // landed anyway" -- two completely different bugs.
    output wire [31:0] cnt_faulted_reads,
    output wire [31:0] cnt_dropped_writes,
    output wire [31:0] cnt_claims,
    output wire [31:0] cnt_headers_written,
    output wire [31:0] cnt_epoch_bumps,
    output wire [31:0] cnt_rejected,
    output wire [31:0] cnt_aliased,
    output wire [31:0] cnt_reclaimed,
    output wire [31:0] cnt_foreign,
    output wire [31:0] cnt_leaves,
    output wire [31:0] cnt_leaves_refused
);
    `UNUSED_SPARAM (INSTANCE_ID)

    localparam NUM_OWNERS = 1 << CHK_OWNER_W;
`ifdef VX_CFG_CHECKER_ENABLE
    `STATIC_ASSERT(CHK_LABEL_W == MEM_RSP_ATTR_WIDTH, ("the bus response attr must be exactly one policy label"))
`endif
    localparam LAT_W      = `CLOG2(LOOKUP_LATENCY + 2);

    // ---------------------------------------------------------------------
    // Control surface
    // ---------------------------------------------------------------------
    chk_header_t default_header;
    wire                     probe_en, wr_en, install_busy;
    wire [CHK_BUF_ID_W-1:0]  probe_buf_id, wr_buf_id;
    chk_header_t             probe_header, wr_header;
    wire                     probe_claimed, probe_occupied;
    wire [CHK_EPOCH_W-1:0]   epoch_table [NUM_OWNERS];
    // One entry per tenant, flattened: what the predicate's one-hot epoch
    // select and every labeled cache read.
    wire [CHK_TENANTS*CHK_EPOCH_W-1:0] epochs_flat;
    for (genvar t = 0; t < CHK_TENANTS; ++t) begin : g_epochs_flat
        assign epochs_flat[t * CHK_EPOCH_W +: CHK_EPOCH_W] = epoch_table[t];
    end
    `STATIC_ASSERT(LABEL_EPOCHS_W == CHK_TENANTS * CHK_EPOCH_W, ("epoch bus width"))

    VX_checker_dcr #(
        .INSTANCE_ID ($sformatf("%s-dcr", INSTANCE_ID))
    ) ctrl (
        .clk                 (clk),
        .reset               (reset),
        .dcr_bus_if          (dcr_bus_if),
        .dcr_bus_out_if      (dcr_bus_out_if),
        .dcr_issuer          (dcr_issuer),
        .default_header      (default_header),
        .probe_en            (probe_en),
        .probe_buf_id        (probe_buf_id),
        .probe_header        (probe_header),
        .probe_claimed       (probe_claimed),
        .probe_occupied      (probe_occupied),
        .wr_en               (wr_en),
        .wr_buf_id           (wr_buf_id),
        .wr_header           (wr_header),
        .install_busy        (install_busy),
        .epoch_table         (epoch_table),
        .cnt_claims          (cnt_claims),
        .cnt_headers_written (cnt_headers_written),
        .cnt_epoch_bumps     (cnt_epoch_bumps),
        .cnt_rejected        (cnt_rejected),
        .cnt_aliased         (cnt_aliased),
        .cnt_reclaimed       (cnt_reclaimed),
        .cnt_foreign         (cnt_foreign),
        .cnt_leaves          (cnt_leaves),
        .cnt_leaves_refused  (cnt_leaves_refused)
    );

    // ---------------------------------------------------------------------
    // Granule resolve + lookup issue (S0)
    //
    // Only global device memory carries a header. IO traffic is structurally
    // outside the policy and passes untouched, counted as `bypassed` — the
    // attr bit is the RTL counterpart of SimX's addr_type() decode, and it
    // survives to this boundary (VX_cache.sv drives mem_bus req_data.attr).
    // ---------------------------------------------------------------------
    wire [CHK_BUF_ID_W-1:0] req_buf_id = CHK_BUF_ID_W'(req_addr >> CHK_BUF_LOG2);

    // ---------------------------------------------------------------------
    // Address classification — DECODED HERE, from the address, deliberately.
    //
    // The obvious alternative is to consume attr[MEM_ATTR_IO_OFFS], which the
    // LSU already computes. That is strictly weaker: the attr bit travels
    // core -> L1 -> L2 -> L3 before reaching this point, and a request can
    // INHERIT an attr it did not earn — a writeback carries its evictor's attr,
    // and the writeback's address is the victim line's, not the evictor's. A
    // request misclassified as IO would skip the policy check entirely.
    //
    // Trusting metadata that travelled with the request is the same class of
    // mistake as authorizing a writeback on the evictor's identity (§2.3). The
    // enforcement point has the address; it should decide for itself.
    //
    // Mirrors SimX's get_addr_type() (sim/simx/types.h:870) exactly, which R4
    // parity requires: IO aperture first, then local memory, else global.
    // ---------------------------------------------------------------------
    localparam ADDRW = `VX_CFG_MEM_ADDR_WIDTH;
    wire is_io_addr = (req_addr >= ADDRW'(`VX_MEM_IO_BASE_ADDR))
                   && (req_addr <  ADDRW'(`VX_MEM_IO_END_ADDR));
`ifdef VX_CFG_LMEM_ENABLE
    wire is_lmem_addr = (req_addr >= ADDRW'(`VX_MEM_LMEM_BASE_ADDR))
                     && ((req_addr - ADDRW'(`VX_MEM_LMEM_BASE_ADDR))
                          < ADDRW'(1 << `VX_CFG_LMEM_LOG_SIZE));
`else
    wire is_lmem_addr = 1'b0;
`endif
    // Only global device memory carries a policy header. IO and local memory
    // are structurally outside the policy — see PROJECT.md §8.5 for why that is
    // sound rather than a gap.
    wire req_is_io = is_io_addr || is_lmem_addr;

    reg [LAT_W-1:0] lat_cnt;
    wire lat_busy = (lat_cnt != '0);

    // S1 holds the request while its policy answer resolves.
    reg                      s1_valid, s1_rw, s1_bypass;
    reg [`VX_CFG_MEM_ADDR_WIDTH-1:0] s1_addr;
    reg [CHK_OWNER_W-1:0]    s1_owner;
    reg [31:0]               s1_core;
    reg                      s1_export, s1_copy;
    reg                      s1_fetch;
    reg [TAG_WIDTH-1:0]      s1_tag;
    reg [DATA_SIZE*8-1:0]    s1_data;
    reg [DATA_SIZE-1:0]      s1_byteen;

    // A blocked request retires without downstream acceptance: a dropped write
    // goes nowhere, and a poisoned read is satisfied by the fault queue.
    wire retiring, blocked;  // driven with the decision (S1), below
    wire s1_retire = (out_valid && out_ready) || (retiring && blocked);
    wire s1_ready = ~s1_valid || s1_retire;

    // The installer holds the store's write port; a check that would read it
    // mid-install stalls instead of observing a half-installed range. Claims
    // arrive at launch boundaries with the pipe drained (§2.2 Bound 1), so
    // this costs nothing real — but it is a rule, not an accident.
    wire s0_fire = req_valid && req_ready;
    assign req_ready = s1_ready && ~lat_busy && ~install_busy;

    wire lookup_en = s0_fire && ~req_is_io;

    chk_header_t rd_header;
    wire         rd_claimed;

    VX_checker_store #(
        .INSTANCE_ID ($sformatf("%s-store", INSTANCE_ID))
    ) store (
        .clk            (clk),
        .reset          (reset),
        .default_header (default_header),
        .rd_en          (lookup_en),
        .rd_buf_id      (req_buf_id),
        .rd_header      (rd_header),
        .rd_claimed     (rd_claimed),
        .wr_en          (wr_en),
        .wr_buf_id      (wr_buf_id),
        .wr_header      (wr_header),
        .probe_en       (probe_en),
        .probe_buf_id   (probe_buf_id),
        .probe_header   (probe_header),
        .probe_claimed  (probe_claimed),
        .probe_occupied (probe_occupied)
    );
    `UNUSED_VAR (rd_claimed)

    // Latency injection: every lookup costs LOOKUP_LATENCY. Held as a stall
    // rather than a pipeline depth so the knob can be swept without
    // re-elaborating the datapath.
    always @(posedge clk) begin
        if (reset) begin
            lat_cnt <= '0;
        end else if (lookup_en) begin
            lat_cnt <= LAT_W'(LOOKUP_LATENCY);
        end else if (lat_busy) begin
            lat_cnt <= lat_cnt - 1;
        end
    end

    always @(posedge clk) begin
        if (reset) begin
            s1_valid <= 1'b0;
        end else if (s0_fire) begin
            s1_valid  <= 1'b1;
            s1_rw     <= req_rw;
            s1_addr   <= req_addr;
            s1_owner  <= req_owner;
            s1_core   <= req_core;
            s1_export <= req_export;
            s1_copy   <= req_copy;
            s1_fetch  <= req_fetch;
            s1_bypass <= req_is_io;
            s1_tag    <= req_tag;
            s1_data   <= req_data;
            s1_byteen <= req_byteen;
        end else if (s1_retire) begin
            s1_valid <= 1'b0;
        end
    end

    // ---------------------------------------------------------------------
    // The decision (S1). One predicate, shared with the testbench through the
    // package so the two cannot drift.
    // ---------------------------------------------------------------------
    wire [CHK_EPOCH_W-1:0] owner_epoch = chk_owner_epoch(rd_header.owners, epochs_flat);

    // T12: a stack address is judged by the slice rule, not by its header.
    wire s1_stack = chk_in_stack(64'(s1_addr));
    wire authorized = s1_stack ? ((STACK_DENY_ALL == 0) && chk_stack_allow(64'(s1_addr), s1_core, s1_fetch))
                               : chk_authorize(rd_header, s1_owner, s1_rw, s1_fetch, owner_epoch);
    // S6 (CP path, with taint): exports and copies keep confined data on the
    // device. A copy's taint is the OR of what the current chunk's reads
    // contribute; a read after a write starts the next chunk.
    wire s6_refuse;
    if (S6_ENABLE != 0) begin : g_s6
        chk_label_t s1_lbl;
        assign s1_lbl = chk_label_of(rd_header);
        wire [CHK_TENANTS-1:0] s1_contrib = chk_contrib(s1_lbl, s1_owner);
        reg [CHK_TENANTS-1:0] copy_taint_r;
        reg                   copy_wr_last_r;
        wire export_refuse = ~s1_rw && s1_export && (s1_contrib != '0);
        wire copy_refuse   =  s1_rw && s1_copy   && ~chk_covers(s1_lbl, copy_taint_r);
        assign s6_refuse = ~s1_stack && (export_refuse || copy_refuse);
        always @(posedge clk) begin
            if (reset) begin
                copy_taint_r   <= '0;
                copy_wr_last_r <= 1'b1;
            end else if (s1_valid && s1_retire && s1_copy && ~s1_bypass) begin
                if (s1_rw) begin
                    copy_wr_last_r <= 1'b1;
                end else begin
                    copy_taint_r   <= (copy_wr_last_r ? '0 : copy_taint_r)
                                    | ((authorized && ~s1_stack) ? s1_contrib : '0);
                    copy_wr_last_r <= 1'b0;
                end
            end
        end
    end else begin : g_no_s6
        assign s6_refuse = 1'b0;
        `UNUSED_VAR ({s1_export, s1_copy})
    end
    wire denied     = s1_valid && ~s1_bypass && (~authorized || s6_refuse) && (LABEL_MODE == 0);

    // Under enforcement a denied request is NOT forwarded to DRAM: a read is
    // answered with poison instead (fast-fail, no DRAM round trip) and a write
    // is dropped, which is what makes the drop denial semantics rather than
    // just denial timing (PROJECT.md §8.5). Without ENFORCE the deny is counted
    // and the request still goes through, so a default run stays comparable to
    // baseline.
    assign blocked  = denied && (ENFORCE != 0);
    assign retiring = s1_valid && ~lat_busy;

    assign out_valid = retiring && ~blocked;
    assign out_rw    = s1_rw;
    assign out_addr   = s1_addr;
    assign out_data   = s1_data;
    assign out_byteen = s1_byteen;
    assign out_tag    = s1_tag;
    assign out_deny   = denied;
    assign out_fault = retiring && blocked;

    // A blocked read must produce exactly one response, carrying its own tag.
    // A blocked write produces none -- writes are posted here.
    wire fault_push = retiring && blocked && ~s1_rw;

    // ---------------------------------------------------------------------
    // Labeled lines: the label table. A fill's label is captured when its
    // read is forwarded to DRAM (S1 holds the resolved header) and attached to
    // its response, found by the low tag bits that name an outstanding LLC
    // fill (LABEL_IDX_W: MSHR id, bank and the selects below them), so the
    // table holds one entry per fill that can be in flight. The response
    // quotes its request's tag. Capturing at request time means a claim
    // installed while the read is in flight cannot be raced; claims arrive at
    // launch boundaries anyway. IO reads take an NC path no labeled cache
    // stores, so they neither write the table nor need its answer.
    // ---------------------------------------------------------------------
    localparam LBL_IDX_W = `UP(`MIN(LABEL_IDX_W, TAG_WIDTH - UUID_WIDTH));
    if (LABEL_MODE != 0) begin : g_label_tbl
        reg [CHK_LABEL_W-1:0] label_tbl [1 << LBL_IDX_W];
        wire [LBL_IDX_W-1:0] wr_idx = LBL_IDX_W'(s1_tag);
        wire [LBL_IDX_W-1:0] rd_idx = LBL_IDX_W'(rsp_tag);
        wire lbl_write = out_valid && out_ready && ~s1_rw && ~s1_bypass;
        always @(posedge clk) begin
            if (lbl_write) begin
                label_tbl[wr_idx] <= chk_label_of(rd_header);
            end
        end
        assign rsp_label = `UP(MEM_RSP_ATTR_WIDTH)'(label_tbl[rd_idx]);
    `ifdef SIMULATION
        // The index is derived from the tag layout (VX_gpu_pkg), not from the
        // tag itself, so check it: a slot is never reissued while its fill is
        // still outstanding. Any response frees its slot, which can only hide
        // a collision, never invent one.
        reg [(1 << LBL_IDX_W)-1:0] lbl_busy;
        always @(posedge clk) begin
            if (reset) begin
                lbl_busy <= '0;
            end else begin
                if (rsp_valid && rsp_ready) begin
                    lbl_busy[rd_idx] <= 1'b0;
                end
                if (lbl_write) begin
                    lbl_busy[wr_idx] <= 1'b1;
                end
            end
        end
        `RUNTIME_ASSERT (~lbl_write || ~lbl_busy[wr_idx], ("%t: %s label table slot %0d reissued while its fill is outstanding (tag=0x%0h): LABEL_FILL_ID_W does not match the tag layout", $time, INSTANCE_ID, wr_idx, s1_tag))
    `endif
    end else begin : g_no_label_tbl
        assign rsp_label = '0;
    end

    assign epochs_out = epochs_flat;

    VX_checker_fault #(
        .DATA_SIZE (DATA_SIZE),
        .TAG_WIDTH (TAG_WIDTH),
        .DEPTH     (FAULT_DEPTH)
    ) fault_unit (
        .clk            (clk),
        .reset          (reset),
        .fault_push     (fault_push),
        .fault_tag      (s1_tag),
        .dram_rsp_valid (dram_rsp_valid),
        .dram_rsp_data  (dram_rsp_data),
        .dram_rsp_tag   (dram_rsp_tag),
        .dram_rsp_ready (dram_rsp_ready),
        .rsp_valid      (rsp_valid),
        .rsp_data       (rsp_data),
        .rsp_tag        (rsp_tag),
        .rsp_ready      (rsp_ready),
        .fault_overflow (fault_overflow)
    );

    // ---------------------------------------------------------------------
    // Counters
    // ---------------------------------------------------------------------
    reg [31:0] reqs_r, checked_r, bypassed_r, allows_r, denies_r;
    reg [31:0] faulted_reads_r, dropped_writes_r;
    reg [31:0] labeled_passed_r;
    wire retire = s1_retire;

    always @(posedge clk) begin
        if (reset) begin
            reqs_r     <= '0;
            checked_r  <= '0;
            bypassed_r <= '0;
            allows_r   <= '0;
            denies_r   <= '0;
            faulted_reads_r  <= '0;
            dropped_writes_r <= '0;
            labeled_passed_r <= '0;
        end else if (retire) begin
            if ((LABEL_MODE != 0) && ~s1_bypass) begin
                labeled_passed_r <= labeled_passed_r + 1;
            end
            reqs_r <= reqs_r + 1;
            if (s1_bypass) begin
                bypassed_r <= bypassed_r + 1;
            end else begin
                checked_r <= checked_r + 1;
                if (denied) begin
                    denies_r <= denies_r + 1;
                    if (blocked) begin
                        if (s1_rw) dropped_writes_r <= dropped_writes_r + 1;
                        else       faulted_reads_r  <= faulted_reads_r + 1;
                    end
                end else begin
                    allows_r <= allows_r + 1;
                end
            end
        end
    end

    assign cnt_reqs     = reqs_r;
    assign cnt_checked  = checked_r;
    assign cnt_bypassed = bypassed_r;
    assign cnt_allows   = allows_r;
    assign cnt_denies   = denies_r;
    assign cnt_faulted_reads  = faulted_reads_r;
    assign cnt_dropped_writes = dropped_writes_r;

`ifdef SIMULATION
    // Counter escape for rtlsim (R4). Prints in SimX's exact `CHECKER:` format
    // (sim/simx/sec/mem_checker.cpp dump()), so parity against §7.2 is a diff
    // rather than a transcription. stderr, to stay out of the PERF stream the
    // harness parses — same discipline as VX_CHECKER_STATS.
    //
    // THIS IS rtlsim-ONLY. The FPGA has no stderr, so the board needs the DCR
    // readback path instead (RTL_PLAN.md R3/R5). Flagged there rather than left
    // as a surprise during bring-up.
    final begin
        if (cnt_reqs != 0) begin
            $fdisplay(32'h8000_0002, "CHECKER[%s]: reqs=%0d, checked=%0d, bypassed=%0d, allow=%0d, deny=%0d",
                      INSTANCE_ID, cnt_reqs, cnt_checked, cnt_bypassed, cnt_allows, cnt_denies);
            $fdisplay(32'h8000_0002, "CHECKER[%s]: enforce: faulted_reads=%0d, dropped_writes=%0d",
                      INSTANCE_ID, cnt_faulted_reads, cnt_dropped_writes);
            $fdisplay(32'h8000_0002, "CHECKER[%s]: setup: dcr_claims=%0d, headers_written=%0d, epoch_bumps=%0d",
                      INSTANCE_ID, cnt_claims, cnt_headers_written, cnt_epoch_bumps);
            $fdisplay(32'h8000_0002, "CHECKER[%s]: claims: rejected=%0d, aliased=%0d, reclaimed=%0d, foreign=%0d, leaves=%0d, leaves_refused=%0d",
                      INSTANCE_ID, cnt_rejected, cnt_aliased, cnt_reclaimed, cnt_foreign,
                      cnt_leaves, cnt_leaves_refused);
            if (LABEL_MODE != 0)
                $fdisplay(32'h8000_0002, "CHECKER[%s]: labels: port_passed=%0d", INSTANCE_ID, labeled_passed_r);
            if (fault_overflow)
                $fdisplay(32'h8000_0002, "CHECKER[%s]: *** FAULT QUEUE OVERFLOW — the MSHR bound argument is wrong",
                          INSTANCE_ID);
        end
    end
`endif

endmodule
