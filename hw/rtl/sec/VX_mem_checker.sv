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
//   * Latency is injected as stall cycles. Whether HIT_LATENCY = 0 is
//     achievable at all is a TIMING question, not a behavioural one, and only
//     synthesis answers it (R5). It is load-bearing: at a ~99.99% hit rate,
//     zero-versus-one cycle is +0.000% against +0.339% in SimX (§7.3), which
//     is 340x the entire miss path.
//
// Throughput: one request in flight. With a header-cache hit and HIT_LATENCY=0
// it accepts one request per cycle; a miss stalls for MISS_LATENCY. That is
// enough for R4's deny-count parity and for R5's area and timing, and the
// pipelined/multi-outstanding version belongs with R3's arbiter work rather
// than ahead of the first testbench.

`include "VX_define.vh"

module VX_mem_checker import VX_gpu_pkg::*, VX_sec_pkg::*; #(
    parameter `STRING INSTANCE_ID = "",
    parameter HIT_LATENCY  = `VX_CFG_CHECKER_HIT_LATENCY,
    parameter MISS_LATENCY = `VX_CFG_CHECKER_MISS_LATENCY,
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
    parameter LABEL_MODE   = 0
) (
    input  wire clk,
    input  wire reset,

    // DCR control surface (staged claims, epoch table, installer).
    VX_dcr_bus_if.slave  dcr_bus_if,
    VX_dcr_bus_if.master dcr_bus_out_if,

    // Request in (LLC side).
    input  wire                      req_valid,
    input  wire                      req_rw,
    input  wire [`VX_CFG_MEM_ADDR_WIDTH-1:0] req_addr,
    input  wire [CHK_OWNER_W-1:0]    req_owner,   // R2 moves this onto the bus
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
    output wire [31:0] cnt_hc_hits,
    output wire [31:0] cnt_hc_misses,
    output wire [31:0] cnt_claims,
    output wire [31:0] cnt_headers_written,
    output wire [31:0] cnt_epoch_bumps,
    output wire [31:0] cnt_rejected,
    output wire [31:0] cnt_aliased,
    output wire [31:0] cnt_reclaimed
);
    `UNUSED_SPARAM (INSTANCE_ID)

    localparam NUM_OWNERS = 1 << CHK_OWNER_W;
`ifdef VX_CFG_CHECKER_ENABLE
    `STATIC_ASSERT(CHK_LABEL_W == MEM_RSP_ATTR_WIDTH, ("the bus response attr must be exactly one policy label"))
`endif
    localparam LAT_W      = `CLOG2(((HIT_LATENCY > MISS_LATENCY)
                                  ? HIT_LATENCY : MISS_LATENCY) + 2);

    // ---------------------------------------------------------------------
    // Control surface
    // ---------------------------------------------------------------------
    chk_header_t default_header;
    wire                     probe_en, wr_en, install_busy;
    wire [CHK_BUF_ID_W-1:0]  probe_buf_id, wr_buf_id;
    chk_header_t             probe_header, wr_header;
    wire                     probe_claimed, probe_occupied;
    wire [CHK_EPOCH_W-1:0]   epoch_table [NUM_OWNERS];

    VX_checker_dcr #(
        .INSTANCE_ID ($sformatf("%s-dcr", INSTANCE_ID))
    ) ctrl (
        .clk                 (clk),
        .reset               (reset),
        .dcr_bus_if          (dcr_bus_if),
        .dcr_bus_out_if      (dcr_bus_out_if),
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
        .cnt_reclaimed       (cnt_reclaimed)
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
    reg [TAG_WIDTH-1:0]      s1_tag;
    reg [DATA_SIZE*8-1:0]    s1_data;
    reg [DATA_SIZE-1:0]      s1_byteen;

    // A blocked request retires without downstream acceptance: a dropped write
    // goes nowhere, and a poisoned read is satisfied by the fault queue.
    wire s1_retire = (out_valid && out_ready) || (retiring && blocked);
    wire s1_ready = ~s1_valid || s1_retire;

    // The installer holds the store's write port; a check that would read it
    // mid-install stalls instead of observing a half-installed range. Claims
    // arrive at launch boundaries with the pipe drained (§2.2 Bound 1), so
    // this costs nothing real — but it is a rule, not an accident.
    wire s0_fire = req_valid && req_ready;
    assign req_ready = s1_ready && ~lat_busy && ~install_busy;

    wire lookup_en = s0_fire && ~req_is_io;
    wire hc_hit;

    VX_checker_hcache hcache (
        .clk        (clk),
        .reset      (reset),
        .lookup_en  (lookup_en),
        .buf_id     (req_buf_id),
        .hit        (hc_hit),
        .cnt_hits   (cnt_hc_hits),
        .cnt_misses (cnt_hc_misses)
    );

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

    // Latency injection: a hit costs HIT_LATENCY, a miss MISS_LATENCY. Held as
    // a stall rather than a pipeline depth so the knob can be swept without
    // re-elaborating the datapath.
    always @(posedge clk) begin
        if (reset) begin
            lat_cnt <= '0;
        end else if (lookup_en) begin
            lat_cnt <= hc_hit ? LAT_W'(HIT_LATENCY) : LAT_W'(MISS_LATENCY);
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
    wire [CHK_EPOCH_W-1:0] owner_epoch = epoch_table[rd_header.owner];

    wire authorized = chk_authorize(rd_header, s1_owner, s1_rw, owner_epoch);
    wire denied     = s1_valid && ~s1_bypass && ~authorized && (LABEL_MODE == 0);

    // Under enforcement a denied request is NOT forwarded to DRAM: a read is
    // answered with poison instead (fast-fail, no DRAM round trip) and a write
    // is dropped, which is what makes the drop denial semantics rather than
    // just denial timing (PROJECT.md §8.5). Without ENFORCE the deny is counted
    // and the request still goes through, so a default run stays comparable to
    // baseline.
    wire blocked  = denied && (ENFORCE != 0);
    wire retiring = s1_valid && ~lat_busy;

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
    // its response, found by the tag's value bits: outstanding reads have
    // unique values (bank + MSHR id), and the response quotes its request's
    // tag. Capturing at request time means a claim installed while the read is
    // in flight cannot be raced; claims arrive at launch boundaries anyway.
    // ---------------------------------------------------------------------
    localparam LBL_IDX_W = `UP(TAG_WIDTH - UUID_WIDTH);
    if (LABEL_MODE != 0) begin : g_label_tbl
        reg [CHK_LABEL_W-1:0] label_tbl [1 << LBL_IDX_W];
        wire [LBL_IDX_W-1:0] wr_idx = LBL_IDX_W'(s1_tag);
        wire [LBL_IDX_W-1:0] rd_idx = LBL_IDX_W'(rsp_tag);
        always @(posedge clk) begin
            if (out_valid && out_ready && ~s1_rw) begin
                label_tbl[wr_idx] <= chk_label_of(rd_header);
            end
        end
        assign rsp_label = `UP(MEM_RSP_ATTR_WIDTH)'(label_tbl[rd_idx]);
    end else begin : g_no_label_tbl
        assign rsp_label = '0;
    end

    for (genvar o = 0; o < NUM_OWNERS; ++o) begin : g_epochs_out
        assign epochs_out[o * CHK_EPOCH_W +: CHK_EPOCH_W] = epoch_table[o];
    end
    if (LABEL_EPOCHS_W > NUM_OWNERS * CHK_EPOCH_W) begin : g_epochs_pad
        assign epochs_out[LABEL_EPOCHS_W-1:NUM_OWNERS * CHK_EPOCH_W] = '0;
    end

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
            $fdisplay(32'h8000_0002, "CHECKER[%s]: hcache: hits=%0d, misses=%0d",
                      INSTANCE_ID, cnt_hc_hits, cnt_hc_misses);
            $fdisplay(32'h8000_0002, "CHECKER[%s]: setup: dcr_claims=%0d, headers_written=%0d, epoch_bumps=%0d",
                      INSTANCE_ID, cnt_claims, cnt_headers_written, cnt_epoch_bumps);
            $fdisplay(32'h8000_0002, "CHECKER[%s]: claims: rejected=%0d, aliased=%0d, reclaimed=%0d",
                      INSTANCE_ID, cnt_rejected, cnt_aliased, cnt_reclaimed);
            if (LABEL_MODE != 0)
                $fdisplay(32'h8000_0002, "CHECKER[%s]: labels: port_passed=%0d", INSTANCE_ID, labeled_passed_r);
            if (fault_overflow)
                $fdisplay(32'h8000_0002, "CHECKER[%s]: *** FAULT QUEUE OVERFLOW — the MSHR bound argument is wrong",
                          INSTANCE_ID);
        end
    end
`endif

endmodule
