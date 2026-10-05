// Copyright © 2019-2023
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

`include "VX_define.vh"

module Vortex import VX_gpu_pkg::*, VX_trace_pkg::*, VX_tlb_pkg::*; (
    `SCOPE_IO_DECL

    // Clock
    input  wire                             clk,
    input  wire                             reset,

    // Memory request
    output wire                             mem_req_valid [VX_MEM_PORTS],
    output wire                             mem_req_rw [VX_MEM_PORTS],
    output wire [VX_MEM_BYTEEN_WIDTH-1:0]   mem_req_byteen [VX_MEM_PORTS],
    output wire [VX_MEM_ADDR_WIDTH-1:0]     mem_req_addr [VX_MEM_PORTS],
    output wire [VX_MEM_DATA_WIDTH-1:0]     mem_req_data [VX_MEM_PORTS],
    output wire [VX_MEM_TAG_WIDTH-1:0]      mem_req_tag [VX_MEM_PORTS],
    input  wire                             mem_req_ready [VX_MEM_PORTS],

    // Memory response
    input wire                              mem_rsp_valid [VX_MEM_PORTS],
    input wire [VX_MEM_DATA_WIDTH-1:0]      mem_rsp_data [VX_MEM_PORTS],
    input wire [VX_MEM_TAG_WIDTH-1:0]       mem_rsp_tag [VX_MEM_PORTS],
    output wire                             mem_rsp_ready [VX_MEM_PORTS],

    // DCR write request
    input  wire                             dcr_req_valid,
    input  wire                             dcr_req_rw,
    input  wire [VX_DCR_ADDR_WIDTH-1:0]     dcr_req_addr,
    input  wire [VX_DCR_DATA_WIDTH-1:0]     dcr_req_data,

    // DCR read response
    output wire                             dcr_rsp_valid,
    output wire [VX_DCR_DATA_WIDTH-1:0]     dcr_rsp_data,

    // ctrl/status
    input  wire                             start,
    output wire                             busy
);
    // Check clustering configuration
    `STATIC_ASSERT(`IS_POW2(`VX_CFG_NUM_CLUSTERS), ("NUM_CLUSTERS must be a power of 2"));
    `STATIC_ASSERT(`IS_POW2(`VX_CFG_NUM_CORES), ("NUM_CORES must be a power of 2"));
    `STATIC_ASSERT(`IS_POW2(`VX_CFG_SOCKET_SIZE), ("SOCKET_SIZE must be a power of 2"));

    // Every cache strictly above the LLC must be write-through.
    // A WB intermediate could absorb a hart-B store without the LLC
    // seeing it; a later SC from hart-A on the same line would
    // spuriously succeed. RVA permits spurious failure, not spurious success.
`ifdef VX_CFG_EXT_A_ENABLE
  `ifdef VX_CFG_L3_ENABLE
    `STATIC_ASSERT(`VX_CFG_DCACHE_WRITEBACK == 0, ("AMO requires write-through L1 (DCACHE_WRITEBACK=0) when L3 is the LLC"));
    `STATIC_ASSERT(`VX_CFG_L2_WRITEBACK == 0,     ("AMO requires write-through L2 (L2_WRITEBACK=0) when L3 is the LLC"));
  `elsif VX_CFG_L2_ENABLE
    `STATIC_ASSERT(`VX_CFG_DCACHE_WRITEBACK == 0, ("AMO requires write-through L1 (DCACHE_WRITEBACK=0) when L2 is the LLC"));
  `endif
`endif

    VX_dcr_bus_if dcr_bus_if();
    assign dcr_bus_if.req_valid = dcr_req_valid;
    assign dcr_bus_if.req_data.rw = dcr_req_rw;
    assign dcr_bus_if.req_data.addr = dcr_req_addr;
    assign dcr_bus_if.req_data.data = dcr_req_data;
    assign dcr_rsp_valid = dcr_bus_if.rsp_valid;
    assign dcr_rsp_data = dcr_bus_if.rsp_data;

    // Kernel Management Unit
    VX_kmu_bus_if kmu_bus_in[1]();
    wire kmu_busy;
`ifdef VX_CFG_EXT_RASTER_ENABLE
    VX_raster_launch_if raster_launch_if();
`endif
    VX_kmu #(
        .INSTANCE_ID ("kmu")
    ) kmu (
        .clk        (clk),
        .reset      (reset),
        .start      (start),
        .busy       (kmu_busy),
        .dcr_req_valid (dcr_req_valid),
        .dcr_req_rw (dcr_req_rw),
        .dcr_req_addr(dcr_req_addr),
        .dcr_req_data(dcr_req_data),
    `ifdef VX_CFG_EXT_RASTER_ENABLE
        .raster_launch_if (raster_launch_if),
    `endif
        .kmu_bus_if (kmu_bus_in[0])
    );

`ifdef SCOPE
    localparam scope_cluster = 0;
    `SCOPE_IO_SWITCH (`VX_CFG_NUM_CLUSTERS);
`endif

`ifdef PERF_ENABLE
    cache_perf_t l3_perf;
    mem_perf_t mem_perf;
    sysmem_perf_t sysmem_perf;
    always @(*) begin
        sysmem_perf = '0;
        sysmem_perf.l3cache = l3_perf;
        sysmem_perf.mem = mem_perf;
    end
`endif

    VX_mem_bus_if #(
        .DATA_SIZE (L2_SECTOR_SIZE),
        .TAG_WIDTH (L3_TAG_WIDTH)
    ) per_cluster_mem_bus_if[`VX_CFG_NUM_CLUSTERS * L2_MEM_PORTS]();

    VX_mem_bus_if #(
        .DATA_SIZE (L3_SECTOR_SIZE),
        .TAG_WIDTH (L3_MEM_TAG_WIDTH)
    ) mem_bus_if[L3_MEM_PORTS]();

    // Labeled lines: the checker's live per-owner epoch table, fanned out to
    // every labeled cache so a revocation expires every cached copy at once.
    wire [LABEL_EPOCHS_W-1:0] label_epochs;

`ifdef VX_CFG_CHECKER_ENABLE
    // A labeled LLC must be write-back: then everything leaving it is a fill
    // (judged where its data is delivered) or a writeback of bytes that were
    // authorized when they entered, and the port checker can pass both. A
    // write-through LLC would forward unjudged misses to DRAM.
    `STATIC_ASSERT(!(`VX_CFG_L3_ENABLED) || `VX_CFG_L3_WRITEBACK, ("labeled lines: a labeled L3 LLC must be write-back"))
    `STATIC_ASSERT((`VX_CFG_L3_ENABLED) || !(`VX_CFG_L2_ENABLED) || `VX_CFG_L2_WRITEBACK, ("labeled lines: a labeled L2 LLC must be write-back"))
`endif

    VX_cache_wrap #(
        .INSTANCE_ID    ("l3cache"),
        .CACHE_SIZE     (`VX_CFG_L3_SIZE),
        .LINE_SIZE      (`VX_CFG_L3_LINE_SIZE),
        .SECTOR_SIZE    (L3_SECTOR_SIZE),
        .NUM_BANKS      (L3_NUM_BANKS),
        .NUM_WAYS       (`VX_CFG_L3_NUM_WAYS),
        .WORD_SIZE      (L3_WORD_SIZE),
        .NUM_REQS       (L3_NUM_REQS),
        .MEM_PORTS      (L3_MEM_PORTS),
        .CRSQ_SIZE      (`VX_CFG_L3_CRSQ_SIZE),
        .MSHR_SIZE      (`VX_CFG_L3_MSHR_SIZE),
        .MRSQ_SIZE      (`VX_CFG_L3_MRSQ_SIZE),
        .MREQ_SIZE      (`VX_CFG_L3_MREQ_SIZE),
        .LATENCY        (`VX_CFG_L3_LATENCY),
        .TAG_WIDTH      (L3_TAG_WIDTH),
        .WRITE_ENABLE   (1),
        .WRITEBACK      (`VX_CFG_L3_WRITEBACK),
        .DIRTY_BYTES    (`VX_CFG_L3_DIRTYBYTES),
        .REPL_POLICY    (`VX_CFG_L3_REPL_POLICY),
        .CORE_OUT_BUF   (3),
        .MEM_OUT_BUF    (3),
        .NC_ENABLE      (1),
        .PASSTHRU       (!`VX_CFG_L3_ENABLED),
        .IS_LLC         (L3_IS_LLC),
        .AMO_ENABLE     (`VX_CFG_EXT_A_ENABLED),
        // Labeled lines: the L3 is shared by every cluster; it is the edge
        // (judges reads) only when there is no L2 between it and the L1s.
        .LABEL_ENABLE   (`VX_CFG_CHECKER_ENABLED && `VX_CFG_L3_ENABLED),
        .LABEL_EDGE     (!`VX_CFG_L2_ENABLED)
    ) l3cache (
        .clk            (clk),
        .reset          (reset),
        .label_epochs   (label_epochs),

    `ifdef PERF_ENABLE
        .cache_perf     (l3_perf),
    `endif

        .core_bus_if    (per_cluster_mem_bus_if),
        .mem_bus_if     (mem_bus_if)
    );

`ifdef VX_CFG_CHECKER_ENABLE
    // ====================================================================
    // Data-plane access checker, spliced on the LLC->DRAM wire.
    //
    // This is the off-chip boundary in EVERY cache configuration: the L3 is
    // instantiated with PASSTHRU when disabled and acts as a transparent
    // arbiter, so the splice point does not move when a sweep changes cache
    // config. Placing it here also means every lane inherits it from one
    // instantiation -- rtlsim, OPAE and the Alveo path all instantiate Vortex.
    //
    // Note the checker sits UPSTREAM of the port assignment below, where attr
    // is discarded. Owner identity therefore never crosses the top-level port,
    // so the AXI shell does not inherit the width (RTL_PLAN.md §2).
    //
    // One instance per port, each with its own policy state, with the DCR
    // stream chained through them so every instance observes every claim and
    // revocation. That duplicates the header store per port (2x 12 KB at the
    // default config) -- correct and simple, but an R5 area item: a shared
    // store with per-port header caches would halve it.
    // ====================================================================
    localparam CHK_ASHIFT = `CLOG2(L3_SECTOR_SIZE);

    VX_dcr_bus_if chk_dcr_if[L3_MEM_PORTS+1]();
    assign chk_dcr_if[0].req_valid = dcr_bus_if.req_valid;
    assign chk_dcr_if[0].req_data  = dcr_bus_if.req_data;

    for (genvar i = 0; i < L3_MEM_PORTS; ++i) begin : g_checker
        wire chk_out_valid, chk_out_rw, chk_out_deny, chk_out_fault;
        wire [`VX_CFG_MEM_ADDR_WIDTH-1:0] chk_out_addr;
        wire [L3_SECTOR_SIZE*8-1:0] chk_out_data;
        wire [L3_SECTOR_SIZE-1:0]   chk_out_byteen;
        wire [L3_MEM_TAG_WIDTH-1:0] chk_out_tag;
        wire [LABEL_EPOCHS_W-1:0] chk_epochs;
        `UNUSED_VAR ({chk_out_deny, chk_out_fault})
        // Every instance sees the same DCR stream, so every epoch table is the
        // same; the caches take port 0's.
        if (i == 0) begin : g_epochs
            assign label_epochs = chk_epochs;
        end else begin : g_no_epochs
            `UNUSED_VAR (chk_epochs)
        end

        VX_mem_checker #(
            .INSTANCE_ID ($sformatf("checker%0d", i)),
            .DATA_SIZE   (L3_SECTOR_SIZE),
            .TAG_WIDTH   (L3_MEM_TAG_WIDTH),
            .FAULT_DEPTH (`VX_CFG_L3_MSHR_SIZE),
            // Any enabled shared level is labeled, and the LLC is then a
            // labeled write-back cache (asserted above).
            .LABEL_MODE  (`VX_CFG_L2_ENABLED || `VX_CFG_L3_ENABLED)
        ) chk_inst (
            .clk            (clk),
            .reset          (reset),
            .dcr_bus_if     (chk_dcr_if[i]),
            .dcr_bus_out_if (chk_dcr_if[i+1]),
            // The bus carries a BLOCK address; the checker resolves granules
            // from a byte address, as SimX does.
            .req_valid      (mem_bus_if[i].req_valid),
            .req_rw         (mem_bus_if[i].req_data.rw),
            .req_addr       (`VX_CFG_MEM_ADDR_WIDTH'(mem_bus_if[i].req_data.addr) << CHK_ASHIFT),
            .req_owner      (mem_bus_if[i].req_data.attr[MEM_ATTR_OWNER_OFFS +: MEM_OWNER_WIDTH]),
            .req_tag        (mem_bus_if[i].req_data.tag),
            .req_data       (mem_bus_if[i].req_data.data),
            .req_byteen     (mem_bus_if[i].req_data.byteen),
            .req_ready      (mem_bus_if[i].req_ready),
            .out_valid      (chk_out_valid),
            .out_rw         (chk_out_rw),
            .out_addr       (chk_out_addr),
            .out_data       (chk_out_data),
            .out_byteen     (chk_out_byteen),
            .out_tag        (chk_out_tag),
            .out_deny       (chk_out_deny),
            .out_fault      (chk_out_fault),
            .out_ready      (mem_req_ready[i]),
            .dram_rsp_valid (mem_rsp_valid[i]),
            .dram_rsp_data  (mem_rsp_data[i]),
            .dram_rsp_tag   (mem_rsp_tag[i]),
            .dram_rsp_ready (mem_rsp_ready[i]),
            .rsp_valid      (mem_bus_if[i].rsp_valid),
            .rsp_data       (mem_bus_if[i].rsp_data.data),
            .rsp_tag        (mem_bus_if[i].rsp_data.tag),
            .rsp_label      (mem_bus_if[i].rsp_data.attr),
            .rsp_ready      (mem_bus_if[i].rsp_ready),
            .epochs_out     (chk_epochs),
            `UNUSED_PIN (fault_overflow),
            `UNUSED_PIN (cnt_reqs),    `UNUSED_PIN (cnt_checked),
            `UNUSED_PIN (cnt_bypassed),`UNUSED_PIN (cnt_allows),
            `UNUSED_PIN (cnt_denies),  `UNUSED_PIN (cnt_hc_hits),
            `UNUSED_PIN (cnt_faulted_reads), `UNUSED_PIN (cnt_dropped_writes),
            `UNUSED_PIN (cnt_hc_misses),`UNUSED_PIN (cnt_claims),
            `UNUSED_PIN (cnt_headers_written), `UNUSED_PIN (cnt_epoch_bumps),
            `UNUSED_PIN (cnt_rejected),`UNUSED_PIN (cnt_aliased),
            `UNUSED_PIN (cnt_reclaimed)
        );

        // Request side: the checker gates what reaches DRAM. Payload fields it
        // does not inspect (data, byteen) pass through unchanged.
        assign mem_req_valid[i]  = chk_out_valid;
        assign mem_req_rw[i]     = chk_out_rw;
        assign mem_req_addr[i]   = chk_out_addr[`VX_CFG_MEM_ADDR_WIDTH-1 -: VX_MEM_ADDR_WIDTH];
        // ALL of these must come from the checker's output stage, not the bus
        // input: the checker pipelines the request, so mixing the two pairs one
        // request's address with the next one's payload.
        assign mem_req_byteen[i] = chk_out_byteen;
        assign mem_req_data[i]   = chk_out_data;
        assign mem_req_tag[i]    = chk_out_tag;
    end

    // Tail of the DCR chain continues to the clusters.
    assign dcr_bus_if.rsp_valid = chk_dcr_if[L3_MEM_PORTS].rsp_valid;
    assign dcr_bus_if.rsp_data  = chk_dcr_if[L3_MEM_PORTS].rsp_data;
`else
    for (genvar i = 0; i < L3_MEM_PORTS; ++i) begin : g_mem_bus_if
        assign mem_req_valid[i]  = mem_bus_if[i].req_valid;
        assign mem_req_rw[i]     = mem_bus_if[i].req_data.rw;
        assign mem_req_byteen[i] = mem_bus_if[i].req_data.byteen;
        assign mem_req_addr[i]   = mem_bus_if[i].req_data.addr;
        assign mem_req_data[i]   = mem_bus_if[i].req_data.data;
        assign mem_req_tag[i]    = mem_bus_if[i].req_data.tag;
        `UNUSED_VAR (mem_bus_if[i].req_data.attr)
        assign mem_bus_if[i].req_ready = mem_req_ready[i];

        assign mem_bus_if[i].rsp_valid     = mem_rsp_valid[i];
        assign mem_bus_if[i].rsp_data.attr = '0;
        assign mem_bus_if[i].rsp_data.data = mem_rsp_data[i];
        assign mem_bus_if[i].rsp_data.tag  = mem_rsp_tag[i];
        assign mem_rsp_ready[i] = mem_bus_if[i].rsp_ready;
    end
    assign label_epochs = '0;
`endif

    wire [`VX_CFG_NUM_CLUSTERS-1:0] per_cluster_busy;

    VX_kmu_bus_if per_cluster_kmu_bus_if[`VX_CFG_NUM_CLUSTERS]();

    VX_kmu_bus_arb #(
        .NUM_INPUTS (1),
        .NUM_OUTPUTS (`VX_CFG_NUM_CLUSTERS),
        .DEST_LSB   (KMU_DEST_LSB_DEVICE),
        .OUT_BUF    ((`VX_CFG_NUM_CLUSTERS > 1) ? 3 : 0)  // register per-cluster kmu fan-out (SLR-crossing skid)
    ) kmu_arb (
        .clk        (clk),
        .reset      (reset),
        .bus_in_if  (kmu_bus_in),
        .bus_out_if (per_cluster_kmu_bus_if)
    );

`ifdef VX_CFG_EXT_RASTER_ENABLE
    VX_raster_launch_if per_cluster_raster_launch_if[`VX_CFG_NUM_CLUSTERS]();
    VX_raster_launch_fork #(
        .NUM_OUTPUTS (`VX_CFG_NUM_CLUSTERS)
    ) raster_launch_fork (
        .clk        (clk),
        .reset      (reset),
        .bus_in_if  (raster_launch_if),
        .bus_out_if (per_cluster_raster_launch_if)
    );
`endif

    // The device MMU surface filters the DCR stream: it assembles the
    // page-table root, pulses the TLB flush, and answers fault reads before
    // the rest of the DCR traffic fans to the clusters.
    VX_dcr_bus_if dcr_cluster_src_if();
`ifdef VX_CFG_VM_ENABLE
    wire [`VX_CFG_XLEN-1:0] mmu_satp;
    wire                    mmu_flush_req;
    wire [`VX_CFG_NUM_CLUSTERS-1:0]                   cl_mmu_flush_done;
    wire [`VX_CFG_NUM_CLUSTERS-1:0]                   cl_mmu_fault_valid;
    wire [`VX_CFG_NUM_CLUSTERS-1:0][`VX_CFG_XLEN-1:0] cl_mmu_fault_va;
    wire [`VX_CFG_NUM_CLUSTERS-1:0][1:0]              cl_mmu_fault_access;
    wire [`VX_CFG_NUM_CLUSTERS-1:0]                   cl_mmu_fault_amo;

    VX_mmu_dcr mmu_dcr (
        .clk                  (clk),
        .reset                (reset),
        .dcr_bus_if           (dcr_bus_if),
        .dcr_bus_out_if       (dcr_cluster_src_if),
        .satp                 (mmu_satp),
        .flush_req            (mmu_flush_req),
        .cluster_flush_done   (cl_mmu_flush_done),
        .cluster_fault_valid  (cl_mmu_fault_valid),
        .cluster_fault_va     (cl_mmu_fault_va),
        .cluster_fault_access (cl_mmu_fault_access),
        .cluster_fault_amo    (cl_mmu_fault_amo)
    );
`else
    assign dcr_cluster_src_if.req_valid = dcr_bus_if.req_valid;
    assign dcr_cluster_src_if.req_data  = dcr_bus_if.req_data;
    assign dcr_bus_if.rsp_valid = dcr_cluster_src_if.rsp_valid;
    assign dcr_bus_if.rsp_data  = dcr_cluster_src_if.rsp_data;
`endif

    VX_dcr_bus_if per_cluster_dcr_bus_if[`VX_CFG_NUM_CLUSTERS]();
    VX_dcr_arb #(
        .NUM_REQS    (`VX_CFG_NUM_CLUSTERS),
        .REQ_OUT_BUF ((`VX_CFG_NUM_CLUSTERS > 1) ? 1 : 0)
    ) dcr_cluster_arb (
        .clk        (clk),
        .reset      (reset),
        .bus_in_if  (dcr_cluster_src_if),
        .bus_out_if (per_cluster_dcr_bus_if)
    );

    // Generate all clusters
    for (genvar cluster_id = 0; cluster_id < `VX_CFG_NUM_CLUSTERS; ++cluster_id) begin : g_clusters

        VX_cluster #(
            .CLUSTER_ID (cluster_id),
            .INSTANCE_ID (`SFORMATF(("cluster%0d", cluster_id)))
        ) cluster (
            `SCOPE_IO_BIND (scope_cluster + cluster_id)

            .clk                (clk),
            .reset              (reset),

        `ifdef PERF_ENABLE
            .sysmem_perf        (sysmem_perf),
        `endif

            .dcr_bus_if         (per_cluster_dcr_bus_if[cluster_id]),

            .mem_bus_if         (per_cluster_mem_bus_if[cluster_id * L2_MEM_PORTS +: L2_MEM_PORTS]),
            .label_epochs       (label_epochs),

            .kmu_bus_if         (per_cluster_kmu_bus_if[cluster_id +: 1]),

        `ifdef VX_CFG_EXT_RASTER_ENABLE
            .raster_launch_if   (per_cluster_raster_launch_if[cluster_id +: 1]),
        `endif

        `ifdef VX_CFG_VM_ENABLE
            .mmu_satp           (mmu_satp),
            .mmu_flush_req      (mmu_flush_req),
            .mmu_flush_done     (cl_mmu_flush_done[cluster_id]),
            .mmu_fault_valid    (cl_mmu_fault_valid[cluster_id]),
            .mmu_fault_va       (cl_mmu_fault_va[cluster_id]),
            .mmu_fault_access   (cl_mmu_fault_access[cluster_id]),
            .mmu_fault_amo      (cl_mmu_fault_amo[cluster_id]),
        `endif

            .busy               (per_cluster_busy[cluster_id])
        );
    end
    // Launch liveness: a beat resident in a per-cluster output skid is folded into
    // busy combinationally. The device input
    // (kmu_bus_in) needs no separate term -- kmu_busy (combinational) covers the
    // presented cycle and the registered per_cluster_busy covers the cycles after.
    wire [`VX_CFG_NUM_CLUSTERS-1:0] per_cluster_kmu_valid;
    for (genvar c = 0; c < `VX_CFG_NUM_CLUSTERS; ++c) begin : g_kmu_link_valid
        assign per_cluster_kmu_valid[c] = per_cluster_kmu_bus_if[c].valid;
    end
    wire busy_r;
    `BUFFER_EX(busy_r, kmu_busy | dcr_bus_if.req_valid | (|per_cluster_busy), 1'b1, 1, (`VX_CFG_NUM_CLUSTERS > 1));
    assign busy = busy_r | kmu_busy | dcr_bus_if.req_valid | (|per_cluster_kmu_valid);

`ifdef PERF_ENABLE

    localparam MEM_PORTS_CTR_W = `CLOG2(VX_MEM_PORTS+1);

    wire [VX_MEM_PORTS-1:0] mem_req_fire, mem_rsp_fire;
    wire [VX_MEM_PORTS-1:0] mem_rd_req_fire, mem_wr_req_fire;

    for (genvar i = 0; i < VX_MEM_PORTS; ++i) begin : g_perf_ctrs
        assign mem_req_fire[i] = mem_req_valid[i] & mem_req_ready[i];
        assign mem_rsp_fire[i] = mem_rsp_valid[i] & mem_rsp_ready[i];
        assign mem_rd_req_fire[i] = mem_req_fire[i] & ~mem_req_rw[i];
        assign mem_wr_req_fire[i] = mem_req_fire[i] & mem_req_rw[i];
    end

    wire [MEM_PORTS_CTR_W-1:0] perf_mem_reads_per_cycle;
    wire [MEM_PORTS_CTR_W-1:0] perf_mem_writes_per_cycle;
    wire [MEM_PORTS_CTR_W-1:0] perf_mem_rsps_per_cycle;

    `POP_COUNT(perf_mem_reads_per_cycle, mem_rd_req_fire);
    `POP_COUNT(perf_mem_writes_per_cycle, mem_wr_req_fire);
    `POP_COUNT(perf_mem_rsps_per_cycle, mem_rsp_fire);

    reg [PERF_CTR_BITS-1:0] perf_mem_pending_reads;

    always @(posedge clk) begin
        if (reset) begin
            perf_mem_pending_reads <= '0;
        end else begin
            perf_mem_pending_reads <= $signed(perf_mem_pending_reads) +
                PERF_CTR_BITS'($signed((MEM_PORTS_CTR_W+1)'(perf_mem_reads_per_cycle) - (MEM_PORTS_CTR_W+1)'(perf_mem_rsps_per_cycle)));
        end
    end

    always @(posedge clk) begin
        if (reset) begin
            mem_perf <= '0;
        end else begin
            mem_perf.reads <= mem_perf.reads + PERF_CTR_BITS'(perf_mem_reads_per_cycle);
            mem_perf.writes <= mem_perf.writes + PERF_CTR_BITS'(perf_mem_writes_per_cycle);
            mem_perf.latency <= mem_perf.latency + perf_mem_pending_reads;
        end
    end

`endif

    // dump device configuration
    initial begin
        `TRACE(0, ("CONFIGS: num_threads=%0d, num_warps=%0d, num_cores=%0d, num_clusters=%0d, socket_size=%0d, local_mem_base=0x%0h, num_barriers=%0d\n",
                    `VX_CFG_NUM_THREADS, `VX_CFG_NUM_WARPS, `VX_CFG_NUM_CORES, `VX_CFG_NUM_CLUSTERS, `VX_CFG_SOCKET_SIZE, `VX_MEM_LMEM_BASE_ADDR, `VX_CFG_NUM_BARRIERS))
    end

`ifdef DBG_TRACE_MEM
    for (genvar i = 0; i < VX_MEM_PORTS; ++i) begin : g_trace
        always @(posedge clk) begin
            if (mem_bus_if[i].req_valid && mem_bus_if[i].req_ready) begin
                if (mem_bus_if[i].req_data.rw) begin
                    `TRACE(2, ("%t: MEM Wr Req[%0d]: addr=0x%0h, byteen=0x%h, data=0x%h, tag=0x%0h (#%0d)\n", $time, i, `TO_FULL_ADDR(mem_bus_if[i].req_data.addr), mem_bus_if[i].req_data.byteen, mem_bus_if[i].req_data.data, mem_bus_if[i].req_data.tag.value, mem_bus_if[i].req_data.tag.uuid))
                end else begin
                    `TRACE(2, ("%t: MEM Rd Req[%0d]: addr=0x%0h, byteen=0x%h, tag=0x%0h (#%0d)\n", $time, i, `TO_FULL_ADDR(mem_bus_if[i].req_data.addr), mem_bus_if[i].req_data.byteen, mem_bus_if[i].req_data.tag.value, mem_bus_if[i].req_data.tag.uuid))
                end
            end
            if (mem_bus_if[i].rsp_valid && mem_bus_if[i].rsp_ready) begin
                `TRACE(2, ("%t: MEM Rd Rsp[%0d]: data=0x%h, tag=0x%0h (#%0d)\n", $time, i, mem_bus_if[i].rsp_data.data, mem_bus_if[i].rsp_data.tag.value, mem_bus_if[i].rsp_data.tag.uuid))
            end
        end
    end
`endif

`ifdef SIMULATION
    always @(posedge clk) begin
        $fflush(); // flush stdout buffer
    end
`endif

endmodule
