// Standalone top for VX_mem_checker (R1 testbench, and the R5 synthesis DUT).
//
// Flattens the DCR bus interface and the request/response ports so Verilator's
// C++ harness can drive them directly, following hw/unittest/cache's
// VX_cache_top. The same wrapper is what the Yosys and Xilinx gates
// synthesize, so the module R5 measures is the module the TB verifies.

`include "VX_define.vh"

module VX_mem_checker_top import VX_gpu_pkg::*, VX_sec_pkg::*; #(
    parameter HIT_LATENCY  = `VX_CFG_CHECKER_HIT_LATENCY,
    parameter MISS_LATENCY = `VX_CFG_CHECKER_MISS_LATENCY
) (
    input  wire clk,
    input  wire reset,

    // DCR write port (flattened; reads are R3's, see VX_checker_dcr)
    input  wire                      dcr_wr_valid,
    input  wire [11:0]               dcr_wr_addr,
    input  wire [31:0]               dcr_wr_data,

    // request in
    input  wire                      req_valid,
    input  wire                      req_rw,
    input  wire [`VX_CFG_MEM_ADDR_WIDTH-1:0] req_addr,
    input  wire [CHK_OWNER_W-1:0]    req_owner,
    output wire                      req_ready,

    // request out + verdict
    output wire                      out_valid,
    output wire                      out_rw,
    output wire [`VX_CFG_MEM_ADDR_WIDTH-1:0] out_addr,
    output wire [511:0]              out_data,
    output wire [63:0]               out_byteen,
    output wire [15:0]               out_tag,
    output wire                      out_deny,
    output wire                      out_fault,
    input  wire                      out_ready,

    // R3: response channel + fault injection
    input  wire [15:0]               req_tag,
    input  wire [511:0]              req_data,
    input  wire [63:0]               req_byteen,
    input  wire                      dram_rsp_valid,
    input  wire [511:0]              dram_rsp_data,
    input  wire [15:0]               dram_rsp_tag,
    output wire                      dram_rsp_ready,
    output wire                      rsp_valid,
    output wire [511:0]              rsp_data,
    output wire [15:0]               rsp_tag,
    input  wire                      rsp_ready,
    output wire                      fault_overflow,

    // counters
    output wire [31:0] cnt_reqs,
    output wire [31:0] cnt_checked,
    output wire [31:0] cnt_bypassed,
    output wire [31:0] cnt_allows,
    output wire [31:0] cnt_denies,
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
    VX_dcr_bus_if dcr_in_if();
    VX_dcr_bus_if dcr_out_if();

    assign dcr_in_if.req_valid     = dcr_wr_valid;
    assign dcr_in_if.req_data.rw   = 1'b1;
    assign dcr_in_if.req_data.addr = `VX_DCR_ADDR_BITS'(dcr_wr_addr);
    assign dcr_in_if.req_data.data = `VX_DCR_DATA_BITS'(dcr_wr_data);

    // Nothing downstream in the standalone harness; terminate the pass-through.
    // The checker drives dcr_out_if.req_* onward and mirrors rsp_* back, so
    // those are driven, not unused — only the onward request has no consumer
    // here, and Verilator is content to leave it dangling in a top module.
    assign dcr_out_if.rsp_valid = 1'b0;
    assign dcr_out_if.rsp_data  = '0;

    VX_mem_checker #(
        .INSTANCE_ID  ("checker"),
        .HIT_LATENCY  (HIT_LATENCY),
        .MISS_LATENCY (MISS_LATENCY),
        .ENFORCE      (1),          // the TB exercises enforcement explicitly
        .DATA_SIZE    (64),
        .TAG_WIDTH    (16),
        .FAULT_DEPTH  (16)
    ) chk_inst (
        .clk                 (clk),
        .reset               (reset),
        .dcr_bus_if          (dcr_in_if),
        .dcr_bus_out_if      (dcr_out_if),
        .req_valid           (req_valid),
        .req_rw              (req_rw),
        .req_addr            (req_addr),
        .req_owner           (req_owner),
        .req_ready           (req_ready),
        .out_valid           (out_valid),
        .out_rw              (out_rw),
        .out_addr            (out_addr),
        .out_data            (out_data),
        .out_byteen          (out_byteen),
        .out_tag             (out_tag),
        .out_deny            (out_deny),
        .out_fault           (out_fault),
        .out_ready           (out_ready),
        .req_tag             (req_tag),
        .req_data            (req_data),
        .req_byteen          (req_byteen),
        .dram_rsp_valid      (dram_rsp_valid),
        .dram_rsp_data       (dram_rsp_data),
        .dram_rsp_tag        (dram_rsp_tag),
        .dram_rsp_ready      (dram_rsp_ready),
        .rsp_valid           (rsp_valid),
        .rsp_data            (rsp_data),
        .rsp_tag             (rsp_tag),
        .rsp_ready           (rsp_ready),
        .fault_overflow      (fault_overflow),
        .cnt_reqs            (cnt_reqs),
        .cnt_checked         (cnt_checked),
        .cnt_bypassed        (cnt_bypassed),
        .cnt_allows          (cnt_allows),
        .cnt_denies          (cnt_denies),
        .cnt_faulted_reads   (cnt_faulted_reads),
        .cnt_dropped_writes  (cnt_dropped_writes),
        .cnt_hc_hits         (cnt_hc_hits),
        .cnt_hc_misses       (cnt_hc_misses),
        .cnt_claims          (cnt_claims),
        .cnt_headers_written (cnt_headers_written),
        .cnt_epoch_bumps     (cnt_epoch_bumps),
        .cnt_rejected        (cnt_rejected),
        .cnt_aliased         (cnt_aliased),
        .cnt_reclaimed       (cnt_reclaimed)
    );

endmodule
