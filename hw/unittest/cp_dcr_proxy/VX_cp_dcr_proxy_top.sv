// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

`include "VX_define.vh"

// ============================================================================
// VX_cp_dcr_proxy_top — verilator-friendly wrapper around VX_cp_dcr_proxy.
//
// Repackages the `cmd_t` input into a flat packed bus so the C++ harness
// can build commands as raw bits. The DCR request/response wires are
// already plain scalars; pass them through.
// ============================================================================

module VX_cp_dcr_proxy_top
  import VX_cp_pkg::*;
#(
  parameter int NUM_QUEUES = 4,
  localparam int QW = (NUM_QUEUES > 1) ? $clog2(NUM_QUEUES) : 1
)(
  input  wire                          clk,
  input  wire                          reset,

  input  wire                          grant,
  input  wire [QW-1:0]                 grant_q,
  output wire                          idle,
  input  wire [$bits(cmd_t)-1:0]       cmd_packed,
  output wire                          done,

  output wire [`VX_DCR_DATA_BITS-1:0]  last_rsp_data,
  output wire                          rsp_update,
  output wire [QW-1:0]                 cur_q,
  output wire                          blocked,

  output wire                          shadow_wr,
  output wire [7:0]                    shadow_idx,
  output wire [`VX_DCR_DATA_BITS-1:0]  shadow_wr_data,
  input  wire [`VX_DCR_DATA_BITS-1:0]  shadow_rd_data,

  output wire                          dcr_req_valid,
  output wire                          dcr_req_rw,
  output wire [`VX_DCR_ADDR_BITS-1:0]  dcr_req_addr,
  output wire [`VX_DCR_DATA_BITS-1:0]  dcr_req_data,
  output wire [QW-1:0]                 dcr_req_issuer,
  input  wire                          dcr_rsp_valid,
  input  wire [`VX_DCR_DATA_BITS-1:0]  dcr_rsp_data
);

  cmd_t cmd_typed;
  assign cmd_typed = cmd_t'(cmd_packed);
  wire [SHADOW_IDX_W-1:0] idx;
  assign shadow_idx = 8'(idx);

  VX_cp_dcr_proxy #(.NUM_QUEUES(NUM_QUEUES)) u_dut (
    .clk            (clk),
    .reset          (reset),
    .grant          (grant),
    .grant_q        (grant_q),
    .idle           (idle),
    .cmd            (cmd_typed),
    .done           (done),
    .last_rsp_data  (last_rsp_data),
    .rsp_update     (rsp_update),
    .cur_q          (cur_q),
    .blocked        (blocked),
    .shadow_wr      (shadow_wr),
    .shadow_idx     (idx),
    .shadow_wr_data (shadow_wr_data),
    .shadow_rd_data (shadow_rd_data),
    .dcr_req_valid  (dcr_req_valid),
    .dcr_req_rw     (dcr_req_rw),
    .dcr_req_addr   (dcr_req_addr),
    .dcr_req_data   (dcr_req_data),
    .dcr_req_issuer (dcr_req_issuer),
    .dcr_rsp_valid  (dcr_rsp_valid),
    .dcr_rsp_data   (dcr_rsp_data)
  );

endmodule : VX_cp_dcr_proxy_top
