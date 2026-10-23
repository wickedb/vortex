// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

`include "VX_define.vh"

// ============================================================================
// VX_cp_launch_top — verilator-friendly wrapper around VX_cp_launch, built
// with four queues so the launch-shadow replay is exercised per queue. The
// shadow store itself lives in VX_cp_core; the test models it in C++ and
// answers shadow_rd_data from (launch_q, shadow_idx). The shadow geometry is
// exported so the test needs no copy of the DCR map.
// ============================================================================

module VX_cp_launch_top
  import VX_cp_pkg::*;
#(
  parameter int NUM_QUEUES = 4,
  localparam int QW = (NUM_QUEUES > 1) ? $clog2(NUM_QUEUES) : 1
)(
  input  wire                          clk,
  input  wire                          reset,
  input  wire                          grant,
  input  wire [QW-1:0]                 grant_q,
  output wire                          start,
  input  wire                          gpu_busy,
  output wire                          done,
  output wire                          idle,
  output wire                          replaying,
  output wire [7:0]                    shadow_idx,
  input  wire [`VX_DCR_DATA_BITS-1:0]  shadow_rd_data,
  output wire [QW-1:0]                 launch_q,
  output wire                          dcr_req_valid,
  output wire [`VX_DCR_ADDR_BITS-1:0]  dcr_req_addr,
  output wire [`VX_DCR_DATA_BITS-1:0]  dcr_req_data,
  input  wire                          dcr_req_ready,
  // Shadow geometry, constant.
  output wire [7:0]                    num_shadow,
  output wire [`VX_DCR_ADDR_BITS-1:0]  shadow_base
);

  wire [SHADOW_IDX_W-1:0] idx;

  VX_cp_launch #(.NUM_QUEUES(NUM_QUEUES)) u_dut (
    .clk            (clk),
    .reset          (reset),
    .grant          (grant),
    .grant_q        (grant_q),
    .start          (start),
    .gpu_busy       (gpu_busy),
    .done           (done),
    .idle           (idle),
    .replaying      (replaying),
    .shadow_idx     (idx),
    .shadow_rd_data (shadow_rd_data),
    .launch_q       (launch_q),
    .dcr_req_valid  (dcr_req_valid),
    .dcr_req_addr   (dcr_req_addr),
    .dcr_req_data   (dcr_req_data),
    .dcr_req_ready  (dcr_req_ready)
  );

  assign shadow_idx  = 8'(idx);
  assign num_shadow  = 8'(NUM_SHADOW);
  assign shadow_base = `VX_DCR_ADDR_BITS'(`VX_DCR_KMU_STATE_BEGIN);

endmodule : VX_cp_launch_top
