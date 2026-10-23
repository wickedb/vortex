// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

`include "VX_define.vh"

// ============================================================================
// VX_cp_launch — KMU start/busy wrapper. Owned by the KMU resource arbiter.
//
// KMU arbitration holds for the entire duration of a launch:
//   IDLE         : no grant yet
//   REPLAY       : write the launching queue's shadowed launch registers
//                  into the GPU (authorship; see VX_cp_pkg launch shadow)
//   SETTLE       : let the last replayed write reach the GPU before start
//   PULSE_START  : assert `start` for one cycle
//   WAIT_BUSY    : Vortex pulls `busy` high (kernel started)
//   WAIT_DRAIN   : Vortex drops `busy` low (kernel done) → fire `done`,
//                  go back to IDLE
//
// The core lets the KMU arbiter grant only while this FSM is idle, so exactly
// one CPE waits on each `done`.
//
// `grant` is the OR of per-CPE grants from the KMU arbiter (the CP core
// glues all N bids onto this single input).
// ============================================================================

module VX_cp_launch
  import VX_cp_pkg::*;
#(
  parameter int NUM_QUEUES = VX_CP_NUM_QUEUES_C,
  localparam int QW = (NUM_QUEUES > 1) ? $clog2(NUM_QUEUES) : 1
)(
  input  wire  clk,
  input  wire  reset,

  input  wire  grant,         // OR of per-CPE grants from KMU arbiter
  input  wire [QW-1:0] grant_q,  // the queue granted (launch issuer)
  output logic start,         // pulsed to gpu_if.start (Vortex)
  input  wire  gpu_busy,      // from gpu_if.busy (Vortex)
  output logic done,          // back to engine: launch fully drained
  output logic idle,          // no launch held: the KMU arbiter may grant

  // Launch-shadow replay (spec D4). Between the grant and `start` the launch
  // owns the GPU's DCR bus and writes the launching queue's shadow into it,
  // so the kernel runs with that queue's launch registers whatever other
  // queues wrote in between. The core muxes the bus to us while `replaying`.
  output logic                         replaying,
  output logic [SHADOW_IDX_W-1:0]      shadow_idx,
  input  wire  [`VX_DCR_DATA_BITS-1:0] shadow_rd_data,
  output logic [QW-1:0]                launch_q,
  output logic                         dcr_req_valid,
  output logic [`VX_DCR_ADDR_BITS-1:0] dcr_req_addr,
  output logic [`VX_DCR_DATA_BITS-1:0] dcr_req_data,
  input  wire                          dcr_req_ready
);

  // The DCR request path (the GPU-side elastic buffer) is deeper than the
  // start pipe, so `start` waits a few cycles after the last replayed write
  // to reach the GPU behind it rather than ahead of it.
  localparam int SETTLE = 4;

  typedef enum logic [2:0] {
    S_IDLE,
    S_REPLAY,
    S_SETTLE,
    S_PULSE_START,
    S_WAIT_BUSY,
    S_WAIT_DRAIN
  } state_e;

  state_e state;
  logic [SHADOW_IDX_W-1:0] idx;
  logic [2:0]              settle;
  logic [QW-1:0]           q_r;

  always_ff @(posedge clk) begin
    if (reset) begin
      state  <= S_IDLE;
      idx    <= '0;
      settle <= '0;
      q_r    <= '0;
    end else begin
      case (state)
        S_IDLE: begin
          if (grant) begin
            q_r   <= grant_q;
            idx   <= '0;
            state <= S_REPLAY;
          end
        end
        S_REPLAY: begin
          if (dcr_req_ready) begin
            if (int'(idx) == NUM_SHADOW - 1) begin
              settle <= 3'(SETTLE);
              state  <= S_SETTLE;
            end else begin
              idx <= idx + SHADOW_IDX_W'(1);
            end
          end
        end
        S_SETTLE: begin
          settle <= settle - 3'd1;
          if (settle == 3'd1) state <= S_PULSE_START;
        end
        S_PULSE_START: begin
          state <= S_WAIT_BUSY;
        end
        S_WAIT_BUSY: begin
          // Vortex's busy might rise the next cycle after `start` fires;
          // we wait for that rising edge.
          if (gpu_busy) state <= S_WAIT_DRAIN;
        end
        S_WAIT_DRAIN: begin
          if (!gpu_busy) state <= S_IDLE;
        end
        default: state <= S_IDLE;
      endcase
    end
  end

  always_comb begin
    start         = (state == S_PULSE_START);
    done          = (state == S_WAIT_DRAIN) && !gpu_busy;
    idle          = (state == S_IDLE);
    replaying     = (state == S_REPLAY);
    shadow_idx    = idx;
    launch_q      = q_r;
    dcr_req_valid = (state == S_REPLAY);
    dcr_req_addr  = shadow_addr(idx);
    dcr_req_data  = shadow_rd_data;
  end

endmodule : VX_cp_launch
