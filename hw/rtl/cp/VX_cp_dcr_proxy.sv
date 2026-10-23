// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

`include "VX_define.vh"

// ============================================================================
// VX_cp_dcr_proxy — DCR request/response gateway between the CP and Vortex.
// Owned by the DCR resource arbiter.
//
// For CMD_DCR_WRITE (cmd.arg0 = dcr_addr, cmd.arg1 = dcr_value):
//   IDLE → REQ (drive dcr_req with rw=1) → DONE → IDLE.
//
// For CMD_DCR_READ (cmd.arg0 = dcr_addr):
//   IDLE → REQ (drive dcr_req with rw=0) → WAIT_RSP (latch dcr_rsp_data
//        when valid) → DONE → IDLE.
//
// For CMD_CACHE_FLUSH (cmd.arg0 = number of cores):
//   A cache flush is a per-core DCR-read to VX_DCR_BASE_CACHE_FLUSH whose
//   response is the per-core flush-complete signal (see VX_dcr_data). One
//   CMD_CACHE_FLUSH sweeps that read across every core — REQ/WAIT_RSP per
//   core — and retires only once the last core's flush completes. This is
//   the ACQUIRE_MEM model: a single command in the ring, executed by
//   the CP across all cores, that the host posts after CMD_LAUNCH so it
//   sees coherent results. The host fills cmd.arg0 from VX_CAPS_NUM_CORES.
//
// The most-recent read response is published on `last_rsp_data` and is
// also exposed on the AXI-Lite regfile so the host can poll it after
// observing the seqnum advance.
// ============================================================================

module VX_cp_dcr_proxy
  import VX_cp_pkg::*;
#(
  parameter int NUM_QUEUES = VX_CP_NUM_QUEUES_C,
  localparam int QW = (NUM_QUEUES > 1) ? $clog2(NUM_QUEUES) : 1
)(
  input  wire clk,
  input  wire reset,

  input  wire  grant,
  // The queue granted this cycle: the command's issuer (authorship).
  input  wire [QW-1:0] grant_q,
  // High while no command is in flight. The core lets the DCR arbiter grant
  // only then, so exactly one queue waits on each `done`.
  output logic idle,
  // verilator lint_off UNUSED
  // Only cmd.hdr.opcode, cmd.arg0, and cmd.arg1 are read here. arg2 and
  // profile_slot pass through untouched on the way to the engine; the
  // top-level instantiation hands us the full struct.
  input  cmd_t cmd,
  // verilator lint_on UNUSED
  output logic done,

  // Most recent CMD_DCR_READ response value (valid while `done` is high
  // after a read; tied to 0 after writes). Engine snapshots this when it
  // observes done for a read command.
  output logic [`VX_DCR_DATA_BITS-1:0] last_rsp_data,
  // `done` for a command that produced a response, and the queue it is for:
  // each queue keeps its own Q_LAST_DCR_RSP.
  output logic                         rsp_update,
  output logic [QW-1:0]                cur_q,
  // One-cycle pulse: a read of the checker window was refused (spec D5).
  output logic                         blocked,

  // Launch shadow (spec D4): a write of a launch register is captured for the
  // issuing queue instead of reaching the GPU, and a read of one is answered
  // from that queue's shadow.
  output logic                         shadow_wr,
  output logic [SHADOW_IDX_W-1:0]      shadow_idx,
  output logic [`VX_DCR_DATA_BITS-1:0] shadow_wr_data,
  input  wire  [`VX_DCR_DATA_BITS-1:0] shadow_rd_data,

  // Vortex DCR port (driven through VX_cp_gpu_if by VX_cp_core).
  output logic                         dcr_req_valid,
  output logic                         dcr_req_rw,
  output logic [`VX_DCR_ADDR_BITS-1:0] dcr_req_addr,
  output logic [`VX_DCR_DATA_BITS-1:0] dcr_req_data,
  output logic [QW-1:0]                dcr_req_issuer,
  input  wire                          dcr_rsp_valid,
  input  wire  [`VX_DCR_DATA_BITS-1:0] dcr_rsp_data
);

  typedef enum logic [1:0] {
    S_IDLE,
    S_REQ,           // hold dcr_req_valid until consumed (single cycle here)
    S_WAIT_RSP,      // read commands only
    S_DONE
  } state_e;

  // Width of the per-core sweep counter for CMD_CACHE_FLUSH. The flush
  // targets `mpm_target_cid` in dcr_req_data[15:0] (see VX_dcr_data).
  localparam int CIDW = 16;

  state_e state;
  logic   pending_is_read;
  logic   pending_is_flush;
  // cmd fields are only valid for one cycle (grant pulse); capture on IDLE → REQ.
  logic [`VX_DCR_ADDR_BITS-1:0]  pending_addr;
  logic [`VX_DCR_DATA_BITS-1:0]  pending_data;
  logic [`VX_DCR_DATA_BITS-1:0]  rsp_data_r;
  logic [CIDW-1:0]               flush_total;  // cores remaining + done
  logic [CIDW-1:0]               flush_cid;    // core currently flushing

  wire                          is_read    = (cmd.hdr.opcode == 8'(CMD_DCR_READ));
  wire                          is_flush   = (cmd.hdr.opcode == 8'(CMD_CACHE_FLUSH));
  wire [`VX_DCR_ADDR_BITS-1:0]  cmd_addr   = cmd.arg0[`VX_DCR_ADDR_BITS-1:0];
  wire [`VX_DCR_DATA_BITS-1:0]  cmd_data   = cmd.arg1[`VX_DCR_DATA_BITS-1:0];
  wire [CIDW-1:0]               cmd_ncores = cmd.arg0[CIDW-1:0];

  // Commands the proxy completes without the GPU's DCR bus.
  wire to_shadow  = !is_read && !is_flush && is_shadow_addr(cmd_addr);
  wire from_shadow = is_read && is_shadow_addr(cmd_addr);
  // VX_CFG_CHECKER_DEBUG_READS is always defined (0 by default).
  wire refuse_read = (`VX_CFG_CHECKER_DEBUG_READS == 0) && is_read && is_checker_addr(cmd_addr);
  logic [QW-1:0] q_r;

  always_ff @(posedge clk) begin
    if (reset) begin
      state            <= S_IDLE;
      pending_is_read  <= 1'b0;
      pending_is_flush <= 1'b0;
      pending_addr     <= '0;
      pending_data     <= '0;
      rsp_data_r       <= '0;
      flush_total      <= '0;
      flush_cid        <= '0;
      q_r              <= '0;
    end else begin
      case (state)
        S_IDLE: begin
          if (grant) begin
            pending_is_read  <= is_read;
            pending_is_flush <= is_flush;
            pending_addr     <= cmd_addr;
            pending_data     <= cmd_data;
            q_r              <= grant_q;
            if (to_shadow) begin
              state <= S_DONE;              // captured below; nothing to send
            end else if (from_shadow) begin
              rsp_data_r <= shadow_rd_data; // this queue's launch register
              state      <= S_DONE;
            end else if (refuse_read) begin
              rsp_data_r <= '0;
              state      <= S_DONE;
            end else if (is_flush) begin
              flush_total <= cmd_ncores;
              flush_cid   <= '0;
              // a 0-core flush (degenerate) retires immediately
              state       <= (cmd_ncores == '0) ? S_DONE : S_REQ;
            end else begin
              state <= S_REQ;
            end
          end
        end
        S_REQ: begin
          // The Vortex DCR bus consumes the request in a single cycle
          // (req_valid handshakes combinationally; no req_ready backpressure).
          if (pending_is_read || pending_is_flush)
            state <= S_WAIT_RSP;
          else
            state <= S_DONE;
        end
        S_WAIT_RSP: begin
          if (dcr_rsp_valid) begin
            rsp_data_r <= dcr_rsp_data;
            if (pending_is_flush && ((flush_cid + CIDW'(1)) < flush_total)) begin
              // this core flushed; advance the sweep to the next core
              flush_cid <= flush_cid + CIDW'(1);
              state     <= S_REQ;
            end else begin
              state <= S_DONE;
            end
          end
        end
        S_DONE: begin
          state <= S_IDLE;
        end
        default: state <= S_IDLE;
      endcase
    end
  end

  always_comb begin
    dcr_req_valid = (state == S_REQ);
    if (pending_is_flush) begin
      // a cache flush is a per-core DCR read to VX_DCR_BASE_CACHE_FLUSH;
      // the target core index rides in the low 16 bits of dcr_req_data.
      dcr_req_rw   = 1'b0;
      dcr_req_addr = `VX_DCR_ADDR_BITS'(`VX_DCR_BASE_CACHE_FLUSH);
      dcr_req_data = `VX_DCR_DATA_BITS'(flush_cid);
    end else begin
      dcr_req_rw   = !pending_is_read;
      dcr_req_addr = pending_addr;
      dcr_req_data = pending_data;
    end
    dcr_req_issuer = q_r;
    done          = (state == S_DONE);
    last_rsp_data = rsp_data_r;
    rsp_update    = (state == S_DONE) && (pending_is_read || pending_is_flush);
    cur_q         = q_r;
    idle          = (state == S_IDLE);
  end

  // Shadow port: the write lands, and the read is looked up, in the grant
  // cycle, for the queue being granted.
  assign shadow_wr      = (state == S_IDLE) && grant && to_shadow;
  assign shadow_idx     = shadow_index(cmd_addr);
  assign shadow_wr_data = cmd_data;
  assign blocked        = (state == S_IDLE) && grant && refuse_read;

endmodule : VX_cp_dcr_proxy
