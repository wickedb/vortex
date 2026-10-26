// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

`include "VX_define.vh"

// ============================================================================
// VX_cp_core — top-level Command Processor wrapper.
//
// Integrates everything in rtl/cp/ into one block the AFU shim can
// instantiate alongside Vortex:
//
//                         ┌──────────────────────────┐
//   AXI4-Lite host ──────►│  VX_cp_axil_regfile      │── per-queue
//   (control plane)       │                          │   cpe_state
//                         └──┬───────────────────────┘
//                            │ q_state[NUM_QUEUES]
//                  ┌─────────┴────────┬──────────────┬──────────┐
//                  │ fetch[NUM_QUEUES] │ engine[N]    │ cmpl     │
//                  │ + embedded unpack │  + 4 bid     │  retire  │
//                  │  → cmd_in stream  │    arbiters  │   slots  │
//                  └─────────┬─────────┴───┬──────────┴────┬─────┘
//                            │              │               │
//                            ▼              ▼               ▼
//      ┌──────────────────────────────┐   ┌────────────────────────┐
//      │  host xbar: fetch[N] + cmpl  │   │  dev xbar: DMA(dev) +   │
//      │            + DMA(host)       │   │            event       │
//      └───────────────┬──────────────┘   └───────────┬────────────┘
//                      ▼ axi_host (AXI4)              ▼ axi_dev (AXI4)
//
//   Dual data plane: XRT pins each kernel AXI master to exactly one memory
//   resource, so the CP carries two — axi_host reaches host memory (the
//   command ring lives there; it is one end of every upload/download) and
//   axi_dev reaches device memory. The DMA engine straddles both: its
//   opcode picks the read-source and write-destination port.
//
//   The shared KMU launch / DCR proxy connect to gpu_if (Vortex side).
//
// AXI master TID layout (per xbar):
//   bit [ID_W-1 : ID_W-SRC_W]  = source index (xbar sets/inspects this for
//                                response routing)
//   bit [ID_W-SRC_W-1 : 0]     = sub-tag, source-defined
// ============================================================================

// Connect a VX_mem_axi_if `src` (master) to a `slot` of an xbar's `src`
// array (the xbar drives that array as an AXI slave).
`define CP_AXI_LINK_ID(slot, src, awid_v, arid_v) \
  assign slot.awvalid = src.awvalid;      \
  assign slot.awaddr  = src.awaddr;       \
  assign slot.awid    = awid_v;           \
  assign slot.awlen   = src.awlen;        \
  assign slot.awsize  = src.awsize;       \
  assign slot.awburst = src.awburst;      \
  assign src.awready  = slot.awready;     \
  assign slot.wvalid  = src.wvalid;       \
  assign slot.wdata   = src.wdata;        \
  assign slot.wstrb   = src.wstrb;        \
  assign slot.wlast   = src.wlast;        \
  assign src.wready   = slot.wready;      \
  assign src.bvalid   = slot.bvalid;      \
  assign src.bid      = slot.bid;         \
  assign src.bresp    = slot.bresp;       \
  assign slot.bready  = src.bready;       \
  assign slot.arvalid = src.arvalid;      \
  assign slot.araddr  = src.araddr;       \
  assign slot.arid    = arid_v;           \
  assign slot.arlen   = src.arlen;        \
  assign slot.arsize  = src.arsize;       \
  assign slot.arburst = src.arburst;      \
  assign src.arready  = slot.arready;     \
  assign src.rvalid   = slot.rvalid;      \
  assign src.rdata    = slot.rdata;       \
  assign src.rid      = slot.rid;         \
  assign src.rlast    = slot.rlast;       \
  assign src.rresp    = slot.rresp;       \
  assign slot.rready  = src.rready

`define CP_AXI_LINK(slot, src) `CP_AXI_LINK_ID(slot, src, src.awid, src.arid)

module VX_cp_core
  import VX_cp_pkg::*;
#(
  parameter int NUM_QUEUES = VX_CP_NUM_QUEUES_C,
  parameter int ADDR_W     = 64,
  parameter int DATA_W     = 512,
  parameter int ID_W       = VX_CP_AXI_TID_WIDTH_C,
  parameter int AXIL_AW    = 16
)(
  input  wire                       clk,
  input  wire                       reset,

  // Host control plane (AXI4-Lite slave).
  VX_cp_axil_s_if.slave             axil_s,

  // Host-memory data plane (AXI4 master) — command ring + completion +
  // host side of every upload/download.
  VX_mem_axi_if.master             axi_host,

  // Device-memory data plane (AXI4 master) — device side of upload/download
  // and event-counter traffic.
  VX_mem_axi_if.master             axi_dev,

  // AFU host-port drain counters, packed by VX_afu_wrap; regfile debug regs.
  input  wire [31:0]               dbg_host_w_counts,
  input  wire [31:0]               dbg_host_r_counts,

  // GPU-facing handshake (Vortex DCR + start/busy).
  VX_cp_gpu_if.master               gpu_if,

  // One-cycle pulse after any queue retires a command (drives the
  // platform irq pin). Named `irq` rather than `interrupt` because the
  // latter is a SystemVerilog reserved keyword (Verilator SYMRSVDWORD).
  output wire                       irq
);

  // Host xbar sources: fetch[NUM_QUEUES] + completion + DMA(host side).
  localparam int N_SRC_HOST = NUM_QUEUES + 2;
  // Device xbar sources: DMA(dev side) + event unit.
  localparam int N_SRC_DEV  = 2;

  // Source-slot indices.
  localparam int SLOT_CMPL     = NUM_QUEUES;       // host xbar
  localparam int SLOT_DMA_HOST = NUM_QUEUES + 1;   // host xbar
  localparam int SLOT_DMA_DEV  = 0;                // dev xbar
  localparam int SLOT_EVENT    = 1;                // dev xbar

  // ----- Regfile-owned per-queue programmable state -----
  cpe_state_t q_state          [NUM_QUEUES];
  logic       q_reset_pulse    [NUM_QUEUES];

  // Telemetry inputs from CPEs to the regfile.
  logic [63:0] q_head_to_reg   [NUM_QUEUES];
  logic [63:0] q_seqnum_to_reg [NUM_QUEUES];
  logic [31:0] q_error_to_reg  [NUM_QUEUES];

  // Aggregated CP status seen by the host through CP_STATUS.
  logic cp_busy;
  logic cp_error;

  wire [`VX_DCR_DATA_BITS-1:0] dcr_last_rsp_data;
  // Per-queue Q_LAST_DCR_RSP and Q_DCR_BLOCKED: a queue's read result must not
  // be overwritten by another queue's read before its host collects it.
  logic [`VX_DCR_DATA_BITS-1:0] q_last_rsp [NUM_QUEUES];
  logic [31:0]                  q_blocked  [NUM_QUEUES];

  // Queue-reset plumbing (used by the regfile port map directly below and by
  // the g_queue_reset block; declared BEFORE first use -- Vivado mints 1-bit
  // implicit nets at a pre-declaration use and keeps both, which silently
  // severed q_clear_ack from the real q_clear in synthesis while Verilator
  // accepted the ordering. Same footgun as the drain-counter wires in
  // VX_afu_wrap.)
  logic       q_reset_pending [NUM_QUEUES];
  logic       q_clear         [NUM_QUEUES];
  logic       fetch_idle      [NUM_QUEUES];
  logic       engine_idle     [NUM_QUEUES];

  VX_cp_axil_regfile #(
    .NUM_QUEUES (NUM_QUEUES),
    .ADDR_W     (AXIL_AW)
  ) u_regfile (
    .clk            (clk),
    .reset          (reset),
    .axil_s         (axil_s),
    .cp_busy        (cp_busy),
    .cp_error       (cp_error),
    .q_head         (q_head_to_reg),
    .q_seqnum       (q_seqnum_to_reg),
    .q_error        (q_error_to_reg),
    .last_dcr_rsp   (q_last_rsp),
    .dcr_blocked    (q_blocked),
    .q_state        (q_state),
    .q_reset_pulse  (q_reset_pulse),
    .q_clear_ack    (q_clear),
    .dbg_host_w_counts (dbg_host_w_counts),
    .dbg_host_r_counts (dbg_host_r_counts)
  );

  // ----- Per-CPE wires -----
  logic [63:0] seqnum_out [NUM_QUEUES];

  // Bid lines to the four arbiters.
  VX_cp_engine_bid_if bid_kmu   [NUM_QUEUES] ();
  VX_cp_engine_bid_if bid_dma   [NUM_QUEUES] ();
  VX_cp_engine_bid_if bid_dcr   [NUM_QUEUES] ();
  VX_cp_engine_bid_if bid_event [NUM_QUEUES] ();

  // Retire + profile pulses from each CPE. retire_evt is held by the
  // engine until retire_ready (from VX_cp_completion) handshakes.
  logic        retire_evt    [NUM_QUEUES];
  logic [63:0] retire_seqnum [NUM_QUEUES];
  logic        retire_ready  [NUM_QUEUES];
  logic        submit_evt    [NUM_QUEUES];
  logic        start_evt     [NUM_QUEUES];
  logic        end_evt       [NUM_QUEUES];
  logic [63:0] profile_slot  [NUM_QUEUES];

  // Per-CPE fetch → engine streaming command port.
  logic       cpe_cmd_valid [NUM_QUEUES];
  cmd_t       cpe_cmd       [NUM_QUEUES];
  logic       cpe_cmd_ready [NUM_QUEUES];

  // Shared-resource done pulses.
  logic launch_done, dma_done, dcr_done, event_done;

  // Per-CPE AXI sub-master ports (fetch is the only AXI user per CPE).
  VX_mem_axi_if #(.ADDR_W(ADDR_W), .DATA_W(DATA_W), .ID_W(ID_W))
                       fetch_axi [NUM_QUEUES] ();

  // ----- N CPEs (fetch + engine) -----
  generate
    for (genvar q = 0; q < NUM_QUEUES; ++q) begin : g_cpe
      VX_cp_fetch #(.QID(q)) u_fetch (
        .clk           (clk),
        .reset         (reset),
        .state_in      (q_state[q]),
        .head_out      (q_head_to_reg[q]),
        .cmd_out_valid (cpe_cmd_valid[q]),
        .cmd_out       (cpe_cmd[q]),
        .cmd_out_ready (cpe_cmd_ready[q]),
        .stop_req      (q_reset_pending[q]),
        .clear         (q_clear[q]),
        .idle          (fetch_idle[q]),
        .axi_m         (fetch_axi[q])
      );

      VX_cp_engine #(.QID(q)) u_engine (
        .clk           (clk),
        .reset         (reset),
        .prio_in       (q_state[q].prio),
        .seqnum_out    (seqnum_out[q]),
        .cmd_in_valid  (cpe_cmd_valid[q]),
        .cmd_in        (cpe_cmd[q]),
        .cmd_in_ready  (cpe_cmd_ready[q]),
        .bid_kmu       (bid_kmu[q]),
        .bid_dma       (bid_dma[q]),
        .bid_dcr       (bid_dcr[q]),
        .bid_event     (bid_event[q]),
        // Done pulses are broadcast from the shared resource modules to
        // every CPE. A resource's arbiter grants only while the resource is
        // idle (g_bid_gate), so only the granted CPE is in S_WAIT_DONE when
        // the matching pulse arrives.
        .kmu_done_i    (launch_done),
        .dma_done_i    (dma_done),
        .dcr_done_i    (dcr_done),
        .event_done_i  (event_done),
        .retire_evt    (retire_evt[q]),
        .retire_seqnum (retire_seqnum[q]),
        .retire_ready_i(retire_ready[q]),
        .submit_evt    (submit_evt[q]),
        .start_evt     (start_evt[q]),
        .end_evt       (end_evt[q]),
        .profile_slot  (profile_slot[q]),
        .clear         (q_clear[q]),
        .idle          (engine_idle[q])
      );

      // Telemetry up to the regfile.
      assign q_seqnum_to_reg[q] = seqnum_out[q];
      assign q_error_to_reg [q] = 32'd0;   // per-queue error reporting reserved
    end
  endgenerate

  // ----- Four resource arbiters (round-robin) -----
  wire        kmu_valid   [NUM_QUEUES];
  wire [1:0]  kmu_prio    [NUM_QUEUES];
  cmd_t       kmu_cmd     [NUM_QUEUES];
  logic       kmu_grant   [NUM_QUEUES];

  wire        dma_valid   [NUM_QUEUES];
  wire [1:0]  dma_prio    [NUM_QUEUES];
  cmd_t       dma_cmd     [NUM_QUEUES];
  logic       dma_grant   [NUM_QUEUES];

  wire        dcr_valid   [NUM_QUEUES];
  wire [1:0]  dcr_prio    [NUM_QUEUES];
  cmd_t       dcr_cmd     [NUM_QUEUES];
  logic       dcr_grant   [NUM_QUEUES];

  wire        event_valid [NUM_QUEUES];
  wire [1:0]  event_prio  [NUM_QUEUES];
  cmd_t       event_cmd   [NUM_QUEUES];
  logic       event_grant [NUM_QUEUES];

  generate
    for (genvar q = 0; q < NUM_QUEUES; ++q) begin : g_unpack_bids
      assign kmu_valid[q]     = bid_kmu[q].valid;
      assign kmu_prio[q]      = bid_kmu[q].priority_;
      assign kmu_cmd[q]       = bid_kmu[q].cmd;
      assign bid_kmu[q].grant = kmu_grant[q];

      assign dma_valid[q]     = bid_dma[q].valid;
      assign dma_prio[q]      = bid_dma[q].priority_;
      assign dma_cmd[q]       = bid_dma[q].cmd;
      assign bid_dma[q].grant = dma_grant[q];

      assign dcr_valid[q]     = bid_dcr[q].valid;
      assign dcr_prio[q]      = bid_dcr[q].priority_;
      assign dcr_cmd[q]       = bid_dcr[q].cmd;
      assign bid_dcr[q].grant = dcr_grant[q];

      assign event_valid[q]     = bid_event[q].valid;
      assign event_prio[q]      = bid_event[q].priority_;
      assign event_cmd[q]       = bid_event[q].cmd;
      assign bid_event[q].grant = event_grant[q];
    end
  endgenerate

  // A resource's arbiter sees bids only while the resource is idle. The
  // grant is a one-cycle pulse and the resource ignores it unless idle, so
  // ungated, a second queue granted mid-command would wait on the first's
  // `done` and retire without ever executing. The launch replays onto the
  // DCR bus, so it also needs the DCR proxy idle, and the DCR arbiter yields
  // to a launch grant and to a launch replay.
  logic launch_idle, dcr_idle, dma_idle, event_idle, launch_replaying;
  logic kmu_valid_g   [NUM_QUEUES];
  logic dma_valid_g   [NUM_QUEUES];
  logic dcr_valid_g   [NUM_QUEUES];
  logic event_valid_g [NUM_QUEUES];
  logic any_kmu_bid;
  always_comb begin
    any_kmu_bid = 1'b0;
    for (int i = 0; i < NUM_QUEUES; ++i)
      any_kmu_bid = any_kmu_bid | kmu_valid_g[i];
  end
  generate
    for (genvar q = 0; q < NUM_QUEUES; ++q) begin : g_bid_gate
      assign kmu_valid_g[q]   = kmu_valid[q] && launch_idle && dcr_idle;
      assign dma_valid_g[q]   = dma_valid[q] && dma_idle;
      assign dcr_valid_g[q]   = dcr_valid[q] && dcr_idle && !launch_replaying && !any_kmu_bid;
      assign event_valid_g[q] = event_valid[q] && event_idle;
    end
  endgenerate

  VX_cp_arbiter #(.N(NUM_QUEUES)) u_arb_kmu (
    .clk(clk), .reset(reset),
    .bid_valid(kmu_valid_g), .bid_priority(kmu_prio), .bid_grant(kmu_grant)
  );
  VX_cp_arbiter #(.N(NUM_QUEUES)) u_arb_dma (
    .clk(clk), .reset(reset),
    .bid_valid(dma_valid_g), .bid_priority(dma_prio), .bid_grant(dma_grant)
  );
  VX_cp_arbiter #(.N(NUM_QUEUES)) u_arb_dcr (
    .clk(clk), .reset(reset),
    .bid_valid(dcr_valid_g), .bid_priority(dcr_prio), .bid_grant(dcr_grant)
  );
  VX_cp_arbiter #(.N(NUM_QUEUES)) u_arb_event (
    .clk(clk), .reset(reset),
    .bid_valid(event_valid_g), .bid_priority(event_prio), .bid_grant(event_grant)
  );

  // ----- Pick the granted bid's cmd for each shared resource -----
  // ...and the granted queue: the issuer of the DCR command, the launching
  // queue of a launch (authorship).
  localparam int QW = (NUM_QUEUES > 1) ? $clog2(NUM_QUEUES) : 1;
  logic any_kmu_grant, any_dma_grant, any_dcr_grant, any_event_grant;
  cmd_t granted_kmu_cmd, granted_dma_cmd, granted_dcr_cmd, granted_event_cmd;
  logic [QW-1:0] granted_kmu_q, granted_dcr_q, granted_dma_q, granted_event_q;
  always_comb begin
    any_kmu_grant = 1'b0; granted_kmu_cmd = '0; granted_kmu_q = '0;
    any_dma_grant = 1'b0; granted_dma_cmd = '0; granted_dma_q = '0;
    any_dcr_grant = 1'b0; granted_dcr_cmd = '0; granted_dcr_q = '0;
    any_event_grant = 1'b0; granted_event_cmd = '0; granted_event_q = '0;
    for (int i = 0; i < NUM_QUEUES; ++i) begin
      if (kmu_grant[i])   begin any_kmu_grant   = 1'b1; granted_kmu_cmd   = kmu_cmd[i]; granted_kmu_q = QW'(i); end
      if (dma_grant[i])   begin any_dma_grant   = 1'b1; granted_dma_cmd   = dma_cmd[i]; granted_dma_q = QW'(i); end
      if (dcr_grant[i])   begin any_dcr_grant   = 1'b1; granted_dcr_cmd   = dcr_cmd[i]; granted_dcr_q = QW'(i); end
      if (event_grant[i]) begin any_event_grant = 1'b1; granted_event_cmd = event_cmd[i]; granted_event_q = QW'(i); end
    end
  end

  // The queue each device-side master is working for (D7): latched at the
  // grant, which the bid gate only gives an idle unit, and held until its next
  // grant. A unit retires a command only after its last device beat has
  // answered (R data, or B), so no beat outlives the queue it was issued for.
  logic [QW-1:0] dma_q_r, event_q_r;
  always_ff @(posedge clk) begin
    if (reset) begin
      dma_q_r   <= '0;
      event_q_r <= '0;
    end else begin
      if (any_dma_grant)   dma_q_r   <= granted_dma_q;
      if (any_event_grant) event_q_r <= granted_event_q;
    end
  end

  `UNUSED_VAR (granted_kmu_cmd)

  // Internal CP-side bundle; the register slice isolating it from the Vortex
  // boundary (gpu_if) is instantiated at the bottom of the module.
  VX_cp_gpu_if gpu_if_int();

  // ----- Launch shadow (spec D4) -----
  // Per queue, the launch registers that queue last wrote: captured by the
  // DCR proxy instead of reaching the GPU, replayed by the launch.
  logic [`VX_DCR_DATA_BITS-1:0] shadow_r [NUM_QUEUES][NUM_SHADOW];
  logic                         px_shadow_wr;
  logic [SHADOW_IDX_W-1:0]      px_shadow_idx, ln_shadow_idx;
  logic [`VX_DCR_DATA_BITS-1:0] px_shadow_wr_data;
  logic [QW-1:0]                ln_q;

  always_ff @(posedge clk) begin
    if (reset) begin
      for (int q = 0; q < NUM_QUEUES; ++q)
        for (int i = 0; i < NUM_SHADOW; ++i)
          shadow_r[q][i] <= shadow_reset(i);
    end else if (px_shadow_wr) begin
      shadow_r[granted_dcr_q][px_shadow_idx] <= px_shadow_wr_data;
    end
  end

  // ----- Shared KMU launch (consumes the kmu bid grant) -----
  logic                         ln_req_valid;
  logic [`VX_DCR_ADDR_BITS-1:0] ln_req_addr;
  logic [`VX_DCR_DATA_BITS-1:0] ln_req_data;
  VX_cp_launch #(.NUM_QUEUES(NUM_QUEUES)) u_launch (
    .clk            (clk),
    .reset          (reset),
    .grant          (any_kmu_grant),
    .grant_q        (granted_kmu_q),
    .start          (gpu_if_int.start),
    .gpu_busy       (gpu_if_int.busy),
    .done           (launch_done),
    .idle           (launch_idle),
    .replaying      (launch_replaying),
    .shadow_idx     (ln_shadow_idx),
    .shadow_rd_data (shadow_r[ln_q][ln_shadow_idx]),
    .launch_q       (ln_q),
    .dcr_req_valid  (ln_req_valid),
    .dcr_req_addr   (ln_req_addr),
    .dcr_req_data   (ln_req_data),
    .dcr_req_ready  (gpu_if_int.dcr_req_ready)
  );

  // ----- Shared DCR proxy -----
  logic                         px_req_valid, px_req_rw;
  logic [`VX_DCR_ADDR_BITS-1:0] px_req_addr;
  logic [`VX_DCR_DATA_BITS-1:0] px_req_data;
  logic [QW-1:0]                px_req_issuer, px_cur_q;
  logic                         px_rsp_update, px_blocked;
  VX_cp_dcr_proxy #(.NUM_QUEUES(NUM_QUEUES)) u_dcr (
    .clk            (clk),
    .reset          (reset),
    .grant          (any_dcr_grant),
    .grant_q        (granted_dcr_q),
    .idle           (dcr_idle),
    .cmd            (granted_dcr_cmd),
    .done           (dcr_done),
    .last_rsp_data  (dcr_last_rsp_data),
    .rsp_update     (px_rsp_update),
    .cur_q          (px_cur_q),
    .blocked        (px_blocked),
    .shadow_wr      (px_shadow_wr),
    .shadow_idx     (px_shadow_idx),
    .shadow_wr_data (px_shadow_wr_data),
    .shadow_rd_data (shadow_r[granted_dcr_q][px_shadow_idx]),
    .dcr_req_valid  (px_req_valid),
    .dcr_req_rw     (px_req_rw),
    .dcr_req_addr   (px_req_addr),
    .dcr_req_data   (px_req_data),
    .dcr_req_issuer (px_req_issuer),
    .dcr_rsp_valid  (gpu_if_int.dcr_rsp_valid),
    .dcr_rsp_data   (gpu_if_int.dcr_rsp_data)
  );

  // The GPU's DCR bus: the launch while it replays, the proxy otherwise.
  // The arbiter gating above keeps the two from ever overlapping.
  assign gpu_if_int.dcr_req_valid  = launch_replaying ? ln_req_valid : px_req_valid;
  assign gpu_if_int.dcr_req_rw     = launch_replaying ? 1'b1         : px_req_rw;
  assign gpu_if_int.dcr_req_addr   = launch_replaying ? ln_req_addr  : px_req_addr;
  assign gpu_if_int.dcr_req_data   = launch_replaying ? ln_req_data  : px_req_data;
  assign gpu_if_int.dcr_req_issuer = `VX_DCR_ISSUER_BITS'(launch_replaying ? ln_q : px_req_issuer);

  // Per-queue Q_LAST_DCR_RSP and Q_DCR_BLOCKED (declared above the regfile).
  always_ff @(posedge clk) begin
    if (reset) begin
      for (int q = 0; q < NUM_QUEUES; ++q) begin
        q_last_rsp[q] <= '0;
        q_blocked[q]  <= '0;
      end
    end else begin
      if (px_rsp_update)
        q_last_rsp[px_cur_q] <= dcr_last_rsp_data;
      if (px_blocked && (q_blocked[granted_dcr_q] != 32'hFFFFFFFF))
        q_blocked[granted_dcr_q] <= q_blocked[granted_dcr_q] + 32'd1;
    end
  end

  // ----- DMA (straddles host + dev xbars) -----
  VX_mem_axi_if #(.ADDR_W(ADDR_W), .DATA_W(DATA_W), .ID_W(ID_W)) dma_host_axi ();
  VX_mem_axi_if #(.ADDR_W(ADDR_W), .DATA_W(DATA_W), .ID_W(ID_W)) dma_dev_axi  ();
  VX_mem_axi_if #(.ADDR_W(ADDR_W), .DATA_W(DATA_W), .ID_W(ID_W)) cmpl_axi     ();
  VX_mem_axi_if #(.ADDR_W(ADDR_W), .DATA_W(DATA_W), .ID_W(ID_W)) event_axi    ();

  VX_cp_dma u_dma (
    .clk      (clk),
    .reset    (reset),
    .grant    (any_dma_grant),
    .cmd      (granted_dma_cmd),
    .done     (dma_done),
    .idle     (dma_idle),
    .axi_host (dma_host_axi),
    .axi_dev  (dma_dev_axi)
  );

  // ----- Event unit (CMD_EVENT_SIGNAL / CMD_EVENT_WAIT) -----
  VX_cp_event_unit u_event (
    .clk   (clk),
    .reset (reset),
    .grant (any_event_grant),
    .cmd   (granted_event_cmd),
    .done  (event_done),
    .idle  (event_idle),
    .axi_m (event_axi)
  );

  // ----- Completion writeback (host memory) -----
  wire [63:0] cmpl_addr_arr [NUM_QUEUES];
  generate
    for (genvar q = 0; q < NUM_QUEUES; ++q) begin : g_cmpl_addr
      assign cmpl_addr_arr[q] = q_state[q].cmpl_addr;
    end
  endgenerate

  VX_cp_completion #(
    .NUM_QUEUES (NUM_QUEUES)
  ) u_completion (
    .clk           (clk),
    .reset         (reset),
    .retire_evt    (retire_evt),
    .retire_seqnum (retire_seqnum),
    .cmpl_addr     (cmpl_addr_arr),
    .retire_ready  (retire_ready),
    .axi_m         (cmpl_axi)
  );

  // ============================================================================
  // Host xbar — fetch[N] + completion + DMA(host) → axi_host.
  // ============================================================================
  VX_mem_axi_if #(.ADDR_W(ADDR_W), .DATA_W(DATA_W), .ID_W(ID_W))
                       xbar_host_src [N_SRC_HOST] ();

  generate
    for (genvar q = 0; q < NUM_QUEUES; ++q) begin : g_host_fetch
      `CP_AXI_LINK(xbar_host_src[q], fetch_axi[q]);
    end
  endgenerate

  `CP_AXI_LINK(xbar_host_src[SLOT_CMPL],     cmpl_axi);
  `CP_AXI_LINK(xbar_host_src[SLOT_DMA_HOST], dma_host_axi);

  // Register slice that breaks the long, routing-dominated path from the CP
  // masters to the far-side host-memory AXI so the kernel clock can close.
  VX_mem_axi_if #(
    .ADDR_W (ADDR_W),
    .DATA_W (DATA_W),
    .ID_W   (ID_W)
  ) axi_host_pre [1] ();

  // Multi-outstanding (ID-routed) fan-in: sources leave the top LOG2UP(N) ID
  // bits free; the arb tags them with the source index and demuxes B/R back,
  // so the CP's sources keep concurrent transactions in flight.
  VX_mem_axi_xbar #(
    .NUM_INPUTS  (N_SRC_HOST),
    .NUM_OUTPUTS (1),
    .ADDR_WIDTH  (ADDR_W),
    .DATA_WIDTH  (DATA_W),
    .ID_WIDTH    (ID_W),
    .MULTI_OUT   (1)
  ) u_xbar_host (
    .clk   (clk),
    .reset (reset),
    .s     (xbar_host_src),
    .m     (axi_host_pre)
  );

  VX_mem_axi_slice #(
    .ADDR_WIDTH (ADDR_W),
    .DATA_WIDTH (DATA_W),
    .ID_WIDTH   (ID_W)
  ) u_slice_host (
    .clk   (clk),
    .reset (reset),
    .s     (axi_host_pre[0]),
    .m     (axi_host)
  );

  // ============================================================================
  // Device xbar — DMA(dev) + event → axi_dev.
  // ============================================================================
  VX_mem_axi_if #(.ADDR_W(ADDR_W), .DATA_W(DATA_W), .ID_W(ID_W))
                       xbar_dev_src [N_SRC_DEV] ();

  // Every device-side beat carries its queue in the low ID bits (D7). The
  // xbar prefixes the source slot above them and the AFU's AXI-to-membus
  // bridge carries the ID into the request tag unchanged, so the checker on
  // the CP's device path reads the issuer off each request's tag -- the same
  // queue = tenant identity the DCR path carries on dcr_req_issuer. DMA and
  // event units keep running concurrently: nothing is shared but the stamp.
  `STATIC_ASSERT(QW + $clog2(N_SRC_DEV) <= ID_W, ("CP device AXI ID too narrow for the queue index and the xbar source"))
  `CP_AXI_LINK_ID(xbar_dev_src[SLOT_DMA_DEV], dma_dev_axi, ID_W'(dma_q_r),   ID_W'(dma_q_r));
  `CP_AXI_LINK_ID(xbar_dev_src[SLOT_EVENT],   event_axi,   ID_W'(event_q_r), ID_W'(event_q_r));
  `UNUSED_VAR (dma_dev_axi.awid)
  `UNUSED_VAR (dma_dev_axi.arid)
  `UNUSED_VAR (event_axi.awid)
  `UNUSED_VAR (event_axi.arid)

  // Register slice on the path to device memory (memory subsystem).
  VX_mem_axi_if #(
    .ADDR_W (ADDR_W),
    .DATA_W (DATA_W),
    .ID_W   (ID_W)
  ) axi_dev_pre [1] ();

  VX_mem_axi_xbar #(
    .NUM_INPUTS  (N_SRC_DEV),
    .NUM_OUTPUTS (1),
    .ADDR_WIDTH  (ADDR_W),
    .DATA_WIDTH  (DATA_W),
    .ID_WIDTH    (ID_W),
    .MULTI_OUT   (1)
  ) u_xbar_dev (
    .clk   (clk),
    .reset (reset),
    .s     (xbar_dev_src),
    .m     (axi_dev_pre)
  );

  VX_mem_axi_slice #(
    .ADDR_WIDTH (ADDR_W),
    .DATA_WIDTH (DATA_W),
    .ID_WIDTH   (ID_W)
  ) u_slice_dev (
    .clk   (clk),
    .reset (reset),
    .s     (axi_dev_pre[0]),
    .m     (axi_dev)
  );

  // ----- Aggregated status -----
  // Busy if any CPE has a command in flight or any shared resource is active.
  always_comb begin
    cp_busy = 1'b0;
    cp_error = 1'b0;
    for (int i = 0; i < NUM_QUEUES; ++i) begin
      if (cpe_cmd_valid[i]) cp_busy = 1'b1;
    end
    if (any_kmu_grant || any_dma_grant || any_dcr_grant ||
        any_event_grant) cp_busy = 1'b1;
  end

  // ----- Queue reset (Q_CONTROL.reset / CP_CTRL.reset_all) -----
  //
  // The pulse from the regfile is latched as a *pending* request rather than
  // applied immediately. While it is pending the fetch stops issuing new
  // reads, so the CPE drains to idle on its own; the clear is then applied in
  // the single cycle when both the fetch and the engine report idle. That
  // keeps the head pointer, the retire counter and the host-visible tail
  // consistent, and it never abandons an AXI read the fetch has in flight.
  //
  // Without this the counters survived a process exit, a fresh process
  // inherited them, and its queue silently never ran because the fetch gate
  // is `head < tail` on absolute byte counts.
  generate
    for (genvar q = 0; q < NUM_QUEUES; ++q) begin : g_queue_reset
      always_ff @(posedge clk) begin
        if (reset) begin
          q_reset_pending[q] <= 1'b0;
        end else if (q_reset_pulse[q]) begin
          q_reset_pending[q] <= 1'b1;
        end else if (q_clear[q]) begin
          q_reset_pending[q] <= 1'b0;
        end
      end

      assign q_clear[q] = q_reset_pending[q]
                       && fetch_idle[q]
                       && engine_idle[q];
    end
  endgenerate

  // ----- IRQ: one-cycle pulse after any queue retires a command.
  // No host-visible ack/ISR register yet (runtime polls Q_SEQNUM);
  // this drives the platform irq pin for future interrupt-driven launch-wait. -----
  reg irq_r;
  always_ff @(posedge clk) begin
    if (reset) begin
      irq_r <= 1'b0;
    end else begin
      irq_r <= 1'b0;
      for (int q = 0; q < NUM_QUEUES; ++q) begin
        if (retire_evt[q])
          irq_r <= 1'b1;
      end
    end
  end
  assign irq = irq_r;

  // Profiling pulses fired by each engine are not routed externally yet;
  // suppress unused-signal warnings here.
  generate
    for (genvar q = 0; q < NUM_QUEUES; ++q) begin : g_unused_prof
      `UNUSED_VAR (submit_evt[q])
      `UNUSED_VAR (start_evt[q])
      `UNUSED_VAR (end_evt[q])
      `UNUSED_VAR (profile_slot[q])
    end
  endgenerate

  `UNUSED_PARAM (ADDR_W)
  `UNUSED_PARAM (DATA_W)

  // Register slice on the CP <-> Vortex boundary (SLR-safe crossing).
  VX_cp_gpu_slice u_gpu_slice (
    .clk      (clk),
    .reset    (reset),
    .cp_side  (gpu_if_int),
    .gpu_side (gpu_if)
  );

endmodule : VX_cp_core

`undef CP_AXI_LINK
