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

`ifndef VX_CP_PKG_VH
`define VX_CP_PKG_VH

`include "VX_define.vh"

`IGNORE_UNUSED_BEGIN

package VX_cp_pkg;

  // ------------------------------------------------------------------------
  // Compile-time parameters mirrored from VX_config.toml / build flags.
  //
  // These have safe defaults so the rtl/cp tree builds even without the
  // [cp] block populated in VX_config.toml. The configure script overrides
  // them via -D flags when the [cp] block is present.
  // ------------------------------------------------------------------------

  `ifndef VX_CP_NUM_QUEUES
    `define VX_CP_NUM_QUEUES 1
  `endif

  `ifndef VX_CP_RING_SIZE_LOG2
    `define VX_CP_RING_SIZE_LOG2 16   // 64 KiB per queue ring
  `endif

  `ifndef VX_CP_MAX_CMDS_PER_CL
    `define VX_CP_MAX_CMDS_PER_CL 5
  `endif

  `ifndef VX_CP_AXI_TID_WIDTH
    `define VX_CP_AXI_TID_WIDTH 6
  `endif

  localparam int VX_CP_NUM_QUEUES_C      = `VX_CP_NUM_QUEUES;
  localparam int VX_CP_RING_SIZE_LOG2_C  = `VX_CP_RING_SIZE_LOG2;
  localparam int VX_CP_MAX_CMDS_PER_CL_C = `VX_CP_MAX_CMDS_PER_CL;
  localparam int VX_CP_AXI_TID_WIDTH_C   = `VX_CP_AXI_TID_WIDTH;

  // ------------------------------------------------------------------------
  // Cache line geometry. Matches CACHE_BLOCK_SIZE in the rest of Vortex.
  // ------------------------------------------------------------------------

  localparam int CL_BYTES = 64;
  localparam int CL_BITS  = CL_BYTES * 8;

  // ------------------------------------------------------------------------
  // Command opcodes.
  // ------------------------------------------------------------------------

  typedef enum logic [7:0] {
    CMD_NOP          = 8'h00,
    CMD_MEM_WRITE    = 8'h01,
    CMD_MEM_READ     = 8'h02,
    CMD_MEM_COPY     = 8'h03,
    CMD_DCR_WRITE    = 8'h04,
    CMD_DCR_READ     = 8'h05,
    CMD_LAUNCH       = 8'h06,
    CMD_FENCE        = 8'h07,
    CMD_EVENT_SIGNAL = 8'h08,
    CMD_EVENT_WAIT   = 8'h09,
    CMD_CACHE_FLUSH  = 8'h0A
  } cp_opcode_e;

  // ------------------------------------------------------------------------
  // Header flag bits.
  // ------------------------------------------------------------------------

  localparam int F_PROFILE   = 0;
  localparam int F_FENCE_PRE = 1;

  typedef struct packed {
    logic [15:0] reserved;
    logic [7:0]  flags;
    logic [7:0]  opcode;
  } cmd_header_t;

  // ------------------------------------------------------------------------
  // Decoded command record produced by VX_cp_unpack.
  //
  // Worst-case payload is 28 B (CMD_MEM_*, CMD_EVENT_WAIT, CMD_DCR_READ);
  // F_PROFILE adds an 8 B profile_slot trailer.
  // ------------------------------------------------------------------------

  typedef struct packed {
    cmd_header_t hdr;
    logic [63:0] arg0;
    logic [63:0] arg1;
    logic [63:0] arg2;
    logic [63:0] profile_slot;  // valid iff hdr.flags[F_PROFILE]
  } cmd_t;

  // ------------------------------------------------------------------------
  // EVENT_WAIT comparison operations (encoded in arg2[1:0]).
  // ------------------------------------------------------------------------

  typedef enum logic [1:0] {
    WAIT_OP_EQ = 2'd0,
    WAIT_OP_GE = 2'd1,
    WAIT_OP_GT = 2'd2,
    WAIT_OP_NE = 2'd3
  } wait_op_e;

  // ------------------------------------------------------------------------
  // FENCE op masks (encoded in arg0[1:0]).
  // ------------------------------------------------------------------------

  localparam int FENCE_DMA_BIT = 0;
  localparam int FENCE_GPU_BIT = 1;

  // ------------------------------------------------------------------------
  // Per-CPE persistent state.
  //
  // One instance lives inside each VX_cp_engine. Host-visible registers in
  // the AXI-Lite slave write to these.
  // ------------------------------------------------------------------------

  typedef struct packed {
    logic [63:0]                       ring_base;        // host IO addr of ring
    logic [VX_CP_RING_SIZE_LOG2_C-1:0] ring_size_mask;   // size_bytes - 1
    logic [63:0]                       head_addr;        // CP publishes head here
    logic [63:0]                       cmpl_addr;        // CP publishes seqnum here
    logic [63:0]                       tail;             // last committed via doorbell
    logic [63:0]                       head;             // CPE consumer pointer
    logic [63:0]                       seqnum;           // next-to-retire seqnum
    logic [1:0]                        prio;             // 0=lo, 3=hi
    logic                              enabled;
    logic                              profile_en;
  } cpe_state_t;

  // ------------------------------------------------------------------------
  // Per-resource arbiter request (CPE -> arbiter).
  //
  // Each CPE has three such bid lines (KMU, DMA, DCR).
  // ------------------------------------------------------------------------

  typedef enum logic [1:0] {
    RES_KMU = 2'd0,
    RES_DMA = 2'd1,
    RES_DCR = 2'd2,
    RES_EVT = 2'd3      // handles CMD_EVENT_SIGNAL + CMD_EVENT_WAIT
  } cp_resource_e;

  // ------------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------------

  // True for opcodes this CP decodes. VX_cp_unpack drops the rest of a
  // cache line on an unknown opcode: its size is unknowable, so walking on
  // would re-parse its payload bytes as phantom commands.
  function automatic logic cmd_opcode_valid(cp_opcode_e op);
    case (op)
      CMD_NOP,
      CMD_MEM_WRITE,
      CMD_MEM_READ,
      CMD_MEM_COPY,
      CMD_DCR_WRITE,
      CMD_DCR_READ,
      CMD_LAUNCH,
      CMD_FENCE,
      CMD_EVENT_SIGNAL,
      CMD_EVENT_WAIT,
      CMD_CACHE_FLUSH: return 1'b1;
      default:         return 1'b0;
    endcase
  endfunction

  // Returns the on-wire byte size of a command given its opcode and the
  // F_PROFILE flag. Used by VX_cp_unpack to know how much of the cache
  // line to consume per command.
  function automatic int unsigned cmd_size_bytes(cp_opcode_e op,
                                                 logic profiled);
    int unsigned base;
    case (op)
      CMD_NOP:          base = 4;
      CMD_LAUNCH:       base = 12;
      CMD_FENCE:        base = 8;
      CMD_CACHE_FLUSH:  base = 12;
      CMD_DCR_WRITE:    base = 20;
      CMD_DCR_READ:     base = 20;
      CMD_EVENT_SIGNAL: base = 20;
      CMD_EVENT_WAIT:   base = 28;
      CMD_MEM_WRITE:    base = 28;
      CMD_MEM_READ:     base = 28;
      CMD_MEM_COPY:     base = 28;
      default:          base = 4;
    endcase
    return base + (profiled ? 8 : 0);
  endfunction

  // ------------------------------------------------------------------------
  // Launch shadow (authorship, P1_and_taint_specv2.md D4).
  //
  // The launch registers -- the KMU block, and the MMU root under VM -- are
  // captured per queue by the DCR proxy instead of being written through, and
  // replayed into the GPU by VX_cp_launch when that queue's launch holds the
  // KMU. Another queue's writes in between therefore cannot change what a
  // launch runs. Shadow slot i holds DCR shadow_addr(i); reset values are the
  // KMU's own (dims, cluster dims and warp steps 1, all else 0), matching
  // sim/common/cmd_processor.cpp.
  // ------------------------------------------------------------------------

  localparam int SHADOW_KMU_N = int'(`VX_DCR_KMU_STATE_END) - int'(`VX_DCR_KMU_STATE_BEGIN);
`ifdef VX_CFG_VM_ENABLE
  localparam int NUM_SHADOW   = SHADOW_KMU_N + 2;   // + MMU SATP_LO/HI
`else
  localparam int NUM_SHADOW   = SHADOW_KMU_N;
`endif
  localparam int SHADOW_IDX_W = $clog2(NUM_SHADOW);

  function automatic logic is_shadow_addr(input logic [`VX_DCR_ADDR_BITS-1:0] addr);
    if (addr >= `VX_DCR_ADDR_BITS'(`VX_DCR_KMU_STATE_BEGIN)
     && addr <  `VX_DCR_ADDR_BITS'(`VX_DCR_KMU_STATE_END))
      return 1'b1;
`ifdef VX_CFG_VM_ENABLE
    if (addr == `VX_DCR_ADDR_BITS'(`VX_DCR_MMU_SATP_LO)
     || addr == `VX_DCR_ADDR_BITS'(`VX_DCR_MMU_SATP_HI))
      return 1'b1;
`endif
    return 1'b0;
  endfunction

  function automatic logic [SHADOW_IDX_W-1:0] shadow_index(input logic [`VX_DCR_ADDR_BITS-1:0] addr);
`ifdef VX_CFG_VM_ENABLE
    if (addr == `VX_DCR_ADDR_BITS'(`VX_DCR_MMU_SATP_LO)) return SHADOW_IDX_W'(SHADOW_KMU_N);
    if (addr == `VX_DCR_ADDR_BITS'(`VX_DCR_MMU_SATP_HI)) return SHADOW_IDX_W'(SHADOW_KMU_N + 1);
`endif
    return SHADOW_IDX_W'(addr - `VX_DCR_ADDR_BITS'(`VX_DCR_KMU_STATE_BEGIN));
  endfunction

  function automatic logic [`VX_DCR_ADDR_BITS-1:0] shadow_addr(input logic [SHADOW_IDX_W-1:0] idx);
`ifdef VX_CFG_VM_ENABLE
    if (int'(idx) == SHADOW_KMU_N)     return `VX_DCR_ADDR_BITS'(`VX_DCR_MMU_SATP_LO);
    if (int'(idx) == SHADOW_KMU_N + 1) return `VX_DCR_ADDR_BITS'(`VX_DCR_MMU_SATP_HI);
`endif
    return `VX_DCR_ADDR_BITS'(`VX_DCR_KMU_STATE_BEGIN) + `VX_DCR_ADDR_BITS'(idx);
  endfunction

  function automatic logic [`VX_DCR_DATA_BITS-1:0] shadow_reset(input int idx);
    logic [`VX_DCR_ADDR_BITS-1:0] a;
    a = `VX_DCR_ADDR_BITS'(`VX_DCR_KMU_STATE_BEGIN) + `VX_DCR_ADDR_BITS'(idx);
    case (a)
      `VX_DCR_KMU_BLOCK_DIM_X,   `VX_DCR_KMU_BLOCK_DIM_Y,   `VX_DCR_KMU_BLOCK_DIM_Z,
      `VX_DCR_KMU_GRID_DIM_X,    `VX_DCR_KMU_GRID_DIM_Y,    `VX_DCR_KMU_GRID_DIM_Z,
      `VX_DCR_KMU_CLUSTER_DIM_X, `VX_DCR_KMU_CLUSTER_DIM_Y, `VX_DCR_KMU_CLUSTER_DIM_Z,
      `VX_DCR_KMU_WARP_STEP_X,   `VX_DCR_KMU_WARP_STEP_Y,   `VX_DCR_KMU_WARP_STEP_Z:
        return (idx < SHADOW_KMU_N) ? `VX_DCR_DATA_BITS'(1) : '0;
      default:
        return '0;
    endcase
  endfunction

  // The checker's configuration window. Reads of it are refused (answered
  // with 0 and counted) unless the build sets VX_CFG_CHECKER_DEBUG_READS:
  // per-owner state must not be readable by other tenants (spec D5).
  function automatic logic is_checker_addr(input logic [`VX_DCR_ADDR_BITS-1:0] addr);
    return (addr >= `VX_DCR_ADDR_BITS'(`VX_DCR_CHECKER_STATE_BEGIN))
        && (addr <  `VX_DCR_ADDR_BITS'(`VX_DCR_CHECKER_STATE_END));
  endfunction

endpackage : VX_cp_pkg

`IGNORE_UNUSED_END

`endif // VX_CP_PKG_VH
