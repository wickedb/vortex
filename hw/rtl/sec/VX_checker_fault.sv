// Fault delivery for a denied access (R3).
//
// Enforcement semantics, matching SimX exactly because R4 parity depends on it
// (PROJECT.md §8.5):
//
//   denied READ  -> the request never reaches DRAM (fast-fail, no round trip);
//                   a synthesized response carrying a poison block is injected
//                   on the response channel so the LLC's outstanding fill
//                   completes and the requester observably receives poison
//                   instead of the protected data.
//   denied WRITE -> dropped. Writes are posted at this boundary (DRAM responds
//                   only to reads), so a dropped write never lands. That is
//                   denial semantics, not merely its timing.
//
// This mirrors what real memory-side protection hardware does: poison and log.
// Precise traps to the offending warp are architecturally out of reach from
// behind the LLC.
//
// EXACTLY ONCE, EXACT TAG. The LLC holds one outstanding entry per in-flight
// read. An injected response must carry the denied request's own tag and must
// be injected exactly once, or the MSHR entry leaks (never freed) or is freed
// twice. That is the single most important property in this module.
//
// QUEUE DEPTH -- why this can never overflow, and why there is no back-pressure
// on the request path:
//
//   * A cacheable read reaches memory only via
//       fill_req_push = (do_read_stc || do_write_stc)
//                    && ~stC.lk.is_hit && ~stC.lk.mshr_pending
//     (VX_cache_bank.sv). The ~mshr_pending term means a secondary miss to a
//     line already being fetched issues NO second memory read, so outstanding
//     memory reads per bank are bounded by MSHR_SIZE.
//   * Bypassed (non-cacheable / IO) traffic reaches the same memory port
//     without touching the cache MSHR -- but the checker never denies it
//     (is_addr_io short-circuits to `bypassed`), so it contributes nothing
//     here.
//
// Hence: denied reads in flight <= (banks sharing this port) * MSHR_SIZE, and a
// queue of that depth cannot fill. Sizing it this way keeps the request path
// free of a stall that would otherwise land on exactly the wire R5 measures for
// the hit_latency=0 question.
//
// The comment above is an argument, not a proof, so `fault_overflow` latches if
// the invariant is ever violated and the testbench checks it. An invariant that
// is only asserted in a comment is the kind this project keeps getting wrong.

`include "VX_define.vh"

module VX_checker_fault import VX_gpu_pkg::*, VX_sec_pkg::*; #(
    parameter DATA_SIZE = 64,
    parameter TAG_WIDTH = 1,
    parameter DEPTH     = 16
) (
    input  wire clk,
    input  wire reset,

    // A denied read retires here, carrying the tag its response must quote.
    input  wire                      fault_push,
    input  wire [TAG_WIDTH-1:0]      fault_tag,

    // DRAM-side response (from memory).
    input  wire                      dram_rsp_valid,
    input  wire [DATA_SIZE*8-1:0]    dram_rsp_data,
    input  wire [TAG_WIDTH-1:0]      dram_rsp_tag,
    output wire                      dram_rsp_ready,

    // LLC-side response (to the cache), muxed.
    output wire                      rsp_valid,
    output wire [DATA_SIZE*8-1:0]    rsp_data,
    output wire [TAG_WIDTH-1:0]      rsp_tag,
    input  wire                      rsp_ready,

    output wire                      fault_overflow
);
    // Only the tag is queued. The payload is always the same poison block, so
    // storing it per entry would be DATA_SIZE*8 bits of identical data.
    wire                  q_empty, q_full;
    wire [TAG_WIDTH-1:0]  q_tag;
    wire                  q_pop;

    VX_fifo_queue #(
        .DATAW (TAG_WIDTH),
        .DEPTH (DEPTH)
    ) fault_q (
        .clk     (clk),
        .reset   (reset),
        .push    (fault_push),
        .pop     (q_pop),
        .data_in (fault_tag),
        .data_out(q_tag),
        .empty   (q_empty),
        .full    (q_full),
        `UNUSED_PIN (alm_empty),
        `UNUSED_PIN (alm_full),
        `UNUSED_PIN (size)
    );

    // DRAM wins the slot; injection retries next cycle. Keeps the response
    // path's baseline timing untouched, which is what SimX's try_send/retry
    // models. Poison cannot starve: DRAM responses are bounded by the reads
    // actually in flight, and a denied read issues none.
    wire inject = ~q_empty && ~dram_rsp_valid;

    assign rsp_valid = dram_rsp_valid || inject;
    assign rsp_data  = dram_rsp_valid ? dram_rsp_data : {(DATA_SIZE*8/8){8'hDD}};
    assign rsp_tag   = dram_rsp_valid ? dram_rsp_tag  : q_tag;

    assign dram_rsp_ready = rsp_ready;
    assign q_pop = inject && rsp_ready;

    // Latches if the depth argument above was ever wrong. Sticky so a single
    // violation cannot be missed between polls.
    reg overflow_r;
    always @(posedge clk) begin
        if (reset) begin
            overflow_r <= 1'b0;
        end else if (fault_push && q_full) begin
            overflow_r <= 1'b1;
        end
    end
    assign fault_overflow = overflow_r;

endmodule
