// Header cache — presence tags only.
//
// This cache holds NO POLICY DATA. It stores granule ids and nothing else; the
// check always reads the header store itself. Its only job is to select
// hit-latency versus miss-latency, i.e. to model whether the header was
// already on chip.
//
// That is not an implementation shortcut, it is the property the design rests
// on: because the cache holds no data, IT CANNOT GO STALE, which is precisely
// why revocation needs no header-cache invalidation (PROJECT.md ledger #7). A
// claim takes effect the instant the DCR write lands. Do not add a data path
// here, and do not add an invalidate — either would create the staleness this
// design is built to avoid. (The *data* cache invalidate is a different and
// unsolved question, ledger #9.)
//
// Replacement is FIFO per set, not the exact LRU SimX models. The divergence
// is deliberate and benign: a 64-bit recency timestamp per way is a simulation
// convenience, Vortex's own L3 defaults to FIFO, and SimX measured 4 entries
// already saturating at a 99.99% hit rate — there is almost nothing for a
// replacement policy to get wrong on a working set of a handful of granules.
// It does mean RTL and SimX hit RATES may differ slightly; R4 parity is on
// deny counts and values, never on hit rates (RTL_PLAN.md §2).

`include "VX_define.vh"

module VX_checker_hcache import VX_gpu_pkg::*, VX_sec_pkg::*; #(
    parameter ENTRIES = `VX_CFG_CHECKER_HCACHE_ENTRIES,
    parameter ASSOC   = `VX_CFG_CHECKER_HCACHE_ASSOC
) (
    input  wire clk,
    input  wire reset,

    input  wire                     lookup_en,
    input  wire [CHK_BUF_ID_W-1:0]  buf_id,
    output wire                     hit,

    output wire [31:0]              cnt_hits,
    output wire [31:0]              cnt_misses
);
    // ENTRIES == 0 disables the cache so every check pays the store fetch —
    // the configuration SimX uses to measure the miss path in isolation.
    localparam DISABLED = (ENTRIES == 0);
    localparam NUM_WAYS = DISABLED ? 1 : ((ASSOC > ENTRIES) ? ENTRIES : ASSOC);
    localparam NUM_SETS = DISABLED ? 1 : (ENTRIES / NUM_WAYS);
    localparam SET_W    = `CLOG2(NUM_SETS);
    localparam WAY_W    = `CLOG2(NUM_WAYS);
    localparam TAG_W    = (CHK_BUF_ID_W > SET_W) ? (CHK_BUF_ID_W - SET_W) : 1;

    reg [31:0] hits_r, misses_r;

    if (DISABLED) begin : g_disabled

        assign hit = 1'b0;
        always @(posedge clk) begin
            if (reset) misses_r <= '0;
            else if (lookup_en) misses_r <= misses_r + 1;
        end
        always @(posedge clk) begin
            if (reset) hits_r <= '0;
        end

    end else begin : g_enabled

        // Set index from the low granule-id bits, tag from the rest. A granule
        // id is only CHK_BUF_ID_W bits (12 at the design point), so these are
        // small structures — LUTRAM, not BRAM.
        wire [SET_W-1:0] set_idx = (NUM_SETS > 1) ? buf_id[SET_W-1:0] : '0;
        wire [TAG_W-1:0] req_tag = (CHK_BUF_ID_W > SET_W)
                                 ? buf_id[CHK_BUF_ID_W-1:SET_W]
                                 : TAG_W'(buf_id);

        reg [NUM_SETS-1:0][NUM_WAYS-1:0]              valid_r;
        reg [NUM_SETS-1:0][NUM_WAYS-1:0][TAG_W-1:0]   tag_r;
        reg [NUM_SETS-1:0][`UP(WAY_W)-1:0]            fifo_ptr_r;

        wire [NUM_WAYS-1:0] way_match;
        for (genvar w = 0; w < NUM_WAYS; ++w) begin : g_match
            assign way_match[w] = valid_r[set_idx][w] && (tag_r[set_idx][w] == req_tag);
        end

        wire found = (| way_match);
        assign hit = lookup_en && found;

        // On a miss the id is installed, evicting the FIFO victim. The install
        // is unconditional because a miss means the header had to be fetched,
        // so it is now on chip whether or not we keep it.
        wire do_install = lookup_en && ~found;
        wire [`UP(WAY_W)-1:0] victim = fifo_ptr_r[set_idx];

        always @(posedge clk) begin
            if (reset) begin
                valid_r    <= '0;
                tag_r      <= '0;
                fifo_ptr_r <= '0;
                hits_r     <= '0;
                misses_r   <= '0;
            end else begin
                if (lookup_en) begin
                    if (found) begin
                        hits_r <= hits_r + 1;
                    end else begin
                        misses_r <= misses_r + 1;
                        valid_r[set_idx][victim] <= 1'b1;
                        tag_r[set_idx][victim]   <= req_tag;
                        if (NUM_WAYS > 1)
                            fifo_ptr_r[set_idx] <= (victim == `UP(WAY_W)'(NUM_WAYS-1))
                                                 ? '0 : (victim + 1);
                    end
                end
            end
        end
        `UNUSED_VAR (do_install)
    end

    assign cnt_hits   = hits_r;
    assign cnt_misses = misses_r;

endmodule
