// The isolated header store — the authoritative policy state.
//
// Direct-mapped and TAGGED: entry (buffer_id mod ENTRIES) holds the header for
// buffer `tag`, and only for that buffer. A lookup whose tag does not match is
// not a header for that buffer — the buffer is unclaimed and falls to the boot
// default. Without the tag, two buffer ids colliding modulo the store size
// would silently share one header, so a claim on one would rewrite the other's
// policy and a check on one would be answered from the other's owner. That was
// a real soundness hole in SimX (PROJECT.md §10 #5, fixed 22 Sep) and it is not
// being reintroduced here.
//
// The permissive default on a tag miss is sound ONLY because an installed
// header is never displaced — a colliding claim is refused by the installer
// rather than evicting the occupant — so "tag does not match" always means
// "never claimed", never "claimed and evicted". The two halves live in
// different modules, so the invariant is restated in both.
//
// At the design point the tag is ZERO BITS WIDE: a 32-bit space at 1 MB
// granularity has 4096 granules and the store has 4096 entries, so the index
// spans the whole granule id and no two buffers can collide. The tag only
// becomes storage in the fine-granularity sweep, where the store can no longer
// cover the address space. Confirmed by elaboration, not asserted.
//
// "Isolated" means no memory request can reach it: the only write port is the
// DCR-driven installer. That is the RTL counterpart of SimX's private
// header_store_ vector, and it is what PROJECT.md §3 means by "header
// integrity by construction, no crypto" — the mechanism m1 still owes a
// written argument for.

`include "VX_define.vh"

module VX_checker_store import VX_gpu_pkg::*, VX_sec_pkg::*; #(
    parameter `STRING INSTANCE_ID = ""
) (
    input  wire clk,
    input  wire reset,

    // Boot default: the policy every granule with no claim of its own falls to.
    // Held in one register rather than pre-filled across every entry, which is
    // what lets an entry's valid bit mean "claimed" — the property the tag
    // check depends on.
    input  chk_header_t             default_header,

    // Lookup port (the check path). The id is registered on rd_en and the RAM
    // is read at the REGISTERED id, so the policy answer lands the cycle after
    // the index and HOLDS for as long as the request sits in S1.
    input  wire                     rd_en,
    input  wire [CHK_BUF_ID_W-1:0]  rd_buf_id,
    output chk_header_t             rd_header,
    output wire                     rd_claimed,   // a header was installed for this buffer

    // Install port (the DCR path). One entry per cycle.
    input  wire                     wr_en,
    input  wire [CHK_BUF_ID_W-1:0]  wr_buf_id,
    input  chk_header_t             wr_header,

    // Read-back for the installer's fail-closed pre-pass: it must see the
    // occupant of an entry before deciding whether a claim may land.
    input  wire                     probe_en,
    input  wire [CHK_BUF_ID_W-1:0]  probe_buf_id,
    output chk_header_t             probe_header,
    output wire                     probe_claimed,   // installed AND for this buffer
    // Raw occupancy, independent of the tag compare. The installer needs the
    // three cases kept apart: unoccupied (claim may land), occupied by THIS
    // buffer (a same-owner re-claim), or occupied by a DIFFERENT buffer (an
    // alias, which must be refused). Resolving through probe_claimed alone
    // collapses the first and third, which would make the alias refusal
    // unreachable and `header_alias`'s aliased=1 unmeetable.
    output wire                     probe_occupied
);
    `UNUSED_SPARAM (INSTANCE_ID)

    localparam IDX_W = CHK_IDX_W;
    localparam TAG_W = CHK_TAG_W;

    // Index / tag split. With TAG_W == 0 the whole id is the index and the tag
    // comparison degenerates to a constant 1 — which is correct, not a
    // shortcut: at the design point a collision is impossible.
    function automatic logic [IDX_W-1:0] idx_of(input logic [CHK_BUF_ID_W-1:0] id);
        return id[IDX_W-1:0];
    endfunction

    /* verilator lint_off UNUSEDSIGNAL */
    // At the design point TAG_W == 0, so no bits of `id` are read here at all —
    // the index already spans the whole granule id and a collision is
    // impossible. The argument stays for the fine-granularity configurations
    // where the store cannot cover the address space.
    function automatic logic [`UP(TAG_W)-1:0] tag_of(input logic [CHK_BUF_ID_W-1:0] id);
        if (TAG_W == 0)
            return '0;
        else
            return id[CHK_BUF_ID_W-1 -: `UP(TAG_W)];
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */

    // Stored entry: the header carries its own valid and tag fields, so the
    // RAM word is exactly chk_header_t and there is no side array to keep in
    // step with it.
    chk_header_t ram_rdata, probe_rdata;

    chk_header_t wr_word;
    always @(*) begin
        wr_word       = wr_header;
        wr_word.valid = 1'b1;
        wr_word.tag   = tag_of(wr_buf_id);
    end

    // Two read ports (check path + installer probe) over one write port. Kept
    // as two VX_dp_ram instances with a mirrored write rather than a true
    // 1W2R macro so the RAM inference stays portable across the Xilinx and
    // Yosys flows R5 measures with.
    // RESET_RAM is NOT optional here. An unreset array comes up X, and with
    // --x-initial unique those X's resolve to random values -- so a `valid` bit
    // can read 1 for an entry that was never claimed. The installer then sees
    // probe_occupied with a non-matching tag and refuses the claim as an ALIAS,
    // at the design point where TAG_W = 0 makes aliasing structurally
    // impossible. Observed exactly that: one checker instance installed both
    // claims, the other refused both (rejected=1, aliased=1) from the same DCR
    // stream, purely on power-up state.
    //
    // SimX never had this because StoreEntry declares `valid = false`. An
    // explicit reset is the RTL equivalent of that member initializer, and it
    // is what makes "tag does not match => never claimed" true from cycle zero.
    VX_dp_ram #(
        .DATAW     (CHK_HEADER_W),
        .SIZE      (CHK_ENTRIES),
        .OUT_REG   (0),
        .RESET_RAM (1),
        .RDW_MODE  ("R")
    ) store_rd (
        .clk   (clk),
        .reset (reset),
        .read  (1'b1),
        .write (wr_en),
        .wren  (1'b1),
        .waddr (idx_of(wr_buf_id)),
        .wdata (wr_word),
        .raddr (idx_of(rd_id_r)),
        .rdata (ram_rdata)
    );

    VX_dp_ram #(
        .DATAW     (CHK_HEADER_W),
        .SIZE      (CHK_ENTRIES),
        .OUT_REG   (0),
        .RESET_RAM (1),
        .RDW_MODE  ("R")
    ) store_probe (
        .clk   (clk),
        .reset (reset),
        .read  (probe_en),
        .write (wr_en),
        .wren  (1'b1),
        .waddr (idx_of(wr_buf_id)),
        .wdata (wr_word),
        .raddr (idx_of(probe_buf_id)),
        .rdata (probe_rdata)
    );

    // OUT_REG(0) makes VX_dp_ram an async read (`read` is ignored), so the
    // check port is addressed with the registered id: the bus moves on to the
    // next request while S1 is still resolving this one.
    reg [CHK_BUF_ID_W-1:0] rd_id_r;
    always @(posedge clk) begin
        if (rd_en) rd_id_r <= rd_buf_id;
    end

    // The tag comparison is the whole aliasing fix. Each port compares against
    // the id it actually read: the registered id on the check port, the live
    // probe id on the installer port (whose FSM consumes the probe in the cycle
    // it drives it).
    wire rd_hit    = ram_rdata.valid   && (ram_rdata.tag   == tag_of(rd_id_r));
    wire probe_hit = probe_rdata.valid && (probe_rdata.tag == tag_of(probe_buf_id));

    assign rd_header    = rd_hit ? ram_rdata : default_header;
    assign rd_claimed   = rd_hit;
    assign probe_claimed  = probe_hit;
    assign probe_occupied = probe_rdata.valid;
    // On an alias the installer needs the OCCUPANT's header, not the default,
    // so it can report which owner it collided with.
    assign probe_header = probe_rdata.valid ? probe_rdata : default_header;

endmodule
