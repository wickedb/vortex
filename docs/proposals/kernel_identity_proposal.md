# Kernel identity as the requester, and policy header v2

Status: draft, 12 Oct 2026; revised 15 Oct 2026 to close the measurement and
residue holes; 16 Oct 2026: parity dropped, per-core KID with one kernel
per core, "slot" renamed "kernel index", launch sequencer added. Branch
`sec-mem-checker`.

## Why

Today the identity on every memory request is the core id
(`VX_lsu_slice.sv:120`, `VX_fetch.sv:235`, SimX `MemChecker::owner_of`), and the
same value is compared against a granule's `owner`. That conflates two things:

- **Who owns data.** A party (tenant) that claims granules at setup time and
  keeps them across many launches.
- **Who is asking.** The code issuing a load, store or fetch right now.

Because the two are the same value, a grant can only name a tenant, and a
tenant's kernel can copy whatever it was granted into a buffer it owns.
Revocation does not undo the copy. This is the catch in the hospital scenario:
the model and the images must meet at training time, and whichever party's
kernel runs the training holds the other party's data.

Separating the two lets a grant name a *kernel* rather than a tenant. An agreed
training kernel that acts as no tenant owns nothing, so it can write only to the
buffers it was explicitly granted. Data then leaves only through the agreed
output, and neither party's own kernels can read the other's data.

That holds only if two further things hold, and the 12 Oct draft left both
open:

- **The grantee runs the agreed code.** A grant to a kernel is consent to
  whatever that kernel executes. If whoever allocates the kernel chooses its
  code, the grant confines nothing. See *Allocation, sealing and measurement*.
- **Nothing the kernel leaves behind is readable by the next one.** Local
  memory, registers, private caches and scratch buffers all outlive a kernel
  today. See *Residue*.

The core id is also the wrong requester for a GPU in general: a core runs
whatever CTAs it is given, and with concurrent kernels CTAs from different
kernels share one core (SM).

## Requirements

1. The requester id names a kernel instance, not a core.
2. Ownership stays with tenants and persists across launches.
3. Must not break under **time-slicing** (kernels from different tenants take
   turns on the same cores) or under **concurrent kernels** (CTAs of different
   kernels resident at once, possibly on one core). Where a case is not yet
   supported, hardware must refuse it, not run it unchecked.
4. Judging points (checker, every labeled cache) read no state beyond today's
   per-owner epoch table and a per-index generation table (below), so the hit
   path cost stays zero. Measurements never enter a label.
5. Revocation stays as it is: an owner revokes by advancing its own epoch, and
   no other tenant's activity moves that epoch.
6. SimX and RTL change together (model_parity).
7. **A grant to a kernel is a grant to measured code.** The bytes measured are
   the bytes executed and the arguments read, from measurement until the
   kernel's index is retired, and the check that a grant matches the measurement
   happens in the same step that installs the grant.
8. **No residue crosses a kernel index boundary.** No state a kernel leaves in a core
   or in a scratch buffer is readable by a requester in a different kernel index.

## Principals

| Principal | Set by | Lifetime | Used for |
|---|---|---|---|
| Tenant `T` | session setup (later: the command queue, see Authorship) | session | `owner` in headers; owner access |
| Kernel index `k` | the command processor, at allocation | one allocation (one or more launches); the kernel index is then reused | the requester on every request; grants that name a kernel |

Each kernel index carries an **acts-as tenant**, which may be `NONE`:

- A tenant's own kernel acts as that tenant and has the tenant's owner rights.
- An agreed (neutral) kernel acts as `NONE`. It has no owner rights; everything
  it touches must be granted to it. Because it gains nothing it was not granted,
  any party may launch it, and consent is expressed by each owner issuing its
  own grant against the kernel index's measurement rather than by a joint registration
  step.

A kernel index holds an **agreed program**: up to `Q` kernels (8 proposed) that are
allocated, measured and retired together. A training step is many kernels
(GEMMs, activations, a reduction, an optimizer step), and the tensors passed
between them must stay inside the agreement. A kernel index per kernel would put those
intermediates in granules granted to one kernel index at a time. A kernel index per program
keeps them in the program's scratch across launches. Because the program's
kernels share scratch, the order they run in is part of what the owners agree
to: a launch names only the kernel index, and a **sequencer** in the command
processor picks which of the program's kernels runs next (*Launch sequencer*).

## Where the requester id lives: per core

Three placements were considered.

- **Device-wide register**, latched at launch. Correct only while one kernel
  occupies the device. Breaks under concurrency.
- **Per-core register (chosen).** The KMU attaches the kernel's index and acts-as
  tenant to each CTA dispatch alongside `ctx_id`. `VX_cta_dispatch` holds them in
  a per-core KID register, the same shape it already uses for the launch
  counter: `kmu_req.ctx_id` (`VX_kmu.sv:255`) is held per core in
  `cur_ctx_id_r` (`VX_cta_dispatch.sv:468`). The LSU and fetch tag each request
  with the core's KID. Different cores may run different kernels.
- **Per warp.** Needed only if one core hosts CTAs of two kernels at once. Kept
  as an extension.

**A core runs one kernel at a time.** `VX_cta_dispatch` holds a CTA whose kernel index
differs from the core's KID until every warp on the core has retired, then runs
the kernel-change scrub (*Residue*) and loads the new KID. A concurrent schedule
that would co-locate two kernels on a core is serialized there, not run under
the wrong identity. With one kernel on the device every core gets the same KID,
which reproduces the device-wide case. The request format is the same as a
per-warp design would use, so moving to per-warp later changes only where the
LSU and fetch read the value from.

### What the request carries

`mem_bus_attr_t.owner` (today `CLOG2(cores)` bits) becomes:

```
requester = { tenant : TENANT_W,   // acts-as tenant; TENANT_NONE reserved
              kidx   : KIDX_W }    // kernel index, log2(max live kernels)
```

Both are resolved at dispatch and already travel with requests through MSHR
replay, as the owner field does today. At 8 tenants and 8 live kernel indices the
requester is 6 bits; neither width depends on core count.

### Every global-memory requester carries it

The LSU and fetch are not the only units that issue global requests. DXA
(`VX_dxa_gmem_req.sv:203`) and RTU (`VX_rtu_core.sv:247`) drive `attr = '0`,
so their requests carry requester 0 to the checker and to every labeled cache.
Both are off by default (`VX_CFG_EXT_DXA_ENABLE = false`), but nothing refuses
them with the checker on. Now: a static assert refuses DXA and RTU when the
checker is enabled, the same treatment as the configurations in `d2f7b4aca`.
Extension: each takes the core's KID with the request. TCU's
`attr = '0` (`VX_tcu_abuf.sv:261`, `VX_tcu_bbuf.sv:360`) is on the LMEM bus
only, which *Residue* covers.

## Kernel index reuse: per-index generations

A kernel index is reused by later allocations, so a grant naming kernel index `k` must not carry
over to the next program in `k`. Making the kernel id unique for the session
instead would need ~16 bits on the bus and in every label.

Instead each kernel index has a **generation counter**, held in a per-index table wired
to every judging point like the epoch table. Allocating a kernel index advances its
generation and returns the handle `(kidx, gen)` to software, which grants
to that handle.

The two kinds of grant then have different lifetimes, each stated directly by
the programmer with nothing to predict:

- **To a tenant:** "until I revoke". Exactly v1: holds while
  `epoch[owner] <= grant_epoch`; the owner revokes by advancing its own epoch;
  software chooses `grant_epoch`.
- **To a kernel:** "while this allocation lives". For a kernel grantee the
  label's `grant_epoch` field holds the handle's generation, and the grant holds
  while `gen[req.kidx] == grant_epoch`. The next allocation in the kernel index has a
  new generation, so the old grants stop matching.

Consequences:

- **Revocation is untouched.** Owner epochs move only when that owner revokes;
  allocations never touch them.
- **A kernel grant cannot be cut off by its owner while a launch runs.** It ends
  with the allocation. Between launches of the same kernel index, an owner can still
  withdraw by rewriting its own header (only the kernel index's own sealed ranges are
  frozen, below). That matches the bound already claimed: revocation takes
  effect no later than the next launch boundary. Under concurrency, cutting a
  running kernel off early means killing it, which is how mainstream GPU stacks
  stop a context. If mid-kernel revocation is needed later, the 16-bit field
  can be split into generation and epoch bits, trading wrap headroom.
- **Granting to a kernel requires its handle and its measurement**, so
  allocation is a command separate from launch: allocate, grant, launch.
- **Wrap is per kernel index.** A 16-bit generation allows ~65K reuses of each kernel index;
  when one wraps, that kernel index is retired until the session is re-established.
  Other kernel indices and every owner's revocation are unaffected.

## Allocation, sealing and measurement

### The hole

Without this section, kernel grants confine nothing. In the hospital case M
allocates `K`, chooses its entry point, and grants it RX on a code granule M
owns. H grants R on the images to `(k, g)`. `K` reads the images and writes
them into M's output buffer, which M owns and reads. Every access was granted.
The X bit does not help: it fixes what `K` *can* execute, not what H agreed to.

The fix has five parts, each closing one way around the measurement:

| Requirement | Without it |
|---|---|
| The command processor computes the measurement, not the host | The allocator reports whatever measurement H expects |
| It covers everything that determines `K`'s behaviour: code, arguments, launch geometry, acts-as tenant | Agreed code, different arguments ("dump inputs to output") or a different entry point |
| Measured state is frozen until the kernel index retires | The allocator rewrites the code or arguments after H checks |
| The grant is installed only if the measurement matches, in the same step | H reads the measurement, then the allocator swaps code before H's grant lands |
| The launch order is measured and enforced by the command processor | Agreed kernels run in an order nobody agreed to, e.g. the kernel that exports to the output straight after the one that stages images into scratch |

### `CMD_KALLOC`

`CMD_KALLOC { qmds[1..Q], prologue, body, code, args, scratch, acts_as }`,
where `code`, `args` and `scratch` are granule-aligned ranges, each QMD is an
in-memory KMU descriptor of the kind `CMD_LAUNCH_QMD` already reads
(`sim/common/cmd_processor.h:186`), and `prologue` and `body` are lists of QMD
indices giving the launch order (*Launch sequencer*). The command processor:

1. **Checks ownership.** The allocating tenant `A` (from its queue, see
   Authorship) must own every granule in `code`, `args` and `scratch`. The code
   and argument granules must have owner perms without W, and no listed granule
   may carry a live grant. `acts_as` must be `NONE` or `A`. Every QMD's entry
   and startup address must lie in `code`, and its argument pointer in `args`.
   `body` must be non-empty, and every entry of `prologue` and `body` must name
   one of the QMDs. Otherwise refused.
2. **Picks a free kernel index** `k` and advances `gen[k]` to `g`.
3. **Seals.** It installs a grant to `(k, g)` in each listed header: RX on
   `code`, R on `args`, RW on `scratch`. It sets the scratch granules' owner
   perms to none ("blind"), so the scratch owner cannot read what the program
   leaves there. It records the three ranges in a per-index table.
4. **Snapshots** the QMDs and the launch order into the kernel index's
   descriptor table, and sets the sequencer to the first entry. Launches of `k`
   use the snapshot; KMU DCR writes and edits to the in-memory QMDs after
   allocation change nothing.
5. **Measures:** `meas[k] = SHA-256(acts_as ‖ Q ‖ QMD snapshots ‖ prologue ‖
   body ‖ range bases and sizes ‖ code bytes ‖ argument bytes)`. The reads are
   the command processor's own, not attributed to any tenant.
6. **Returns** `(k, g, meas[k])` to the allocating queue.

Scratch contents and sizes are not part of the measurement beyond their range.
Scratch starts zeroed (below), so its contents are not an input.

### Freeze

While kernel index `k` is live, the command processor refuses any `BUF_COMMIT`, from
any queue, whose range overlaps one of `k`'s sealed ranges. With
checker-mediated command-processor DMA (issue 2), owner writes to code and
arguments are denied (owner perms lack W), and owner reads of scratch are
denied (blind). Kernels cannot write code or arguments either: the only grant
on them is RX or R to `(k, g)`. So the bytes measured are the bytes executed
and the arguments read, for as long as any grant to `(k, g)` can match.

### Conditional grant

A grant to a kernel handle carries the measurement its owner expects. A new
staged register `BUF_KMEAS` (256 bits, eight words) sits next to the other
`BUF_*` fields. A `BUF_COMMIT` with `grantee_kind == KERNEL` is installed only
if:

- kernel index `k` is live,
- `gen[k] == g`, and
- `meas[k] == BUF_KMEAS`.

Otherwise it is refused and counted. H computes the expected value offline from
the agreed binaries, arguments and launch geometry, so H's grant means "kernel index
`k`, generation `g`, running exactly this program". Check and install are one
step, so nothing can change between them. The comparison runs on the setup path
in the command processor. The label and the predicate do not change, and the
measurement never reaches a judging point.

### Launch and retirement

`CMD_LAUNCH { k }` launches the kernel the sequencer names for kernel index `k`,
from the snapshot. It is refused unless `k` is live, not failed, and has no
launch running. Any party may launch, any number of times; repeated launches
are the training loop.

### Launch sequencer

The kernels of one program share scratch, so a kernel's effect depends on what
ran before it. Measuring the kernels as a set would make H agree to every
interleaving of them; measuring the order makes H agree to one program.

The order is two lists of QMD indices, fixed at allocation and measured:
`prologue` runs once (initialization, loading a batch layout), then `body`
repeats (one training step). The command processor keeps one position per
kernel index, `pos[k]`, in the descriptor table:

- `CMD_LAUNCH { k }` launches `(prologue ‖ body)[pos[k]]`. The caller names no
  kernel, so there is no out-of-order launch to refuse.
- `pos[k]` advances when that launch **completes**. After the last body entry it
  returns to the first body entry, never to the prologue.
- One launch of `k` runs at a time. A second `CMD_LAUNCH { k }` while one is
  running is refused, so the order cannot be raced from two queues.
- A launch that does not complete (killed, timed out, faulted) marks `k`
  **failed**. Every later launch of `k` is refused; only `CMD_KFREE` is
  accepted, which zeroes the scratch. A half-run kernel's scratch is never fed
  to the next kernel in the order.

What it does not bind: who launches (any party; a launch only runs the agreed
program over granted data), and how many times the body repeats. An agreed
program that must run a final step once, such as writing a result, writes it
as part of the body, or the owners accept that it can be skipped.

Cost: a position counter and a failed bit per kernel index, a lookup in the
snapshot on each launch, and two order lists of at most `Q` entries each
(16 bytes at `Q = 8`) in the descriptor table. All in the command-processor
model; nothing on any judging point.

`CMD_KFREE { k }`, or a new allocation in `k`, retires the kernel index:

1. Waits until no launch of `k` is running.
2. Zeroes the scratch range with the command processor's own writes.
3. Advances `gen[k]`. Every grant to `(k, g)` stops matching, including the
   seal grants on code, arguments and scratch.
4. Clears the kernel index table entry, which unfreezes the ranges. The scratch owner
   gets back a granule of zeros, with owner perms restored.

On Vortex the per-launch flush leaves no cached line of the scratch range at
retirement. A GPU that keeps L2 warm across kernels must write back and
invalidate the scratch range before zeroing it. That is the same generality
question as issue 13, not a Vortex cost.

### Where it is built, and what is modelled

All of the above lives in the C++ command-processor model that both SimX and
rtlsim drive (rtlsim does not use `hw/rtl/cp` for launches). That includes the
kernel index table, `CMD_KALLOC`/`CMD_KFREE`/launch-by-index, the launch
sequencer, the freeze, the conditional
commit, the SHA-256 and the scrub. The RTL command processor implements
host-ring launches only. So the claim is: "the command processor measures,
seals and gates; built in the command-processor model". A hardware hash engine,
and signing `meas[k]` with a device key so a remote party can verify it, are
design. Vortex has no device key, so attestation to a remote H is modelled as
H reading `meas[k]` over its authenticated queue.

What H trusts at the end: the command processor (it stamps, measures, seals,
gates and scrubs), the checker's fixed predicate, and the agreed program. None
of M's software.

### Limits

- A header holds one grant, so a sealed granule serves one kernel index at a time, and
  a program's code must sit in granules of its own (up to two granules of slack
  at 1 MB). The grantee mask relaxes this if it is built.
- One range each for code, arguments and scratch. More ranges widen the kernel index
  table, not the label.
- Confinement is as good as the agreed program: `K` can write anything it reads
  into the agreed output. That is the clean room's model too, but the measured
  code is one program rather than a whole operating system and driver.

## Policy header v2

Changes, all landing together because each changes the label width:

| Field | v1 | v2 | Why |
|---|---|---|---|
| `owner` | core id, binary | tenant id, binary | ownership is a tenant property |
| `owner_any` | wildcard bit | removed; `OWNER_UNCLAIMED` is a reserved `owner` value | one field fewer; unclaimed is an owner value, not a mode |
| `perms` | R, W | R, W, X | fetch must refuse granules not granted for execution; lets an owner lock code; a blind scratch granule has none |
| grantee | none: `shared_perms` applied to every non-owner | `grantee_kind` (tenant / kernel) + `grantee` id, `max(TENANT_W, KIDX_W)` bits | a grant must name whom it is for |
| `shared_perms` | R, W | renamed `grant_perms`; R, W, X | |
| `grant_epoch` | compared to the owner's epoch | unchanged for a tenant grantee; holds the kernel index generation for a kernel grantee | kernel index reuse without a second field or a change to revocation |
| `tag` | `` `UP(CHK_TAG_W) `` = 1 dead bit at the design point | zero-width when `CHK_TAG_W == 0` (generate) | not in the label, but costs one bit per header-store entry; still needed when `CHK_ENTRIES != 0` |

The measurement is not a header field. It lives in the command processor's
per-index table and is checked only when a kernel grant is committed.

Encodings considered and rejected:

- **One-hot `owner`.** A single id needs N bits one-hot against ⌈log₂N⌉ binary,
  equal only at N ≤ 2. The natural one-hot encoding of "unclaimed" is all-zero,
  which a single flip on a claimed granule reaches, so it is also fail-open.
- **Grantee as a session-unique 16-bit KID.** 41-bit label; replaced by a kernel index
  plus per-index generations.
- **One session clock** advancing on every revocation and allocation, with
  grants stamped by hardware. Solves kernel index reuse in the same 29 bits, but couples
  tenants (any tenant's allocations move the clock and spend its wrap budget,
  which then blocks everyone's revocation), takes `grant_epoch` out of
  software's hands, and gives one field two meanings.
- **Measurement in the label.** Would let a judging point check code identity
  per access, at 256 bits per line. Unnecessary: the kernel index's generation already
  names one measured, frozen program.

Predicate (replaces `chk_authorize_label`):

```
need = is_write ? W : (is_fetch ? X : R)
owner_ok = lbl.owner == OWNER_UNCLAIMED
         | (req.tenant != NONE & req.tenant == lbl.owner)
if owner_ok                                      -> need ∈ lbl.perms
if lbl.grantee_kind == TENANT
    return req.tenant != NONE & req.tenant == lbl.grantee
         & need ∈ lbl.grant_perms & epoch[lbl.owner] <= lbl.grant_epoch
else
    return req.kidx == lbl.grantee
         & need ∈ lbl.grant_perms & gen[req.kidx] == lbl.grant_epoch
```

Owner access is still never epoch-gated, and the epoch that gates a tenant
grant is still the granting owner's. A blind scratch granule has `perms = {}`,
so `owner_ok` grants its owner nothing and only the kernel grant applies.

### Grantee: id by default, mask as a parameter

A grantee mask (one bit per principal, no kind bit) lets one grant name several
principals ("tenants 1 and 3, not 2"). A mask beats a list of ids only for sets;
for one grantee it costs more. The grantee encoding is a build parameter:

- `id` (default): one grantee. Covers the hospital case, where each owner grants
  to the one agreed program.
- `mask`: `TENANTS + KIDXS` bits, no kind bit. One `grant_epoch` field cannot
  hold an owner epoch and a kernel index generation at once, so a mask grant names
  either tenants only or kernels only, keeping a kind bit, or names at most one
  kernel. To be settled if the mask is built.

### Label width

8 tenants, 8 kernel indices, 16-bit epoch:

| Layout | owner | perms | grantee | grant perms | epoch | Label | Requester |
|---|---|---|---|---|---|---|---|
| v1 today (2 cores) | 1 + `owner_any` 1 | 2 | — | 2 | 16 | 22 | 1 |
| v2, id grantee | 3 | 3 | 1 + 3 | 3 | 16 | **29** | 6 |
| v2, mask over 16 principals | 3 | 3 | 16 | 3 | 16 | 41 | 6 |
| v2, mask over 4 + 4 | 2 | 3 | 8 | 3 | 16 | 32 | 4 |

The mask stays close to the id up to about 8 principals, then the id wins.

R5's label sweep (0, 10, 22) does not reach 29; extend it before quoting area.

No parity or ECC on headers or labels. Soft errors and fault injection are out
of scope; a single flip in a stored header or a cached label can change a
decision, as in v1.
The 16-bit epoch/generation field is the largest; narrowing it trades revocations
per owner and reuses per kernel index for label bits.

## Residue

Every place a kernel can leave data that another requester could read:

| Where | Today | Closed by |
|---|---|---|
| Private L1 D-cache and I-cache | flushed after every launch; unlabeled, unjudged | invalidate on kernel index change (below) |
| Local memory (16 KB per core by default) | never cleared; absolute addressing (`VX_cta_dispatch.sv:564`); unchecked | zeroed on kernel index change |
| Register file, int and FP | `gpr_ram` resets only under `GPR_RESET`, i.e. debug simulation, and only at device reset (`VX_opc_unit.sv:16-22,289`) | zeroed on kernel index change |
| Per-warp CSRs (`fcsr` and similar) | carried over | reset on kernel index change |
| Scratch buffers | owned by a tenant, readable by it afterwards | blind while the kernel index lives; zeroed at retirement |
| Shared L2/L3 lines | labeled | already judged against the line's label for every requester |
| DXA, RTU global requests | requester 0 | refused with the checker on (above) |

Shared levels (L2, L3) are already correct under both time-slicing and
concurrency. They judge each delivery against the line's label and the current
requester, whoever brought the line in. A line `K` left in L2 keeps its owner's
label, and a later kernel in another kernel index is judged against it.

### Kernel-change scrub

Decision: **build it general, enforce a restriction for now.**

1. **Now: one kernel per core at a time, enforced** (see *Where the requester
   id lives*). When the core's KID changes, `VX_cta_dispatch` runs a scrub
   before dispatching:
   - invalidate the core's L1s;
   - zero local memory through its write port;
   - zero every warp's int and FP registers through the GPR banks' write ports;
   - reset per-warp CSRs.

   One small FSM in `VX_cta_dispatch` drives all four. SimX does the same in its
   dispatch path. A concurrent schedule that would co-locate two kernel indices is
   serialized on that core, not run unchecked.
2. **Extension: per-warp KID, labeled L1s and per-CTA local-memory bounds.**
   Move the KID into per-warp registers, turn the D-cache and I-cache into
   delivery edges (`LABEL_ENABLE`/`LABEL_EDGE` already exist per cache-bank
   instance), and bound each CTA's local-memory accesses to its kernel index. This lifts
   the one-kernel-per-core restriction. It costs a label store in every L1 and a
   bounds compare on the local-memory path.

**Why a scrub, not bounds, for now.** With one kernel index per core enforced, local
memory and registers are never shared between kernel indices at the same time. The only
path is temporal, and zeroing at the change closes it. Bounds matter only with
co-resident kernel indices.

**Cost, estimated at the default configuration.** Local memory: 16 KB at
`LMEM_NUM_BANKS` × 4 B per cycle, about 1K cycles. Registers: 64 × 4 warps × 4
threads × 4 B = 4 KB over 4 banks, under 300 cycles. So roughly 1.1K cycles per
core per kernel index change, against about 180 for the L1 invalidate alone and 17.2K
for the L2+L3 flush. Measure before quoting.

**Optimization, not built.** Skip the scrub when the old and new kernel indices act as
the same tenant and neither is `NONE`. Every change to or from a `NONE` kernel index
scrubs. Launches of the same kernel index never scrub, since the program's own residue
is its own.

## Hospital walk-through

1. H claims the images (owner perms RW). M claims the weights and an output
   buffer (RW), the training program's code and argument granules (owner perms
   R), and a scratch range.
2. M issues `CMD_KALLOC` naming the program's QMDs, code, arguments and scratch,
   acting as `NONE`. The command processor checks that M owns them, seals them
   (code RX, arguments R, scratch RW to `(k, g)`; scratch blind), snapshots the
   QMDs, measures, and returns `(k, g, m)` to M. M passes `(k, g)` to H over any
   channel; it need not be trusted.
3. H computes `m'` from the agreed binaries, arguments and geometry, and on its
   own queue grants R on the images to `(k, g)` with `BUF_KMEAS = m'`. The
   commit installs only if `m' == meas[k]`. M grants R on the weights and W on
   the output to `(k, g)` the same way.
4. Either party launches `k`, as many times as training needs; the sequencer
   runs the prologue once and then the body's kernels in the agreed order. They
   read the images, weights and arguments, write the output and scratch, and
   execute only the code granules. Any write elsewhere is denied, since `K` owns
   nothing.
5. Between launches, H's kernels cannot read the weights or the scratch, and M's
   cannot read the images or the scratch (blind). Each core whose kernel index changes
   is scrubbed: L1s, local memory, registers, CSRs. M cannot rewrite the code or
   arguments: they are frozen, and their owner perms lack W. H can withdraw the
   image grant between launches by rewriting its own header, which is not
   frozen.
6. `CMD_KFREE k`: scratch is zeroed, `gen[k]` advances, every grant to `(k, g)`
   stops matching, and the ranges unfreeze.

Negative case: M allocates with different code or arguments. `meas[k]` differs,
H's commit is refused, and the images stay ungranted. A launch of `k` then reads
poison from them.

Holes this alone does not close:
- Command-processor DMA bypasses the checker (`cp_axi_dev`,
  `VX_afu_wrap.sv:719-736`). H can still download the weights with
  `CMD_MEM_READ`, and M can read the blind scratch the same way.
- Setup writes are not authenticated. M can re-claim H's images, and nothing
  attributes H's conditional grant or M's allocation to a tenant.

Both are separate work (below).

## Dependencies

- **Authorship.** The checker must know which tenant wrote each setup command.
  A write is `{addr, value}` on the DCR bus; any identity inside it
  (`BUF_OWNER` today) is chosen by the writer. The identity has to come from the
  channel: one command queue per tenant, bound to the tenant at session setup,
  with the command processor stamping each DCR write, allocation and launch with
  its queue's tenant. This models the per-tenant authenticated channel a CC GPU
  builds with a per-session key. `VX_CP_NUM_QUEUES` exists (default 1).
  `CMD_KALLOC`'s ownership check and the conditional commit both need it.
- **CP DMA through the checker.** DMA beats tagged with the queue's tenant and
  no kernel index, routed through a checker. Freeze and blind scratch need it to mean
  anything against the tenants' own queues.

The **plumbing** (requester, kernel indices, generations, header v2, kernel-change scrub)
depends on neither and can be built first. The **security** of kernel grants
depends on both. The 12 Oct draft said kernel identity depended on neither;
that was true of the plumbing only. The paper must state kernel-bound grants,
like P1, as holding by design until both land.

## Plan

Build order, chosen so that each step's regressions mean something when it
lands:

1. **Header v2 and the predicate**, in RTL, SimX, `VX_types.toml` and the host
   claim path, with the grantee encoding parameter. Before the L2+L3
   evaluation runs, because it changes the label width.
2. **Authorship and CP DMA through the checker** (issues 1 and 2).
3. **Requester plumbing, behaviour-neutral.** Kernel index and acts-as tenant in
   `kmu_req_t`, a per-core KID register in `VX_cta_dispatch`, request attr from
   the KID in LSU and fetch; SimX core state and `MemChecker` take the requester
   from the request. A test mode makes the KMU assign `tenant = kernel index = core id`,
   so every existing regression and the model_parity gate stay green unchanged.
   Static assert refusing DXA and RTU with the checker on.
4. **Kernel indices in the command-processor model.** Per-index generation table, kernel index
   table, `CMD_KALLOC`, `CMD_KFREE`, launch-by-index with the sequencer, the
   freeze, `BUF_KMEAS` and
   the conditional commit, SHA-256, and the retirement scrub.
5. **Dispatch rule and kernel-change scrub** in RTL and SimX: one kernel index per core,
   L1 invalidate, local-memory and register zeroing, CSR reset.
6. **Regressions.**
   - `hospital`: the walk-through, each step checked by value and deny count.
   - `hospital_badcode`: M allocates different code; H's conditional commit is
     refused, and `K` reads poison from the images. The same with the agreed
     code but a different `prologue` or `body`.
   - `sequence`: launches of `k` run the prologue once and then cycle the body,
     checked by a per-kernel trace in scratch; a second launch while one runs
     is refused; after a killed launch every launch is refused until
     `CMD_KFREE`, and the scratch reads zeros afterwards.
   - `seal`: M's write to sealed code or arguments is denied, by kernel store
     and by `CMD_MEM_WRITE`; M's `BUF_COMMIT` overlapping a sealed range is
     refused.
   - `residue`: kernel index A writes a pattern to local memory and leaves it in
     registers; kernel index B, next on the same cores, reads zeros, on both models.
     The same run with the scrub disabled must show the pattern; that is the
     exhibit.
   - `scratch`: M reads the scratch during the allocation (denied) and after
     `CMD_KFREE` (zeros).
   - Kernel index reuse: a grant to `(k, g)` is denied to the next allocation in `k`,
     and a tenant grant by the same owner survives the reallocation.
   - Time-slice: two kernel indices with the per-launch flush disabled; 0 breaches.
   - Fetch from a claimed granule (review issue 6), with X: allowed with RX,
     denied without.
7. **Re-synthesis** at the new label width, with the scrub FSM.

Labeled L1s, per-CTA local-memory bounds, a hardware hash engine and device-key
attestation remain design unless time allows.

## Open questions

- Generation width: 16 bits shares the field with the epoch. Is ~65K
  allocations per kernel index per session enough?
- Is a kernel grant that cannot be cut off mid-launch acceptable, or should the
  field be split?
- `KIDX_W`: how many live kernel indices to provision. 8 is proposed; with one kernel index on
  the device at a time today, the extra kernel indices matter for keeping several agreed
  programs allocated, and for concurrency.
- `Q`, kernels per program: 8 proposed. A real training step has more kernels
  than that unless fused; is the kernel index's QMD table the right place to grow?
- The measurement binds the launch order (*Launch sequencer*). Should it also
  bind who may launch, or how many times the body repeats? Proposed: no.
  Launching only runs the agreed program over granted data.
- Is prologue plus a repeating body enough structure, or do programs need an
  epilogue that runs once on request (e.g. a final export)? Proposed: no
  epilogue until a workload needs one.
- Does a grant to a tenant also cover that tenant's neutral kernels? Proposed:
  no. A tenant grant matches only requesters acting as that tenant.
