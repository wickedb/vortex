# Kernel identity as the requester, and policy header v2

Status: draft, 12 Oct 2026; revised 15 Oct 2026 to close the measurement and
residue holes. Branch `sec-mem-checker`.

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
   per-owner epoch table and a per-slot generation table (below), so the hit
   path cost stays zero. Measurements never enter a label.
5. Revocation stays as it is: an owner revokes by advancing its own epoch, and
   no other tenant's activity moves that epoch.
6. SimX and RTL change together (model_parity).
7. **A grant to a kernel is a grant to measured code.** The bytes measured are
   the bytes executed and the arguments read, from measurement until the
   kernel's slot is retired, and the check that a grant matches the measurement
   happens in the same step that installs the grant.
8. **No residue crosses a slot boundary.** No state a kernel leaves in a core
   or in a scratch buffer is readable by a requester in a different slot.

## Principals

| Principal | Set by | Lifetime | Used for |
|---|---|---|---|
| Tenant `T` | session setup (later: the command queue, see Authorship) | session | `owner` in headers; owner access |
| Kernel slot `S` | the command processor, at allocation | one allocation (one or more launches); the slot is then reused | the requester on every request; grants that name a kernel |

Each slot carries an **acts-as tenant**, which may be `NONE`:

- A tenant's own kernel acts as that tenant and has the tenant's owner rights.
- An agreed (neutral) kernel acts as `NONE`. It has no owner rights; everything
  it touches must be granted to it. Because it gains nothing it was not granted,
  any party may launch it, and consent is expressed by each owner issuing its
  own grant against the slot's measurement rather than by a joint registration
  step.

A slot holds an **agreed program**: up to `Q` kernels (8 proposed) that are
allocated, measured and retired together. A training step is many kernels
(GEMMs, activations, a reduction, an optimizer step), and the tensors passed
between them must stay inside the agreement. A slot per kernel would put those
intermediates in granules granted to one slot at a time. A slot per program
keeps them in the program's scratch across launches. Launches name the slot
and an index into its program.

## Where the requester id lives: per warp

Three placements were considered.

- **Device-wide register**, latched at launch. Correct only while one kernel
  occupies the device. Breaks under concurrency.
- **Per-core register.** Different cores may run different kernels, but one core
  cannot host two. Vortex already has this shape for the launch counter:
  `kmu_req.ctx_id` (`VX_kmu.sv:255`) is held per core in `cur_ctx_id_r`
  (`VX_cta_dispatch.sv:468`). Breaks under co-resident kernels.
- **Per warp (chosen).** The KMU attaches the kernel's slot and acts-as tenant
  to each CTA dispatch alongside `ctx_id`. `VX_cta_dispatch` writes them into
  per-warp registers when it initializes the CTA's warps. The LSU and fetch tag
  each request with the issuing warp's values.

With one kernel on the device every warp gets the same values, which reproduces
the device-wide case at no extra cost. Nothing built now is thrown away when
concurrency arrives.

### What the request carries

`mem_bus_attr_t.owner` (today `CLOG2(cores)` bits) becomes:

```
requester = { tenant : TENANT_W,   // acts-as tenant; TENANT_NONE reserved
              slot   : SLOT_W }    // kernel slot, log2(max live slots)
```

Both are resolved at dispatch and already travel with requests through MSHR
replay, as the owner field does today. At 8 tenants and 8 live slots the
requester is 6 bits; neither width depends on core count.

### Every global-memory requester carries it

The LSU and fetch are not the only units that issue global requests. DXA
(`VX_dxa_gmem_req.sv:203`) and RTU (`VX_rtu_core.sv:247`) drive `attr = '0`,
so their requests carry requester 0 to the checker and to every labeled cache.
Both are off by default (`VX_CFG_EXT_DXA_ENABLE = false`), but nothing refuses
them with the checker on. Now: a static assert refuses DXA and RTU when the
checker is enabled, the same treatment as the configurations in `d2f7b4aca`.
Extension: each takes the issuing warp's requester with the request. TCU's
`attr = '0` (`VX_tcu_abuf.sv:261`, `VX_tcu_bbuf.sv:360`) is on the LMEM bus
only, which *Residue* covers.

## Slot reuse: per-slot generations

A slot is reused by later allocations, so a grant naming slot `s` must not carry
over to the next program in `s`. Making the kernel id unique for the session
instead would need ~16 bits on the bus and in every label.

Instead each slot has a **generation counter**, held in a per-slot table wired
to every judging point like the epoch table. Allocating a slot advances its
generation and returns the handle `(slot, gen)` to software, which grants
to that handle.

The two kinds of grant then have different lifetimes, each stated directly by
the programmer with nothing to predict:

- **To a tenant:** "until I revoke". Exactly v1: holds while
  `epoch[owner] <= grant_epoch`; the owner revokes by advancing its own epoch;
  software chooses `grant_epoch`.
- **To a kernel:** "while this allocation lives". For a kernel grantee the
  label's `grant_epoch` field holds the handle's generation, and the grant holds
  while `gen[req.slot] == grant_epoch`. The next allocation in the slot has a
  new generation, so the old grants stop matching.

Consequences:

- **Revocation is untouched.** Owner epochs move only when that owner revokes;
  allocations never touch them.
- **A kernel grant cannot be cut off by its owner while a launch runs.** It ends
  with the allocation. Between launches of the same slot, an owner can still
  withdraw by rewriting its own header (only the slot's own sealed ranges are
  frozen, below). That matches the bound already claimed: revocation takes
  effect no later than the next launch boundary. Under concurrency, cutting a
  running kernel off early means killing it, which is how mainstream GPU stacks
  stop a context. If mid-kernel revocation is needed later, the 16-bit field
  can be split into generation and epoch bits, trading wrap headroom.
- **Granting to a kernel requires its handle and its measurement**, so
  allocation is a command separate from launch: allocate, grant, launch.
- **Wrap is per slot.** A 16-bit generation allows ~65K reuses of each slot;
  when one wraps, that slot is retired until the session is re-established.
  Other slots and every owner's revocation are unaffected.

## Allocation, sealing and measurement

### The hole

Without this section, kernel grants confine nothing. In the hospital case M
allocates `K`, chooses its entry point, and grants it RX on a code granule M
owns. H grants R on the images to `(s, g)`. `K` reads the images and writes
them into M's output buffer, which M owns and reads. Every access was granted.
The X bit does not help: it fixes what `K` *can* execute, not what H agreed to.

The fix has four parts, each closing one way around the measurement:

| Requirement | Without it |
|---|---|
| The command processor computes the measurement, not the host | The allocator reports whatever measurement H expects |
| It covers everything that determines `K`'s behaviour: code, arguments, launch geometry, acts-as tenant | Agreed code, different arguments ("dump inputs to output") or a different entry point |
| Measured state is frozen until the slot retires | The allocator rewrites the code or arguments after H checks |
| The grant is installed only if the measurement matches, in the same step | H reads the measurement, then the allocator swaps code before H's grant lands |

### `CMD_KALLOC`

`CMD_KALLOC { qmds[1..Q], code, args, scratch, acts_as }`, where `code`,
`args` and `scratch` are granule-aligned ranges, and each QMD is an in-memory
KMU descriptor of the kind `CMD_LAUNCH_QMD` already reads
(`sim/common/cmd_processor.h:186`). The command processor:

1. **Checks ownership.** The allocating tenant `A` (from its queue, see
   Authorship) must own every granule in `code`, `args` and `scratch`. The code
   and argument granules must have owner perms without W, and no listed granule
   may carry a live grant. `acts_as` must be `NONE` or `A`. Every QMD's entry
   and startup address must lie in `code`, and its argument pointer in `args`.
   Otherwise refused.
2. **Picks a free slot** `s` and advances `gen[s]` to `g`.
3. **Seals.** It installs a grant to `(s, g)` in each listed header: RX on
   `code`, R on `args`, RW on `scratch`. It sets the scratch granules' owner
   perms to none ("blind"), so the scratch owner cannot read what the program
   leaves there. It records the three ranges in a per-slot table.
4. **Snapshots** the QMDs into the slot's descriptor table. Launches of `s` use
   the snapshot; KMU DCR writes and edits to the in-memory QMDs after
   allocation change nothing.
5. **Measures:** `meas[s] = SHA-256(acts_as ‖ Q ‖ QMD snapshots ‖ range bases
   and sizes ‖ code bytes ‖ argument bytes)`. The reads are the command
   processor's own, not attributed to any tenant.
6. **Returns** `(s, g, meas[s])` to the allocating queue.

Scratch contents and sizes are not part of the measurement beyond their range.
Scratch starts zeroed (below), so its contents are not an input.

### Freeze

While slot `s` is live, the command processor refuses any `BUF_COMMIT`, from
any queue, whose range overlaps one of `s`'s sealed ranges. With
checker-mediated command-processor DMA (issue 2), owner writes to code and
arguments are denied (owner perms lack W), and owner reads of scratch are
denied (blind). Kernels cannot write code or arguments either: the only grant
on them is RX or R to `(s, g)`. So the bytes measured are the bytes executed
and the arguments read, for as long as any grant to `(s, g)` can match.

### Conditional grant

A grant to a kernel handle carries the measurement its owner expects. A new
staged register `BUF_KMEAS` (256 bits, eight words) sits next to the other
`BUF_*` fields. A `BUF_COMMIT` with `grantee_kind == KERNEL` is installed only
if:

- slot `s` is live,
- `gen[s] == g`, and
- `meas[s] == BUF_KMEAS`.

Otherwise it is refused and counted. H computes the expected value offline from
the agreed binaries, arguments and launch geometry, so H's grant means "slot
`s`, generation `g`, running exactly this program". Check and install are one
step, so nothing can change between them. The comparison runs on the setup path
in the command processor. The label and the predicate do not change, and the
measurement never reaches a judging point.

### Launch and retirement

`CMD_LAUNCH { s, i }` launches QMD `i` of slot `s` from the snapshot. It is
refused unless `s` is live. Any party may launch, any number of times; repeated
launches are the training loop.

`CMD_KFREE { s }`, or a new allocation in `s`, retires the slot:

1. Waits until no launch of `s` is running.
2. Zeroes the scratch range with the command processor's own writes.
3. Advances `gen[s]`. Every grant to `(s, g)` stops matching, including the
   seal grants on code, arguments and scratch.
4. Clears the slot table entry, which unfreezes the ranges. The scratch owner
   gets back a granule of zeros, with owner perms restored.

On Vortex the per-launch flush leaves no cached line of the scratch range at
retirement. A GPU that keeps L2 warm across kernels must write back and
invalidate the scratch range before zeroing it. That is the same generality
question as issue 13, not a Vortex cost.

### Where it is built, and what is modelled

All of the above lives in the C++ command-processor model that both SimX and
rtlsim drive (rtlsim does not use `hw/rtl/cp` for launches). That includes the
slot table, `CMD_KALLOC`/`CMD_KFREE`/launch-by-slot, the freeze, the conditional
commit, the SHA-256 and the scrub. The RTL command processor implements
host-ring launches only. So the claim is: "the command processor measures,
seals and gates; built in the command-processor model". A hardware hash engine,
and signing `meas[s]` with a device key so a remote party can verify it, are
design. Vortex has no device key, so attestation to a remote H is modelled as
H reading `meas[s]` over its authenticated queue.

What H trusts at the end: the command processor (it stamps, measures, seals,
gates and scrubs), the checker's fixed predicate, and the agreed program. None
of M's software.

### Limits

- A header holds one grant, so a sealed granule serves one slot at a time, and
  a program's code must sit in granules of its own (up to two granules of slack
  at 1 MB). The grantee mask relaxes this if it is built.
- One range each for code, arguments and scratch. More ranges widen the slot
  table, not the label.
- Confinement is as good as the agreed program: `K` can write anything it reads
  into the agreed output. That is the clean room's model too, but the measured
  code is one program rather than a whole operating system and driver.

## Policy header v2

Changes, all landing together because each changes the label width:

| Field | v1 | v2 | Why |
|---|---|---|---|
| `owner` | core id, binary | tenant id, binary | ownership is a tenant property |
| `owner_any` | wildcard bit | removed; `OWNER_UNCLAIMED` is a reserved `owner` value | one flipped bit made a private granule public |
| `perms` | R, W | R, W, X | fetch must refuse granules not granted for execution; lets an owner lock code; a blind scratch granule has none |
| grantee | none: `shared_perms` applied to every non-owner | `grantee_kind` (tenant / kernel) + `grantee` id, `max(TENANT_W, SLOT_W)` bits | a grant must name whom it is for |
| `shared_perms` | R, W | renamed `grant_perms`; R, W, X | |
| `grant_epoch` | compared to the owner's epoch | unchanged for a tenant grantee; holds the slot generation for a kernel grantee | slot reuse without a second field or a change to revocation |
| parity | none | one bit over the header and over every label; mismatch denies | with the reserved encoding, a single flip in the store or any cached label fails closed |
| `tag` | `` `UP(CHK_TAG_W) `` = 1 dead bit at the design point | zero-width when `CHK_TAG_W == 0` (generate) | not in the label, but costs one bit per header-store entry; still needed when `CHK_ENTRIES != 0` |

The measurement is not a header field. It lives in the command processor's
per-slot table and is checked only when a kernel grant is committed.

Encodings considered and rejected:

- **One-hot `owner`.** A single id needs N bits one-hot against ⌈log₂N⌉ binary,
  equal only at N ≤ 2. The natural one-hot encoding of "unclaimed" is all-zero,
  which a single flip on a claimed granule reaches, so it is also fail-open.
- **Grantee as a session-unique 16-bit KID.** 41-bit label; replaced by slot id
  plus per-slot generations.
- **One session clock** advancing on every revocation and allocation, with
  grants stamped by hardware. Solves slot reuse in the same 30 bits, but couples
  tenants (any tenant's allocations move the clock and spend its wrap budget,
  which then blocks everyone's revocation), takes `grant_epoch` out of
  software's hands, and gives one field two meanings.
- **Measurement in the label.** Would let a judging point check code identity
  per access, at 256 bits per line. Unnecessary: the slot's generation already
  names one measured, frozen program.

Predicate (replaces `chk_authorize_label`):

```
need = is_write ? W : (is_fetch ? X : R)
if parity_bad(lbl)                               -> deny
owner_ok = lbl.owner == OWNER_UNCLAIMED
         | (req.tenant != NONE & req.tenant == lbl.owner)
if owner_ok                                      -> need ∈ lbl.perms
if lbl.grantee_kind == TENANT
    return req.tenant != NONE & req.tenant == lbl.grantee
         & need ∈ lbl.grant_perms & epoch[lbl.owner] <= lbl.grant_epoch
else
    return req.slot == lbl.grantee
         & need ∈ lbl.grant_perms & gen[req.slot] == lbl.grant_epoch
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
- `mask`: `TENANTS + SLOTS` bits, no kind bit. One `grant_epoch` field cannot
  hold an owner epoch and a slot generation at once, so a mask grant names
  either tenants only or kernels only, keeping a kind bit, or names at most one
  kernel. To be settled if the mask is built.

### Label width

8 tenants, 8 slots, 16-bit epoch, 1 parity bit:

| Layout | owner | perms | grantee | grant perms | epoch | parity | Label | Requester |
|---|---|---|---|---|---|---|---|---|
| v1 today (2 cores) | 1 + `owner_any` 1 | 2 | — | 2 | 16 | — | 22 | 1 |
| v2, id grantee | 3 | 3 | 1 + 3 | 3 | 16 | 1 | **30** | 6 |
| v2, mask over 16 principals | 3 | 3 | 16 | 3 | 16 | 1 | 42 | 6 |
| v2, mask over 4 + 4 | 2 | 3 | 8 | 3 | 16 | 1 | 33 | 4 |

The mask stays close to the id up to about 8 principals, then the id wins.

R5's label sweep (0, 10, 22) does not reach 30; extend it before quoting area.
The 16-bit epoch/generation field is the largest; narrowing it trades revocations
per owner and reuses per slot for label bits.

## Residue

Every place a kernel can leave data that another requester could read:

| Where | Today | Closed by |
|---|---|---|
| Private L1 D-cache and I-cache | flushed after every launch; unlabeled, unjudged | invalidate on slot change (below) |
| Local memory (16 KB per core by default) | never cleared; absolute addressing (`VX_cta_dispatch.sv:564`); unchecked | zeroed on slot change |
| Register file, int and FP | `gpr_ram` resets only under `GPR_RESET`, i.e. debug simulation, and only at device reset (`VX_opc_unit.sv:16-22,289`) | zeroed on slot change |
| Per-warp CSRs (`fcsr` and similar) | carried over | reset on slot change |
| Scratch buffers | owned by a tenant, readable by it afterwards | blind while the slot lives; zeroed at retirement |
| Shared L2/L3 lines | labeled | already judged against the line's label for every requester |
| DXA, RTU global requests | requester 0 | refused with the checker on (above) |

Shared levels (L2, L3) are already correct under both time-slicing and
concurrency. They judge each delivery against the line's label and the current
requester, whoever brought the line in. A line `K` left in L2 keeps its owner's
label, and a later kernel in another slot is judged against it.

### Slot-change scrub

Decision: **build it general, enforce a restriction for now.**

1. **Now: one slot per core at a time, enforced.** `VX_cta_dispatch` holds a CTA
   whose slot differs from that of warps still live on the core. When the
   core's slot changes, it runs a scrub before dispatching:
   - invalidate the core's L1s;
   - zero local memory through its write port;
   - zero every warp's int and FP registers through the GPR banks' write ports;
   - reset per-warp CSRs.

   One small FSM in `VX_cta_dispatch` drives all four. SimX does the same in its
   dispatch path. A concurrent schedule that would co-locate two slots is
   serialized on that core, not run unchecked.
2. **Extension: labeled L1s and per-CTA local-memory bounds.** Turn the D-cache
   and I-cache into delivery edges (`LABEL_ENABLE`/`LABEL_EDGE` already exist
   per cache-bank instance), and bound each CTA's local-memory accesses to its
   slot. This lifts the one-slot-per-core restriction. It costs a label store in
   every L1 and a bounds compare on the local-memory path.

**Why a scrub, not bounds, for now.** With one slot per core enforced, local
memory and registers are never shared between slots at the same time. The only
path is temporal, and zeroing at the change closes it. Bounds matter only with
co-resident slots.

**Cost, estimated at the default configuration.** Local memory: 16 KB at
`LMEM_NUM_BANKS` × 4 B per cycle, about 1K cycles. Registers: 64 × 4 warps × 4
threads × 4 B = 4 KB over 4 banks, under 300 cycles. So roughly 1.1K cycles per
core per slot change, against about 180 for the L1 invalidate alone and 17.2K
for the L2+L3 flush. Measure before quoting.

**Optimization, not built.** Skip the scrub when the old and new slots act as
the same tenant and neither is `NONE`. Every change to or from a `NONE` slot
scrubs. Launches of the same slot never scrub, since the program's own residue
is its own.

## Hospital walk-through

1. H claims the images (owner perms RW). M claims the weights and an output
   buffer (RW), the training program's code and argument granules (owner perms
   R), and a scratch range.
2. M issues `CMD_KALLOC` naming the program's QMDs, code, arguments and scratch,
   acting as `NONE`. The command processor checks that M owns them, seals them
   (code RX, arguments R, scratch RW to `(s, g)`; scratch blind), snapshots the
   QMDs, measures, and returns `(s, g, m)` to M. M passes `(s, g)` to H over any
   channel; it need not be trusted.
3. H computes `m'` from the agreed binaries, arguments and geometry, and on its
   own queue grants R on the images to `(s, g)` with `BUF_KMEAS = m'`. The
   commit installs only if `m' == meas[s]`. M grants R on the weights and W on
   the output to `(s, g)` the same way.
4. Either party launches kernels of `s`, as many times as training needs. They
   read the images, weights and arguments, write the output and scratch, and
   execute only the code granules. Any write elsewhere is denied, since `K` owns
   nothing.
5. Between launches, H's kernels cannot read the weights or the scratch, and M's
   cannot read the images or the scratch (blind). Each core whose slot changes
   is scrubbed: L1s, local memory, registers, CSRs. M cannot rewrite the code or
   arguments: they are frozen, and their owner perms lack W. H can withdraw the
   image grant between launches by rewriting its own header, which is not
   frozen.
6. `CMD_KFREE s`: scratch is zeroed, `gen[s]` advances, every grant to `(s, g)`
   stops matching, and the ranges unfreeze.

Negative case: M allocates with different code or arguments. `meas[s]` differs,
H's commit is refused, and the images stay ungranted. A launch of `s` then reads
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
  no slot, routed through a checker. Freeze and blind scratch need it to mean
  anything against the tenants' own queues.

The **plumbing** (requester, slots, generations, header v2, slot-change scrub)
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
3. **Requester plumbing, behaviour-neutral.** Slot and acts-as tenant in
   `kmu_req_t`, per-warp registers in `VX_cta_dispatch`, request attr from the
   warp in LSU and fetch; SimX warp state and `MemChecker` take the requester
   from the request. A test mode makes the KMU assign `tenant = slot = core id`,
   so every existing regression and the model_parity gate stay green unchanged.
   Static assert refusing DXA and RTU with the checker on.
4. **Slots in the command-processor model.** Per-slot generation table, slot
   table, `CMD_KALLOC`, `CMD_KFREE`, launch-by-slot, the freeze, `BUF_KMEAS` and
   the conditional commit, SHA-256, and the retirement scrub.
5. **Dispatch rule and slot-change scrub** in RTL and SimX: one slot per core,
   L1 invalidate, local-memory and register zeroing, CSR reset.
6. **Regressions.**
   - `hospital`: the walk-through, each step checked by value and deny count.
   - `hospital_badcode`: M allocates different code; H's conditional commit is
     refused, and `K` reads poison from the images.
   - `seal`: M's write to sealed code or arguments is denied, by kernel store
     and by `CMD_MEM_WRITE`; M's `BUF_COMMIT` overlapping a sealed range is
     refused.
   - `residue`: slot A writes a pattern to local memory and leaves it in
     registers; slot B, next on the same cores, reads zeros, on both models.
     The same run with the scrub disabled must show the pattern; that is the
     exhibit.
   - `scratch`: M reads the scratch during the allocation (denied) and after
     `CMD_KFREE` (zeros).
   - Slot reuse: a grant to `(s, g)` is denied to the next allocation in `s`,
     and a tenant grant by the same owner survives the reallocation.
   - Time-slice: two slots with the per-launch flush disabled; 0 breaches.
   - Fetch from a claimed granule (review issue 6), with X: allowed with RX,
     denied without.
   - Parity: a forced flip in a header and in a cached label denies.
7. **Re-synthesis** at the new label width, with the scrub FSM.

Labeled L1s, per-CTA local-memory bounds, a hardware hash engine and device-key
attestation remain design unless time allows.

## Open questions

- Generation width: 16 bits shares the field with the epoch. Is ~65K
  allocations per slot per session enough?
- Is a kernel grant that cannot be cut off mid-launch acceptable, or should the
  field be split?
- `SLOT_W`: how many live slots to provision. 8 is proposed; with one slot on
  the device at a time today, the extra slots matter for keeping several agreed
  programs allocated, and for concurrency.
- `Q`, kernels per program: 8 proposed. A real training step has more kernels
  than that unless fused; is the slot's QMD table the right place to grow?
- Should the measurement also bind who may launch, or how many times? Proposed:
  no. Launching only runs the agreed program over granted data.
- Is fault injection in the threat model, or are soft errors the only reason for
  parity? Parity is cheap enough to add either way.
- Does a grant to a tenant also cover that tenant's neutral kernels? Proposed:
  no. A tenant grant matches only requesters acting as that tenant.
