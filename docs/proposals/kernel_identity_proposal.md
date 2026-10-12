# Kernel identity as the requester, and policy header v2

Status: draft, 12 Oct 2026. Branch `sec-mem-checker`.

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
   path cost stays zero.
5. Revocation stays as it is: an owner revokes by advancing its own epoch, and
   no other tenant's activity moves that epoch.
6. SimX and RTL change together (model_parity).

## Principals

| Principal | Set by | Lifetime | Used for |
|---|---|---|---|
| Tenant `T` | session setup (later: the command queue, see Authorship) | session | `owner` in headers; owner access |
| Kernel slot `S` | the command processor, at kernel allocation | one kernel instance; the slot is then reused | the requester on every request; grants that name a kernel |

Each kernel carries an **acts-as tenant**, which may be `NONE`:

- A tenant's own kernel acts as that tenant and has the tenant's owner rights.
- An agreed (neutral) kernel acts as `NONE`. It has no owner rights; everything
  it touches must be granted to it. Because it gains nothing it was not granted,
  any party may launch it, and consent is expressed by each owner issuing its
  own grant rather than by a joint registration step.

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
              slot   : SLOT_W }    // kernel slot, log2(max live kernels)
```

Both are resolved at dispatch and already travel with requests through MSHR
replay, as the owner field does today. At 8 tenants and 8 live kernels the
requester is 6 bits; neither width depends on core count.

## Slot reuse: per-slot generations

A slot is reused by later kernels, so a grant naming slot `s` must not carry
over to the next kernel in `s`. Making the kernel id unique for the session
instead would need ~16 bits on the bus and in every label.

Instead each slot has a **generation counter**, held in a per-slot table wired
to every judging point like the epoch table. Allocating a kernel advances its
slot's generation and returns the handle `(slot, gen)` to software, which grants
to that handle.

The two kinds of grant then have different lifetimes, each stated directly by
the programmer with nothing to predict:

- **To a tenant:** "until I revoke". Exactly v1: holds while
  `epoch[owner] <= grant_epoch`; the owner revokes by advancing its own epoch;
  software chooses `grant_epoch`.
- **To a kernel:** "while this kernel runs". For a kernel grantee the label's
  `grant_epoch` field holds the handle's generation, and the grant holds while
  `gen[req.slot] == grant_epoch`. The next kernel in the slot has a new
  generation, so the old grants stop matching.

Consequences:

- **Revocation is untouched.** Owner epochs move only when that owner revokes;
  allocations never touch them.
- **A kernel grant is not revocable by its owner while the kernel runs.** It
  ends with the kernel. That matches the bound already claimed: revocation takes
  effect no later than the next launch boundary. Under concurrency, cutting a
  running kernel off early means killing it, which is how mainstream GPU stacks
  stop a context. If mid-kernel revocation is needed later, the 16-bit field
  can be split into generation and epoch bits, trading wrap headroom.
- **Granting to a kernel requires its handle**, so allocation is a command
  separate from launch: allocate, grant, launch.
- **Wrap is per slot.** A 16-bit generation allows ~65K reuses of each slot;
  when one wraps, that slot is retired until the session is re-established.
  Other slots and every owner's revocation are unaffected.

## Policy header v2

Changes, all landing together because each changes the label width:

| Field | v1 | v2 | Why |
|---|---|---|---|
| `owner` | core id, binary | tenant id, binary | ownership is a tenant property |
| `owner_any` | wildcard bit | removed; `OWNER_UNCLAIMED` is a reserved `owner` value | one flipped bit made a private granule public |
| `perms` | R, W | R, W, X | fetch must refuse granules not granted for execution; lets an owner lock code (below) |
| grantee | none: `shared_perms` applied to every non-owner | `grantee_kind` (tenant / kernel) + `grantee` id, `max(TENANT_W, SLOT_W)` bits | a grant must name whom it is for |
| `shared_perms` | R, W | renamed `grant_perms`; R, W, X | |
| `grant_epoch` | compared to the owner's epoch | unchanged for a tenant grantee; holds the slot generation for a kernel grantee | slot reuse without a second field or a change to revocation |
| parity | none | one bit over the header and over every label; mismatch denies | with the reserved encoding, a single flip in the store or any cached label fails closed |
| `tag` | `` `UP(CHK_TAG_W) `` = 1 dead bit at the design point | zero-width when `CHK_TAG_W == 0` (generate) | not in the label, but costs one bit per header-store entry; still needed when `CHK_ENTRIES != 0` |

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
grant is still the granting owner's.

### Grantee: id by default, mask as a parameter

A grantee mask (one bit per principal, no kind bit) lets one grant name several
principals ("tenants 1 and 3, not 2"). A mask beats a list of ids only for sets;
for one grantee it costs more. The grantee encoding is a build parameter:

- `id` (default): one grantee. Covers the hospital case, where each owner grants
  to the one agreed kernel.
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

## Caches and local memory

The labeled-lines argument says L1 hits need no judging because each L1 serves
one principal. That stops holding once the requester is a kernel:

- **Time-slicing.** Kernel B can hit lines kernel A left in the core's L1.
  Today the flush after every launch hides this.
- **Concurrent kernels.** Two kernels share one core's D-cache and I-cache.

Shared levels (L2, L3) are already correct for both: they judge each delivery
against the line's label and the current requester, whoever brought the line in.

Decision: **build it general, enforce a restriction for now.**

1. **Now: one kernel per core at a time, enforced.** `VX_cta_dispatch` holds a
   CTA whose slot differs from that of warps still live on the core, and when
   the core's slot changes it invalidates the core's L1s before dispatching.
   With private L1s this is sound under time-slicing without the per-launch
   flush (the review prices an L1-only invalidate at about 180 cycles per
   core). A concurrent schedule that would co-locate two kernels is serialized
   on that core, not run unchecked.
2. **Extension: labeled L1s.** Turn the D-cache and I-cache into delivery edges
   (`LABEL_ENABLE`/`LABEL_EDGE` already exist per cache-bank instance), lifting
   the one-kernel-per-core restriction. Costs a label store in every L1.

**Local memory** is unchecked today. Concurrent CTAs share it, and a kernel can
leave data in it for the next. Needs per-CTA bounds and a scrub when a CTA ends.
Stated as design until built.

## Code identity

A grant to a kernel is only meaningful if it runs the agreed code. Measurement
(a hash of code, entry, start PCs and argument block computed by the command
processor) is out of scope for now and modelled. What makes the modelled
measurement mean something is that the code cannot change while the kernel is
live, which time-slicing and concurrency both otherwise allow. With X:

- The code's owner holds it with owner perms R only, and grants the agreed
  kernel RX. Nobody can write the code while the grant stands.
- Fetch requires X, so the kernel cannot execute any other granule.

Argument contents need no protection for confinement: an agreed kernel given a
pointer to a buffer it was not granted is denied there.

## Hospital walk-through

1. H claims the images; M claims the weights and an output buffer, and the
   training code with owner perms R.
2. Either party allocates kernel K, acting as `NONE`, and receives the handle
   `(s, g)`.
3. H grants R on the images to `(s, g)`; M grants R on the weights, W on the
   output and RX on the code to `(s, g)`.
4. K is launched, reads both inputs and writes the output. Any write elsewhere
   is denied, since K owns nothing.
5. H's kernels cannot read the weights; M's cannot read the images.
6. When `s` is next allocated its generation moves past `g` and every grant
   from step 3 stops matching. Tenant grants made by H or M are unaffected.

Holes this alone does not close: command-processor DMA bypasses the checker
(`cp_axi_dev`, `VX_afu_wrap.sv:719-736`), so H can still download the weights
with `CMD_MEM_READ`; and setup writes are not authenticated, so M can re-claim
H's images. Both are separate work (below).

## Dependencies

- **Authorship.** The checker must know which tenant wrote each setup command.
  A write is `{addr, value}` on the DCR bus; any identity inside it
  (`BUF_OWNER` today) is chosen by the writer. The identity has to come from the
  channel: one command queue per tenant, bound to the tenant at session setup,
  with the command processor stamping each DCR write, allocation and launch with
  its queue's tenant. This models the per-tenant authenticated channel a CC GPU
  builds with a per-session key. `VX_CP_NUM_QUEUES` exists (default 1).
  With authorship, a tenant kernel's acts-as tenant comes from the queue that
  allocated it; until then it is a field of the allocation command on the
  trusted setup path.
- **CP DMA through the checker.** DMA beats tagged with the queue's tenant and
  no slot, routed through a checker.

Kernel identity depends on neither and is built first. The paper must keep
stating that P1 holds by design only, until both land.

## Plan

1. **Requester plumbing, behaviour-neutral.** Slot and acts-as tenant in
   `kmu_req_t`, per-warp registers in `VX_cta_dispatch`, request attr from the
   warp in LSU and fetch; SimX warp state and `MemChecker` take the requester
   from the request. A test mode makes the KMU assign `tenant = slot = core id`,
   so every existing regression and the model_parity gate stay green unchanged.
2. **Per-slot generation table** and the kernel-allocation command returning
   `(slot, gen)`.
3. **Header v2 and the predicate**, in RTL, SimX, `VX_types.toml` and the host
   claim path, with the grantee encoding parameter. The one-kernel-per-core
   dispatch rule and L1 invalidate on slot change.
4. **Regressions.**
   - `hospital`: the walk-through, each step checked by value and deny count.
   - Slot reuse: a grant to `(s, g)` is denied to the next kernel allocated in
     `s`, and a tenant grant by the same owner survives the reallocation.
   - Time-slice: two kernels in different slots with the per-launch flush
     disabled; 0 breaches.
   - Fetch from a claimed granule (open issue 5), with X: allowed with RX,
     denied without.
   - Parity: a forced flip in a header and in a cached label denies.
5. **Re-synthesis** at the new label width.

Labeled L1s, LMEM bounds and scrub, and measurement remain design unless time
allows.

## Open questions

- Generation width: 16 bits shares the field with the epoch. Is ~65K reuses
  per slot per session enough?
- Is a kernel grant that cannot be revoked mid-kernel acceptable, or should the
  field be split?
- `SLOT_W`: how many live kernels to provision. 8 is proposed; with one kernel
  at a time today, the extra slots only matter for concurrency.
- Is fault injection in the threat model, or are soft errors the only reason for
  parity? Parity is cheap enough to add either way.
- Does a grant to a tenant also cover that tenant's neutral kernels? Proposed:
  no. A tenant grant matches only requesters acting as that tenant.
