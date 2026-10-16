# Confinement by data-plane taint, and policy header v2

Status: draft, 16 Oct 2026. Branch `sec-mem-checker`. Proposes a replacement for
the measurement design in `kernel_identity_proposal.md` (12 Oct, revised 15 and
16 Oct). That design is summarised in the appendix so the two can be compared;
nothing in either is built.

## Why

Today the identity on every memory request is the core id
(`VX_lsu_slice.sv:120`, `VX_fetch.sv:235`, SimX `MemChecker::owner_of`), and the
same value is compared against a granule's `owner`. One tenant per core makes
that work, but it conflates two things:

- **Who owns data.** A tenant that claims granules at setup and keeps them
  across many launches.
- **Who is asking.** The code issuing a load, store or fetch right now.

The conflation also leaves the catch in the hospital scenario open. A grant
names a tenant, so the grantee's kernel can copy whatever it reads into a buffer
it owns, and revocation does not undo the copy. The model and the images must
meet at training time, and whichever party's kernel runs the training holds the
other party's data.

The 15 Oct proposal closed that by binding grants to a *measured kernel*. It
works, but it needs a measurement, a conditional commit, sealing and freezing,
descriptor snapshots, a launch sequencer, blind scratch and per-index
generations, all on the setup path. Each piece exists only to stop the
allocator changing what "the agreed kernel" means after the other owner has
agreed to it. The setup path grows to the size of Graviton's.

This proposal closes the same hole the way the rest of the design works: the
policy travels with the data, including through computation. Data derived from
a confined read keeps its contributor's ownership wherever it is written. No
code is measured, and nothing about a kernel is trusted.

## The idea in one paragraph

A granule is owned by a **set** of tenants. Each core keeps a **taint**, the set
of tenants whose confined data the running kernel has read. Every read delivered
to the core adds its granule's contributors to the taint. A write lands only in
a granule whose owner set **covers** the taint. So a kernel that has read H's
images can write only into granules H co-owns, whatever its code does, in any
order, through any page-table mapping. Joint data leaves only when every other
owner has stepped out of the owner set, and only an owner can step itself out.
This is a coarse floating label (HiStar, Flume, LIO, COWL), done in the GPU
memory hierarchy, with the label carried by cache lines.

## Requirements

1. Ownership stays with tenants and persists across launches.
2. A confined read's contributors follow everything the reader writes afterwards,
   independent of the reader's code, launch order and translation.
3. Joint data reaches a single party only with the consent of every other owner,
   given by that owner through its own queue.
4. Judging points read no state beyond today's per-owner epoch table. The taint
   arrives on the request, so the hit path stays zero cycles.
5. Revocation stays as it is: an owner revokes a grant by advancing its own
   epoch.
6. Must not break under time-slicing or concurrent kernels. Where a case is not
   supported, hardware refuses it rather than running it unchecked.
7. No residue crosses a kernel boundary on a core.
8. SimX and RTL change together (model_parity).

## Principals and the requester

| Principal | Set by | Lifetime | Used for |
|---|---|---|---|
| Tenant `T` | session setup; later, the command queue (Authorship) | session | owner sets in headers; who launched a kernel |

There is no neutral principal and no kernel principal. The agreed training
kernel is launched by one of the tenants and runs as that tenant. What confines
it is the taint, not who it is.

The request carries:

```
requester = { tenant : TENANT_W,    // the launching tenant
              taint  : TENANTS }    // bitmask: whose confined data this kernel has read
```

At 8 tenants that is 3 + 8 = 11 bits. Neither width depends on core count.

**No kernel index.** The 15 Oct design needed a kernel index on every request so
a grant could name a kernel. Here nothing is granted to a kernel, so the checker
never needs to know which kernel is asking. The dispatch logic still needs to
know when the kernel on a core changes, and it has that already in `ctx_id`.

### Where it lives: per core, one kernel per core

`VX_cta_dispatch` holds the launching tenant and the taint in per-core registers,
next to the launch counter it already keeps: `kmu_req.ctx_id`
(`VX_kmu.sv:255`) is held per core in `cur_ctx_id_r` (`VX_cta_dispatch.sv:468`).
The KMU attaches the tenant to each CTA dispatch alongside `ctx_id`. The LSU and
fetch tag each request with the core's tenant and taint.

**A core runs one kernel at a time.** `VX_cta_dispatch` holds a CTA from a
different launch until every warp on the core has retired, then runs the
kernel-change scrub (*Residue*), clears the taint and loads the new tenant. A
concurrent schedule that would co-locate two kernels on a core is serialized
there.

The taint is per core, not per warp: every warp of the kernel on the core shares
it. That is conservative. A read by one warp taints writes by all of them, which
can only over-restrict. Moving the tenant and taint into per-warp registers is
the extension that lifts one-kernel-per-core.

### Updating the taint

Every delivered read returns a **contributor mask** to the core with its data:

```
contrib = denied                         ? ∅
        : lbl.owners == ∅                ? ∅                      // unclaimed
        : req.tenant ∈ lbl.owners        ? lbl.owners \ {req.tenant}
        : grant is confined              ? lbl.owners
        :                                  ∅                      // trusting grant
```

The core ORs `contrib` into its taint register. Reads, fetches and AMOs all
count; fetched code is data that shapes every later write.

The one timing invariant: **the taint is updated no later than the read's
writeback to the register file.** A write that depends on the value, by data or
by a branch, issues after that writeback, so it carries the updated taint. A
write that issued earlier cannot contain the value.

L1 hits need nothing new. A line in a private L1 was filled through a delivery
edge during this kernel on this core, so its contributors are already in the
taint. Across kernels the L1s are invalidated by the scrub.

The contributor mask travels on the read response from the delivery edge (L2, or
L3 with no L2, or the port with private caches only) back through the L1 to the
LSU and fetch. That is `TENANTS` bits on the response path, alongside the label
bits that path already carries.

### Every global-memory requester carries it

DXA (`VX_dxa_gmem_req.sv:203`) and RTU (`VX_rtu_core.sv:247`) drive `attr = '0`.
Both are off by default (`VX_CFG_EXT_DXA_ENABLE = false`). Now: a static assert
refuses both when the checker is enabled, as for the configurations in
`d2f7b4aca`. Extension: each carries the core's tenant and taint, and returns
contributors. TCU's `attr = '0` is on the LMEM bus only, which the scrub covers.

## The predicate

```
need = is_write ? W : (is_fetch ? X : R)
owner = req.tenant ∈ lbl.owners

if lbl.owners == ∅                               // unclaimed: boot default
    may = need ∈ DEFAULT_PERMS
elif owner
    may = need ∈ lbl.perms
else                                             // grant to a tenant
    may = req.tenant == lbl.grantee
        & need ∈ lbl.grant_perms
        & epoch[the owner] <= lbl.grant_epoch

if is_write
    return may & (lbl.owners ⊇ req.taint)        // covering write
return may                                       // and return contrib (above)
```

Owner access is still never epoch-gated, and the epoch that gates a grant is
still the granting owner's. Grants exist only on single-owner granules (rule S4),
so "the owner" is well defined.

The covering check is `(req.taint & ~lbl.owners) == 0`, one AND and an OR
reduction over `TENANTS` bits, in parallel with the rest of the predicate.

Three consequences fall out without further rules:

- **Unclaimed memory is closed to tainted writes.** Its owner set is empty, so
  it covers only an empty taint. A kernel that has read confined data cannot
  spill it into unclaimed memory, whether or not issue 3 closes unclaimed memory
  by default.
- **Page tables cannot launder data.** The check is on the physical granule the
  write lands on. Whoever writes the kernel's page tables can send its writes
  anywhere, and each lands on a granule judged like any other.
- **Code and order do not matter.** Malicious code, swapped arguments and
  out-of-order launches can all compute anything from H's data, and all of it
  stays in granules H co-owns.

## The setup path: six fixed rules

Each rule is applied by the command processor to a command attributed to the
tenant `T` whose queue it arrived on (Authorship).

| # | Rule | Why it is safe |
|---|---|---|
| S1 | **Claim.** `T` may claim unclaimed granules with any owner set that contains `T`. | Naming another tenant as co-owner only gives that tenant a veto over the granule's exit. It costs `T` its own memory, nothing else. |
| S2 | **Leave.** An owner may remove *itself* from a granule's owner set, if at least one owner remains. | This is release: when H leaves `{H, M}`, the granule is M's. Nobody can remove anyone else. |
| S3 | **Zero.** An owner may have the command processor zero a granule; its owner set becomes `{T}`. | Zeroed memory carries no one's data. This is how scratch and stacks are reclaimed. |
| S4 | **Grant.** The sole owner of a granule may grant one tenant R, W or X, as **trusting** or **confined**; it revokes by advancing its epoch, as today. Joint granules carry no grant. | Trusting is today's grant: the grantee may keep what it reads. Confined taints the reader. |
| S5 | **Upload.** `CMD_MEM_WRITE` by `T` is a write by `T` with an empty taint. | The host's data enters under the normal write rule. |
| S6 | **Download.** `CMD_MEM_READ` by `T` of a granule is allowed only if its owner set is `{T}`, or `T` holds a trusting R grant on it. | The host is the exit. Joint data and confined grants never leave as a download. |

Compared with the measurement design, the setup path never reads code or
arguments, keeps no per-kernel state, and has nothing that must be atomic across
a measurement and a grant.

## Policy header v2

All changes land together, because each changes the label width.

| Field | v1 | v2 | Why |
|---|---|---|---|
| `owner` | core id, binary | `owners`: tenant bitmask | joint ownership; the empty set is "unclaimed", so the `owner_any` wildcard goes |
| `owner_any` | wildcard bit | removed | replaced by `owners == ∅` |
| `perms` | R, W | R, W, X | fetch must refuse granules not granted for execution; applies to every owner |
| grantee | none: `shared_perms` applied to every non-owner | `grantee`: tenant id | a grant names whom it is for |
| `shared_perms` | R, W | renamed `grant_perms`; R, W, X | |
| `confined` | none | 1 bit | trusting or confined grant (S4) |
| `grant_epoch` | compared to the owner's epoch | unchanged | |
| `tag` | `` `UP(CHK_TAG_W) `` = 1 dead bit at the design point | zero-width when `CHK_TAG_W == 0` (generate) | not in the label; still needed when `CHK_ENTRIES != 0` |

No parity or ECC. Soft errors and fault injection are out of scope; a single
flip in a stored header or a cached label can change a decision, as in v1. With
an owner bitmask, a flip that clears an owner bit drops that owner's veto.

### Label width

16-bit epoch:

| Layout | owners | perms | grantee | grant perms | confined | epoch | Label | Requester |
|---|---|---|---|---|---|---|---|---|
| v1 today (2 cores) | 1 + `owner_any` 1 | 2 | — | 2 | — | 16 | 22 | 1 |
| v2, 4 tenants | 4 | 3 | 2 | 3 | 1 | 16 | 29 | 2 + 4 |
| v2, 8 tenants | 8 | 3 | 3 | 3 | 1 | 16 | **34** | 3 + 8 |

R5's label sweep (0, 10, 22) does not reach 34; extend it before quoting area.
The 16-bit epoch is the largest field; narrowing it trades revocations per owner
for label bits.

## Residue

Taint makes residue a harder requirement, not a softer one: if a kernel's
registers outlive it, the next kernel on that core reads confined data with an
empty taint and can write it anywhere.

| Where | Today | Closed by |
|---|---|---|
| Private L1 D-cache and I-cache | flushed after every launch; unlabeled, unjudged | invalidated by the kernel-change scrub |
| Local memory (16 KB per core by default) | never cleared; absolute addressing (`VX_cta_dispatch.sv:564`); unchecked | zeroed by the scrub |
| Register file, int and FP | `gpr_ram` resets only under `GPR_RESET`, i.e. debug simulation, and only at device reset (`VX_opc_unit.sv:16-22,289`) | zeroed by the scrub |
| Per-warp CSRs (`fcsr` and similar) | carried over | reset by the scrub |
| Stack | global memory at a fixed address, `VX_MEM_STACK_BASE_ADDR` (`VX_types.toml:22`), `sp = base − hart << 13` (`vx_start.S:95-97`); unclaimed; the same bytes for every kernel on a hart | claimed by the launching tenant with the owner set its kernel will need (below) |
| Shared L2/L3 lines | labeled | already judged against the line's label for every requester |
| Taint itself | — | cleared by the scrub, never before it |

### Kernel-change scrub

When the kernel on a core changes, `VX_cta_dispatch` runs one FSM before
dispatching the new kernel's first CTA:

- invalidate the core's L1s;
- zero local memory through its write port;
- zero every warp's int and FP registers through the GPR banks' write ports;
- reset per-warp CSRs;
- clear the taint and load the new tenant.

SimX does the same in its dispatch path.

**Cost, estimated at the default configuration.** Local memory: 16 KB at
`LMEM_NUM_BANKS` × 4 B per cycle, about 1K cycles. Registers: 64 × 4 warps × 4
threads × 4 B = 4 KB over 4 banks, under 300 cycles. Roughly 1.1K cycles per
core per kernel change, against about 180 for the L1 invalidate alone and 17.2K
for the L2+L3 flush. Measure before quoting.

**Optimization, not built.** Skip the scrub when the old kernel's taint was
empty and the new kernel has the same tenant. A kernel that read nothing
confined left nothing that is not its own tenant's.

### Stacks and scratch

A tainted kernel can write only to granules that cover its taint, and that
includes its stack. So the launching tenant claims the stack range, and any
scratch, with the owner set the kernel will reach: `{H, M}` for the training
kernel. Afterwards it reclaims them with S3 (zero, owner set `{M}`). Nothing is
"blind": M can read the joint scratch with its own kernels, but every such read
taints them with `{H}`, so the data stays joint.

The stack base is a compile-time constant today. Claiming it per launch works
without changing that, at the cost of serialising launches that need different
owner sets on the stack range. A per-launch stack base in the KMU descriptor is
the cleaner extension.

## Hospital walk-through

1. **Claim.** H claims the images, `{H}`, RW. M claims the weights, `{M}`, RW,
   and an output buffer, scratch and the stack range as `{H, M}` (S1).
2. **Grant.** H grants M a **confined** R on the images (S4).
3. **Train.** M launches its training kernels, any code, any number, any order.
   Each core's taint becomes `{H}` the first time it reads an image. Writes to
   the output, scratch and stack (`{H, M}`) pass. Writes to M's own buffers, to
   unclaimed memory, or anywhere a page table points that is not co-owned by H,
   are denied. M's `CMD_MEM_READ` of the output or scratch is refused (S6).
4. **Between launches.** M's other kernels can read the weights as before. If
   one reads the output, it becomes tainted `{H}` and can only write joint
   granules. H's kernels read the images as before. H can revoke the confined
   grant at any time by advancing its epoch; it takes effect at the next launch
   boundary, and everything already derived stays joint.
5. **Release.** When H agrees to release the trained weights, H leaves the
   output (S2). The owner set becomes `{M}`, and M downloads it.
6. **Reclaim.** M zeroes the scratch and stack (S3); they become `{M}`.

Negative cases, each a regression: M's kernel copies images into M's weights
buffer (denied, covering write), into unclaimed memory (denied), through a
remapped virtual address (denied); M downloads the scratch before release
(refused); M removes H from the output's owner set (refused: an owner can remove
only itself).

### What H trusts at the end

The command processor's six rules, the checker's fixed predicate, and the
scrub. Not M's software, not the training code, not the order of launches, not
the page tables.

What H still decides is **release**. Once H leaves the output, M has whatever is
in it, and the output is computed by code M chose. H's decision to leave is
therefore a decision about that code, made out of band: H agreed which program
would run, or audited what ran, or accepts the output whatever produced it. The
design makes that one explicit act the only exit; it does not make the act
safe. An attested launch log (the command processor records the hash of every
kernel launched while the output was joint) would inform the decision without
putting measurement back on the enforcement path. It is optional and not
proposed now.

Also not addressed, as in a clean room: the output is a function of the
weights, which M controls. Gradient-inversion attacks recover training inputs
from weight updates, so releasing trained weights can release information about
the images whatever the code was.

## Comparison with the 15 Oct measurement design

| | Measurement design (15–16 Oct) | Taint design (this proposal) |
|---|---|---|
| What confines the data | A grant to a measured, frozen program; the program writes only what it is granted | The taint: derived data stays in granules the contributor co-owns |
| Setup-path work | `CMD_KALLOC` (ownership check, kernel index, generation, seal, snapshot, launch order, SHA-256), conditional commit, freeze on every `BUF_COMMIT`, sequencer on every launch, `CMD_KFREE` (wait, zero, generation, unfreeze) | Six fixed rules (S1–S6); no per-kernel state; never reads code |
| What H must trust for confinement | The command processor's measurement and the agreed program | Nothing about any kernel; only the predicate and the scrub |
| What H decides | Whether `meas[k]` matches the agreed program, before granting | Whether to leave the output, after training |
| Malicious code | Refused at the conditional commit | Runs; its writes stay joint |
| Code or arguments changed after agreement | Prevented by seal, freeze and snapshot | Irrelevant |
| Launch order | Bound by the sequencer | Irrelevant |
| Page tables written by the other party (VM on) | Hole: remapping scratch or code defeats the measurement unless page tables are sealed and measured too | Irrelevant: writes are judged on the physical granule |
| Unclaimed memory open (issue 3) | Hole: the neutral kernel can write into it | Closed to tainted writes by construction |
| Intermediates between kernels | Blind scratch sealed to the kernel index; zeroed at `CMD_KFREE` | Joint granules; readable by owners' kernels, which become tainted |
| Copies after revocation | Ends with the kernel index | Stay joint; the contributor keeps its veto |
| Requester on the bus | tenant + kernel index (6 bits at 8 + 8) | tenant + taint (11 bits at 8 tenants) |
| Label | 29 bits (8 tenants, 8 kernel indices) | 34 bits (8 tenants) |
| Data-path hardware | Per-index generation table at every judging point | Covering-write check at every write judge; contributor mask on read responses; taint register per core |
| Residue scrub | Needed | Needed, and load-bearing |
| Depends on authorship (issue 1) and CP DMA through the checker (issue 2) | Both | Both |
| Depends on unclaimed closed (issue 3) | Yes | No, for confinement |
| Where it is built | Mostly the C++ command-processor model; RTL for plumbing and scrub | RTL and SimX data path; command-processor model for S1–S6 |
| Granularity cost | One grant per header, so a sealed granule serves one kernel index | Taint is per core for the whole kernel: one confined read restricts every later write |
| Prior work | Ryoan (measured, confined module) | HiStar, Flume, LIO, COWL (floating labels); Ryoan |

## Dependencies

- **Authorship (issue 1).** S1–S4 all depend on knowing which tenant issued a
  command: "only an owner can remove itself" means nothing if the writer chooses
  its own identity. One command queue per tenant, with the command processor
  stamping every setup command and launch with its queue's tenant.
- **CP DMA through the checker (issue 2).** S5 and S6 are rules about DMA. Today
  `cp_axi_dev` merges with Vortex's memory port past the checkers
  (`VX_afu_wrap.sv:719-736`), so a queue can download a joint granule directly.
- **Claims in physical addresses (issue 3).** Still needed for isolation with VM
  on, because claims must name the granules the data actually occupies. Not
  needed for confinement, which judges whatever granule a write lands on.

The **plumbing** (owner sets, taint, contributor mask, covering write, header
v2, scrub) depends on none of these and can be built first. The **security** of
confinement depends on issues 1 and 2. The paper states confinement, like P1,
as holding by design until both land.

## Plan

1. **Header v2 and the predicate** in RTL, SimX, `VX_types.toml` and the host
   claim path: owner sets, X, grantee, confined bit. Before the L2+L3 evaluation
   runs, because it changes the label width.
2. **Requester plumbing, behaviour-neutral.** Tenant and taint in `kmu_req_t`
   and per-core registers in `VX_cta_dispatch`; request attr from those in the
   LSU and fetch; the contributor mask on read responses back to the core; SimX
   core state and `MemChecker` likewise. A test mode sets `tenant = core id` and
   never sets `confined`, so every existing regression and the model_parity gate
   stay green unchanged. Static assert refusing DXA and RTU with the checker on.
3. **Kernel-change scrub and the one-kernel-per-core rule** in RTL and SimX.
4. **Authorship and CP DMA through the checker** (issues 1 and 2), with S5 and
   S6.
5. **S1–S4** in the command-processor model: owner-set claims, leave, zero,
   trusting and confined grants.
6. **Regressions.**
   - `hospital`: the walk-through, each step checked by value and deny count.
   - `launder`: M's tainted kernel writes images into M's own buffer, into
     unclaimed memory, and through a remapped VA; all denied, on both models.
   - `release`: M downloads the output before H leaves (refused) and after
     (allowed); M tries to remove H (refused).
   - `trusting`: a trusting grant behaves exactly as today's grant; the reader
     is not tainted.
   - `residue`: kernel A reads confined data and leaves it in local memory and
     registers; kernel B, next on the same cores with an empty taint, reads
     zeros. The same run with the scrub disabled shows the pattern and lets B
     write it to its own buffer; that is the exhibit.
   - `taint_timing`: a store dependent on a just-returned confined load is
     denied; a store issued before the load is not.
   - `crosscore`: core A writes derived data to a joint granule; core B reads it
     and becomes tainted.
   - Time-slice: two tenants' kernels with the per-launch flush disabled;
     0 breaches.
   - Fetch from a claimed granule (review issue 6), with X: allowed with RX,
     denied without.
7. **Re-synthesis** at the new label width, with the covering-write check, the
   contributor mask on the response path, and the scrub FSM.

Per-warp tenant and taint, labeled L1s, per-CTA local-memory bounds, and the
attested launch log remain design unless time allows.

## Open questions

- **Taint granularity.** Per core for the whole kernel. A kernel that reads one
  confined byte can write only joint granules from then on. Is that acceptable
  for the workloads, or do some need per-warp taint?
- **Contributor mask on the response path.** `TENANTS` more bits from the
  delivery edge through the L1 to the LSU and fetch. Does it fit the existing
  response attr, and does it touch the L1's critical paths?
- **Release.** Is "H leaves" enough, or should release name a target ("H leaves
  only if the remaining owners are exactly `{M}`") so H cannot be surprised by
  an owner set it did not expect? A compare-and-leave is one more operand on S2.
- **S3 and availability.** Any owner may zero a joint granule and take it. That
  destroys the co-owner's data but never discloses it. Acceptable, or should
  zeroing need all owners?
- **Stack.** Per-launch claims of the fixed stack range, or a per-launch stack
  base in the KMU descriptor?
- **Deny counters.** A tainted kernel can try a write and the host can read
  whether it was denied. That is a covert channel, like timing; both are out of
  scope, but per-tenant counters should not be readable by other tenants.
- **Stale cached labels.** S2 and S3 rewrite headers, and cached labels
  do not see a rewrite. On Vortex every launch flushes, so this is exact. On a
  GPU that keeps L2 warm, a stale `{H, M}` label after H leaves still covers a
  `{H}` taint, which lets H-derived writes land after release. Same generality
  question as issue 13.

## Appendix: the measurement design, for reference

Full text in `kernel_identity_proposal.md`. In short: a kernel index (a small
index into a table of live kernels, with a per-index generation so reuse does
not inherit grants) is carried on every request; a grant can name `(kernel
index, generation)`; and the command processor makes that name mean one agreed
program. Each of its setup pieces closes one way for the allocator to change the
program after the other owner agreed:

| Piece | Without it, the allocator can… |
|---|---|
| Measurement (SHA-256 in the command processor) | load any code under the kernel index |
| Conditional commit (`BUF_KMEAS` must match) | show the right measurement, then swap code before the grant lands |
| Seal and freeze | rewrite the code or argument bytes after measurement |
| Snapshot of the launch descriptors | keep the code and change the entry PC or argument pointer |
| Launch sequencer | run the agreed kernels in an order nobody agreed to |
| Blind scratch, zeroed at `CMD_KFREE` | read the intermediates the program leaves behind |
| Generation advanced at `CMD_KFREE` | reuse the kernel index and inherit the grants |
| Kernel-change scrub | read what the program left in local memory and registers |

Two holes remained open in it: with VM on, the allocator's page tables can remap
the measured program's scratch or code; and with unclaimed memory open, the
agreed kernel can write into it. The taint design closes both by construction.
