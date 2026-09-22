# Data-plane access checker — demo guide

A prototype data-centric TEE for Vortex, built entirely in the SimX cycle model
(`sim/simx/`). No RTL is involved: `MemChecker` is a `SimObject` spliced into the
`l3cache_ → memsim_` request path, which is the off-chip boundary in every cache
configuration.

Two pieces live here:

| | Role |
|---|---|
| `checker.{h,cpp}` | **Pass-through observer.** Counts and classifies every request crossing the LLC→DRAM boundary. Attached to `Memory`'s pre-send hook, whose `const&` signature makes stalling or mutating a request structurally impossible. Always present. |
| `mem_checker.{h,cpp}` | **Inline checker.** Per-buffer headers (owner, perms, shared perms, grant epoch) behind a header cache, programmed over DCR. Can stall, deny, and inject faults. Constructed *only* when `VX_CHECKER=1`. |

When `VX_CHECKER` is unset, `MemChecker` is never constructed and the L3→DRAM
binding is byte-for-byte what upstream does.

## Build

Vortex builds **out of tree**: all commands below run from a configured build
directory, not the source root (`make -C sim/simx` from the source root fails —
it has no `config.mk`). If you do not already have one, configure it once (see
the top-level `README.md` for toolchain setup):

```sh
mkdir build && cd build
../configure --xlen=32 --tooldir=$HOME/tools
make -s            # full build (first time)
```

To rebuild only the SimX simulator after editing `sec/` or `mem/` sources:

```sh
make -C sim/simx   # run from inside the build directory
```

## The demos

Run **from the build directory** (`blackbox.sh` resolves apps against the build
tree). Each ends in `PASSED!` or `FAILED!`.

> **New regression tests.** When a test directory is added under
> `tests/regression/` in the source tree (e.g. `revoke_scope`), copy it into the
> build tree before running it — the build tree is populated at configure time:
> `cp -r ../tests/regression/revoke_scope tests/regression/`.

### 1. I didn't break the baseline

`vecadd_claimed` is `vecadd` with its buffers claimed over the DCR setup path —
same allocation order, same sizes, and literally the same kernel binary (its
Makefile compiles `vecadd/kernel.cpp`). The only additions are host-side DCR
writes, which allocate no device memory.

```sh
# reference
./ci/blackbox.sh --driver=simx --app=vecadd --perf=1

# same kernel under real per-buffer policy
VX_CHECKER=1 VX_CHECKER_STATS=1 \
  ./ci/blackbox.sh --driver=simx --app=vecadd_claimed --perf=1
```

**Measured** (default config, `-n64`), re-run 22 Sep 2026:

| Run | cycles | vs baseline | `added_cycles` |
|---|---:|---:|---:|
| `vecadd` baseline | 1266 | — | — |
| `vecadd_claimed`, checker not constructed | 1266 | **0** | — |
| `vecadd_claimed`, defaults | 1276 | **+10** | 8 |
| `vecadd_claimed`, `VX_CHECKER_MISS_LAT=0` | 1272 | **+6** | 0 |

All runs report `deny=0` and `PASSED!`, and all execute 400 instructions.

> **These numbers superseded the ones recorded through 7 Sep 2026** (1240 /
> 1244 / 1240). The baseline itself moved 1240 → 1266 when this branch was
> rebased onto upstream master on 7 Sep — `vecadd` contains no checker, so
> that shift is entirely upstream's. The rest did not survive the move intact;
> see below.

Two things the table separates, because they are different claims:

- **The DCR setup path is free.** Running `vecadd_claimed` with the checker
  *not* constructed costs exactly the baseline 1266, so the host-side claim
  writes add nothing. That still holds.
- **The splice is not free any more.** At `MISS_LAT=0` the checker reports
  `added_cycles=0` and the run still takes **+6 cycles**. Those 6 cycles are
  the pipeline stage the checker adds between the LLC and DRAM — `tick()`
  forwards with `send(req, 1 + added)` — and they are invisible to
  `added_cycles`, which counts only header-lookup latency.

The claim this README carried until 7 Sep — *"set the miss penalty to zero and
the count returns to exactly the baseline"* — was true against the older
upstream, where the extra stage was hidden by slack in the memory system. It
is **not true of this tree** and must not be repeated from the old recording.
What survives is narrower and still worth stating:

> Every cycle of *header-lookup* overhead is attributable to a header-cache
> miss, and the 2 misses here are **compulsory** (cold) — the first touch of
> each claimed buffer, not scaling with the workload. The splice's own cost is
> separate, small, and now measurable rather than assumed.

Whether the +6 is a real cost or a modelling artifact of inserting a SimObject
into the path is **open, and is the first thing the evaluation has to settle** —
at `-n64` the whole run is 19 requests, so 6 cycles is not a rate. Re-measure at
a footprint where it can be: if it stays ~6 cycles it is a fixed startup cost,
if it scales with request count the zero-overhead headline needs rewriting.

Note the checker sees traffic even though this config has `VX_CFG_L2_ENABLED=0`
and `VX_CFG_L3_ENABLED=0`: the L3 SimObject is still constructed as a transparent
arbiter, so the splice point is the off-chip boundary in *every* cache
configuration. 19 requests crossed it.

### 2. Cross-tenant isolation

One kernel spans both cores. Tenant 0's buffer is claimed for eid 0, tenant 1's
for eid 1; everything else stays shared. Requires `--cores=2`.

```sh
VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 \
  ./ci/blackbox.sh --driver=simx --app=twotenant --cores=2
```

**The claim, both directions at once:**

- *negative* — core-1 tasks read poison from tenant 0's buffer, and their writes
  to it never land
- *positive* — core-0 tasks read real data and their writes land, and core-1's
  writes to its **own** buffer land

A checker that simply blocked everything would fail the positive half.

**Measured** (`--cores=2`):

```
tasks: core0=512 core1=512
CHECKER: reqs=1864, checked=1864, bypassed=0, allow=1576, deny=288
CHECKER: enforce: faulted_reads=32, dropped_writes=256
CHECKER: hcache: hits=1860, misses=4, hit_rate=99.7854%
CHECKER: added_cycles=16, per_req=0.00858369 cyc
CHECKER: first_fault: addr=0x100040, hart_id=16, op=read, total=288
PASSED!
```

The 288 denies split into 32 faulted reads and 256 dropped writes — reads get a
poison response, writes are simply dropped, since writes are posted and have no
response to fault.

**Under the full cache hierarchy** (`--l2cache --l3cache`), the same demo also
passes:

```sh
VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 \
  ./ci/blackbox.sh --driver=simx --app=twotenant --cores=2 --l2cache --l3cache
```

```
CHECKER: reqs=452, checked=452, bypassed=0, allow=388, deny=64
CHECKER: enforce: faulted_reads=32, dropped_writes=32
PASSED!
```

This configuration previously **failed** with 992 errors — tenant 1's writes
landed in tenant 0's buffer — because a dirty-line writeback from a shared
write-back LLC carried the *evictor's* identity, not the writer's, so the
memory-side checker misattributed it (`todo.md` #8, adapting CHERIoT's
identity-carrying metadata). The fix stamps the writing hart into each dirtied
sector (`mem/cache.cpp`) and replays it into every writeback, so requester
identity survives the write-back cache. Single-tenant runs are byte-identical to
before (the tag is inert when there is one owner).

### 3. Epoch revocation

Tenant 0 grants tenant 1 read access for epoch 0. The host revokes with **two
register writes** — stage which owner is being revoked, then commit the new
epoch — no header is touched, on the setup path or any access path.

```sh
VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 \
  ./ci/blackbox.sh --driver=simx --app=revoke --cores=2
```

**The claim:** launch 1, both cores read real data. Then
`vx_enqueue_dcr_write(DCR_CHECKER_REVOKE_OWNER, 0)` followed by
`vx_enqueue_dcr_write(DCR_CHECKER_EPOCH, 1)` — those two writes are the entire
revocation. Launch 2: core 0 is unaffected, core 1 reads poison.

The epoch is tracked **per owner**, indexed by the granting owner's eid, so
revoking owner 0's grants can never advance a different owner's epoch entry
and expire *their* grants too — see `revoke_scope` below for a demo that
exercises exactly that property.

The grant state lives only in the checker, so revocation writes no header.
The cache shootdown a real revocation would need is **not** demonstrated:
SimX resets every cache sector between launches, which is *stronger* than
anything this design can issue — `flush_caches()` drains dirty sectors without
clearing `sec.valid`, so there is no invalidate primitive to cost (`todo.md`
#9). Revocation's real cost is two register writes plus that missing
invalidate; costing it is RTL work.

**Measured** (`--cores=2`):

```
tasks: phase1 core0=512 core1=512 | phase2 core0=512 core1=512
CHECKER: reqs=2448, checked=2448, bypassed=0, allow=2416, deny=32
CHECKER: enforce: faulted_reads=32, dropped_writes=0
CHECKER: setup: dcr_claims=1, headers_written=1, epoch_bumps=1, last_revoked_owner=0, epoch=1
PASSED!
```

`dcr_claims=1` with `epoch_bumps=1` is the headline: **one** claim was ever
installed, and revocation moved owner 0's epoch-table entry rather than
rewriting a header or a device-wide counter. All 32 denies are faulted reads —
tenant 1 losing its grant.

### 4. Scoped revocation — owner A's revoke doesn't touch owner C's grant

Two independently owned buffers, each granting READ to the other tenant.
Revoking **only** owner 0's grant must leave owner 1's grant untouched.

```sh
VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 \
  ./ci/blackbox.sh --driver=simx --app=revoke_scope --cores=2
```

**The claim:** launch 1, core 1 reads owner 0's buffer (real data, via the
grant) and core 0 reads owner 1's buffer (real data, via the grant). The host
then revokes owner 0 only: `vx_enqueue_dcr_write(DCR_CHECKER_REVOKE_OWNER, 0)`
+ `vx_enqueue_dcr_write(DCR_CHECKER_EPOCH, 1)`. Launch 2: core 1's read of
owner 0's buffer comes back poison (revoked), but core 0's read of owner 1's
buffer is still real data — owner 1's grant was never touched. Before the
per-owner epoch table, this same test failed: bumping the single global epoch
revoked both grants at once.

### 5. Header-store aliasing — a claim that collides is refused, not merged

The header store is direct-mapped: entry index is `buffer_id & mask`. Two
buffers whose granule ids collide modulo the store size want the same entry.
The store therefore carries a **tag** (the `buffer_id`) alongside each header,
and a claim landing on an entry held by a different buffer is refused whole.

```sh
VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 \
  VX_CHECKER_HEADER_ENTRIES=1 \
  ./ci/blackbox.sh --driver=simx --app=header_alias --cores=2
```

`VX_CHECKER_HEADER_ENTRIES=1` pins the store to one entry, so *any* two
granules collide — the collision is forced rather than hoped for. At the
design point (1 MB granules, 32-bit space) the store has 4096 entries and
covers the address space exactly, so no collision is possible and
`aliased` stays 0 in every other demo.

**The claim:** both buffers are claimed by the **same** owner, differing only
in what they grant — `bufA` grants nothing, `bufB` grants READ to everyone.
Same owner on purpose: granule exclusivity (§ *claims*) only refuses claims
whose granule belongs to a *different* owner, so it cannot see this pair. The
tag is the only thing that does. Without it, claim B overwrites `bufA`'s
header, `bufA` inherits `shared_perms=R`, and core 1 can read a buffer its
owner never granted.

**Measured** (`--cores=2`):

```
tasks: core0=512 core1=512
CHECKER: reqs=1672, checked=1672, bypassed=0, allow=1640, deny=32
CHECKER: claims: rejected=0, aliased=1, reclaimed=0, unaligned=2
PASSED!
```

`aliased=1` is the refusal; the 32 denies are core 1's reads of `bufA`, which
still carries its own owner's policy.

**What "fail closed" means here, exactly.** A refused claim does not lock its
buffer — it means no policy was installed, so `bufB` falls to the boot default
(`OWNER_ANY`, R|W) and is simply **unprotected**. A host that ignores
`claims_aliased` therefore ends up with a buffer it believes is protected and
is not. The counter is the only signal, which is why it is in the dump and why
the regression asserts the unprotected read rather than pretending it denies.
Making the refusal itself unforgeable to the tenant is the authorship problem
(`todo.md` #4), not this one.

## The setup channel, and what is *not* part of it

The checker's policy registers (`0x300`–`0x340`) are configuration, not data.
The threat model treats the **host command ring** as the attested channel that
owns them: every demo above programs its policy with `vx_enqueue_dcr_write`,
which the runtime turns into a `CMD_DCR_WRITE` ring command.

Device-resident command bundles are deliberately *not* part of that channel.
Two of them exist — a `CMD_LAUNCH_QMD` descriptor and an `OP_DRAW` step list —
and both are read out of device memory by the Command Processor at execution
time. That memory is unclaimed, and the boot policy leaves unclaimed memory
`OWNER_ANY | R|W`, so a tenant kernel can rewrite a bundle after the host
staged it and before the CP reads it. Replaying its pairs unfiltered would let
a tenant forge

```
{DCR_CHECKER_BUF_OWNER (0x302), self}   {DCR_CHECKER_BUF_COMMIT (0x305), 1}
```

and claim a victim's buffer, or `{DCR_CHECKER_EPOCH (0x306), 0}` to attempt to
walk a revocation back. The CP reads the bundle *functionally* — a `memcpy` out
of RAM, never a `MemReq` — so nothing about this attack crosses the LLC→DRAM
enforcement point and the checker cannot see it at all: the data plane is
simply told to hand the buffer over.

`CommandProcessor::DCR_PRIV_BEGIN`/`END` (`sim/common/cmd_processor.h`) close
it: DCR writes into the checker's window are dropped when they arrive from a
bundle, and counted in the CP's read-only `Q_DCR_BLOCKED` register (MMIO
`0x134`) so the attempt is observable rather than silent. The window is
duplicated as literals there because `sim/common` must not depend on the
simx-only checker; `mem_checker.cpp` carries `static_assert`s tying the two
definitions together, so the window cannot move on one side only.

Nothing legitimate is filtered — the runtime only ever packs KMU registers
(`VX_DCR_KMU_*`, `0x010`–`0x023`) into a QMD (`cmd_stage_qmds()` in
`sw/runtime/common/queue.cpp`), and the ring path is untouched. The regression
is `tests/unittest/cp_dcr_filter`, which drives the real CP model through its
MMIO surface with a forged bundle:

```sh
make -C tests/unittest/cp_dcr_filter run   # from the build directory
```

It asserts that the legitimate KMU pairs in the same bundle still apply in
order, that nothing in `[0x300, 0x340)` reaches the DCR bus, that
`Q_DCR_BLOCKED` counts exactly the attempts, and that a ring `CMD_DCR_WRITE`
still programs the checker. Neutering the filter makes it fail.

Note the scope: this closes the *reachability* of the control plane from a
tenant. It does not authenticate the policy's author on the channel that
remains — a DCR write is still `{addr, value}` on a broadcast bus with no
requester identity, so the checker still cannot distinguish an owner
re-claiming its own buffer from a second tenant claiming it over the ring. See
`todo.md` §4.

## Environment variables

`VX_CHECKER` gates everything else — with it unset, the rest are ignored and the
checker is never built into the datapath.

| Variable | Default | Effect |
|---|---|---|
| `VX_CHECKER` | off | Construct the inline checker and splice it into the request path |
| `VX_CHECKER_ENFORCE` | off | A deny actually blocks: reads answered with poison, writes dropped. Without this, denies are counted but harmless |
| `VX_CHECKER_STATS` | off | Dump counters to **stderr** at teardown (kept out of the `PERF` stream the harness parses) |
| `VX_CHECKER_BUF_LOG2` | `20` | log2 bytes covered by one header (default 1 MB) |
| `VX_CHECKER_HEADER_ENTRIES` | `0` | Header-store entries, rounded up to a power of two. `0` sizes the store to cover the whole address space at the current granularity, which is the design point. A smaller value models a store that cannot, so colliding claims are refused (`aliased`) — see demo 5 |
| `VX_CHECKER_HCACHE_ENTRIES` | `16` | Header-cache entries; `0` disables it so every check misses |
| `VX_CHECKER_HCACHE_ASSOC` | `4` | Header-cache associativity |
| `VX_CHECKER_HIT_LAT` | `0` | Cycles added on a header-cache hit |
| `VX_CHECKER_MISS_LAT` | `4` | Cycles added on a miss |
| `VX_CHECKER_TEST_DENY` | `0` | Synthetic denies, for exercising the fault path without policy |

## Reading the stats

With `VX_CHECKER_STATS=1`, teardown writes `CHECKER:` lines to stderr:

```
CHECKER: reqs=…, checked=…, bypassed=…, allow=…, deny=…
CHECKER: hcache: hits=…, misses=…, hit_rate=…%
CHECKER: added_cycles=…, per_req=… cyc
CHECKER: config: buffer=…B, header_entries=…, hcache_entries=…, assoc=…, hit_lat=…, miss_lat=…, enforce=…
CHECKER: enforce: faulted_reads=…, dropped_writes=…      (only when enforcing)
CHECKER: setup: dcr_claims=…, headers_written=…          (only when claims were made)
CHECKER: claims: rejected=…, aliased=…, reclaimed=…, unaligned=…
```

- `bypassed` is IO and local-mem traffic — it carries no buffer header and is
  never gated.
- `added_cycles` / `per_req` is header-lookup latency only. It does **not**
  include the splice's own pipeline cost — see §1, where `added_cycles=0` and
  the run is still +6 cycles.
- `rejected` and `aliased` are both fail-closed claim refusals, counted apart
  because they mean different things: `rejected` is a cross-owner policy
  conflict, `aliased` is the header store being too small for the granularity
  in use. Either one non-zero means a buffer the host believes it claimed is
  **unprotected** — check them before trusting a setup.

## Sweeping the overhead

The header cache is the whole performance story, so the interesting sweep is its
size against a fixed workload:

```sh
for e in 0 4 16 64; do
  echo "== hcache_entries=$e =="
  VX_CHECKER=1 VX_CHECKER_STATS=1 VX_CHECKER_HCACHE_ENTRIES=$e \
    ./ci/blackbox.sh --driver=simx --app=vecadd_claimed --perf=1 2>&1 \
    | grep -E "CHECKER:|^PERF: instrs"
done
```

**Measured** (baseline `vecadd` = 1266 cycles), re-run 22 Sep 2026:

| `hcache_entries` | cycles | vs baseline | `added_cycles` | hit rate |
|---:|---:|---:|---:|---:|
| 0 (disabled) | 1300 | +34 | 76 | 0% |
| 4 | 1276 | +10 | 8 | 89.5% |
| 16 (default) | 1276 | +10 | 8 | 89.5% |
| 64 | 1276 | +10 | 8 | 89.5% |

All four `PASSED!`. Two things to point at during a demo:

- **4 entries already saturate.** Going to 16 or 64 changes nothing, because the
  1 MB header granule keeps the working set to a handful of headers. That is the
  granule size doing its job.
- **`entries=0` is the worst case** — every one of the 19 checks misses and pays
  the full 4-cycle penalty. Even then it is +34 cycles on 1266, about 2.7%.

Each row carries the +6 splice cost described in §1 on top of its
`added_cycles`; the column differences between rows are pure header-cache
effect.

The residual 89.5% (not 100%) is the compulsory miss floor: 2 cold misses out of
19 checks.
