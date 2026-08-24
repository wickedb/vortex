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

```sh
make -C sim/simx
```

## The three demos

Run from the repo root. Each ends in `PASSED!` or `FAILED!`.

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

**Measured** (default config, `-n64`):

| Run | cycles | vs baseline | `added_cycles` |
|---|---:|---:|---:|
| `vecadd` baseline | 1240 | — | — |
| `vecadd_claimed`, defaults | 1244 | **+4** | 8 |
| `vecadd_claimed`, `VX_CHECKER_MISS_LAT=0` | **1240** | **0** | 0 |

Both runs report `deny=0` and `PASSED!`, and both execute 400 instructions.

The honest version of the zero-overhead claim is therefore *not* "the cycle
counts are identical at defaults" — they are not. It is this:

> **Every cycle of overhead is attributable to a header-cache miss.** The splice
> itself is free. Set the miss penalty to zero and the count returns to exactly
> the baseline 1240.

That is the stronger claim anyway, because the 2 misses here are **compulsory**
(cold) — the first touch of each claimed buffer. They do not scale with the
workload, so the overhead is a fixed startup cost, not a per-access tax.

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
CHECKER: reqs=450, checked=450, allow=388, deny=62
CHECKER: enforce: faulted_reads=31, dropped_writes=31
PASSED!
```

This configuration previously **failed** with 992 errors — tenant 1's writes
landed in tenant 0's buffer — because a dirty-line writeback from a shared
write-back LLC carried the *evictor's* identity, not the writer's, so the
memory-side checker misattributed it (`caches.md` #8, adapting CHERIoT's
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

SimX resets caches at each launch, which models the cache shootdown a real
revocation would require; the grant state itself lives only in the checker.

**Measured** (`--cores=2`):

```
tasks: phase1 core0=512 core1=512 | phase2 core0=480 core1=544
CHECKER: reqs=2432, checked=2432, bypassed=0, allow=2398, deny=34
CHECKER: enforce: faulted_reads=34, dropped_writes=0
CHECKER: setup: dcr_claims=1, headers_written=1, epoch_bumps=1, last_revoked_owner=0, epoch=1
PASSED!
```

`dcr_claims=1` with `epoch_bumps=1` is the headline: **one** claim was ever
installed, and revocation moved owner 0's epoch-table entry rather than
rewriting a header or a device-wide counter. All 34 denies are faulted reads —
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

## Environment variables

`VX_CHECKER` gates everything else — with it unset, the rest are ignored and the
checker is never built into the datapath.

| Variable | Default | Effect |
|---|---|---|
| `VX_CHECKER` | off | Construct the inline checker and splice it into the request path |
| `VX_CHECKER_ENFORCE` | off | A deny actually blocks: reads answered with poison, writes dropped. Without this, denies are counted but harmless |
| `VX_CHECKER_STATS` | off | Dump counters to **stderr** at teardown (kept out of the `PERF` stream the harness parses) |
| `VX_CHECKER_BUF_LOG2` | `20` | log2 bytes covered by one header (default 1 MB) |
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
CHECKER: config: buffer=…B, hcache_entries=…, assoc=…, hit_lat=…, miss_lat=…, enforce=…
CHECKER: enforce: faulted_reads=…, dropped_writes=…      (only when enforcing)
CHECKER: setup: dcr_claims=…, headers_written=…          (only when claims were made)
```

- `bypassed` is IO and local-mem traffic — it carries no buffer header and is
  never gated.
- `added_cycles` / `per_req` is the overhead number. For demo 1 it should be `0`
  at the default `HIT_LAT=0`.

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

**Measured** (baseline `vecadd` = 1240 cycles):

| `hcache_entries` | cycles | vs baseline | `added_cycles` | hit rate |
|---:|---:|---:|---:|---:|
| 0 (disabled) | 1268 | +28 | 76 | 0% |
| 4 | 1244 | +4 | 8 | 89.5% |
| 16 (default) | 1244 | +4 | 8 | 89.5% |
| 64 | 1244 | +4 | 8 | 89.5% |

All four `PASSED!`. Two things to point at during a demo:

- **4 entries already saturate.** Going to 16 or 64 changes nothing, because the
  1 MB header granule keeps the working set to a handful of headers. That is the
  granule size doing its job.
- **`entries=0` is the worst case** — every one of the 19 checks misses and pays
  the full 4-cycle penalty. Even then it is +28 cycles on 1240, about 2.3%.

The residual 89.5% (not 100%) is the compulsory miss floor: 2 cold misses out of
19 checks.
