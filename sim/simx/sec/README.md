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

**The claim:** identical cycle counts, and `deny=0` in the checker line. Compare
the `cycles=` field between the two runs — that equality *is* the result.

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

### 3. Epoch revocation

Tenant 0 grants tenant 1 read access for epoch 0. The host revokes with **one
register write** — no header is touched, on the setup path or any access path.

```sh
VX_CHECKER=1 VX_CHECKER_ENFORCE=1 VX_CHECKER_STATS=1 \
  ./ci/blackbox.sh --driver=simx --app=revoke --cores=2
```

**The claim:** launch 1, both cores read real data. Then
`vx_enqueue_dcr_write(DCR_CHECKER_EPOCH, 1)` — that single write is the entire
revocation. Launch 2: core 0 is unaffected, core 1 reads poison.

SimX resets caches at each launch, which models the cache shootdown a real
revocation would require; the grant state itself lives only in the checker.

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
    | grep -E "CHECKER:|cycles="
done
```

`entries=0` forces every check to miss and gives the worst case; the point of the
1 MB header granule is that the working set stays small enough for even a few
entries to hold it.
