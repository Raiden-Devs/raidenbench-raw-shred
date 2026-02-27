# Raiden Raw Shred Bench

Comparative latency benchmark for Solana shred streams. Measures head-to-head latency between multiple shred endpoints using NIC-level timestamps.

## What it does

- Binds one UDP socket per endpoint, each on its own isolated thread
- Captures shreds with kernel/NIC timestamps (`SO_TIMESTAMPNS` / `SO_TIMESTAMPING`)
- Validates shred structure (size, variant, slot, index, FEC set index)
- Tracks packet sizes and shred types per endpoint
- Computes per-shred latency deltas against the global first arrival
- Head-to-head comparison with histogram and time-consistency analysis

## Build

```bash
cargo build --release
```

## Usage

```bash
./target/release/raiden-raw-shred-bench config.toml
```

Press `Ctrl+C` to stop early. The benchmark stops automatically when the target shred count is reached.

## Configuration

All settings go in a single `config.toml` file.

### `[config]` section

| Parameter | Type | Default | Description |
|---|---|---|---|
| `shreds` | integer | *required* | Target unique shred count. Benchmark stops when any endpoint reaches this number. |
| `measure_strat` | integer | `0` | FEC position filter. `0` = no filter (measure all shreds). `N > 0` = only shreds with FEC position < N. |
| `shred_type` | string | `"coding-data"` | Which shred types to include when `measure_strat > 0`. Options: `"coding"`, `"data"`, `"coding-data"`. |
| `windows` | integer | `10` | Number of time windows for consistency-over-time analysis. `0` = skip consistency section. |

### `[backend]` section (optional)

Upload results to [bench.api.raiden.wtf](https://bench.api.raiden.wtf) after the benchmark completes. Remove this section entirely to skip uploading.

| Parameter | Type | Description |
|---|---|---|
| `url` | string | Backend URL (e.g. `https://bench.api.raiden.wtf`). |

Results are uploaded via WebSocket with BLAKE3 proof verification — each shred observation is signed with a server-provided session nonce, making results tamper-evident.

### `[[endpoint]]` entries

Each endpoint is a UDP address where shreds arrive. Add as many as needed.

| Parameter | Type | Description |
|---|---|---|
| `name` | string | Display name for this endpoint in the report. |
| `url` | string | UDP bind address in format `http://IP:PORT` or `IP:PORT`. |

### Example

```toml
[config]
shreds = 100000
measure_strat = 0
shred_type = "coding-data"
windows = 10

[backend]
url = "https://bench.api.raiden.wtf"

[[endpoint]]
name = "Raiden Surge APEX FRA"
url = "http://160.202.131.151:20001"

[[endpoint]]
name = "Jito Shredstream FRA"
url = "http://160.202.131.151:20000"
```

### Filter examples

**No filter** — measure all shreds as they arrive:
```toml
measure_strat = 0
```

**First 32 shreds per FEC set** (coding + data):
```toml
measure_strat = 32
shred_type = "coding-data"
```

**First 1 coding shred per FEC set** (earliest arrival only):
```toml
measure_strat = 1
shred_type = "coding"
```

## Output

```
  ▶ Jito AMS
    Received: 271295  |  Unique: 102565  |  Dupes: 168730 (62.19%)  |  Non-shreds: 44
    Shred sizes:  1203 × 135543 (50.0%)  1228 × 135752 (50.0%)
    Shred types:  MerkleCode+Chain × 84350 (31.1%)  MerkleData+Chain × 84256 (31.1%)  MerkleCode+Chain+Resign × 51402 (18.9%)  MerkleData+Chain+Resign × 51287 (18.9%)
    Non-shred packets (3 samples):
      #1: bad size 29 (expected 1180..1228) (29 bytes)
        0000: 0a 09 61 6d 73 74 65 72 64 61 6d 12 0c 08 c9 a7  ..amsterdam.....
        0010: 86 cd 06 10 b3 c2 e6 c7 01 18 f7 d1 01           .............
      #2: bad size 29 (expected 1180..1228) (29 bytes)
        0000: 0a 09 61 6d 73 74 65 72 64 61 6d 12 0c 08 c9 a7  ..amsterdam.....
        0010: 86 cd 06 10 b3 c2 e6 c7 01 18 f7 d1 01           .............
      #3: bad size 29 (expected 1180..1228) (29 bytes)
        0000: 0a 09 61 6d 73 74 65 72 64 61 6d 12 0c 08 ca a7  ..amsterdam.....
        0010: 86 cd 06 10 d2 85 e9 c7 01 18 f8 d1 01           .............   
```

**Sections:**
- **Per-endpoint summary** — received, unique, dupes, non-shreds, size/type breakdown
- **Latency delta** — p5/p25/p50/p95/p99 vs global first arrival, win count
- **Head-to-head** — direct comparison on common shreds (2 endpoints only)
- **Latency distribution** — histogram of advantage buckets
- **Consistency over time** — windowed p50/p95/p99 with visual trend

## Shred validation

Packets are validated before counting:

- **Size**: 1180–1228 bytes (varies by Merkle proof depth)
- **Variant**: must be a known coding or data shred type
- **Slot**: non-zero and < 2^40
- **Index**: < 2^20
- **FEC set index**: < 2^20, and for data shreds: fec_set_index ≤ index

Rejected packets are counted as non-shreds with hex dump samples for debugging.

## Requirements

- Linux (uses `recvmsg`, `SO_TIMESTAMPNS`, `SO_TIMESTAMPING`)
- UDP ports must be reachable and receiving shred traffic
- Rust 1.70+
