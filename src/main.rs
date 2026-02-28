use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tungstenite::{connect, Message};

// ─── Config ────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
struct Config {
    config: GlobalConfig,
    endpoint: Vec<Endpoint>,
    backend: Option<BackendConfig>,
}

#[derive(Deserialize, Debug, Clone)]
struct BackendConfig {
    url: String,
}

#[derive(Deserialize, Debug, Clone)]
struct GlobalConfig {
    shreds: u64,
    /// 0 = measure all shreds, N > 0 = only shreds with index <= N (filtered by shred_type)
    #[serde(default)]
    measure_strat: u32,
    /// "coding" = only coding shreds, "data" = only data shreds,
    /// "coding-data" = both coding and data shreds (first N of either type)
    /// Only applies when measure_strat > 0. Defaults to "coding-data".
    #[serde(default = "default_shred_type")]
    shred_type: String,
    /// Number of time windows for consistency analysis. Defaults to 10.
    #[serde(default = "default_windows")]
    windows: usize,
}

fn default_shred_type() -> String {
    "coding-data".to_string()
}

fn default_windows() -> usize {
    10
}

/// Parsed filter mode for the hot path (no string matching in the loop).
/// Position is 0-based within the FEC set:
///   Data shreds:   index - fec_set_index
///   Coding shreds: position field from coding header
#[derive(Clone, Copy, Debug)]
enum ShredFilter {
    /// measure_strat = 0: accept everything
    All,
    /// Only coding shreds with FEC position < N
    CodingOnly(u32),
    /// Only data shreds with FEC position < N
    DataOnly(u32),
    /// Coding or data shreds with FEC position < N
    CodingData(u32),
}

impl ShredFilter {
    fn from_config(cfg: &GlobalConfig) -> Self {
        if cfg.measure_strat == 0 {
            return ShredFilter::All;
        }
        let n = cfg.measure_strat;
        match cfg.shred_type.as_str() {
            "coding" => ShredFilter::CodingOnly(n),
            "data" => ShredFilter::DataOnly(n),
            "coding-data" => ShredFilter::CodingData(n),
            other => {
                eprintln!(
                    "{}",
                    format!(
                        "Unknown shred_type '{}', expected 'coding', 'data', or 'coding-data'. Defaulting to 'coding-data'.",
                        other
                    )
                    .bright_yellow()
                );
                ShredFilter::CodingData(n)
            }
        }
    }

    /// Returns true if this packet should be ACCEPTED for measurement.
    /// `pos` is the 0-based position within the FEC set (computed via fec_position()).
    #[inline]
    fn accept(&self, variant_byte: u8, pos: u32) -> bool {
        match *self {
            ShredFilter::All => true,
            ShredFilter::CodingOnly(n) => is_coding_shred(variant_byte) && pos < n,
            ShredFilter::DataOnly(n) => is_data_shred(variant_byte) && pos < n,
            ShredFilter::CodingData(n) => {
                (is_coding_shred(variant_byte) || is_data_shred(variant_byte)) && pos < n
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
struct Endpoint {
    name: String,
    url: String,
}

// ─── WebSocket protocol types ──────────────────────────────────────────────

#[derive(Serialize)]
struct WsStartMessage {
    r#type: String,
    config: WsBenchmarkConfig,
    endpoints: Vec<String>,
}

#[derive(Serialize)]
struct WsBenchmarkConfig {
    target_shreds: u64,
    measure_strat: u32,
    shred_type: String,
}

#[derive(Serialize)]
struct WsShredMessage {
    r#type: String,
    shred_id: String,
    observations: Vec<WsShredObservation>,
}

#[derive(Serialize)]
struct WsShredObservation {
    endpoint: String,
    time_diff_ms: f64,
    proof: String,
}

#[derive(Serialize)]
struct WsProgressMessage {
    r#type: String,
    shreds: u64,
    total: u64,
    percent: u64,
}

#[derive(Serialize)]
struct WsEndMessage {
    r#type: String,
    endpoints: Vec<WsEndpointResult>,
}

#[derive(Serialize)]
struct WsEndpointResult {
    name: String,
    win_rate: f64,
    p5: f64,
    p25: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    total_received: u64,
    unique_shreds: u64,
    duplicates: u64,
    non_shreds: u64,
    win_count: u64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct WsStartAck {
    r#type: String,
    run_id: String,
    session_nonce: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct WsCompleteMessage {
    r#type: String,
    url: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct WsErrorMessage {
    r#type: String,
    message: String,
}

#[derive(Deserialize)]
struct WsTypeCheck {
    r#type: String,
}

// ─── BLAKE3 proof computation ──────────────────────────────────────────────

fn compute_proof(nonce: &[u8; 32], endpoint: &str, shred_id: &str, time_diff_ms: f64) -> String {
    let quantized_steps = (time_diff_ms * 10.0).round() as i64;
    let quantized_ts = quantized_steps as f64 / 10.0;

    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce);
    hasher.update(endpoint.as_bytes());
    hasher.update(shred_id.as_bytes());
    hasher.update(&quantized_ts.to_be_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

// ─── Shred identification ──────────────────────────────────────────────────
//
// Solana shred common header layout (little-endian):
//   Offset 0x00 (0):   Signature       [64 bytes] — Ed25519 sig (SAME for all shreds in a Merkle FEC set!)
//   Offset 0x40 (64):  Shred Variant   [1 byte]   — type + auth scheme
//   Offset 0x41 (65):  Slot            [8 bytes]   — u64 LE
//   Offset 0x49 (73):  Index           [4 bytes]   — u32 LE
//   Offset 0x4D (77):  Version         [2 bytes]   — u16 LE
//   Offset 0x4F (79):  FEC Set Index   [4 bytes]   — u32 LE
//
// A shred is uniquely identified by (variant, slot, index).
// We CANNOT use the signature because Merkle shreds share the same signature
// across all shreds in the same FEC set.

const MIN_SHRED_SIZE: usize = 1180;  // smallest valid shred (varies by Merkle proof depth)
const MAX_SHRED_SIZE: usize = 1228;  // largest valid shred
const SHRED_ID_OFFSET: usize = 64;  // skip signature
const SHRED_ID_LEN: usize = 13;     // variant(1) + slot(8) + index(4)

type ShredId = [u8; SHRED_ID_LEN];

// ─── Shred variant parsing ─────────────────────────────────────────────────
//
// Variant byte (offset 64) encodes type + auth scheme:
//   LegacyCode           = 0x5A (0b0101_1010)
//   LegacyData           = 0xA5 (0b1010_0101)
//   MerkleCode           = 0b0100_???? (high nibble 0x4)
//   MerkleCode chained   = 0b0110_???? (high nibble 0x6)
//   MerkleCode ch+resign = 0b0111_???? (high nibble 0x7)
//   MerkleData           = 0b1000_???? (high nibble 0x8)
//   MerkleData chained   = 0b1001_???? (high nibble 0x9)
//   MerkleData ch+resign = 0b1011_???? (high nibble 0xB)

const VARIANT_OFFSET: usize = 64;
#[allow(dead_code)]
const SLOT_OFFSET: usize = 65;
const INDEX_OFFSET: usize = 73;           // variant(1) + slot(8)
const FEC_SET_INDEX_OFFSET: usize = 79;   // + index(4) + version(2)

// Coding shred header starts right after common header (83 bytes):
//   Offset 83: num_data_shreds   [u16 LE]
//   Offset 85: num_coding_shreds [u16 LE]
//   Offset 87: position          [u16 LE]  — position within FEC set for coding shreds
const CODING_POSITION_OFFSET: usize = 87;

#[inline]
fn is_coding_shred(variant_byte: u8) -> bool {
    match variant_byte {
        0x5A => true, // LegacyCode
        v => matches!(v >> 4, 0x4 | 0x6 | 0x7), // MerkleCode variants
    }
}

#[inline]
fn is_data_shred(variant_byte: u8) -> bool {
    match variant_byte {
        0xA5 => true, // LegacyData
        v => matches!(v >> 4, 0x8 | 0x9 | 0xB), // MerkleData variants
    }
}

/// Read shred index (u32 LE) — global index within the slot
#[inline]
fn read_shred_index(buf: &[u8]) -> u32 {
    u32::from_le_bytes([
        buf[INDEX_OFFSET],
        buf[INDEX_OFFSET + 1],
        buf[INDEX_OFFSET + 2],
        buf[INDEX_OFFSET + 3],
    ])
}

/// Read FEC set index (u32 LE) — index of the first data shred in the FEC set
#[inline]
fn read_fec_set_index(buf: &[u8]) -> u32 {
    u32::from_le_bytes([
        buf[FEC_SET_INDEX_OFFSET],
        buf[FEC_SET_INDEX_OFFSET + 1],
        buf[FEC_SET_INDEX_OFFSET + 2],
        buf[FEC_SET_INDEX_OFFSET + 3],
    ])
}

/// Read coding shred position (u16 LE) — position within FEC set for coding shreds
#[inline]
fn read_coding_position(buf: &[u8]) -> u16 {
    u16::from_le_bytes([
        buf[CODING_POSITION_OFFSET],
        buf[CODING_POSITION_OFFSET + 1],
    ])
}

/// Read slot (u64 LE)
#[inline]
fn read_slot(buf: &[u8]) -> u64 {
    u64::from_le_bytes([
        buf[SLOT_OFFSET],
        buf[SLOT_OFFSET + 1],
        buf[SLOT_OFFSET + 2],
        buf[SLOT_OFFSET + 3],
        buf[SLOT_OFFSET + 4],
        buf[SLOT_OFFSET + 5],
        buf[SLOT_OFFSET + 6],
        buf[SLOT_OFFSET + 7],
    ])
}

/// Why a packet was rejected as non-shred
#[derive(Debug, Clone)]
enum RejectReason {
    BadSize(usize),
    BadVariant(u8),
    BadSlot(u64),
    BadIndex(u32),
    BadFecIndex(u32),
    FecIndexGtIndex { fec: u32, index: u32 },
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectReason::BadSize(n) => write!(f, "bad size {} (expected {}..{})", n, MIN_SHRED_SIZE, MAX_SHRED_SIZE),
            RejectReason::BadVariant(v) => write!(f, "unknown variant 0x{:02X}", v),
            RejectReason::BadSlot(s) => write!(f, "bad slot {}", s),
            RejectReason::BadIndex(i) => write!(f, "bad index {}", i),
            RejectReason::BadFecIndex(i) => write!(f, "bad fec_index {}", i),
            RejectReason::FecIndexGtIndex { fec, index } => {
                write!(f, "fec_index {} > index {}", fec, index)
            }
        }
    }
}

/// Validate that a packet looks like a real Solana shred.
/// Returns None if valid, Some(reason) if rejected.
#[inline]
fn validate_shred(buf: &[u8], n: usize) -> Option<RejectReason> {
    if n < MIN_SHRED_SIZE || n > MAX_SHRED_SIZE {
        return Some(RejectReason::BadSize(n));
    }
    let variant = buf[VARIANT_OFFSET];
    if !is_coding_shred(variant) && !is_data_shred(variant) {
        return Some(RejectReason::BadVariant(variant));
    }
    let slot = read_slot(buf);
    if slot == 0 || slot > (1u64 << 40) {
        return Some(RejectReason::BadSlot(slot));
    }
    let index = read_shred_index(buf);
    if index > (1 << 20) {
        return Some(RejectReason::BadIndex(index));
    }
    let fec_idx = read_fec_set_index(buf);
    if fec_idx > (1 << 20) {
        return Some(RejectReason::BadFecIndex(fec_idx));
    }
    if is_data_shred(variant) && fec_idx > index {
        return Some(RejectReason::FecIndexGtIndex { fec: fec_idx, index });
    }
    None
}

/// Human-readable name for a shred variant byte
#[inline]
fn variant_name(v: u8) -> &'static str {
    match v {
        0x5A => "LegacyCode",
        0xA5 => "LegacyData",
        _ => match v >> 4 {
            0x4 => "MerkleCode",
            0x6 => "MerkleCode+Chain",
            0x7 => "MerkleCode+Chain+Resign",
            0x8 => "MerkleData",
            0x9 => "MerkleData+Chain",
            0xB => "MerkleData+Chain+Resign",
            _ => "Unknown",
        },
    }
}

/// Get the 0-based position of this shred within its FEC set.
/// - Data shreds:   index - fec_set_index
/// - Coding shreds: position field from coding header
#[inline]
fn fec_position(buf: &[u8], variant_byte: u8) -> u32 {
    if is_data_shred(variant_byte) {
        let index = read_shred_index(buf);
        let fec_set_index = read_fec_set_index(buf);
        index.saturating_sub(fec_set_index)
    } else {
        // coding shred: use position field from coding header
        read_coding_position(buf) as u32
    }
}

// ─── Per-endpoint local stats (owned entirely by its thread, zero sharing) ─

const MAX_REJECT_SAMPLES: usize = 3;

/// A captured non-shred packet for debugging
#[derive(Clone)]
struct RejectSample {
    reason: RejectReason,
    size: usize,
    /// First 128 bytes (or less) of the packet
    data: Vec<u8>,
}

struct LocalStats {
    /// shred_id -> first NIC timestamp (ns) for this endpoint
    shreds: HashMap<ShredId, u64>,
    /// Total packets received (including dupes)
    total_received: u64,
    /// Duplicate count
    duplicates: u64,
    /// Packets that failed validation
    non_shreds: u64,
    /// First few rejected packets for debugging
    reject_samples: Vec<RejectSample>,
    /// Packet size distribution for valid shreds
    size_counts: HashMap<usize, u64>,
    /// Shred variant type distribution
    type_counts: HashMap<&'static str, u64>,
    /// Cross-tabulation: (variant_name, size) -> count
    size_type_counts: HashMap<(&'static str, usize), u64>,
}

impl LocalStats {
    fn new() -> Self {
        Self {
            shreds: HashMap::with_capacity(200_000),
            total_received: 0,
            duplicates: 0,
            non_shreds: 0,
            reject_samples: Vec::new(),
            size_counts: HashMap::new(),
            type_counts: HashMap::new(),
            size_type_counts: HashMap::new(),
        }
    }

    fn record(&mut self, shred_id: ShredId, nic_ts_ns: u64) {
        self.total_received += 1;
        if self.shreds.contains_key(&shred_id) {
            self.duplicates += 1;
        } else {
            self.shreds.insert(shred_id, nic_ts_ns);
        }
    }
}

// ─── Shared progress counters (atomics only, no locks, no channels) ────────

struct SharedCounters {
    /// Per-endpoint unique shred count (for progress display only)
    unique_counts: Vec<AtomicU64>,
    /// Per-endpoint duplicate count (for progress display only)
    dupe_counts: Vec<AtomicU64>,
    /// Global stop signal
    running: AtomicBool,
}

// ─── NIC timestamping helpers ──────────────────────────────────────────────

fn enable_nic_timestamp(sock: &UdpSocket) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    const SO_TIMESTAMPNS: libc::c_int = 35;
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TIMESTAMPNS,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    enable_hw_timestamp(fd);
    Ok(())
}

fn enable_hw_timestamp(fd: libc::c_int) {
    const SO_TIMESTAMPING: libc::c_int = 37;
    const SOF_TIMESTAMPING_RX_HARDWARE: u32 = 1 << 2;
    const SOF_TIMESTAMPING_RAW_HARDWARE: u32 = 1 << 6;
    const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
    const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;

    let flags: u32 = SOF_TIMESTAMPING_RX_HARDWARE
        | SOF_TIMESTAMPING_RAW_HARDWARE
        | SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_RX_SOFTWARE;

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TIMESTAMPING,
            &flags as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }
}

fn recv_with_timestamp(fd: libc::c_int, buf: &mut [u8]) -> io::Result<(usize, u64)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut ctrl_buf = [0u8; 256];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = ctrl_buf.len();

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let ts_ns = extract_timestamp(&msg).unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    });

    Ok((n as usize, ts_ns))
}

fn extract_timestamp(msg: &libc::msghdr) -> Option<u64> {
    const SCM_TIMESTAMPNS: libc::c_int = 35;
    const SCM_TIMESTAMPING: libc::c_int = 37;

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET {
            if hdr.cmsg_type == SCM_TIMESTAMPNS {
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                let ts: libc::timespec = unsafe { std::ptr::read_unaligned(data as *const _) };
                return Some(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64);
            }
            if hdr.cmsg_type == SCM_TIMESTAMPING {
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                let timestamps: [libc::timespec; 3] =
                    unsafe { std::ptr::read_unaligned(data as *const _) };
                if timestamps[2].tv_sec != 0 || timestamps[2].tv_nsec != 0 {
                    return Some(
                        timestamps[2].tv_sec as u64 * 1_000_000_000
                            + timestamps[2].tv_nsec as u64,
                    );
                }
                if timestamps[0].tv_sec != 0 || timestamps[0].tv_nsec != 0 {
                    return Some(
                        timestamps[0].tv_sec as u64 * 1_000_000_000
                            + timestamps[0].tv_nsec as u64,
                    );
                }
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

// ─── Receiver thread (fully isolated, owns its own LocalStats) ─────────────
//
// ISOLATION GUARANTEE:
//   - Each thread owns its own UdpSocket (separate fd, separate kernel buffer)
//   - Each thread owns its own LocalStats HashMap (no shared allocation)
//   - The only shared state is Arc<SharedCounters> with per-endpoint AtomicU64s
//     that are written via fetch_add(Relaxed) — different cache lines per endpoint,
//     zero contention between threads
//   - A slow/blocked endpoint CANNOT affect another endpoint's recv loop

fn receiver_thread(
    endpoint_idx: usize,
    addr: SocketAddr,
    counters: Arc<SharedCounters>,
    filter: ShredFilter,
) -> LocalStats {
    let sock = UdpSocket::bind(addr).unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Failed to bind UDP socket on {}: {}", addr, e).bright_red()
        );
        std::process::exit(1);
    });

    // Increase socket receive buffer to 8MB to minimize kernel drops
    let buf_size: libc::c_int = 8 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    sock.set_read_timeout(Some(Duration::from_millis(50))).ok();

    if let Err(e) = enable_nic_timestamp(&sock) {
        eprintln!(
            "  {} [ep{}] SO_TIMESTAMPNS unavailable ({}), fallback to clock_gettime",
            "⚠".yellow(),
            endpoint_idx,
            e
        );
    }

    let fd = sock.as_raw_fd();
    let mut buf = [0u8; 2048];
    let mut stats = LocalStats::new();

    let unique_counter = &counters.unique_counts[endpoint_idx];
    let dupe_counter = &counters.dupe_counts[endpoint_idx];

    while counters.running.load(Ordering::Relaxed) {
        match recv_with_timestamp(fd, &mut buf) {
            Ok((n, ts_ns)) => {
                if let Some(reason) = validate_shred(&buf, n) {
                    stats.non_shreds += 1;
                    if stats.reject_samples.len() < MAX_REJECT_SAMPLES {
                        let cap = n.min(128);
                        stats.reject_samples.push(RejectSample {
                            reason,
                            size: n,
                            data: buf[..cap].to_vec(),
                        });
                    }
                    continue;
                }

                let vname = variant_name(buf[VARIANT_OFFSET]);

                // Track packet size, type, and size×type cross-tabulation
                *stats.size_counts.entry(n).or_insert(0) += 1;
                *stats.type_counts.entry(vname).or_insert(0) += 1;
                *stats.size_type_counts.entry((vname, n)).or_insert(0) += 1;

                // Apply shred filter (no-op when ShredFilter::All)
                if !matches!(filter, ShredFilter::All) {
                    let variant_byte = buf[VARIANT_OFFSET];
                    let pos = fec_position(&buf, variant_byte);
                    if !filter.accept(variant_byte, pos) {
                        continue;
                    }
                }

                let mut shred_id = [0u8; SHRED_ID_LEN];
                shred_id.copy_from_slice(&buf[SHRED_ID_OFFSET..SHRED_ID_OFFSET + SHRED_ID_LEN]);

                let was_new = !stats.shreds.contains_key(&shred_id);
                stats.record(shred_id, ts_ns);

                // Atomic progress update — no contention, each endpoint writes its own counter
                if was_new {
                    unique_counter.fetch_add(1, Ordering::Relaxed);
                } else {
                    dupe_counter.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => {
                eprintln!("recv error on endpoint {}: {}", endpoint_idx, e);
                continue;
            }
        }
    }

    stats
}

// ─── Stats & reporting ─────────────────────────────────────────────────────

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn color_val(v: f64) -> ColoredString {
    if v < 1.0 {
        format!("{:.2}µs", v).bright_green()
    } else if v < 100.0 {
        format!("{:.2}µs", v).bright_yellow()
    } else if v < 1000.0 {
        format!("{:.1}µs", v).yellow()
    } else {
        format!("{:.1}ms", v / 1000.0).bright_red()
    }
}

fn print_results(endpoints: &[Endpoint], all_stats: &[LocalStats], elapsed: Duration, config_windows: usize) {
    // Build global first-arrival map
    let mut global_first: HashMap<ShredId, u64> = HashMap::new();
    for stats in all_stats {
        for (&shred_id, &ts) in &stats.shreds {
            let entry = global_first.entry(shred_id).or_insert(ts);
            if ts < *entry {
                *entry = ts;
            }
        }
    }
    let unique_global = global_first.len();

    // ─── Summary ───
    println!("\n{}", "═".repeat(94).bright_cyan());
    println!(
        "{}",
        "                  RAIDEN RAW SHRED BENCHMARK RESULTS"
            .bold()
            .bright_white()
    );
    println!("{}\n", "═".repeat(94).bright_cyan());

    println!(
        "  Duration: {:.2}s  |  Unique shreds (global): {}  |  Rate: {:.0} shreds/s\n",
        elapsed.as_secs_f64(),
        unique_global.to_string().bright_green(),
        unique_global as f64 / elapsed.as_secs_f64()
    );

    // ─── Per-endpoint overview ───
    for (i, ep) in endpoints.iter().enumerate() {
        let st = &all_stats[i];
        let unique = st.shreds.len();
        println!(
            "  {} {}",
            "▶".bright_yellow(),
            ep.name.bold().bright_white()
        );
        println!(
            "    Received: {}  |  Unique: {}  |  Dupes: {} ({:.2}%)  |  Non-shreds: {}",
            st.total_received.to_string().bright_green(),
            unique.to_string().bright_green(),
            st.duplicates.to_string().bright_red(),
            if st.total_received > 0 {
                st.duplicates as f64 / st.total_received as f64 * 100.0
            } else {
                0.0
            },
            st.non_shreds.to_string().bright_yellow(),
        );

        // Show shred size distribution
        if !st.size_counts.is_empty() {
            let mut sizes: Vec<_> = st.size_counts.iter().collect();
            sizes.sort_by_key(|(size, _)| *size);
            let total: u64 = sizes.iter().map(|(_, c)| *c).sum();
            print!("    {}", "Shred sizes:".bright_cyan());
            for (size, count) in &sizes {
                print!(
                    "  {} × {} ({:.1}%)",
                    size.to_string().bright_white(),
                    count.to_string().bright_green(),
                    **count as f64 / total as f64 * 100.0
                );
            }
            println!();
        }

        // Show shred type distribution
        if !st.type_counts.is_empty() {
            let mut types: Vec<_> = st.type_counts.iter().collect();
            types.sort_by(|a, b| b.1.cmp(a.1)); // sort by count descending
            let total: u64 = types.iter().map(|(_, c)| *c).sum();
            print!("    {}", "Shred types:".bright_cyan());
            for (name, count) in &types {
                print!(
                    "  {} × {} ({:.1}%)",
                    name.bright_white(),
                    count.to_string().bright_green(),
                    **count as f64 / total as f64 * 100.0
                );
            }
            println!();
        }

        // Show size × type cross-tabulation (only if there are multiple sizes)
        if st.size_counts.len() > 1 && !st.size_type_counts.is_empty() {
            // Group by type, then list sizes within each type
            let mut by_type: HashMap<&'static str, Vec<(usize, u64)>> = HashMap::new();
            for (&(vname, size), &count) in &st.size_type_counts {
                by_type.entry(vname).or_default().push((size, count));
            }
            // Sort types by total count descending
            let mut type_list: Vec<_> = by_type.into_iter().collect();
            type_list.sort_by(|a, b| {
                let sum_a: u64 = a.1.iter().map(|(_, c)| c).sum();
                let sum_b: u64 = b.1.iter().map(|(_, c)| c).sum();
                sum_b.cmp(&sum_a)
            });

            // Only show this section if at least one type has multiple sizes
            let has_multi_sizes = type_list.iter().any(|(_, sizes)| sizes.len() > 1);
            if has_multi_sizes {
                println!("    {}", "Size by type:".bright_cyan());
                for (vname, mut sizes) in type_list {
                    sizes.sort_by_key(|(s, _)| *s);
                    let parts: Vec<String> = sizes
                        .iter()
                        .map(|(s, c)| format!("{} × {}", s, c))
                        .collect();
                    println!(
                        "      {:<30} {}",
                        vname.bright_white(),
                        parts.join(",  ").dimmed()
                    );
                }
            }
        }

        // Show rejected packet samples if any
        if !st.reject_samples.is_empty() {
            println!(
                "    {} ({} samples):",
                "Non-shred packets".bright_yellow().bold(),
                st.reject_samples.len()
            );
            for (j, sample) in st.reject_samples.iter().enumerate() {
                let type_info = if sample.data.len() > VARIANT_OFFSET {
                    let v = sample.data[VARIANT_OFFSET];
                    if is_coding_shred(v) || is_data_shred(v) {
                        format!(" [{}]", variant_name(v))
                    } else {
                        format!(" [variant 0x{:02X}]", v)
                    }
                } else {
                    String::new()
                };
                println!(
                    "      #{}: {} ({} bytes){}",
                    j + 1,
                    format!("{}", sample.reason).bright_red(),
                    sample.size,
                    type_info.bright_yellow()
                );
                // Hex dump: 16 bytes per line, up to 128 bytes
                for row in 0..(sample.data.len() + 15) / 16 {
                    let offset = row * 16;
                    let end = (offset + 16).min(sample.data.len());
                    let hex: String = sample.data[offset..end]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let ascii: String = sample.data[offset..end]
                        .iter()
                        .map(|b| if *b >= 0x20 && *b <= 0x7E { *b as char } else { '.' })
                        .collect();
                    println!(
                        "        {:04x}: {:<48} {}",
                        offset,
                        hex.dimmed(),
                        ascii.dimmed()
                    );
                }
            }
        }

        println!();
    }

    // ─── Latency deltas vs global first arrival ───
    if endpoints.len() < 2 {
        println!(
            "  {}",
            "Need at least 2 endpoints for comparative latency.".yellow()
        );
        return;
    }

    println!("{}", "─".repeat(94).bright_cyan());
    println!(
        "  {}",
        "LATENCY DELTA vs GLOBAL FIRST ARRIVAL (lower = faster)"
            .bold()
            .bright_white()
    );
    println!("{}\n", "─".repeat(94).bright_cyan());

    println!(
        "  {:<35} {:>10} {:>10} {:>10} {:>10} {:>10}  {:>12}",
        "Endpoint".bold(),
        "p5".bold(),
        "p25".bold(),
        "p50".bold(),
        "p95".bold(),
        "p99".bold(),
        "wins".bold(),
    );
    println!("  {}", "─".repeat(92));

    // Collect per-endpoint deltas for mean/stddev display after the table
    let mut all_deltas: Vec<(&str, Vec<f64>, u64)> = Vec::new();

    for (i, ep) in endpoints.iter().enumerate() {
        let map = &all_stats[i].shreds;
        let mut deltas_us: Vec<f64> = Vec::with_capacity(map.len());
        let mut wins: u64 = 0;

        for (shred_id, ts) in map {
            if let Some(&first_ts) = global_first.get(shred_id) {
                let delta_ns = ts.saturating_sub(first_ts);
                deltas_us.push(delta_ns as f64 / 1_000.0);
                if *ts == first_ts {
                    wins += 1;
                }
            }
        }

        deltas_us.sort_by(|a, b| a.partial_cmp(b).unwrap());

        if deltas_us.is_empty() {
            println!("  {:<35} {:>10}", ep.name, "N/A".dimmed());
            continue;
        }

        let total = map.len();
        let win_pct = wins as f64 / total as f64 * 100.0;

        println!(
            "  {:<35} {:>10} {:>10} {:>10} {:>10} {:>10}  {:>12}",
            ep.name.bright_white(),
            color_val(percentile(&deltas_us, 5.0)),
            color_val(percentile(&deltas_us, 25.0)),
            color_val(percentile(&deltas_us, 50.0)),
            color_val(percentile(&deltas_us, 95.0)),
            color_val(percentile(&deltas_us, 99.0)),
            format!("{} ({:.1}%)", wins, win_pct).bright_cyan(),
        );

        all_deltas.push((&ep.name, deltas_us, wins));
    }

    // ─── Head-to-head ───
    if endpoints.len() == 2 {
        print_head_to_head(endpoints, all_stats, config_windows);
    }

    println!("\n{}\n", "═".repeat(94).bright_cyan());
}


fn print_head_to_head(endpoints: &[Endpoint], all_stats: &[LocalStats], num_windows: usize) {
    let map_a = &all_stats[0].shreds;
    let map_b = &all_stats[1].shreds;

    let mut a_faster: u64 = 0;
    let mut b_faster: u64 = 0;
    let mut ties: u64 = 0;
    let mut deltas_us: Vec<f64> = Vec::new();
    // For time consistency: (timestamp_ns, delta_us)
    let mut time_deltas: Vec<(u64, f64)> = Vec::new();

    for (shred_id, ts_a) in map_a {
        if let Some(ts_b) = map_b.get(shred_id) {
            let diff = *ts_b as i128 - *ts_a as i128; // positive = A arrived first
            let delta = diff as f64 / 1_000.0;
            deltas_us.push(delta);
            time_deltas.push((*ts_a, delta));
            if diff > 0 {
                a_faster += 1;
            } else if diff < 0 {
                b_faster += 1;
            } else {
                ties += 1;
            }
        }
    }

    let common = a_faster + b_faster + ties;
    if common == 0 {
        return;
    }

    println!(
        "\n  {}",
        "HEAD-TO-HEAD (common shreds only)".bold().bright_white()
    );
    println!("  {}", "─".repeat(76));
    println!(
        "  Common shreds: {}",
        common.to_string().bright_green()
    );
    println!(
        "  {} faster: {} ({:.1}%)",
        endpoints[0].name.bright_cyan(),
        a_faster.to_string().bright_green(),
        a_faster as f64 / common as f64 * 100.0
    );
    println!(
        "  {} faster: {} ({:.1}%)",
        endpoints[1].name.bright_cyan(),
        b_faster.to_string().bright_green(),
        b_faster as f64 / common as f64 * 100.0
    );
    println!(
        "  Ties: {} ({:.1}%)",
        ties.to_string().yellow(),
        ties as f64 / common as f64 * 100.0
    );

    deltas_us.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let p5 = percentile(&deltas_us, 5.0);
    let p25 = percentile(&deltas_us, 25.0);
    let p50 = percentile(&deltas_us, 50.0);
    let p95 = percentile(&deltas_us, 95.0);
    let p99 = percentile(&deltas_us, 99.0);

    let (winner, loser) = if p50 >= 0.0 {
        (&endpoints[0].name, &endpoints[1].name)
    } else {
        (&endpoints[1].name, &endpoints[0].name)
    };

    let fmt_adv = |v: f64| -> ColoredString {
        let abs = v.abs();
        if abs < 1.0 {
            format!("{:.2}µs", abs).bright_green()
        } else if abs < 1000.0 {
            format!("{:.2}µs", abs).bright_green()
        } else {
            format!("{:.2}ms", abs / 1000.0).bright_green()
        }
    };

    println!(
        "\n  {} advantage over {}:",
        winner.bright_green().bold(),
        loser.dimmed()
    );
    println!("  {}", "─".repeat(76));
    println!(
        "    {:<12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "".bold(),
        "p5".bold(),
        "p25".bold(),
        "p50".bold(),
        "p95".bold(),
        "p99".bold(),
    );
    println!(
        "    {:<12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "Advantage",
        fmt_adv(p5),
        fmt_adv(p25),
        fmt_adv(p50),
        fmt_adv(p95),
        fmt_adv(p99),
    );

    // ─── Histogram ─────────────────────────────────────────────────────────
    print_histogram(&deltas_us, &endpoints[0].name, &endpoints[1].name);

    // ─── Time consistency ──────────────────────────────────────────────────
    print_time_consistency(&time_deltas, &endpoints[0].name, &endpoints[1].name, num_windows);
}

/// Visual butterfly histogram of head-to-head deltas.
/// Red bars grow LEFT (B faster), green bars grow RIGHT (A faster).
/// Percentage column is always perfectly centered.
fn print_histogram(deltas_us: &[f64], name_a: &str, name_b: &str) {
    if deltas_us.is_empty() {
        return;
    }

    println!(
        "\n  {}",
        "LATENCY DISTRIBUTION".bold().bright_white()
    );
    println!("  {}", "─".repeat(90));

    // Buckets (µs): negative = B faster, positive = A faster
    let bucket_edges: &[f64] = &[
        -50000.0, -20000.0, -10000.0, -5000.0, -2000.0, -1000.0, -500.0,
        0.0,
        500.0, 1000.0, 2000.0, 5000.0, 10000.0, 20000.0, 50000.0,
    ];

    let mut counts = vec![0u64; bucket_edges.len() + 1];
    for &d in deltas_us {
        let mut placed = false;
        for (i, &edge) in bucket_edges.iter().enumerate() {
            if d < edge {
                counts[i] += 1;
                placed = true;
                break;
            }
        }
        if !placed {
            counts[bucket_edges.len()] += 1;
        }
    }

    let total = deltas_us.len() as f64;
    let max_count = *counts.iter().max().unwrap_or(&1) as f64;
    let bar_max: usize = 25; // max bar length on each side

    let fmt_edge = |v: f64| -> String {
        let abs = v.abs();
        if abs < 1000.0 {
            format!("{:.0}µs", v)
        } else {
            format!("{:.0}ms", v / 1000.0)
        }
    };

    let labels: Vec<String> = (0..=bucket_edges.len())
        .map(|i| {
            if i == 0 {
                format!("< {}", fmt_edge(bucket_edges[0]))
            } else if i == bucket_edges.len() {
                format!("> {}", fmt_edge(bucket_edges[bucket_edges.len() - 1]))
            } else {
                format!(
                    "{} .. {}",
                    fmt_edge(bucket_edges[i - 1]),
                    fmt_edge(bucket_edges[i])
                )
            }
        })
        .collect();

    let label_w = labels.iter().map(|l| l.len()).max().unwrap_or(10);

    // Header: place names centered over bar areas
    println!(
        "  {:>lw$}  {:>bw$}        {:<bw$}",
        "",
        format!("◄ {} faster", name_b).bright_red(),
        format!("{} faster ►", name_a).bright_green(),
        lw = label_w,
        bw = bar_max,
    );
    println!();

    // Fixed-column layout per row:
    //   "  " + label(label_w) + "  " + left_bar(bar_max) + " " + pct(5.1%=6ch) + " " + right_bar(bar_max) + "  " + count
    // Every field has a fixed width, so pct is ALWAYS at the exact same column.

    for (i, label) in labels.iter().enumerate() {
        let count = counts[i];
        if count == 0 {
            continue;
        }
        let pct = count as f64 / total * 100.0;
        let bar_len = ((count as f64 / max_count) * bar_max as f64).ceil() as usize;
        let bar_len = bar_len.max(1);

        let is_left = if i == 0 {
            true
        } else if i < bucket_edges.len() {
            bucket_edges[i - 1] < 0.0
        } else {
            false
        };

        // Build display strings: plain spaces + colored bars, always exactly bar_max visible chars
        let left_display: String;
        let right_display: String;

        if is_left {
            let pad = bar_max - bar_len;
            left_display = format!("{}{}", " ".repeat(pad), "█".repeat(bar_len).bright_red());
            right_display = " ".repeat(bar_max);
        } else {
            left_display = " ".repeat(bar_max);
            let trail = bar_max - bar_len;
            right_display = format!("{}{}", "█".repeat(bar_len).bright_green(), " ".repeat(trail));
        }

        println!(
            "  {:>lw$}  {} {:>5.1}% {}  {}",
            label,
            left_display,
            pct,
            right_display,
            format!("({})", count).dimmed(),
            lw = label_w,
        );
    }
}

/// Time-series consistency: split the run into 10 windows and show
/// per-window p50, p95, p99, win% with a visual trend bar.
fn print_time_consistency(time_deltas: &[(u64, f64)], name_a: &str, _name_b: &str, num_windows: usize) {
    if time_deltas.len() < 100 || num_windows == 0 {
        return;
    }

    println!(
        "\n  {}",
        "CONSISTENCY OVER TIME".bold().bright_white()
    );
    println!("  {}", "─".repeat(76));

    let mut sorted = time_deltas.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let window_size = sorted.len() / num_windows;
    if window_size == 0 {
        return;
    }

    let first_ts = sorted.first().unwrap().0;
    let last_ts = sorted.last().unwrap().0;
    let total_duration_s = (last_ts - first_ts) as f64 / 1_000_000_000.0;

    let short_a: String = name_a.chars().take(10).collect();

    println!(
        "  Total duration: {:.1}s, {} windows of ~{} shreds\n",
        total_duration_s,
        num_windows,
        window_size
    );

    println!(
        "  {:<12} {:>10} {:>10} {:>10} {:>10}  {}",
        "Window".bold(),
        "p50".bold(),
        "p95".bold(),
        "p99".bold(),
        format!("{} win%", short_a).bold(),
        "".bold(),
    );
    println!("  {}", "─".repeat(76));

    let fmt_val = |v: f64| -> ColoredString {
        let abs = v.abs();
        if abs < 1000.0 {
            format!("{:.1}µs", abs).bright_green()
        } else {
            format!("{:.2}ms", abs / 1000.0).bright_green()
        }
    };

    for w in 0..num_windows {
        let start = w * window_size;
        let end = if w == num_windows - 1 {
            sorted.len()
        } else {
            (w + 1) * window_size
        };
        let window = &sorted[start..end];

        let mut vals: Vec<f64> = window.iter().map(|(_, d)| *d).collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let wn = vals.len() as f64;
        let w_p50 = percentile(&vals, 50.0);
        let w_p95 = percentile(&vals, 95.0);
        let w_p99 = percentile(&vals, 99.0);
        let w_a_wins = window.iter().filter(|(_, d)| *d > 0.0).count() as f64;
        let w_pct = w_a_wins / wn * 100.0;

        // 10-char visual bar
        let filled = (w_pct / 10.0).round() as usize;
        let trend_bar = format!(
            "{}{}",
            "█".repeat(filled.min(10)).bright_green(),
            "░".repeat(10usize.saturating_sub(filled)).dimmed()
        );

        let ws = (window.first().unwrap().0 - first_ts) as f64 / 1e9;
        let we = (window.last().unwrap().0 - first_ts) as f64 / 1e9;

        println!(
            "  {:<12} {:>10} {:>10} {:>10} {:>10}  {}",
            format!("{:.0}-{:.0}s", ws, we).dimmed(),
            fmt_val(w_p50),
            fmt_val(w_p95),
            fmt_val(w_p99),
            format!("{:.1}%", w_pct).bright_cyan(),
            trend_bar,
        );
    }
}

// ─── URL parsing ───────────────────────────────────────────────────────────

fn parse_addr_from_url(url: &str) -> SocketAddr {
    let stripped = url
        .trim()
        .replace("http://", "")
        .replace("https://", "")
        .replace("udp://", "");
    stripped.parse::<SocketAddr>().unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Invalid endpoint URL '{}': {}", url, e).bright_red()
        );
        std::process::exit(1);
    })
}

// ─── WebSocket helper ──────────────────────────────────────────────────────

/// Read next text message from the WebSocket, automatically responding to Pings.
fn ws_read_text(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
) -> Result<String, String> {
    loop {
        match socket.read() {
            Ok(Message::Text(t)) => return Ok(t),
            Ok(Message::Ping(data)) => {
                let _ = socket.send(Message::Pong(data));
                continue;
            }
            Ok(Message::Pong(_)) => continue,
            Ok(Message::Close(frame)) => {
                return Err(format!("Connection closed by backend: {:?}", frame));
            }
            Ok(other) => {
                return Err(format!("Unexpected message: {:?}", other));
            }
            Err(e) => {
                return Err(format!("WebSocket read error: {}", e));
            }
        }
    }
}

/// Enable TCP_NODELAY on the underlying WebSocket stream to disable Nagle's algorithm.
fn set_tcp_nodelay(
    socket: &tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
) {
    use tungstenite::stream::MaybeTlsStream;
    let tcp = match socket.get_ref() {
        MaybeTlsStream::Plain(s) => s,
        MaybeTlsStream::Rustls(s) => s.get_ref(),
        _ => return,
    };
    let _ = tcp.set_nodelay(true);
}

// ─── Backend upload via WebSocket ──────────────────────────────────────────

fn upload_to_backend(
    backend_url: &str,
    config: &GlobalConfig,
    endpoints: &[Endpoint],
    all_stats: &[LocalStats],
    global_first: &HashMap<ShredId, u64>,
) {
    println!(
        "\n  {} Connecting to backend: {}",
        "📡".bright_cyan(),
        backend_url.bright_white()
    );

    let ws_url = {
        let base = backend_url.trim_end_matches('/');
        let ws_base = if base.starts_with("https://") {
            base.replace("https://", "wss://")
        } else {
            base.replace("http://", "ws://")
        };
        format!("{}/ws/benchmark", ws_base)
    };

    let parsed_url = match url::Url::parse(&ws_url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!(
                "  {} Invalid backend URL: {}",
                "✗".bright_red(),
                e
            );
            return;
        }
    };

    let (mut socket, _response) = match connect(parsed_url) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "  {} Failed to connect to backend: {}",
                "✗".bright_red(),
                e
            );
            return;
        }
    };

    // Disable Nagle's algorithm for lower latency writes
    set_tcp_nodelay(&socket);

    println!(
        "  {} Connected to backend",
        "✓".bright_green()
    );

    // ── Step 1: Send "start" message ──
    let endpoint_names: Vec<String> = endpoints.iter().map(|ep| ep.name.clone()).collect();

    let start_msg = WsStartMessage {
        r#type: "start".to_string(),
        config: WsBenchmarkConfig {
            target_shreds: config.shreds,
            measure_strat: config.measure_strat,
            shred_type: config.shred_type.clone(),
        },
        endpoints: endpoint_names,
    };

    let start_json = serde_json::to_string(&start_msg).unwrap();
    if let Err(e) = socket.send(Message::Text(start_json)) {
        eprintln!("  {} Failed to send start: {}", "✗".bright_red(), e);
        return;
    }

    // ── Step 2: Read "start_ack" ──
    let ack_text = match ws_read_text(&mut socket) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  {} Failed to read start_ack: {}", "✗".bright_red(), e);
            return;
        }
    };

    let type_check: WsTypeCheck = match serde_json::from_str(&ack_text) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  {} Invalid JSON from backend: {}", "✗".bright_red(), e);
            return;
        }
    };

    if type_check.r#type == "error" {
        let err_msg: WsErrorMessage = serde_json::from_str(&ack_text).unwrap();
        eprintln!("  {} Backend error: {}", "✗".bright_red(), err_msg.message);
        return;
    }

    let ack: WsStartAck = match serde_json::from_str(&ack_text) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("  {} Failed to parse start_ack: {}", "✗".bright_red(), e);
            return;
        }
    };

    let nonce_bytes = match hex::decode(&ack.session_nonce) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            eprintln!(
                "  {} Invalid nonce length: {} (expected 32)",
                "✗".bright_red(),
                b.len()
            );
            return;
        }
        Err(e) => {
            eprintln!("  {} Invalid nonce hex: {}", "✗".bright_red(), e);
            return;
        }
    };

    println!(
        "  {} Benchmark ID: {}",
        "✓".bright_green(),
        ack.run_id.bright_cyan()
    );

    // ── Step 3: Stream shred observations with batched flushing ──
    //
    // Instead of socket.send() (which flushes after every message = 1 syscall per shred),
    // we use socket.write() to buffer messages and flush every FLUSH_EVERY messages.
    // With 500k shreds this reduces syscalls from 500k to ~500, massive speedup.
    println!(
        "  {} Uploading shred diffs...",
        "⏳".bright_yellow()
    );

    const FLUSH_EVERY: u64 = 1000;

    let total_unique = global_first.len() as u64;
    let mut sent_shreds: u64 = 0;
    let mut unflushed: u64 = 0;
    let mut last_progress = Instant::now();
    let upload_start = Instant::now();

    let mut all_shred_ids: Vec<&ShredId> = global_first.keys().collect();
    all_shred_ids.sort_by(|a, b| a.cmp(b));

    for shred_id in &all_shred_ids {
        let first_ts = global_first[*shred_id];
        let shred_id_hex = hex::encode(*shred_id);

        let mut observations = Vec::new();

        for (i, ep) in endpoints.iter().enumerate() {
            if let Some(&ep_ts) = all_stats[i].shreds.get(*shred_id) {
                let delta_ns = ep_ts.saturating_sub(first_ts);
                let time_diff_ms = delta_ns as f64 / 1_000_000.0;

                let proof = compute_proof(&nonce_bytes, &ep.name, &shred_id_hex, time_diff_ms);

                observations.push(WsShredObservation {
                    endpoint: ep.name.clone(),
                    time_diff_ms,
                    proof,
                });
            }
        }

        if !observations.is_empty() {
            let shred_msg = WsShredMessage {
                r#type: "shred".to_string(),
                shred_id: shred_id_hex,
                observations,
            };

            let json = serde_json::to_string(&shred_msg).unwrap();
            // write() buffers without flushing — much faster than send()
            if let Err(e) = socket.write(Message::Text(json)) {
                eprintln!("  {} Failed to write shred: {}", "✗".bright_red(), e);
                return;
            }

            sent_shreds += 1;
            unflushed += 1;

            // Flush in batches
            if unflushed >= FLUSH_EVERY {
                if let Err(e) = socket.flush() {
                    eprintln!("  {} Failed to flush: {}", "✗".bright_red(), e);
                    return;
                }
                unflushed = 0;
            }
        }

        // Progress every 2 seconds
        if last_progress.elapsed() >= Duration::from_secs(2) {
            // Flush before sending progress so backend stays up to date
            if unflushed > 0 {
                if let Err(e) = socket.flush() {
                    eprintln!("  {} Failed to flush: {}", "✗".bright_red(), e);
                    return;
                }
                unflushed = 0;
            }

            let pct = (sent_shreds * 100) / total_unique.max(1);
            let elapsed_s = upload_start.elapsed().as_secs_f64();
            let rate = sent_shreds as f64 / elapsed_s;
            let remaining = (total_unique - sent_shreds) as f64 / rate;

            let progress_msg = WsProgressMessage {
                r#type: "progress".to_string(),
                shreds: sent_shreds,
                total: total_unique,
                percent: pct,
            };

            let json = serde_json::to_string(&progress_msg).unwrap();
            if let Err(e) = socket.send(Message::Text(json)) {
                eprintln!("  {} Failed to send progress: {}", "✗".bright_red(), e);
                return;
            }

            eprint!(
                "\r\x1b[2K  📡 Uploading: {}/{} ({}%) — {:.0} shreds/s, ~{:.0}s remaining",
                sent_shreds.to_string().bright_green(),
                total_unique.to_string().dimmed(),
                pct,
                rate,
                remaining,
            );

            last_progress = Instant::now();
        }
    }

    // Final flush for any remaining buffered messages
    if unflushed > 0 {
        if let Err(e) = socket.flush() {
            eprintln!("  {} Failed to flush: {}", "✗".bright_red(), e);
            return;
        }
    }

    let upload_elapsed = upload_start.elapsed();
    eprintln!(
        "\r\x1b[2K  📡 Uploaded {} shreds in {:.1}s ({:.0} shreds/s)",
        sent_shreds.to_string().bright_green(),
        upload_elapsed.as_secs_f64(),
        sent_shreds as f64 / upload_elapsed.as_secs_f64(),
    );

    // ── Step 4: Send "end" message with final stats ──
    let common_count = global_first.keys()
        .filter(|sid| all_stats.iter().all(|st| st.shreds.contains_key(*sid)))
        .count() as f64;

    let mut ws_endpoints = Vec::new();

    for (i, ep) in endpoints.iter().enumerate() {
        let st = &all_stats[i];
        let map = &st.shreds;

        let mut deltas_ms: Vec<f64> = Vec::with_capacity(map.len());
        let mut wins: u64 = 0;

        for (shred_id, ts) in map {
            if let Some(&first_ts) = global_first.get(shred_id) {
                let delta_ns = ts.saturating_sub(first_ts);
                deltas_ms.push(delta_ns as f64 / 1_000_000.0);
                if *ts == first_ts {
                    wins += 1;
                }
            }
        }

        deltas_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let win_rate = if common_count > 0.0 { wins as f64 / common_count } else { 0.0 };

        ws_endpoints.push(WsEndpointResult {
            name: ep.name.clone(),
            win_rate,
            p5: percentile(&deltas_ms, 5.0),
            p25: percentile(&deltas_ms, 25.0),
            p50: percentile(&deltas_ms, 50.0),
            p95: percentile(&deltas_ms, 95.0),
            p99: percentile(&deltas_ms, 99.0),
            total_received: st.total_received,
            unique_shreds: st.shreds.len() as u64,
            duplicates: st.duplicates,
            non_shreds: st.non_shreds,
            win_count: wins,
        });
    }

    let end_msg = WsEndMessage {
        r#type: "end".to_string(),
        endpoints: ws_endpoints,
    };

    let end_json = serde_json::to_string(&end_msg).unwrap();
    if let Err(e) = socket.send(Message::Text(end_json)) {
        eprintln!("  {} Failed to send end: {}", "✗".bright_red(), e);
        return;
    }

    // ── Step 5: Read "complete" response ──
    let complete_text = match ws_read_text(&mut socket) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  {} {}", "✗".bright_red(), e);
            return;
        }
    };

    let type_check: WsTypeCheck = match serde_json::from_str(&complete_text) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("  {} Invalid response from backend", "✗".bright_red());
            return;
        }
    };

    if type_check.r#type == "error" {
        if let Ok(err_msg) = serde_json::from_str::<WsErrorMessage>(&complete_text) {
            eprintln!("  {} Backend error: {}", "✗".bright_red(), err_msg.message);
        }
        return;
    }

    if let Ok(complete) = serde_json::from_str::<WsCompleteMessage>(&complete_text) {
        println!(
            "  {} Benchmark uploaded successfully!",
            "✓".bright_green()
        );
        println!(
            "  {} View results at: {}",
            "🔗".bright_cyan(),
            complete.url.bright_white()
        );
    }

    let _ = socket.close(None);
}

// ─── Main ──────────────────────────────────────────────────────────────────

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let config_str = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Failed to read {}: {}", config_path, e).bright_red()
        );
        std::process::exit(1);
    });

    let config: Config = toml::from_str(&config_str).unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Failed to parse config: {}", e).bright_red()
        );
        std::process::exit(1);
    });

    let target_shreds = config.config.shreds;
    let num_endpoints = config.endpoint.len();

    // ─── Banner ───
    println!("\n{}", "═".repeat(94).bright_cyan());
    println!(
        "{}",
        "            ⚡ RAIDEN RAW SHRED BENCHMARK ⚡"
            .bold()
            .bright_white()
    );
    println!("{}\n", "═".repeat(94).bright_cyan());
    println!(
        "  Target shreds: {}",
        target_shreds.to_string().bright_green()
    );
    let measure_strat = config.config.measure_strat;
    let shred_filter = ShredFilter::from_config(&config.config);
    if measure_strat > 0 {
        println!(
            "  Filter: first {} {} shreds per FEC set (type: {})",
            measure_strat.to_string().bright_yellow(),
            config.config.shred_type.bright_cyan(),
            config.config.shred_type.bright_cyan()
        );
    } else {
        println!(
            "  Filter: {} (all shreds, no filter)",
            "none".bright_green()
        );
    }
    println!("  Endpoints:");
    for ep in &config.endpoint {
        println!(
            "    {} {} ({})",
            "•".bright_yellow(),
            ep.name.bright_white(),
            ep.url.dimmed()
        );
    }
    println!(
        "\n  Architecture: {} fully isolated receiver threads, zero shared state in hot path",
        num_endpoints.to_string().bright_green()
    );
    println!(
        "\n  {} Waiting for shreds...\n",
        "⏳".bright_yellow()
    );

    // ─── Shared counters (atomics only, for progress display) ───
    let counters = Arc::new(SharedCounters {
        unique_counts: (0..num_endpoints)
            .map(|_| AtomicU64::new(0))
            .collect(),
        dupe_counts: (0..num_endpoints)
            .map(|_| AtomicU64::new(0))
            .collect(),
        running: AtomicBool::new(true),
    });

    // Ctrl+C
    {
        let counters = counters.clone();
        ctrlc::set_handler(move || {
            counters.running.store(false, Ordering::Relaxed);
            eprintln!("\n  {} Shutting down...", "⚠".yellow());
        })
        .ok();
    }

    // ─── Spawn fully isolated receiver threads ───
    // Each thread owns: its own UdpSocket, its own LocalStats HashMap, its own recv buffer.
    // Returns LocalStats via JoinHandle when stopped.
    let mut handles: Vec<thread::JoinHandle<LocalStats>> = Vec::new();
    for (i, ep) in config.endpoint.iter().enumerate() {
        let addr = parse_addr_from_url(&ep.url);
        let counters = counters.clone();
        let name = ep.name.clone();
        let filter = shred_filter;
        let h = thread::Builder::new()
            .name(format!("rx-{}", name))
            .spawn(move || receiver_thread(i, addr, counters, filter))
            .unwrap();
        handles.push(h);
    }

    // ─── Progress monitor (main thread, reads atomics only — never blocks receivers) ───
    let start = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(1));

        if !counters.running.load(Ordering::Relaxed) {
            break;
        }

        let elapsed = start.elapsed().as_secs_f64();
        let max_unique = (0..num_endpoints)
            .map(|i| counters.unique_counts[i].load(Ordering::Relaxed))
            .max()
            .unwrap_or(0);
        let total_unique: u64 = (0..num_endpoints)
            .map(|i| counters.unique_counts[i].load(Ordering::Relaxed))
            .sum();
        let rate = total_unique as f64 / elapsed / num_endpoints as f64;

        eprint!("\r\x1b[2K  📊");
        for (i, ep) in config.endpoint.iter().enumerate() {
            let u = counters.unique_counts[i].load(Ordering::Relaxed);
            let d = counters.dupe_counts[i].load(Ordering::Relaxed);
            let short_name = if ep.name.len() > 16 {
                &ep.name[..16]
            } else {
                &ep.name
            };
            eprint!(
                " [{}:{} +{}d]",
                short_name,
                u.to_string().bright_green(),
                d.to_string().dimmed()
            );
        }
        eprint!(
            "  {}/{} ({:.0}/s)",
            max_unique.to_string().bright_green(),
            target_shreds.to_string().dimmed(),
            rate,
        );

        if max_unique >= target_shreds {
            counters.running.store(false, Ordering::Relaxed);
            break;
        }
    }

    eprintln!();
    let elapsed = start.elapsed();

    // ─── Collect results from each thread (only here do we touch their data) ───
    let all_stats: Vec<LocalStats> = handles
        .into_iter()
        .map(|h| h.join().expect("receiver thread panicked"))
        .collect();

    // ─── Print report ───
    print_results(&config.endpoint, &all_stats, elapsed, config.config.windows);

    // ─── Upload to backend if configured ───
    if let Some(ref backend) = config.backend {
        // Build global first-arrival map (same as print_results does internally)
        let mut global_first: HashMap<ShredId, u64> = HashMap::new();
        for stats in &all_stats {
            for (&shred_id, &ts) in &stats.shreds {
                let entry = global_first.entry(shred_id).or_insert(ts);
                if ts < *entry {
                    *entry = ts;
                }
            }
        }

        upload_to_backend(
            &backend.url,
            &config.config,
            &config.endpoint,
            &all_stats,
            &global_first,
        );
    }
}