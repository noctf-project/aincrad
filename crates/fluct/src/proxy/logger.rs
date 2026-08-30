use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use aho_corasick::AhoCorasick;
use fluct::Error;
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};

pub const MAX_PAYLOAD: usize = 0x7FFF;
pub const FOOTER_SIZE: usize = 2;

/// Per-direction streaming needle matcher. AhoCorasick over a single chunk
/// can't span reads, so we retain the last `needle_len - 1` bytes of each
/// direction as carry and test `carry + chunk`; a match crossing a read
/// boundary is still caught. Both buffers are preallocated, so after warmup
/// matching is allocation-free.
struct NeedleMatcher {
    ac: AhoCorasick,
    needle_len: usize,
    state: [StdMutex<NeedleState>; 2],
    hit: AtomicBool,
}

struct NeedleState {
    scratch: Vec<u8>,
    carry: Vec<u8>,
}

impl NeedleState {
    fn new(needle_len: usize) -> Self {
        Self {
            scratch: Vec::with_capacity(needle_len + needle_len - 1),
            carry: Vec::with_capacity(needle_len),
        }
    }
}

impl NeedleMatcher {
    fn new(needle: &str) -> Self {
        assert!(
            !needle.is_empty(),
            "empty needle is rejected before construction"
        );
        let ac = AhoCorasick::new([needle]).expect("valid non-empty needle");
        let len = needle.len();
        Self {
            ac,
            needle_len: len,
            state: std::array::from_fn(|_| StdMutex::new(NeedleState::new(len))),
            hit: AtomicBool::new(false),
        }
    }

    /// Feeds a chunk from one direction. On a hit returns the number of bytes of
    /// this chunk (out to and including the needle) that should be recorded;
    /// `None` means no hit, so the whole chunk can be recorded.
    fn feed(&self, dir: u8, chunk: &[u8]) -> Option<usize> {
        let idx = (dir & 1) as usize;
        let keep = self.needle_len - 1;

        let mut state = self.state[idx].lock().unwrap();
        // Check carry + chunk contiguously for matches crossing the boundary.
        let matched_end = if state.carry.is_empty() {
            self.ac.find(chunk).map(|m| m.end())
        } else {
            let carry_len = state.carry.len();
            let carry = std::mem::take(&mut state.carry);
            state.scratch.extend_from_slice(&carry);
            state.scratch.extend_from_slice(chunk);
            self.ac
                .find(state.scratch.as_slice())
                .map(|m| m.end().saturating_sub(carry_len))
        };

        match matched_end {
            Some(end) => {
                self.hit.store(true, Ordering::Relaxed);
                Some(end.min(chunk.len()))
            }
            None => {
                // Retain the last `keep` bytes of `chunk` for the next
                // cross-boundary check, reusing the carry buffer's capacity.
                state.carry.clear();
                let take = chunk.len().min(keep);
                state.carry.extend_from_slice(&chunk[chunk.len() - take..]);
                state.scratch.clear();
                None
            }
        }
    }
}

/// Thread-safe traffic log that persists to a file on flush. When a needle is
/// configured, recording stops once the needle appears in either direction —
/// the buffered bytes then form a snapshot up to (and not including) that hit.
pub struct TrafficLogger {
    inner: Arc<Mutex<LogBuffer>>,
    needle: Option<NeedleMatcher>,
}

impl TrafficLogger {
    pub fn new(capacity: usize, needle: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(LogBuffer::new(capacity))),
            // An empty/missing needle records and flushes all traffic.
            needle: needle.filter(|n| !n.is_empty()).map(NeedleMatcher::new),
        })
    }

    /// Appends `data` flowing in `dir`. Once a configured needle is hit, the
    /// bytes up to and including the needle are recorded, then recording
    /// becomes a no-op so the buffer stays as a snapshot.
    pub async fn write(&self, dir: u8, data: &[u8]) {
        if let Some(needle) = &self.needle {
            if needle.hit.load(Ordering::Relaxed) {
                return;
            }
            if let Some(keep) = needle.feed(dir, data) {
                if keep > 0 {
                    self.inner.lock().await.write(dir, &data[..keep]);
                }
                return;
            }
        }
        self.inner.lock().await.write(dir, data);
    }

    /// Whether the buffered bytes should be persisted: always when no needle is
    /// configured, otherwise only once the needle has been seen.
    pub fn should_flush(&self) -> bool {
        match &self.needle {
            None => true,
            Some(needle) => needle.hit.load(Ordering::Relaxed),
        }
    }

    /// Writes the buffered bytes (oldest first) in the order it saw them.
    pub async fn flush(&self, path: &Path) -> Result<(), Error> {
        let guard = self.inner.lock().await;
        let (older, newer) = guard.as_slices();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await?;
        file.write_all(older).await?;
        file.write_all(newer).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct LogBuffer {
    buf: Box<[u8]>,
    pos: usize,
    has_wrapped: bool,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity >= FOOTER_SIZE + 1,
            "Capacity must fit at least 1 byte of payload and a footer"
        );
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            pos: 0,
            has_wrapped: false,
        }
    }

    pub fn write(&mut self, dir: u8, mut data: &[u8]) {
        let dir = dir & 1;

        while !data.is_empty() {
            // Try to continue an existing record at current pos
            if let Some((cur_len, cur_dir)) = self.peek_current_record() {
                if cur_dir == dir && cur_len < MAX_PAYLOAD {
                    let available_in_buf = self.buf.len() - self.pos;
                    let available_in_record = MAX_PAYLOAD - cur_len;
                    let space = available_in_buf.min(available_in_record);

                    if space > 0 {
                        let to_write = data.len().min(space);
                        let write_pos = self.pos - FOOTER_SIZE;

                        self.buf[write_pos..write_pos + to_write]
                            .copy_from_slice(&data[..to_write]);
                        let new_len = cur_len + to_write;
                        self.pos = write_pos + to_write;

                        self.write_footer(new_len, dir);
                        data = &data[to_write..];
                        continue;
                    }
                }
            }

            // Start a new record. Check if we need to wrap to index 0.
            let available_at_pos = self.buf.len().saturating_sub(self.pos);
            if available_at_pos < FOOTER_SIZE + 1 {
                self.pos = 0;
                self.has_wrapped = true;
            }

            // Compute how much fits in this new record
            let max_writable = (self.buf.len() - self.pos - FOOTER_SIZE).min(MAX_PAYLOAD);
            let to_write = data.len().min(max_writable);

            self.buf[self.pos..self.pos + to_write].copy_from_slice(&data[..to_write]);
            self.pos += to_write;

            self.write_footer(to_write, dir);
            data = &data[to_write..];
        }
    }

    fn peek_current_record(&self) -> Option<(usize, u8)> {
        if self.pos < FOOTER_SIZE + 1 {
            return None;
        }

        let footer_val = u16::from_le_bytes([self.buf[self.pos - 2], self.buf[self.pos - 1]]);
        let cur_len = (footer_val & 0x7FFF) as usize;
        let cur_dir = (footer_val >> 15) as u8;

        if cur_len == 0 || self.pos < cur_len + FOOTER_SIZE {
            return None;
        }

        Some((cur_len, cur_dir))
    }

    pub fn as_slices(&self) -> (&[u8], &[u8]) {
        if self.has_wrapped {
            (&self.buf[self.pos..], &self.buf[..self.pos])
        } else {
            (&[], &self.buf[..self.pos])
        }
    }

    fn write_footer(&mut self, len: usize, dir: u8) {
        debug_assert!(len <= MAX_PAYLOAD);
        let footer_val = ((len as u16) & 0x7FFF) | (((dir as u16) & 1) << 15);
        self.buf[self.pos..self.pos + FOOTER_SIZE].copy_from_slice(&footer_val.to_le_bytes());
        self.pos += FOOTER_SIZE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(dir: u8, len: usize) -> [u8; 2] {
        let v = ((len as u16) & 0x7FFF) | (((dir as u16) & 1) << 15);
        v.to_le_bytes()
    }

    fn rec(dir: u8, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        out.extend_from_slice(&enc(dir, data.len()));
        out
    }

    #[test]
    fn footer_encodes_len_and_dir() {
        assert_eq!(enc(0, 0), [0x00, 0x00]);
        assert_eq!(enc(1, 0), [0x00, 0x80]);
        assert_eq!(enc(1, 1), [0x01, 0x80]);
        assert_eq!(enc(0, MAX_PAYLOAD), [0xFF, 0x7F]);
    }

    #[test]
    fn empty_write_is_noop() {
        let mut rb = LogBuffer::new(16);
        rb.write(0, b"hi");
        let before = {
            let (o, n) = rb.as_slices();
            (o.to_vec(), n.to_vec())
        };
        rb.write(2, b"");
        let after = {
            let (o, n) = rb.as_slices();
            (o.to_vec(), n.to_vec())
        };
        assert_eq!(after, before);
    }

    #[test]
    fn single_record() {
        let mut rb = LogBuffer::new(16);
        rb.write(0, b"hello");
        assert_eq!(rb.as_slices().1, rec(0, b"hello"));
        assert!(rb.as_slices().0.is_empty());
        assert_eq!(rb.pos, b"hello".len() + FOOTER_SIZE);
    }

    #[test]
    fn coalesces_same_direction() {
        let mut rb = LogBuffer::new(16);
        rb.write(0, b"he");
        rb.write(0, b"llo");
        assert_eq!(rb.as_slices().1, rec(0, b"hello"));
    }

    #[test]
    fn direction_change_breaks_coalesce() {
        let mut rb = LogBuffer::new(16);
        rb.write(0, b"aaa");
        rb.write(1, b"bb");
        rb.write(1, b"cc");
        let expected: Vec<u8> = rec(0, b"aaa").into_iter().chain(rec(1, b"bbcc")).collect();
        assert_eq!(rb.as_slices().1, expected);
        assert!(rb.as_slices().0.is_empty());
    }

    #[test]
    fn payload_over_max_splits_into_records() {
        let mut rb = LogBuffer::new(MAX_PAYLOAD * 2 + 16);
        let big = vec![b'b'; MAX_PAYLOAD + 10];
        rb.write(0, &big);
        let expected: Vec<u8> = rec(0, &big[..MAX_PAYLOAD])
            .into_iter()
            .chain(rec(0, &big[MAX_PAYLOAD..]))
            .collect();
        assert_eq!(rb.as_slices().0, b"");
        assert_eq!(rb.as_slices().1, expected);
        assert_eq!(rb.pos, big.len() + FOOTER_SIZE * 2);
    }

    #[test]
    fn wrap_discards_old_record() {
        // Fill the buffer fully with one direction.
        let mut rb = LogBuffer::new(8);
        rb.write(0, b"ABCDEF");
        assert_eq!(rb.as_slices().1, rec(0, b"ABCDEF"));
        assert_eq!(rb.pos, 8);

        // New direction doesn't fit at the tail: wrap to 0. The tail of the old
        // record that wasn't overwritten remains in the "older" slice.
        rb.write(1, b"xy");
        assert_eq!(rb.as_slices().1, rec(1, b"xy"));
        // Tail of the old dir=0 record that wasn't overwritten hangs on to its
        // footer: "EF" + footer([6,0]) sits in the "older" slice.
        assert_eq!(rb.as_slices().0, b"EF\x06\x00");
        assert_eq!(rb.pos, 4);
        assert_eq!(rb.as_slices().0.len() + rb.as_slices().1.len(), 8);
    }

    #[test]
    fn wrap_partial_then_recomputes_room() {
        // Same direction fills the buffer exactly, leaving no room for the rest.
        let mut rb = LogBuffer::new(16);
        rb.write(0, b"1111");
        rb.write(0, b"2222");
        assert_eq!(rb.as_slices().1, rec(0, b"11112222"));
        assert_eq!(rb.pos, 10);

        // 8 more bytes: 6 fit by coalescing into the tail, final 2 wrap to 0.
        rb.write(0, b"33334444");
        assert_eq!(rb.as_slices().1, rec(0, b"44"));
        assert_eq!(rb.pos, 4);
        // older + newer always partition the whole buffer.
        assert_eq!(rb.as_slices().0.len() + rb.as_slices().1.len(), 16);
    }

    #[test]
    fn invariants_hold_across_random_writes() {
        use rand::RngExt;
        let mut rng = rand::rng();
        for cap in [FOOTER_SIZE + 1, 16usize, 64, 256] {
            let mut rb = LogBuffer::new(cap);
            for _ in 0..500 {
                let dir = rng.random_range(0..2) as u8;
                let size = rng.random_range(0..cap + 4);
                let data: Vec<u8> = (0..size).map(|_| rng.random_range(0..255) as u8).collect();
                rb.write(dir, &data);
                assert!(rb.pos <= cap);
                assert!(rb.as_slices().0.len() + rb.as_slices().1.len() <= cap);
            }
        }
    }

    #[tokio::test]
    async fn no_needle_always_flushes() {
        let log = TrafficLogger::new(1024, None);
        assert!(log.should_flush());
    }

    #[tokio::test]
    async fn empty_needle_treated_as_no_needle() {
        let log = TrafficLogger::new(1024, Some(""));
        assert!(log.should_flush());
        // Recording still happens as normal.
        log.write(0, b"anything").await;
        assert!(log.should_flush());
    }

    #[tokio::test]
    async fn needle_hit_in_either_direction_triggers_flush() {
        let log = TrafficLogger::new(1024, Some("flag"));
        log.write(0, b"nothing here").await;
        assert!(!log.should_flush());

        // Needle in the server->client stream.
        log.write(1, b"the flag is CTF{here}").await;
        assert!(log.should_flush());

        // Needle in the client->server stream also triggers.
        let client_only = TrafficLogger::new(1024, Some("needle"));
        client_only.write(0, b"find needle in client stream").await;
        assert!(client_only.should_flush());
    }

    #[tokio::test]
    async fn recording_freezes_on_needle_hit() {
        // Snapshot semantics: once the needle is seen, further writes are no-op.
        let log = TrafficLogger::new(1024, Some("boom"));
        log.write(0, b"before boom ").await;
        log.write(0, b"boom").await;
        assert!(log.should_flush());
        log.write(0, b"after").await;

        let data_vec = {
            let guard = log.inner.lock().await;
            let (older, newer) = guard.as_slices();
            // Not wrapped: everything lives in `newer`.
            let src = if older.is_empty() { newer } else { older };
            src.to_vec()
        };
        // "after" must not have been recorded.
        assert!(!data_vec.windows(5).any(|w| w == b"after"));
        // The triggering chunk's bytes up to and including the needle ARE kept.
        assert!(data_vec.windows(4).any(|w| w == b"boom"));
    }

    #[tokio::test]
    async fn needle_hit_in_middle_keeps_prefix_through_needle() {
        // Needle in the middle of a chunk: only the prefix through the needle
        // (inclusive) is recorded, the tail is dropped.
        let log = TrafficLogger::new(1024, Some("boom"));
        log.write(0, b"this is boom then trailing garbage").await;
        assert!(log.should_flush());

        let data_vec = {
            let guard = log.inner.lock().await;
            let (older, newer) = guard.as_slices();
            let src = if older.is_empty() { newer } else { older };
            src.to_vec()
        };
        // Needle retained.
        assert!(data_vec.windows(4).any(|w| w == b"boom"));
        // Nothing after the needle is retained.
        assert!(data_vec.windows(4).all(|w| w != b"garb"));
    }

    #[tokio::test]
    async fn needle_spanning_chunk_boundary_is_caught() {
        let log = TrafficLogger::new(1024, Some("helloworld"));
        // "hello" then "world" in separate writes — the match straddles them.
        log.write(0, b"say hello").await;
        log.write(0, b"world now").await;
        assert!(log.should_flush());
    }
}
