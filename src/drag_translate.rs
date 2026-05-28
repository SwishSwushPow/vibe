use std::{
    ffi::OsStr,
    fs, io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use crate::DirectoryShare;

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";
const PASTE_BUF_LIMIT: usize = 64 * 1024;
const UNTERMINATED_PASTE_TIMEOUT: Duration = Duration::from_secs(2);

// -------------------------------------------------------------------
// DropsStaging
// -------------------------------------------------------------------

pub struct DropsStaging {
    pub host_root: PathBuf,
    pub guest_root: PathBuf,
    counter: AtomicU64,
}

impl DropsStaging {
    pub fn new(host_root: PathBuf, guest_root: PathBuf) -> io::Result<Self> {
        if host_root.exists() {
            fs::remove_dir_all(&host_root)?;
        }
        fs::create_dir_all(&host_root)?;
        Ok(Self {
            host_root,
            guest_root,
            counter: AtomicU64::new(0),
        })
    }

    pub fn stage(&self, host_file: &Path) -> io::Result<PathBuf> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let basename = host_file
            .file_name()
            .ok_or_else(|| io::Error::other("file has no basename"))?;
        let subdir = self.host_root.join(n.to_string());
        fs::create_dir_all(&subdir)?;
        let dest = find_unique_path(&subdir, basename);
        if fs::hard_link(host_file, &dest).is_err() {
            fs::copy(host_file, &dest)?;
        }
        let guest = self.guest_root.join(n.to_string()).join(basename);
        Ok(guest)
    }

    pub(crate) fn as_share(&self) -> DirectoryShare {
        DirectoryShare {
            host: self.host_root.clone(),
            guest: self.guest_root.clone(),
            read_only: false,
        }
    }
}

impl Drop for DropsStaging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.host_root);
    }
}

fn find_unique_path(dir: &Path, basename: &OsStr) -> PathBuf {
    let candidate = dir.join(basename);
    if !candidate.exists() {
        return candidate;
    }
    let name = basename.to_string_lossy();
    for i in 1u64.. {
        let c = dir.join(format!("{name}-{i}"));
        if !c.exists() {
            return c;
        }
    }
    unreachable!()
}

// -------------------------------------------------------------------
// Share mapping (canonicalized host prefix → guest prefix)
// -------------------------------------------------------------------

struct ShareMapping {
    canon_host: PathBuf,
    guest: PathBuf,
}

// -------------------------------------------------------------------
// DragTranslator — bracketed-paste state machine
// -------------------------------------------------------------------

enum PasteState {
    Pass,
    /// Partially matched PASTE_START; `idx` bytes matched so far.
    MatchingStart {
        idx: usize,
    },
    /// Fully inside a bracketed paste. `overflow` means we hit the size limit and are
    /// emitting bytes directly to `out` rather than buffering for translation.
    InPaste {
        buf: Vec<u8>,
        last_byte: Instant,
        overflow: bool,
    },
    /// Inside a paste, partially matched PASTE_END; `idx` bytes of PASTE_END matched.
    MatchingEnd {
        buf: Vec<u8>,
        last_byte: Instant,
        overflow: bool,
        idx: usize,
    },
}

pub struct DragTranslator {
    shares: Vec<ShareMapping>,
    drops: Option<DropsStaging>,
    state: PasteState,
    enabled: bool,
}

impl DragTranslator {
    pub(crate) fn new(
        shares: &[DirectoryShare],
        drops: Option<DropsStaging>,
        enabled: bool,
    ) -> Self {
        let mut mappings: Vec<ShareMapping> = shares
            .iter()
            .filter_map(|s| {
                s.host.canonicalize().ok().map(|canon_host| ShareMapping {
                    canon_host,
                    guest: s.guest.clone(),
                })
            })
            .collect();
        // longest host prefix first for correct greedy prefix matching
        mappings.sort_by(|a, b| {
            b.canon_host
                .as_os_str()
                .len()
                .cmp(&a.canon_host.as_os_str().len())
        });
        Self {
            shares: mappings,
            drops,
            state: PasteState::Pass,
            enabled,
        }
    }

    /// Feed raw stdin bytes; returns bytes to forward to the VM.
    /// Call with `&[]` periodically to allow unterminated-paste timeout flush.
    pub fn process(&mut self, input: &[u8]) -> Vec<u8> {
        if !self.enabled {
            return input.to_vec();
        }
        let mut out = Vec::with_capacity(input.len());
        if input.is_empty() {
            self.check_paste_timeout(&mut out);
        } else {
            for &b in input {
                self.process_byte(b, &mut out);
            }
        }
        out
    }

    /// Reset in-flight paste state (called when still in pre-boot discard phase).
    pub fn reset(&mut self) {
        self.state = PasteState::Pass;
    }

    /// Process one byte. Uses take-and-replace so we never hold borrows into
    /// `self.state` when reassigning it.
    fn process_byte(&mut self, b: u8, out: &mut Vec<u8>) {
        let old = std::mem::replace(&mut self.state, PasteState::Pass);
        self.state = match old {
            PasteState::Pass => {
                if b == PASTE_START[0] {
                    PasteState::MatchingStart { idx: 1 }
                } else {
                    out.push(b);
                    PasteState::Pass
                }
            }

            PasteState::MatchingStart { idx } => {
                if b == PASTE_START[idx] {
                    let next_idx = idx + 1;
                    if next_idx == PASTE_START.len() {
                        // Fully matched — consume the start marker, enter paste.
                        PasteState::InPaste {
                            buf: Vec::new(),
                            last_byte: Instant::now(),
                            overflow: false,
                        }
                    } else {
                        PasteState::MatchingStart { idx: next_idx }
                    }
                } else {
                    // Mismatch: emit the bytes we held back (PASTE_START[0..idx]),
                    // then replay the current byte from Pass.
                    out.extend_from_slice(&PASTE_START[..idx]);
                    // Replay b as if we're in Pass state.
                    if b == PASTE_START[0] {
                        PasteState::MatchingStart { idx: 1 }
                    } else {
                        out.push(b);
                        PasteState::Pass
                    }
                }
            }

            PasteState::InPaste {
                mut buf, overflow, ..
            } => {
                if b == PASTE_END[0] {
                    // Possible start of end marker.
                    PasteState::MatchingEnd {
                        buf,
                        last_byte: Instant::now(),
                        overflow,
                        idx: 1,
                    }
                } else if overflow {
                    out.push(b);
                    PasteState::InPaste {
                        buf,
                        last_byte: Instant::now(),
                        overflow: true,
                    }
                } else if buf.len() >= PASTE_BUF_LIMIT {
                    // Transition to overflow: emit start marker + buffered content + this byte.
                    out.extend_from_slice(PASTE_START);
                    out.extend_from_slice(&buf);
                    out.push(b);
                    PasteState::InPaste {
                        buf: Vec::new(),
                        last_byte: Instant::now(),
                        overflow: true,
                    }
                } else {
                    buf.push(b);
                    PasteState::InPaste {
                        buf,
                        last_byte: Instant::now(),
                        overflow: false,
                    }
                }
            }

            PasteState::MatchingEnd {
                mut buf,
                overflow,
                idx,
                ..
            } => {
                if b == PASTE_END[idx] {
                    let next_idx = idx + 1;
                    if next_idx == PASTE_END.len() {
                        // Fully matched PASTE_END — translate the paste.
                        if overflow {
                            out.extend_from_slice(PASTE_END);
                        } else {
                            let translated = self.translate_paste(&buf);
                            out.extend_from_slice(PASTE_START);
                            out.extend_from_slice(&translated);
                            out.extend_from_slice(PASTE_END);
                        }
                        PasteState::Pass
                    } else {
                        PasteState::MatchingEnd {
                            buf,
                            last_byte: Instant::now(),
                            overflow,
                            idx: next_idx,
                        }
                    }
                } else {
                    // Not the end marker. The ESC-like bytes we matched (PASTE_END[0..idx])
                    // are literal paste content. Put them back in buf (or out if overflowing),
                    // then replay b.
                    let partial = &PASTE_END[..idx];
                    if overflow {
                        out.extend_from_slice(partial);
                        // Replay b in overflow mode.
                        if b == PASTE_END[0] {
                            PasteState::MatchingEnd {
                                buf,
                                last_byte: Instant::now(),
                                overflow: true,
                                idx: 1,
                            }
                        } else {
                            out.push(b);
                            PasteState::InPaste {
                                buf,
                                last_byte: Instant::now(),
                                overflow: true,
                            }
                        }
                    } else if buf.len() + partial.len() + 1 > PASTE_BUF_LIMIT {
                        // Adding partial + b would overflow — switch to overflow mode.
                        out.extend_from_slice(PASTE_START);
                        out.extend_from_slice(&buf);
                        out.extend_from_slice(partial);
                        if b == PASTE_END[0] {
                            PasteState::MatchingEnd {
                                buf: Vec::new(),
                                last_byte: Instant::now(),
                                overflow: true,
                                idx: 1,
                            }
                        } else {
                            out.push(b);
                            PasteState::InPaste {
                                buf: Vec::new(),
                                last_byte: Instant::now(),
                                overflow: true,
                            }
                        }
                    } else {
                        buf.extend_from_slice(partial);
                        if b == PASTE_END[0] {
                            // b starts a new potential match of PASTE_END.
                            PasteState::MatchingEnd {
                                buf,
                                last_byte: Instant::now(),
                                overflow: false,
                                idx: 1,
                            }
                        } else {
                            buf.push(b);
                            PasteState::InPaste {
                                buf,
                                last_byte: Instant::now(),
                                overflow: false,
                            }
                        }
                    }
                }
            }
        };
    }

    fn check_paste_timeout(&mut self, out: &mut Vec<u8>) {
        let timed_out = match &self.state {
            PasteState::InPaste { last_byte, .. } | PasteState::MatchingEnd { last_byte, .. } => {
                last_byte.elapsed() >= UNTERMINATED_PASTE_TIMEOUT
            }
            _ => false,
        };
        if !timed_out {
            return;
        }
        let old = std::mem::replace(&mut self.state, PasteState::Pass);
        match old {
            PasteState::InPaste { buf, overflow, .. } if !overflow => {
                // Emit start marker + buffered content without a closing marker.
                out.extend_from_slice(PASTE_START);
                out.extend_from_slice(&buf);
            }
            PasteState::MatchingEnd {
                buf, overflow, idx, ..
            } => {
                if !overflow {
                    out.extend_from_slice(PASTE_START);
                    out.extend_from_slice(&buf);
                    out.extend_from_slice(&PASTE_END[..idx]);
                } else {
                    // Partial end-marker bytes were held back; emit them now.
                    out.extend_from_slice(&PASTE_END[..idx]);
                }
            }
            _ => {}
        }
    }

    fn translate_paste(&mut self, raw: &[u8]) -> Vec<u8> {
        let (tokens, sep) = tokenize(raw);
        let mut out_tokens: Vec<Vec<u8>> = Vec::with_capacity(tokens.len());
        for token in tokens {
            out_tokens.push(self.translate_token(token));
        }
        out_tokens.join(sep.as_slice())
    }

    fn translate_token(&mut self, token: Vec<u8>) -> Vec<u8> {
        // Only process absolute paths.
        if !token.starts_with(b"/") {
            return token;
        }
        // Reject tokens containing newlines (guards against shell snippets).
        if memchr(b'\n', &token).is_some() {
            return token;
        }
        let host_path = PathBuf::from(OsStr::from_bytes(&token));
        // Check existence via symlink_metadata (does not follow dangling symlinks).
        if host_path.symlink_metadata().is_err() {
            return token;
        }
        // Canonicalize for share-prefix matching (resolves symlinks and . ..).
        let canon = host_path
            .canonicalize()
            .unwrap_or_else(|_| host_path.clone());

        // Try longest-prefix share match.
        for mapping in &self.shares {
            if let Ok(suffix) = canon.strip_prefix(&mapping.canon_host) {
                let guest = mapping.guest.join(suffix);
                return guest.as_os_str().as_bytes().to_vec();
            }
        }

        // Not under any share — auto-stage if it's a regular file.
        if let Ok(meta) = host_path.metadata()
            && meta.is_file()
            && let Some(drops) = &self.drops
            && let Ok(guest_path) = drops.stage(&host_path)
        {
            return guest_path.as_os_str().as_bytes().to_vec();
        }

        // Directory outside a share, or staging failed: pass through unchanged.
        token
    }
}

// -------------------------------------------------------------------
// Tokenizer
// -------------------------------------------------------------------
// Handles the three forms macOS terminals produce for Finder drags:
//   1. Backslash-escaped  (Terminal.app / iTerm2 default): /foo/My\ File.txt
//   2. Single-quoted with '\'' for apostrophes (iTerm2 "Quote drag-and-drop")
//   3. Plain / double-quoted (fall-through)

/// Returns (tokens, separator_byte).
fn tokenize(raw: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let trimmed = trim_bytes(raw);
    if trimmed.is_empty() {
        return (vec![trimmed.to_vec()], b" ".to_vec());
    }

    // Single-quoted whole string (including single-token with spaces).
    if trimmed.starts_with(b"'") && trimmed.ends_with(b"'") && trimmed.len() >= 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        let unquoted = unescape_single_quoted(inner);
        if !unquoted.contains(&b'\n') {
            return (vec![unquoted], b" ".to_vec());
        }
    }

    // Double-quoted whole string.
    if trimmed.starts_with(b"\"") && trimmed.ends_with(b"\"") && trimmed.len() >= 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        let unquoted = unescape_double_quoted(inner);
        if !unquoted.contains(&b'\n') {
            return (vec![unquoted], b" ".to_vec());
        }
    }

    // Multi-token / backslash-escaped: split on unescaped whitespace.
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    let mut sep: u8 = b' ';
    let mut cur: Vec<u8> = Vec::new();
    let mut in_token = false;
    let mut i = 0;
    while i < trimmed.len() {
        let b = trimmed[i];
        if b == b'\\' && i + 1 < trimmed.len() {
            in_token = true;
            cur.push(trimmed[i + 1]);
            i += 2;
        } else if b == b' ' || b == b'\t' {
            if in_token {
                tokens.push(cur.clone());
                cur.clear();
                in_token = false;
            }
            sep = b;
            i += 1;
        } else {
            in_token = true;
            cur.push(b);
            i += 1;
        }
    }
    if in_token || !cur.is_empty() {
        tokens.push(cur);
    }

    (tokens, vec![sep])
}

fn unescape_single_quoted(inner: &[u8]) -> Vec<u8> {
    // In single-quoted strings, a literal apostrophe is encoded as: end quote + \' + start quote
    // i.e. the sequence `'\''` where inner already has the outer quotes stripped → `'\\''`
    let mut out = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i..].starts_with(b"'\\''") {
            out.push(b'\'');
            i += 4;
        } else {
            out.push(inner[i]);
            i += 1;
        }
    }
    out
}

fn unescape_double_quoted(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == b'\\' && i + 1 < inner.len() {
            out.push(inner[i + 1]);
            i += 2;
        } else {
            out.push(inner[i]);
            i += 1;
        }
    }
    out
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|&c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|&c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    if start >= end {
        &b[..0]
    } else {
        &b[start..end]
    }
}

// Minimal memchr (avoids adding a dependency).
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

// -------------------------------------------------------------------
// Unit tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn translator_no_shares() -> DragTranslator {
        DragTranslator::new(&[], None, true)
    }

    fn paste(body: &[u8]) -> Vec<u8> {
        let mut v = PASTE_START.to_vec();
        v.extend_from_slice(body);
        v.extend_from_slice(PASTE_END);
        v
    }

    fn process_all(t: &mut DragTranslator, input: &[u8]) -> Vec<u8> {
        t.process(input)
    }

    #[test]
    fn non_paste_passthrough() {
        let mut t = translator_no_shares();
        let input = b"hello world";
        assert_eq!(t.process(input), input);
    }

    #[test]
    fn paste_no_paths_unchanged() {
        let mut t = translator_no_shares();
        let input = paste(b"hello");
        let out = process_all(&mut t, &input);
        assert_eq!(out, input);
    }

    #[test]
    fn paste_fake_path_unchanged() {
        let mut t = translator_no_shares();
        let body = b"/this/path/does/not/exist/at/all/hopefully";
        let input = paste(body);
        let out = process_all(&mut t, &input);
        // path doesn't exist, so token passes through
        assert!(out.windows(body.len()).any(|w| w == body));
    }

    #[test]
    fn split_read_assembles_correctly() {
        let mut t = translator_no_shares();
        let full = paste(b"hello");
        // Feed byte by byte to stress split-read handling
        let mut out = Vec::new();
        for &b in &full {
            out.extend(t.process(&[b]));
        }
        assert_eq!(out, full);
    }

    #[test]
    fn esc_outside_paste_passthrough() {
        let mut t = translator_no_shares();
        // An ESC not followed by [200~ should be emitted as-is
        let input = b"\x1b[A"; // cursor up
        let out = t.process(input);
        assert_eq!(out, input);
    }

    #[test]
    fn partial_paste_start_mismatch_emitted() {
        let mut t = translator_no_shares();
        // \x1b[ followed by something that is NOT 2 (200~ continues with '2')
        let input = b"\x1b[Bhi";
        let out = t.process(input);
        // Should emit the ESC, [, B, h, i
        assert_eq!(out, b"\x1b[Bhi");
    }

    #[test]
    fn oversize_paste_passthrough() {
        let mut t = translator_no_shares();
        let body = vec![b'x'; PASTE_BUF_LIMIT + 100];
        let input = paste(&body);
        let out = process_all(&mut t, &input);
        // Content should pass through (may not have exact markers but data intact)
        assert!(out.windows(10).any(|w| w == &body[..10]));
    }

    #[test]
    fn tokenize_backslash_escaped() {
        let input = b"/Users/dev/My\\ Folder/img.png";
        let (tokens, _) = tokenize(input);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], b"/Users/dev/My Folder/img.png");
    }

    #[test]
    fn tokenize_single_quoted() {
        let input = b"'/Users/dev/My Folder/img.png'";
        let (tokens, _) = tokenize(input);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], b"/Users/dev/My Folder/img.png");
    }

    #[test]
    fn tokenize_single_quoted_apostrophe() {
        // iTerm2 encodes "it's a file.txt" as '/Users/dev/it'\''s a file.txt'
        // After stripping outer quotes: /Users/dev/it'\''s a file.txt
        let input = b"'/Users/dev/it'\\''s a file.txt'";
        let (tokens, _) = tokenize(input);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], b"/Users/dev/it's a file.txt");
    }

    #[test]
    fn tokenize_multi_token() {
        let input = b"/foo/bar /baz/qux";
        let (tokens, _) = tokenize(input);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0], b"/foo/bar");
        assert_eq!(tokens[1], b"/baz/qux");
    }

    #[test]
    fn tokenize_multi_backslash() {
        let input = b"/foo/bar\\ one /baz/qux\\ two";
        let (tokens, _) = tokenize(input);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0], b"/foo/bar one");
        assert_eq!(tokens[1], b"/baz/qux two");
    }

    #[test]
    fn share_prefix_rewrite() {
        // /tmp is a real dir we can canonicalize
        let share = DirectoryShare {
            host: PathBuf::from("/tmp"),
            guest: PathBuf::from("/root/tmp"),
            read_only: false,
        };
        let mut t = DragTranslator::new(&[share], None, true);

        // Create a real temp file under /tmp
        let tmp = PathBuf::from(format!("/tmp/vibe_test_{}", std::process::id()));
        std::fs::write(&tmp, b"hi").unwrap();
        let raw_path = tmp.as_os_str().as_bytes().to_vec();
        let wrapped = paste(&raw_path);
        let out = t.process(&wrapped);
        let _ = std::fs::remove_file(&tmp);

        let expected_prefix = b"/root/tmp/";
        assert!(
            out.windows(expected_prefix.len())
                .any(|w| w == expected_prefix),
            "expected /root/tmp/ prefix in output: {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn disabled_passthrough() {
        let mut t = DragTranslator::new(&[], None, false);
        let host_path = b"/some/host/path";
        let input = paste(host_path);
        let out = t.process(&input);
        assert_eq!(out, input);
    }

    #[test]
    fn text_after_paste_passthrough() {
        let mut t = translator_no_shares();
        let mut input = paste(b"hello");
        input.extend_from_slice(b" world");
        let out = process_all(&mut t, &input);
        let expected = {
            let mut e = paste(b"hello");
            e.extend_from_slice(b" world");
            e
        };
        assert_eq!(out, expected);
    }

    #[test]
    fn multiple_pastes_in_sequence() {
        let mut t = translator_no_shares();
        let mut input = paste(b"one");
        input.extend_from_slice(&paste(b"two"));
        let out = process_all(&mut t, &input);
        assert!(out.windows(3).any(|w| w == b"one"));
        assert!(out.windows(3).any(|w| w == b"two"));
    }
}
