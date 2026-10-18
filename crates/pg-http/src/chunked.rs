//! Incremental chunked transfer-coding decoder (RFC 9112 §7.1).
//!
//! Strict: hex sizes only (<= 16 digits, bounded to `max_chunk`), chunk
//! extensions are rejected, trailers are rejected (a lone CRLF must follow the
//! zero chunk). Zero allocation.

use crate::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError {
    BadSize,
    BadFraming,
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Reading hex digits of chunk-size; `digits` seen so far.
    Size { value: u64, digits: u8 },
    /// Saw CR after size, expecting LF.
    SizeLf { value: u64 },
    /// In chunk data, `remaining` bytes left.
    Data { remaining: u64 },
    /// Expect CR after data.
    DataCr,
    DataLf,
    /// Last chunk (size 0) seen: expect CR then LF (no trailers).
    FinalCr,
    FinalLf,
    Done,
}

/// Result of feeding some input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advance {
    /// Input bytes consumed (framing + payload).
    pub consumed: usize,
    /// Payload bytes found in the consumed input, if any (contiguous span
    /// relative to the input slice). At most one span per call.
    pub data: Option<Span>,
    pub done: bool,
}

#[derive(Clone, Debug)]
pub struct ChunkDecoder {
    state: State,
    max_total: u64,
    total: u64,
}

impl ChunkDecoder {
    /// `max_total` bounds the sum of all chunk payloads.
    pub fn new(max_total: u64) -> Self {
        ChunkDecoder { state: State::Size { value: 0, digits: 0 }, max_total, total: 0 }
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Total payload bytes seen so far.
    pub fn payload_total(&self) -> u64 {
        self.total
    }

    /// Consume as much of `input` as possible, stopping after the first
    /// payload span (so callers can forward it) or at the end of the message.
    pub fn advance(&mut self, input: &[u8]) -> Result<Advance, ChunkError> {
        let mut i = 0usize;
        while i < input.len() {
            match self.state {
                State::Size { value, digits } => {
                    let b = input[i];
                    match b {
                        b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                            if digits >= 16 {
                                return Err(ChunkError::BadSize);
                            }
                            let d = (b as char).to_digit(16).unwrap() as u64;
                            let nv = value.checked_mul(16).ok_or(ChunkError::BadSize)? | d;
                            self.state = State::Size { value: nv, digits: digits + 1 };
                            i += 1;
                        }
                        b'\r' if digits > 0 => {
                            self.state = State::SizeLf { value };
                            i += 1;
                        }
                        // ';' extensions, whitespace, anything else
                        _ => return Err(ChunkError::BadSize),
                    }
                }
                State::SizeLf { value } => {
                    if input[i] != b'\n' {
                        return Err(ChunkError::BadFraming);
                    }
                    i += 1;
                    if value == 0 {
                        self.state = State::FinalCr;
                    } else {
                        self.total = self.total.checked_add(value).ok_or(ChunkError::TooLarge)?;
                        if self.total > self.max_total {
                            return Err(ChunkError::TooLarge);
                        }
                        self.state = State::Data { remaining: value };
                    }
                }
                State::Data { remaining } => {
                    let avail = (input.len() - i) as u64;
                    let take = remaining.min(avail) as usize;
                    let span = Span { start: i, end: i + take };
                    i += take;
                    let left = remaining - take as u64;
                    self.state = if left == 0 { State::DataCr } else { State::Data { remaining: left } };
                    return Ok(Advance { consumed: i, data: Some(span), done: false });
                }
                State::DataCr => {
                    if input[i] != b'\r' {
                        return Err(ChunkError::BadFraming);
                    }
                    i += 1;
                    self.state = State::DataLf;
                }
                State::DataLf => {
                    if input[i] != b'\n' {
                        return Err(ChunkError::BadFraming);
                    }
                    i += 1;
                    self.state = State::Size { value: 0, digits: 0 };
                }
                State::FinalCr => {
                    if input[i] != b'\r' {
                        return Err(ChunkError::BadFraming); // trailers refused
                    }
                    i += 1;
                    self.state = State::FinalLf;
                }
                State::FinalLf => {
                    if input[i] != b'\n' {
                        return Err(ChunkError::BadFraming);
                    }
                    i += 1;
                    self.state = State::Done;
                    return Ok(Advance { consumed: i, data: None, done: true });
                }
                State::Done => break,
            }
        }
        Ok(Advance { consumed: i, data: None, done: self.state == State::Done })
    }
}
