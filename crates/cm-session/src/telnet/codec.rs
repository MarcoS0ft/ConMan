//! Stateful TELNET framing, option negotiation, and NVT byte conversion.
//!
//! The socket driver owns one [`TelnetCodec`] for the lifetime of a connection.
//! Calls to [`TelnetCodec::receive`] may end at any byte boundary; parser and NVT
//! state intentionally survive between calls. Application bytes and socket bytes
//! remain byte-oriented throughout—this module never guesses a character encoding.

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPTION_BINARY: u8 = 0;
const OPTION_ECHO: u8 = 1;
const OPTION_SUPPRESS_GO_AHEAD: u8 = 3;
const OPTION_TERMINAL_TYPE: u8 = 24;
const OPTION_NAWS: u8 = 31;

const TERMINAL_TYPE_IS: u8 = 0;
const TERMINAL_TYPE_SEND: u8 = 1;
const TERMINAL_TYPE: &[u8] = b"xterm-256color";

/// Maximum accepted subnegotiation payload, excluding its option byte.
pub(crate) const MAX_SUBNEGOTIATION_BYTES: usize = 64 * 1024;

/// A TELNET protocol violation that requires closing the session.
///
/// Errors contain protocol metadata only and never include terminal payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CodecError {
    /// A peer exceeded the fixed subnegotiation storage limit.
    #[error("TELNET subnegotiation for option {option} exceeds {limit} bytes")]
    SubnegotiationTooLarge { option: u8, limit: usize },
    /// An `IAC` command other than `IAC` or `SE` appeared inside a completed
    /// subnegotiation frame.
    #[error("invalid TELNET subnegotiation command {command} for option {option}")]
    InvalidSubnegotiationCommand { option: u8, command: u8 },
}

/// Results produced while consuming socket bytes.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CodecOutput {
    /// Bytes belonging to the remote terminal application, after TELNET/NVT
    /// decoding. The driver forwards only these bytes to the VT engine.
    pub(crate) application_data: Vec<u8>,
    /// Negotiation replies and subnegotiations to write back to the socket.
    pub(crate) socket_bytes: Vec<u8>,
    /// Raised once per codec lifetime when the peer explicitly refuses or
    /// withdraws remote ECHO.
    pub(crate) warn_remote_echo_unavailable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseState {
    Data,
    Iac,
    Negotiate { command: u8 },
    SubnegotiationOption,
    Subnegotiation { option: u8, bytes: Vec<u8> },
    SubnegotiationIac { option: u8, bytes: Vec<u8> },
    DiscardOversizedSubnegotiation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Queue {
    Empty,
    Opposite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QState {
    No,
    Yes,
    WantNo(Queue),
    WantYes(Queue),
}

impl QState {
    fn enabled(self) -> bool {
        self == Self::Yes
    }
}

#[derive(Debug, Clone, Copy)]
struct OptionState {
    state: QState,
    // RFC 1143 leaves a rejected option in NO, which otherwise causes one
    // negative reply per repeated invalid offer. Remember the rejection until
    // the peer acknowledges it so a broken peer cannot create a reply loop.
    rejection_sent: bool,
}

impl Default for OptionState {
    fn default() -> Self {
        Self {
            state: QState::No,
            rejection_sent: false,
        }
    }
}

#[derive(Debug, Clone)]
struct DirectionNegotiator {
    options: [OptionState; 256],
}

impl Default for DirectionNegotiator {
    fn default() -> Self {
        Self {
            options: [OptionState::default(); 256],
        }
    }
}

impl DirectionNegotiator {
    fn enabled(&self, option: u8) -> bool {
        self.options[usize::from(option)].state.enabled()
    }

    fn request_enable(&mut self, option: u8, positive_command: u8, out: &mut Vec<u8>) {
        let entry = &mut self.options[usize::from(option)];
        entry.state = match entry.state {
            QState::No => {
                push_negotiation(out, positive_command, option);
                QState::WantYes(Queue::Empty)
            }
            QState::Yes | QState::WantNo(Queue::Opposite) | QState::WantYes(Queue::Empty) => {
                entry.state
            }
            QState::WantNo(Queue::Empty) => QState::WantNo(Queue::Opposite),
            QState::WantYes(Queue::Opposite) => QState::WantYes(Queue::Empty),
        };
    }

    fn request_disable(&mut self, option: u8, negative_command: u8, out: &mut Vec<u8>) {
        let entry = &mut self.options[usize::from(option)];
        entry.state = match entry.state {
            QState::No | QState::WantNo(Queue::Empty) | QState::WantYes(Queue::Opposite) => {
                entry.state
            }
            QState::Yes => {
                push_negotiation(out, negative_command, option);
                QState::WantNo(Queue::Empty)
            }
            QState::WantNo(Queue::Opposite) => QState::WantNo(Queue::Empty),
            QState::WantYes(Queue::Empty) => QState::WantYes(Queue::Opposite),
        };
    }

    /// Process the peer's positive command (`DO` for us, `WILL` for him).
    fn receive_positive(
        &mut self,
        option: u8,
        supported: bool,
        positive_reply: u8,
        negative_reply: u8,
        out: &mut Vec<u8>,
    ) {
        let entry = &mut self.options[usize::from(option)];
        let queued_disable = entry.state == QState::WantYes(Queue::Opposite);
        entry.state = match entry.state {
            QState::No if supported => {
                entry.rejection_sent = false;
                push_negotiation(out, positive_reply, option);
                QState::Yes
            }
            QState::No => {
                if !entry.rejection_sent {
                    push_negotiation(out, negative_reply, option);
                    entry.rejection_sent = true;
                }
                QState::No
            }
            QState::Yes => QState::Yes,
            QState::WantNo(Queue::Empty) => QState::No,
            QState::WantNo(Queue::Opposite) => QState::Yes,
            QState::WantYes(Queue::Empty) => {
                entry.rejection_sent = false;
                QState::Yes
            }
            // RFC 1143: finish the enable negotiation, then immediately act
            // on the one queued opposite request below.
            QState::WantYes(Queue::Opposite) => QState::Yes,
        };
        if queued_disable {
            self.request_disable(option, negative_reply, out);
        }
    }

    /// Process the peer's negative command (`DONT` for us, `WONT` for him).
    fn receive_negative(
        &mut self,
        option: u8,
        positive_reply: u8,
        negative_reply: u8,
        out: &mut Vec<u8>,
    ) {
        let entry = &mut self.options[usize::from(option)];
        entry.rejection_sent = false;
        entry.state = match entry.state {
            QState::No => QState::No,
            QState::Yes => {
                push_negotiation(out, negative_reply, option);
                QState::No
            }
            QState::WantNo(Queue::Empty) => QState::No,
            QState::WantNo(Queue::Opposite) => {
                push_negotiation(out, positive_reply, option);
                QState::WantYes(Queue::Empty)
            }
            QState::WantYes(Queue::Empty) | QState::WantYes(Queue::Opposite) => QState::No,
        };
    }
}

/// Stateful TELNET codec owned exclusively by the socket driver.
#[derive(Debug, Clone)]
pub(crate) struct TelnetCodec {
    parser: ParseState,
    local: DirectionNegotiator,
    remote: DirectionNegotiator,
    outbound_pending_cr: bool,
    inbound_pending_cr: bool,
    cols: u16,
    rows: u16,
    echo_warning_emitted: bool,
}

impl TelnetCodec {
    /// Construct a codec with the current terminal cell dimensions.
    pub(crate) fn new(cols: u16, rows: u16) -> Self {
        Self {
            parser: ParseState::Data,
            local: DirectionNegotiator::default(),
            remote: DirectionNegotiator::default(),
            outbound_pending_cr: false,
            inbound_pending_cr: false,
            cols,
            rows,
            echo_warning_emitted: false,
        }
    }

    /// Offer/request the P10.1 option set. Repeated calls are idempotent.
    #[must_use]
    pub(crate) fn start_negotiation(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(21);
        for option in [
            OPTION_BINARY,
            OPTION_SUPPRESS_GO_AHEAD,
            OPTION_TERMINAL_TYPE,
            OPTION_NAWS,
        ] {
            self.local.request_enable(option, WILL, &mut out);
        }
        for option in [OPTION_BINARY, OPTION_ECHO, OPTION_SUPPRESS_GO_AHEAD] {
            self.remote.request_enable(option, DO, &mut out);
        }
        out
    }

    /// Consume bytes read from the socket.
    ///
    /// Parser state survives calls, including after `IAC`, after a negotiation
    /// command, and anywhere inside a subnegotiation.
    pub(crate) fn receive(&mut self, input: &[u8]) -> Result<CodecOutput, CodecError> {
        let mut output = CodecOutput::default();

        for &byte in input {
            let state = std::mem::replace(&mut self.parser, ParseState::Data);
            self.parser = match state {
                ParseState::Data if byte == IAC => ParseState::Iac,
                ParseState::Data => {
                    self.push_inbound_application(byte, &mut output.application_data);
                    ParseState::Data
                }
                ParseState::Iac => match byte {
                    IAC => {
                        self.push_inbound_application(IAC, &mut output.application_data);
                        ParseState::Data
                    }
                    WILL | WONT | DO | DONT => ParseState::Negotiate { command: byte },
                    SB => ParseState::SubnegotiationOption,
                    _ => ParseState::Data,
                },
                ParseState::Negotiate { command } => {
                    self.handle_negotiation(command, byte, &mut output);
                    ParseState::Data
                }
                ParseState::SubnegotiationOption => ParseState::Subnegotiation {
                    option: byte,
                    bytes: Vec::new(),
                },
                ParseState::Subnegotiation { option, bytes } if byte == IAC => {
                    ParseState::SubnegotiationIac { option, bytes }
                }
                ParseState::Subnegotiation { option, mut bytes } => {
                    if let Err(error) = push_subnegotiation_byte(option, &mut bytes, byte) {
                        self.parser = ParseState::DiscardOversizedSubnegotiation;
                        return Err(error);
                    }
                    ParseState::Subnegotiation { option, bytes }
                }
                ParseState::SubnegotiationIac { option, mut bytes } if byte == IAC => {
                    if let Err(error) = push_subnegotiation_byte(option, &mut bytes, IAC) {
                        self.parser = ParseState::DiscardOversizedSubnegotiation;
                        return Err(error);
                    }
                    ParseState::Subnegotiation { option, bytes }
                }
                ParseState::SubnegotiationIac { option, bytes } if byte == SE => {
                    self.handle_subnegotiation(option, &bytes, &mut output.socket_bytes);
                    ParseState::Data
                }
                ParseState::SubnegotiationIac { option, .. } => {
                    return Err(CodecError::InvalidSubnegotiationCommand {
                        option,
                        command: byte,
                    });
                }
                ParseState::DiscardOversizedSubnegotiation => {
                    ParseState::DiscardOversizedSubnegotiation
                }
            };
        }

        Ok(output)
    }

    /// Encode application bytes for the socket, applying outbound NVT mapping
    /// until local BINARY is enabled and always escaping `IAC`.
    ///
    /// In NVT mode, a trailing CR is held so a following call beginning with LF
    /// can form `CR LF`. Call [`Self::flush_outbound`] at a semantic input-record
    /// boundary when the CR is known to be literal (for example after handling a
    /// complete key event).
    #[must_use]
    pub(crate) fn encode_application(&mut self, input: &[u8]) -> Vec<u8> {
        let mut nvt = Vec::with_capacity(input.len().saturating_mul(2));

        if self.local.enabled(OPTION_BINARY) {
            if self.outbound_pending_cr {
                nvt.extend_from_slice(b"\r\0");
                self.outbound_pending_cr = false;
            }
            nvt.extend_from_slice(input);
        } else {
            for &byte in input {
                if self.outbound_pending_cr {
                    if byte == b'\n' {
                        nvt.extend_from_slice(b"\r\n");
                        self.outbound_pending_cr = false;
                        continue;
                    }
                    nvt.extend_from_slice(b"\r\0");
                    self.outbound_pending_cr = false;
                }

                match byte {
                    b'\r' => self.outbound_pending_cr = true,
                    b'\n' => nvt.extend_from_slice(b"\r\n"),
                    _ => nvt.push(byte),
                }
            }
        }

        escape_iac(&nvt)
    }

    /// Encode an Enter/newline intent without conflating it with a literal CR.
    ///
    /// The engine-owner must call this only when it still has the semantic key
    /// context. Once an encoded lone CR reaches generic [`Self::encode_application`],
    /// Enter and Ctrl+M are indistinguishable. In NVT mode this emits `CR LF`;
    /// in local BINARY mode it emits the engine's raw CR. A preceding pending
    /// literal CR is resolved first as `CR NUL`.
    #[must_use]
    pub(crate) fn encode_newline(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        if self.outbound_pending_cr {
            out.extend_from_slice(b"\r\0");
            self.outbound_pending_cr = false;
        }
        if self.local.enabled(OPTION_BINARY) {
            out.push(b'\r');
        } else {
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    /// Flush a trailing literal CR held by outbound NVT conversion.
    #[must_use]
    pub(crate) fn flush_outbound(&mut self) -> Vec<u8> {
        if self.outbound_pending_cr {
            self.outbound_pending_cr = false;
            vec![b'\r', 0]
        } else {
            Vec::new()
        }
    }

    /// Update the current cell dimensions and return a NAWS frame only when the
    /// peer has enabled local NAWS.
    #[must_use]
    pub(crate) fn resize(&mut self, cols: u16, rows: u16) -> Vec<u8> {
        self.cols = cols;
        self.rows = rows;
        if self.local.enabled(OPTION_NAWS) {
            encode_naws(cols, rows)
        } else {
            Vec::new()
        }
    }

    /// Finish inbound decoding at socket EOF.
    ///
    /// Incomplete TELNET commands/subnegotiations are discarded. A pending NVT
    /// CR is application data and is therefore emitted before disconnect.
    #[must_use]
    pub(crate) fn finish(&mut self) -> CodecOutput {
        self.parser = ParseState::Data;
        let mut output = CodecOutput::default();
        if self.inbound_pending_cr {
            output.application_data.push(b'\r');
            self.inbound_pending_cr = false;
        }
        output
    }

    fn handle_negotiation(&mut self, command: u8, option: u8, output: &mut CodecOutput) {
        match command {
            DO => {
                let was_binary = self.local.enabled(OPTION_BINARY);
                let was_naws = self.local.enabled(OPTION_NAWS);
                let reply_start = output.socket_bytes.len();
                self.local.receive_positive(
                    option,
                    supports_local(option),
                    WILL,
                    WONT,
                    &mut output.socket_bytes,
                );
                if option == OPTION_BINARY
                    && !was_binary
                    && self.local.enabled(OPTION_BINARY)
                    && self.outbound_pending_cr
                {
                    // This CR belongs to application data accepted before the
                    // peer's DO BINARY. Preserve socket ordering by emitting it
                    // before the negotiation response just appended above.
                    output
                        .socket_bytes
                        .splice(reply_start..reply_start, [b'\r', 0]);
                    self.outbound_pending_cr = false;
                }
                if option == OPTION_NAWS && !was_naws && self.local.enabled(OPTION_NAWS) {
                    output
                        .socket_bytes
                        .extend_from_slice(&encode_naws(self.cols, self.rows));
                }
            }
            DONT => {
                self.local
                    .receive_negative(option, WILL, WONT, &mut output.socket_bytes);
            }
            WILL => {
                let was_binary = self.remote.enabled(OPTION_BINARY);
                self.remote.receive_positive(
                    option,
                    supports_remote(option),
                    DO,
                    DONT,
                    &mut output.socket_bytes,
                );
                if option == OPTION_BINARY
                    && !was_binary
                    && self.remote.enabled(OPTION_BINARY)
                    && self.inbound_pending_cr
                {
                    output.application_data.push(b'\r');
                    self.inbound_pending_cr = false;
                }
            }
            WONT => {
                self.remote
                    .receive_negative(option, DO, DONT, &mut output.socket_bytes);
                self.maybe_warn_echo(option, output);
            }
            _ => {}
        }
    }

    fn maybe_warn_echo(&mut self, option: u8, output: &mut CodecOutput) {
        if option == OPTION_ECHO && !self.remote.enabled(OPTION_ECHO) && !self.echo_warning_emitted
        {
            output.warn_remote_echo_unavailable = true;
            self.echo_warning_emitted = true;
        }
    }

    fn handle_subnegotiation(&self, option: u8, bytes: &[u8], out: &mut Vec<u8>) {
        if option == OPTION_TERMINAL_TYPE
            && self.local.enabled(OPTION_TERMINAL_TYPE)
            && bytes == [TERMINAL_TYPE_SEND]
        {
            out.extend_from_slice(&[IAC, SB, OPTION_TERMINAL_TYPE, TERMINAL_TYPE_IS]);
            push_escaped(out, TERMINAL_TYPE);
            out.extend_from_slice(&[IAC, SE]);
        }
    }

    fn push_inbound_application(&mut self, byte: u8, out: &mut Vec<u8>) {
        if self.remote.enabled(OPTION_BINARY) {
            if self.inbound_pending_cr {
                out.push(b'\r');
                self.inbound_pending_cr = false;
            }
            out.push(byte);
            return;
        }

        if self.inbound_pending_cr {
            self.inbound_pending_cr = false;
            match byte {
                0 => {
                    out.push(b'\r');
                    return;
                }
                b'\n' => {
                    out.extend_from_slice(b"\r\n");
                    return;
                }
                _ => out.push(b'\r'),
            }
        }

        if byte == b'\r' {
            self.inbound_pending_cr = true;
        } else {
            out.push(byte);
        }
    }
}

fn supports_local(option: u8) -> bool {
    matches!(
        option,
        OPTION_BINARY | OPTION_SUPPRESS_GO_AHEAD | OPTION_TERMINAL_TYPE | OPTION_NAWS
    )
}

fn supports_remote(option: u8) -> bool {
    matches!(
        option,
        OPTION_BINARY | OPTION_ECHO | OPTION_SUPPRESS_GO_AHEAD
    )
}

fn push_negotiation(out: &mut Vec<u8>, command: u8, option: u8) {
    out.extend_from_slice(&[IAC, command, option]);
}

fn push_subnegotiation_byte(option: u8, bytes: &mut Vec<u8>, byte: u8) -> Result<(), CodecError> {
    if bytes.len() == MAX_SUBNEGOTIATION_BYTES {
        return Err(CodecError::SubnegotiationTooLarge {
            option,
            limit: MAX_SUBNEGOTIATION_BYTES,
        });
    }
    bytes.push(byte);
    Ok(())
}

fn escape_iac(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_add(8));
    push_escaped(&mut out, bytes);
    out
}

fn push_escaped(out: &mut Vec<u8>, bytes: &[u8]) {
    for &byte in bytes {
        out.push(byte);
        if byte == IAC {
            out.push(IAC);
        }
    }
}

fn encode_naws(cols: u16, rows: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    out.extend_from_slice(&[IAC, SB, OPTION_NAWS]);
    push_escaped(&mut out, &cols.to_be_bytes());
    push_escaped(&mut out, &rows.to_be_bytes());
    out.extend_from_slice(&[IAC, SE]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive_all(codec: &mut TelnetCodec, chunks: &[&[u8]]) -> CodecOutput {
        let mut combined = CodecOutput::default();
        for chunk in chunks {
            let output = codec.receive(chunk).expect("test input should be valid");
            combined.application_data.extend(output.application_data);
            combined.socket_bytes.extend(output.socket_bytes);
            combined.warn_remote_echo_unavailable |= output.warn_remote_echo_unavailable;
        }
        combined
    }

    fn receive_at_every_split(input: &[u8], expected: &CodecOutput) {
        for split in 0..=input.len() {
            let mut codec = TelnetCodec::new(80, 24);
            let output = receive_all(&mut codec, &[&input[..split], &input[split..]]);
            assert_eq!(output, *expected, "split at {split}");
        }
    }

    #[test]
    fn plain_empty_escaped_iac_and_adjacent_command() {
        let mut codec = TelnetCodec::new(80, 24);
        assert_eq!(codec.receive(&[]), Ok(CodecOutput::default()));

        let output = codec
            .receive(&[b'a', IAC, IAC, b'b', IAC, 241, b'c'])
            .expect("valid transcript");
        assert_eq!(output.application_data, vec![b'a', IAC, b'b', b'c']);
        assert!(output.socket_bytes.is_empty());
    }

    #[test]
    fn fragmented_will_echo_and_do_naws_match_unsplit() {
        receive_at_every_split(
            &[IAC, WILL, OPTION_ECHO],
            &CodecOutput {
                socket_bytes: vec![IAC, DO, OPTION_ECHO],
                ..CodecOutput::default()
            },
        );
        receive_at_every_split(
            &[IAC, DO, OPTION_NAWS],
            &CodecOutput {
                socket_bytes: [vec![IAC, WILL, OPTION_NAWS], encode_naws(80, 24)].concat(),
                ..CodecOutput::default()
            },
        );
    }

    #[test]
    fn fragmented_terminal_type_send_matches_unsplit() {
        let input = [
            IAC,
            DO,
            OPTION_TERMINAL_TYPE,
            IAC,
            SB,
            OPTION_TERMINAL_TYPE,
            TERMINAL_TYPE_SEND,
            IAC,
            SE,
        ];
        let expected = CodecOutput {
            socket_bytes: [
                vec![IAC, WILL, OPTION_TERMINAL_TYPE],
                vec![IAC, SB, OPTION_TERMINAL_TYPE, TERMINAL_TYPE_IS],
                TERMINAL_TYPE.to_vec(),
                vec![IAC, SE],
            ]
            .concat(),
            ..CodecOutput::default()
        };
        receive_at_every_split(&input, &expected);
    }

    #[test]
    fn fragmented_naws_payload_with_escaped_iac_is_consumed() {
        let input = [IAC, SB, OPTION_NAWS, 0, IAC, IAC, 0, 24, IAC, SE];
        receive_at_every_split(&input, &CodecOutput::default());
    }

    #[test]
    fn one_byte_chunks_preserve_mixed_transcript() {
        let transcript = [
            b'a',
            IAC,
            WILL,
            OPTION_ECHO,
            b'\r',
            0,
            b'b',
            IAC,
            IAC,
            IAC,
            241,
            b'c',
        ];
        let mut codec = TelnetCodec::new(80, 24);
        let chunks: Vec<&[u8]> = transcript.chunks(1).collect();
        let output = receive_all(&mut codec, &chunks);
        assert_eq!(output.application_data, vec![b'a', b'\r', b'b', IAC, b'c']);
        assert_eq!(output.socket_bytes, vec![IAC, DO, OPTION_ECHO]);
    }

    #[test]
    fn unsupported_options_are_rejected_once_until_acknowledged() {
        const UNKNOWN: u8 = 99;
        let mut codec = TelnetCodec::new(80, 24);
        let output = codec
            .receive(&[
                IAC, WILL, UNKNOWN, IAC, WILL, UNKNOWN, IAC, DO, UNKNOWN, IAC, DO, UNKNOWN,
            ])
            .expect("valid negotiations");
        assert_eq!(
            output.socket_bytes,
            vec![IAC, DONT, UNKNOWN, IAC, WONT, UNKNOWN]
        );

        let acknowledged = codec
            .receive(&[IAC, WONT, UNKNOWN, IAC, DONT, UNKNOWN])
            .expect("valid acknowledgements");
        assert!(acknowledged.socket_bytes.is_empty());
        let retried = codec
            .receive(&[IAC, WILL, UNKNOWN, IAC, DO, UNKNOWN])
            .expect("valid repeated requests");
        assert_eq!(
            retried.socket_bytes,
            vec![IAC, DONT, UNKNOWN, IAC, WONT, UNKNOWN]
        );
    }

    #[test]
    fn startup_and_crossed_negotiation_terminate_without_duplicates() {
        let mut codec = TelnetCodec::new(80, 24);
        let start = codec.start_negotiation();
        assert_eq!(
            start,
            vec![
                IAC,
                WILL,
                OPTION_BINARY,
                IAC,
                WILL,
                OPTION_SUPPRESS_GO_AHEAD,
                IAC,
                WILL,
                OPTION_TERMINAL_TYPE,
                IAC,
                WILL,
                OPTION_NAWS,
                IAC,
                DO,
                OPTION_BINARY,
                IAC,
                DO,
                OPTION_ECHO,
                IAC,
                DO,
                OPTION_SUPPRESS_GO_AHEAD,
            ]
        );
        assert!(codec.start_negotiation().is_empty());

        let replies = codec
            .receive(&[
                IAC,
                DO,
                OPTION_BINARY,
                IAC,
                DO,
                OPTION_SUPPRESS_GO_AHEAD,
                IAC,
                DO,
                OPTION_TERMINAL_TYPE,
                IAC,
                DO,
                OPTION_NAWS,
                IAC,
                WILL,
                OPTION_BINARY,
                IAC,
                WILL,
                OPTION_ECHO,
                IAC,
                WILL,
                OPTION_SUPPRESS_GO_AHEAD,
            ])
            .expect("valid startup replies");
        assert_eq!(replies.socket_bytes, encode_naws(80, 24));

        let duplicates = codec
            .receive(&[IAC, DO, OPTION_NAWS, IAC, WILL, OPTION_ECHO])
            .expect("valid duplicate replies");
        assert!(duplicates.socket_bytes.is_empty());
    }

    #[test]
    fn q_method_queues_only_the_opposite_request() {
        let mut q = DirectionNegotiator::default();
        let mut out = Vec::new();
        q.request_enable(OPTION_ECHO, DO, &mut out);
        q.request_disable(OPTION_ECHO, DONT, &mut out);
        q.request_enable(OPTION_ECHO, DO, &mut out);
        assert_eq!(out, vec![IAC, DO, OPTION_ECHO]);

        q.request_disable(OPTION_ECHO, DONT, &mut out);
        q.receive_positive(OPTION_ECHO, true, DO, DONT, &mut out);
        assert_eq!(out, vec![IAC, DO, OPTION_ECHO, IAC, DONT, OPTION_ECHO]);
        assert!(!q.enabled(OPTION_ECHO));

        q.receive_negative(OPTION_ECHO, DO, DONT, &mut out);
        assert!(!q.enabled(OPTION_ECHO));
    }

    #[test]
    fn q_method_positive_receive_table_matches_rfc_1143() {
        let cases = [
            (QState::No, true, QState::Yes, vec![IAC, DO, 42]),
            (QState::No, false, QState::No, vec![IAC, DONT, 42]),
            (QState::Yes, true, QState::Yes, vec![]),
            (QState::WantNo(Queue::Empty), true, QState::No, vec![]),
            (QState::WantNo(Queue::Opposite), true, QState::Yes, vec![]),
            (QState::WantYes(Queue::Empty), true, QState::Yes, vec![]),
            (
                QState::WantYes(Queue::Opposite),
                true,
                QState::WantNo(Queue::Empty),
                vec![IAC, DONT, 42],
            ),
        ];

        for (initial, supported, expected, expected_bytes) in cases {
            let mut q = DirectionNegotiator::default();
            q.options[42].state = initial;
            let mut out = Vec::new();
            q.receive_positive(42, supported, DO, DONT, &mut out);
            assert_eq!(q.options[42].state, expected, "initial {initial:?}");
            assert_eq!(out, expected_bytes, "initial {initial:?}");
        }
    }

    #[test]
    fn q_method_negative_receive_table_matches_rfc_1143() {
        let cases = [
            (QState::No, QState::No, vec![]),
            (QState::Yes, QState::No, vec![IAC, DONT, 42]),
            (QState::WantNo(Queue::Empty), QState::No, vec![]),
            (
                QState::WantNo(Queue::Opposite),
                QState::WantYes(Queue::Empty),
                vec![IAC, DO, 42],
            ),
            (QState::WantYes(Queue::Empty), QState::No, vec![]),
            (QState::WantYes(Queue::Opposite), QState::No, vec![]),
        ];

        for (initial, expected, expected_bytes) in cases {
            let mut q = DirectionNegotiator::default();
            q.options[42].state = initial;
            let mut out = Vec::new();
            q.receive_negative(42, DO, DONT, &mut out);
            assert_eq!(q.options[42].state, expected, "initial {initial:?}");
            assert_eq!(out, expected_bytes, "initial {initial:?}");
        }
    }

    #[test]
    fn terminal_type_response_is_exact_and_requires_enablement() {
        let request = [IAC, SB, OPTION_TERMINAL_TYPE, TERMINAL_TYPE_SEND, IAC, SE];
        let mut codec = TelnetCodec::new(80, 24);
        assert!(
            codec
                .receive(&request)
                .expect("valid request")
                .socket_bytes
                .is_empty()
        );
        codec
            .receive(&[IAC, DO, OPTION_TERMINAL_TYPE])
            .expect("valid negotiation");
        let output = codec.receive(&request).expect("valid request");
        assert_eq!(
            output.socket_bytes,
            [
                vec![IAC, SB, OPTION_TERMINAL_TYPE, TERMINAL_TYPE_IS],
                TERMINAL_TYPE.to_vec(),
                vec![IAC, SE]
            ]
            .concat()
        );
    }

    #[test]
    fn naws_initial_updates_and_escapes_iac() {
        let mut codec = TelnetCodec::new(255, 65_535);
        assert!(codec.resize(10, 20).is_empty());
        let enabled = codec
            .receive(&[IAC, DO, OPTION_NAWS])
            .expect("valid negotiation");
        assert_eq!(
            enabled.socket_bytes,
            [vec![IAC, WILL, OPTION_NAWS], encode_naws(10, 20)].concat()
        );
        assert_eq!(
            codec.resize(255, 65_535),
            vec![
                IAC,
                SB,
                OPTION_NAWS,
                0,
                IAC,
                IAC,
                IAC,
                IAC,
                IAC,
                IAC,
                IAC,
                SE
            ]
        );
        codec
            .receive(&[IAC, DONT, OPTION_NAWS])
            .expect("valid withdrawal");
        assert!(codec.resize(30, 40).is_empty());
    }

    #[test]
    fn outbound_nvt_and_iac_conversion_survive_chunks() {
        let mut codec = TelnetCodec::new(80, 24);
        assert_eq!(codec.encode_application(b"a\r"), b"a");
        assert!(codec.encode_application(b"").is_empty());
        assert_eq!(codec.encode_application(b"\nb\nc\rd"), b"\r\nb\r\nc\r\0d");
        assert_eq!(codec.encode_application(&[IAC]), vec![IAC, IAC]);
        assert_eq!(codec.encode_application(b"\r"), Vec::<u8>::new());
        assert_eq!(codec.flush_outbound(), b"\r\0");
    }

    #[test]
    fn outbound_nvt_is_identical_at_every_chunk_boundary() {
        let input = [b'a', b'\r', b'\n', b'b', b'\r', b'x', b'\n', IAC];
        let expected = [b"a\r\nb\r\0x\r\n".as_slice(), &[IAC, IAC]].concat();

        for split in 0..=input.len() {
            let mut codec = TelnetCodec::new(80, 24);
            let mut encoded = codec.encode_application(&input[..split]);
            encoded.extend(codec.encode_application(&input[split..]));
            encoded.extend(codec.flush_outbound());
            assert_eq!(encoded, expected, "split at {split}");
        }
    }

    #[test]
    fn semantic_newline_respects_binary_mode_and_pending_literal_cr() {
        let mut codec = TelnetCodec::new(80, 24);
        assert_eq!(codec.encode_newline(), b"\r\n");
        assert!(codec.encode_application(b"\r").is_empty());
        assert_eq!(codec.encode_newline(), b"\r\0\r\n");

        codec
            .receive(&[IAC, DO, OPTION_BINARY])
            .expect("enable local binary");
        assert_eq!(codec.encode_newline(), b"\r");

        let mut pending_at_negotiation = TelnetCodec::new(80, 24);
        assert!(pending_at_negotiation.encode_application(b"\r").is_empty());
        assert_eq!(
            pending_at_negotiation
                .receive(&[IAC, DO, OPTION_BINARY])
                .expect("enable local binary")
                .socket_bytes,
            [b"\r\0".as_slice(), &[IAC, WILL, OPTION_BINARY]].concat()
        );
    }

    #[test]
    fn inbound_nvt_conversion_survives_chunks() {
        let mut codec = TelnetCodec::new(80, 24);
        let output = receive_all(&mut codec, &[b"a\r", b"", b"\0b\r", b"\nc\r", b"x"]);
        assert_eq!(output.application_data, b"a\rb\r\nc\rx");
    }

    #[test]
    fn inbound_nvt_is_identical_at_every_chunk_boundary() {
        let input = b"a\r\0b\r\nc\rxd";
        let expected = b"a\rb\r\nc\rxd";
        for split in 0..=input.len() {
            let mut codec = TelnetCodec::new(80, 24);
            let output = receive_all(&mut codec, &[&input[..split], &input[split..]]);
            assert_eq!(output.application_data, expected, "split at {split}");
        }
    }

    #[test]
    fn binary_mode_is_independent_by_direction() {
        let mut codec = TelnetCodec::new(80, 24);
        codec
            .receive(&[IAC, WILL, OPTION_BINARY])
            .expect("enable remote binary");
        assert_eq!(
            codec
                .receive(b"\r\0\n")
                .expect("binary data")
                .application_data,
            b"\r\0\n"
        );
        assert_eq!(codec.encode_application(b"\n"), b"\r\n");

        codec
            .receive(&[IAC, DO, OPTION_BINARY])
            .expect("enable local binary");
        assert_eq!(
            codec.encode_application(&[b'\r', b'\n', IAC]),
            vec![b'\r', b'\n', IAC, IAC]
        );
    }

    #[test]
    fn echo_refusal_or_withdrawal_warns_only_once() {
        let mut codec = TelnetCodec::new(80, 24);
        let _ = codec.start_negotiation();
        let refused = codec
            .receive(&[IAC, WONT, OPTION_ECHO])
            .expect("valid refusal");
        assert!(refused.warn_remote_echo_unavailable);
        let repeated = codec
            .receive(&[IAC, WONT, OPTION_ECHO])
            .expect("valid duplicate refusal");
        assert!(!repeated.warn_remote_echo_unavailable);
    }

    #[test]
    fn maximum_subnegotiation_is_accepted_and_next_byte_is_typed_error() {
        let mut accepted = TelnetCodec::new(80, 24);
        let mut frame = vec![IAC, SB, 99];
        frame.extend(std::iter::repeat_n(b'x', MAX_SUBNEGOTIATION_BYTES));
        frame.extend_from_slice(&[IAC, SE]);
        assert_eq!(accepted.receive(&frame), Ok(CodecOutput::default()));

        let mut rejected = TelnetCodec::new(80, 24);
        let mut oversized = vec![IAC, SB, 99];
        oversized.extend(std::iter::repeat_n(b'x', MAX_SUBNEGOTIATION_BYTES + 1));
        assert_eq!(
            rejected.receive(&oversized),
            Err(CodecError::SubnegotiationTooLarge {
                option: 99,
                limit: MAX_SUBNEGOTIATION_BYTES
            })
        );
    }

    #[test]
    fn invalid_completed_subnegotiation_fails_soft() {
        let mut codec = TelnetCodec::new(80, 24);
        assert_eq!(
            codec.receive(&[IAC, SB, 99, b'x', IAC, WILL]),
            Err(CodecError::InvalidSubnegotiationCommand {
                option: 99,
                command: WILL
            })
        );
    }

    #[test]
    fn eof_in_every_incomplete_parser_state_is_clean() {
        let prefixes: &[&[u8]] = &[
            &[],
            &[IAC],
            &[IAC, WILL],
            &[IAC, SB],
            &[IAC, SB, OPTION_NAWS],
            &[IAC, SB, OPTION_NAWS, 0],
            &[IAC, SB, OPTION_NAWS, 0, IAC],
        ];
        for prefix in prefixes {
            let mut codec = TelnetCodec::new(80, 24);
            codec
                .receive(prefix)
                .expect("incomplete input is not an error");
            assert_eq!(codec.finish(), CodecOutput::default(), "prefix {prefix:?}");
        }

        let mut pending_cr = TelnetCodec::new(80, 24);
        assert!(
            pending_cr
                .receive(b"\r")
                .expect("valid data")
                .application_data
                .is_empty()
        );
        assert_eq!(pending_cr.finish().application_data, b"\r");
    }
}
