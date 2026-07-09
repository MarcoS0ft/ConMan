//! P8.6-A — the scope-enforcement proxy engine.
//!
//! Sits between an MCP client (an "agent") and the vendored Slint MCP server
//! (`i-slint-backend-testing`'s `mcp_server.rs`, enabled via the `automation`/
//! `agent-mode` Cargo feature + `SLINT_MCP_PORT`). That server implements
//! MCP's **Streamable HTTP transport**: a plain HTTP/1.1 `POST /mcp` (or `/`)
//! endpoint carrying one JSON-RPC 2.0 request per call, with **no auth/scoping
//! hook at all** — every one of its 14 tools is unconditionally reachable once
//! the port is up. This module is what makes the granted [`ScopeSet`] actually
//! matter: it terminates the agent's connection on a user-facing loopback
//! port, speaks just enough HTTP to see each request's JSON-RPC body, and
//! only forwards `tools/call` requests whose tool is in an in-scope set —
//! everything else passes straight through to an internal loopback port where
//! the real server listens (never reachable directly by the agent).
//!
//! ## What this proxy does NOT gate (read the module doc before changing this)
//! **`execute` is not a distinct MCP tool** — it rides the *write* tools
//! (`click_element` / `invoke_accessibility_action` / `dispatch_key_event`)
//! when they happen to target a connection-launch UI element. A tool-name
//! keyed proxy structurally cannot tell "click a button" from "click the
//! button that opens an SSH session" — both are just `click_element`. So this
//! proxy enforces **read vs. write only**; the execute boundary is enforced
//! later, at `cm-ui`'s actual session-launch call sites (P8.6-B), which do
//! know what they're about to do. Do not "finish the job" here by trying to
//! infer execute from tool name or arguments — it can't be done reliably at
//! this layer, and a future refactor that "cleans this up" by assuming
//! write==safe-from-launch would silently reopen the exact gap this design
//! note exists to prevent.
//!
//! ## Fail-closed on unrecognized tools
//! [`ToolScope::classify`] classifies exactly the 14 tools from the P8.6-A
//! spec's surface map. A tool name not in that table — a future Slint
//! upgrade adding a 15th tool this build doesn't know about, or a bug in the
//! table — is **never forwarded regardless of granted scopes**, and never
//! advertised in a filtered `tools/list`. The safe default for "we don't know
//! what this does" is deny, not "assume it's harmless" or "assume it's the
//! most permissive scope."
//!
//! ## Deliberate simplifications (v1, loopback-only, dev-facing)
//! - No request pipelining support: each accepted client connection is read
//!   one full request at a time, replied to, then the next is read — the
//!   proxy does not buffer/carry over bytes from a client that sends several
//!   requests back-to-back without waiting for replies. Every known MCP HTTP
//!   client behaves request-then-wait-for-reply; documented here rather than
//!   handled, to keep the gating logic (the part that actually matters for
//!   security) small and auditable.
//! - Every forwarded request opens a **fresh** short-lived connection to the
//!   internal server (`Connection: close`) rather than reusing one — trivial
//!   overhead on loopback, and avoids having to manage two independent
//!   keep-alive state machines.
//! - The `Origin` header is never forwarded to the internal server, so its
//!   own origin check (`Some(o) if is_localhost_origin(o)` / `None` allowed)
//!   always takes the "no Origin" branch — correct for a non-browser proxy
//!   client, but means this proxy does not (yet) forward CORS preflight
//!   faithfully for a hypothetical browser-based MCP client. Loopback-only
//!   either way; flagged, not a security gap for the documented (non-browser
//!   agent) use case.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use cm_core::ScopeSet;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Tool -> scope classification (P8.6-A spec's surface map, verbatim)
// ---------------------------------------------------------------------------

/// read (introspection, no state change) — see the P8.6-impl.md surface map.
const READ_TOOLS: &[&str] = &[
    "list_windows",
    "get_window_properties",
    "get_element_tree",
    "get_element_properties",
    "find_elements_by_id",
    "query_element_descendants",
    "take_screenshot",
    "start_event_recording",
    "stop_event_recording",
];

/// write (mutate UI/data) — see the P8.6-impl.md surface map.
const WRITE_TOOLS: &[&str] = &[
    "click_element",
    "drag_element",
    "invoke_accessibility_action",
    "set_element_value",
    "dispatch_key_event",
];

/// The scope a tool requires, or [`ToolScope::Unknown`] for anything not in
/// [`READ_TOOLS`]/[`WRITE_TOOLS`] — see the module doc's "fail-closed" note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolScope {
    Read,
    Write,
    Unknown,
}

impl ToolScope {
    pub(crate) fn classify(tool_name: &str) -> Self {
        if READ_TOOLS.contains(&tool_name) {
            ToolScope::Read
        } else if WRITE_TOOLS.contains(&tool_name) {
            ToolScope::Write
        } else {
            ToolScope::Unknown
        }
    }

    fn label(self) -> &'static str {
        match self {
            ToolScope::Read => "read",
            ToolScope::Write => "write",
            ToolScope::Unknown => "unknown",
        }
    }

    /// Whether `granted` permits a tool requiring this scope. [`Unknown`]
    /// always returns `false` — see the module doc.
    fn allowed_by(self, granted: &ScopeSet) -> bool {
        match self {
            ToolScope::Read => granted.read,
            ToolScope::Write => granted.write,
            ToolScope::Unknown => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure gate decision (unit-tested without any I/O)
// ---------------------------------------------------------------------------

/// What [`decide_tool_call`] says to do with one `tools/call` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    Forward,
    Deny { scope: &'static str },
}

/// Pure decision function: given a tool name and the currently-granted
/// [`ScopeSet`], says whether the call should be forwarded to the internal
/// server or denied. No I/O — this is the function the unit-test matrix
/// (all 14 tools x granted/denied) exercises directly.
pub(crate) fn decide_tool_call(tool_name: &str, granted: &ScopeSet) -> Decision {
    let scope = ToolScope::classify(tool_name);
    if scope.allowed_by(granted) {
        Decision::Forward
    } else {
        Decision::Deny {
            scope: scope.label(),
        }
    }
}

fn json_rpc_scope_error(id: &Value, tool_name: &str, scope: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32001,
            "message": format!("scope not granted: '{tool_name}' requires '{scope}'"),
        }
    })
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 framing (request read, response read, response write)
// ---------------------------------------------------------------------------

/// Upper bound on the request-line + headers block, mirroring the vendored
/// server's own `64 * 1024` header-size guard.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Upper bound on a request/response body, mirroring the vendored server's
/// own `4 * 1024 * 1024` body-size guard (`MAX_BODY_SIZE` in `mcp_server.rs`).
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// How long a read/write to either side of the proxy may block before the
/// connection is dropped — protects against a stalled agent client or a
/// wedged internal server (mirrors `qa_harness.rs`'s `WRITE_TIMEOUT`
/// reasoning). Generous enough for `take_screenshot`.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

struct ParsedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    /// The agent client asked to close the connection after this request
    /// (`Connection: close`).
    close_after: bool,
}

struct ParsedResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Reads headers into `buf` until the blank-line terminator, bounded by
/// [`MAX_HEADER_BYTES`]. Returns the offset of the `\r\n\r\n` on success.
fn read_headers_into(stream: &mut impl Read, buf: &mut Vec<u8>) -> std::io::Result<Option<usize>> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = find_header_end(buf) {
            return Ok(Some(pos));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None); // EOF before a full header block
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "agent-mode proxy: request headers exceeded the size bound",
            ));
        }
    }
}

/// Reads exactly `content_length` body bytes, starting from whatever body
/// prefix already landed in `buf` past `body_start` (bounded by
/// [`MAX_BODY_BYTES`]).
fn read_body(
    stream: &mut impl Read,
    buf: &[u8],
    body_start: usize,
    content_length: usize,
) -> std::io::Result<Vec<u8>> {
    if content_length > MAX_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent-mode proxy: body exceeded the size bound",
        ));
    }
    let mut body = buf[body_start..].to_vec();
    let mut chunk = [0u8; 4096];
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "agent-mode proxy: connection closed mid-body",
            ));
        }
        let take = (content_length - body.len()).min(n);
        body.extend_from_slice(&chunk[..take]);
    }
    body.truncate(content_length);
    Ok(body)
}

/// Reads one HTTP/1.1 request (request line + headers + `Content-Length`
/// body) from an agent client. `Ok(None)` means a clean EOF before any bytes
/// arrived (the connection is simply done, not an error).
fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<ParsedRequest>> {
    let mut buf = Vec::new();
    let Some(header_end) = read_headers_into(stream, &mut buf)? else {
        return Ok(None);
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(&buf[..header_end + 4]).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("agent-mode proxy: request parse error: {e}"),
        )
    })?;
    if status.is_partial() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent-mode proxy: incomplete request line/headers",
        ));
    }

    let method = req.method.unwrap_or("").to_string();
    let path = req.path.unwrap_or("").to_string();
    let mut content_length = 0usize;
    let mut close_after = false;
    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if name == "content-length" {
            content_length = String::from_utf8_lossy(h.value).trim().parse().unwrap_or(0);
        } else if name == "connection" && h.value.eq_ignore_ascii_case(b"close") {
            close_after = true;
        }
    }

    let body = read_body(stream, &buf, header_end + 4, content_length)?;
    Ok(Some(ParsedRequest {
        method,
        path,
        body,
        close_after,
    }))
}

/// Reads one HTTP/1.1 response (status line + headers + `Content-Length`
/// body) from the internal Slint MCP server.
fn read_response(stream: &mut TcpStream) -> std::io::Result<ParsedResponse> {
    let mut buf = Vec::new();
    let Some(header_end) = read_headers_into(stream, &mut buf)? else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "agent-mode proxy: internal server closed before sending a response",
        ));
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(&buf[..header_end + 4]).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("agent-mode proxy: response parse error: {e}"),
        )
    })?;
    if status.is_partial() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent-mode proxy: incomplete response headers",
        ));
    }

    let code = resp.code.unwrap_or(502);
    let mut content_length = 0usize;
    let mut content_type = "application/json".to_string();
    for h in resp.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if name == "content-length" {
            content_length = String::from_utf8_lossy(h.value).trim().parse().unwrap_or(0);
        } else if name == "content-type" {
            content_type = String::from_utf8_lossy(h.value).trim().to_string();
        }
    }

    let body = read_body(stream, &buf, header_end + 4, content_length)?;
    Ok(ParsedResponse {
        status: code,
        content_type,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let status_text = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// Forwarding to the internal server
// ---------------------------------------------------------------------------

/// Opens a fresh, short-lived connection to the internal server, sends
/// `req` verbatim (method/path/body; `Connection: close` so the internal
/// server closes cleanly once it has replied), and returns its response.
/// Never forwards the agent client's `Origin` header (see the module doc) —
/// the internal server treats an Origin-less request as always allowed.
fn forward(req: &ParsedRequest, internal_port: u16) -> std::io::Result<ParsedResponse> {
    let mut conn = TcpStream::connect(("127.0.0.1", internal_port))?;
    conn.set_read_timeout(Some(IO_TIMEOUT))?;
    conn.set_write_timeout(Some(IO_TIMEOUT))?;

    let head = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{internal_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        req.method,
        req.path,
        req.body.len(),
    );
    conn.write_all(head.as_bytes())?;
    conn.write_all(&req.body)?;
    read_response(&mut conn)
}

/// Forwards `req` unmodified and relays whatever the internal server said,
/// verbatim. Used for anything that isn't a `tools/call`/`tools/list`
/// JSON-RPC request (`initialize`, notifications, OPTIONS, unknown paths,
/// non-JSON bodies, …) — the proxy has no opinion on those.
fn forward_verbatim(req: &ParsedRequest, internal_port: u16) -> (u16, String, Vec<u8>) {
    match forward(req, internal_port) {
        Ok(resp) => (resp.status, resp.content_type, resp.body),
        Err(e) => {
            tracing::warn!("agent-mode: forwarding to the internal server failed: {e}");
            (
                502,
                "text/plain".to_string(),
                b"agent-mode proxy: internal server unreachable".to_vec(),
            )
        }
    }
}

/// Forwards a `tools/list` request, then filters the result to only the
/// tools [`ToolScope::allowed_by`] `granted` — an agent never even sees a
/// tool name it isn't permitted to call.
fn forward_and_filter_tools_list(
    req: &ParsedRequest,
    internal_port: u16,
    granted: &ScopeSet,
) -> (u16, String, Vec<u8>) {
    let (status, content_type, body) = forward_verbatim(req, internal_port);
    if status != 200 {
        return (status, content_type, body);
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&body) else {
        return (status, content_type, body); // malformed upstream body: relay as-is
    };
    if let Some(tools) = value
        .pointer_mut("/result/tools")
        .and_then(|t| t.as_array_mut())
    {
        tools.retain(|tool| {
            tool.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|name| ToolScope::classify(name).allowed_by(granted))
        });
    }
    match serde_json::to_vec(&value) {
        Ok(filtered) => (status, content_type, filtered),
        Err(_) => (status, content_type, body), // re-serialization somehow failed: relay the unfiltered body rather than drop the response
    }
}

/// Inspects one already-parsed request and decides what to send back: gate
/// `tools/call`, filter `tools/list`, forward everything else untouched.
fn process(
    req: &ParsedRequest,
    internal_port: u16,
    scopes: &Arc<RwLock<ScopeSet>>,
) -> (u16, String, Vec<u8>) {
    let is_mcp_endpoint = req.path == "/mcp" || req.path == "/";
    if req.method.eq_ignore_ascii_case("POST")
        && is_mcp_endpoint
        && let Ok(body_str) = std::str::from_utf8(&req.body)
        && let Ok(rpc) = serde_json::from_str::<Value>(body_str)
    {
        let method = rpc.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let granted = scopes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if method == "tools/call" {
            let tool_name = rpc
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Decision::Deny { scope } = decide_tool_call(tool_name, &granted) {
                let id = rpc.get("id").cloned().unwrap_or(Value::Null);
                let err = json_rpc_scope_error(&id, tool_name, scope);
                let body = serde_json::to_vec(&err).unwrap_or_default();
                return (200, "application/json".to_string(), body);
            }
            // In scope: fall through to the plain forward below.
        } else if method == "tools/list" {
            let granted_copy = *granted;
            drop(granted); // release the read lock before the blocking forward call
            return forward_and_filter_tools_list(req, internal_port, &granted_copy);
        }
    }
    forward_verbatim(req, internal_port)
}

// ---------------------------------------------------------------------------
// Connection handling / accept loop
// ---------------------------------------------------------------------------

/// Serves one agent client connection: reads requests one at a time (no
/// pipelining — see the module doc), replies to each, and stops on EOF or
/// `Connection: close`. Never panics on a malformed request — a parse
/// failure just ends this connection (the agent client can reconnect).
fn handle_client(mut stream: TcpStream, internal_port: u16, scopes: Arc<RwLock<ScopeSet>>) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        tracing::warn!("agent-mode: failed to set client socket timeouts; dropping connection");
        return;
    }
    loop {
        let req = match read_request(&mut stream) {
            Ok(Some(req)) => req,
            Ok(None) => return, // clean EOF
            Err(e) => {
                tracing::warn!("agent-mode: client read error: {e}");
                return;
            }
        };
        let close_after = req.close_after;
        let (status, content_type, body) = process(&req, internal_port, &scopes);
        if write_response(&mut stream, status, &content_type, &body).is_err() {
            return;
        }
        if close_after {
            return;
        }
    }
}

/// Accepts agent connections one at a time (each on its own thread) for the
/// lifetime of the process. Never panics on an accept error — logs and
/// keeps serving subsequent connections (mirrors `qa_harness.rs`'s
/// `listen_loop`).
pub(crate) fn run(listener: TcpListener, internal_port: u16, scopes: Arc<RwLock<ScopeSet>>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let scopes = Arc::clone(&scopes);
                std::thread::spawn(move || handle_client(stream, internal_port, scopes));
            }
            Err(e) => tracing::warn!("agent-mode: accept error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(read: bool, write: bool, execute: bool) -> ScopeSet {
        ScopeSet {
            read,
            write,
            execute,
        }
    }

    // ── ToolScope::classify: all 14 tools, exact partition ─────────────────

    #[test]
    fn all_read_tools_classify_as_read() {
        for name in READ_TOOLS {
            assert_eq!(
                ToolScope::classify(name),
                ToolScope::Read,
                "{name} should classify as Read"
            );
        }
    }

    #[test]
    fn all_write_tools_classify_as_write() {
        for name in WRITE_TOOLS {
            assert_eq!(
                ToolScope::classify(name),
                ToolScope::Write,
                "{name} should classify as Write"
            );
        }
    }

    #[test]
    fn read_and_write_sets_are_exactly_the_fourteen_tools_and_disjoint() {
        assert_eq!(READ_TOOLS.len(), 9, "9 read tools per the surface map");
        assert_eq!(WRITE_TOOLS.len(), 5, "5 write tools per the surface map");
        for name in READ_TOOLS {
            assert!(
                !WRITE_TOOLS.contains(name),
                "{name} must not be in both sets"
            );
        }
    }

    #[test]
    fn unrecognized_tool_name_classifies_as_unknown() {
        assert_eq!(ToolScope::classify("launch_connection"), ToolScope::Unknown);
        assert_eq!(ToolScope::classify(""), ToolScope::Unknown);
    }

    // ── decide_tool_call: the actual gate ───────────────────────────────────

    #[test]
    fn read_tool_allowed_only_with_read_granted() {
        assert_eq!(
            decide_tool_call("list_windows", &scopes(true, false, false)),
            Decision::Forward
        );
        assert_eq!(
            decide_tool_call("list_windows", &scopes(false, true, true)),
            Decision::Deny { scope: "read" }
        );
    }

    #[test]
    fn write_tool_allowed_only_with_write_granted() {
        assert_eq!(
            decide_tool_call("click_element", &scopes(false, true, false)),
            Decision::Forward
        );
        assert_eq!(
            decide_tool_call("click_element", &scopes(true, false, true)),
            Decision::Deny { scope: "write" }
        );
    }

    #[test]
    fn write_tool_is_not_forwarded_under_read_only_scope() {
        // The literal scenario the P8.6 spec names as the adversarial case:
        // a write-tool call under a read-only ScopeSet must be denied.
        let read_only = scopes(true, false, false);
        for name in WRITE_TOOLS {
            assert_eq!(
                decide_tool_call(name, &read_only),
                Decision::Deny { scope: "write" },
                "{name} must be denied under read-only scope"
            );
        }
    }

    #[test]
    fn read_tool_is_not_forwarded_under_write_only_scope() {
        let write_only = scopes(false, true, false);
        for name in READ_TOOLS {
            assert_eq!(
                decide_tool_call(name, &write_only),
                Decision::Deny { scope: "read" },
                "{name} must be denied under write-only scope"
            );
        }
    }

    #[test]
    fn unknown_tool_is_always_denied_regardless_of_scopes() {
        let everything = scopes(true, true, true);
        assert_eq!(
            decide_tool_call("some_future_tool", &everything),
            Decision::Deny { scope: "unknown" },
            "an unclassified tool must never be forwarded, even with every scope granted"
        );
    }

    #[test]
    fn no_scopes_granted_denies_every_known_tool() {
        let none = ScopeSet::default();
        for name in READ_TOOLS.iter().chain(WRITE_TOOLS.iter()) {
            assert_ne!(
                decide_tool_call(name, &none),
                Decision::Forward,
                "{name} must not forward with no scopes granted"
            );
        }
    }

    // ── HTTP framing: end-to-end against a hand-rolled mock internal server ─

    /// A minimal single-request HTTP server: accepts one connection, reads
    /// exactly one request (headers + `Content-Length` body), and replies
    /// with `body` (default content-type `application/json`). Enough to
    /// exercise the proxy's request/response framing without needing a real
    /// Slint MCP server.
    fn spawn_mock_internal_server(status: u16, body: Vec<u8>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("local_addr").port();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            // Drain exactly one request (headers + Content-Length body) so
            // the write below isn't racing a half-read request on the wire.
            let _ = read_request(&mut stream);
            let _ = write_response(&mut stream, status, "application/json", &body);
        });
        port
    }

    fn parsed_request(method: &str, path: &str, body: &[u8]) -> ParsedRequest {
        ParsedRequest {
            method: method.to_string(),
            path: path.to_string(),
            body: body.to_vec(),
            close_after: true,
        }
    }

    #[test]
    fn forward_verbatim_relays_the_internal_servers_response() {
        let canned = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec();
        let port = spawn_mock_internal_server(200, canned.clone());
        let req = parsed_request(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        );
        let (status, content_type, body) = forward_verbatim(&req, port);
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        assert_eq!(body, canned);
    }

    #[test]
    fn tools_call_in_scope_forwards_to_the_internal_server() {
        let canned = br#"{"jsonrpc":"2.0","id":5,"result":{"content":[]}}"#.to_vec();
        let port = spawn_mock_internal_server(200, canned.clone());
        let scopes_lock = Arc::new(RwLock::new(scopes(true, false, false)));
        let req = parsed_request(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_windows","arguments":{}}}"#,
        );
        let (status, _content_type, body) = process(&req, port, &scopes_lock);
        assert_eq!(status, 200);
        assert_eq!(body, canned, "an in-scope call must forward, not be gated");
    }

    #[test]
    fn tools_call_out_of_scope_is_rejected_without_forwarding() {
        // No mock server started at all: if the gate forwarded, `forward`
        // would fail to connect (nothing listening on this port) and the
        // test would observe a 502, not a clean scope-denied 200 — this
        // structurally proves the deny path never reaches `forward`.
        let unused_port = TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let scopes_lock = Arc::new(RwLock::new(scopes(true, false, false))); // read-only
        let req = parsed_request(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"click_element","arguments":{}}}"#,
        );
        let (status, content_type, body) = process(&req, unused_port, &scopes_lock);
        assert_eq!(status, 200, "a JSON-RPC-level error is still HTTP 200");
        assert_eq!(content_type, "application/json");
        let parsed: Value = serde_json::from_slice(&body).expect("valid JSON-RPC error body");
        assert_eq!(parsed["id"], 9);
        assert!(
            parsed["error"]["message"]
                .as_str()
                .unwrap()
                .contains("requires 'write'")
        );
    }

    #[test]
    fn tools_list_is_filtered_to_granted_scopes_only() {
        let upstream_list = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {"name": "list_windows"},
                    {"name": "click_element"},
                    {"name": "take_screenshot"},
                ]
            }
        });
        let port = spawn_mock_internal_server(
            200,
            serde_json::to_vec(&upstream_list).expect("serialize canned tools/list"),
        );
        let scopes_lock = Arc::new(RwLock::new(scopes(true, false, false))); // read only
        let req = parsed_request(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        );
        let (status, _content_type, body) = process(&req, port, &scopes_lock);
        assert_eq!(status, 200);
        let parsed: Value = serde_json::from_slice(&body).expect("valid JSON");
        let names: Vec<&str> = parsed["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"list_windows"));
        assert!(names.contains(&"take_screenshot"));
        assert!(
            !names.contains(&"click_element"),
            "the write tool must be filtered out of a read-only tools/list"
        );
    }

    #[test]
    fn non_json_rpc_request_is_forwarded_untouched() {
        // OPTIONS (CORS preflight) is not a JSON-RPC call at all -- the proxy
        // must not try to interpret it, just relay whatever the internal
        // server says.
        let canned = b"".to_vec();
        let port = spawn_mock_internal_server(204, canned.clone());
        let scopes_lock = Arc::new(RwLock::new(ScopeSet::default())); // nothing granted
        let req = parsed_request("OPTIONS", "/mcp", b"");
        let (status, _content_type, body) = process(&req, port, &scopes_lock);
        assert_eq!(
            status, 204,
            "a non-JSON-RPC request must pass through even with zero scopes granted"
        );
        assert_eq!(body, canned);
    }
}
