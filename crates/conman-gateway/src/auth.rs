use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordVerifier as PasswordVerifierTrait},
};
use tokio::sync::{Semaphore, watch};
use zeroize::{Zeroize, Zeroizing};

pub const OWNER_USERNAME: &str = "owner";
pub const MAX_PASSWORD_BYTES: usize = 256;
pub const MAX_LOGIN_BODY_BYTES: usize = 1024;
pub const MAX_AUTH_SESSIONS: usize = 16;
pub const MAX_WEBSOCKETS: usize = 16;
pub const MAX_CONCURRENT_HASHES: usize = 2;
pub const MAX_QUEUED_HASHES: usize = 8;
pub const LOGIN_BURST: u64 = 5;
pub const LOGIN_REFILL_PERIOD: Duration = Duration::from_secs(60);
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const SESSION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);
pub const WS_TICKET_LIFETIME: Duration = Duration::from_secs(30);
pub const WS_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
pub const SESSION_COOKIE_NAME: &str = "__Host-conman_session";

pub fn validate_login_body_len(length: usize) -> Result<(), AuthError> {
    if length <= MAX_LOGIN_BODY_BYTES {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_BYTES: usize = TOKEN_BYTES * 2;
const MAX_HASH_ADMISSIONS: usize = MAX_CONCURRENT_HASHES + MAX_QUEUED_HASHES;
const EXPIRY_POLL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    Logout,
    Reauthentication,
    IdleExpiry,
    AbsoluteExpiry,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    Unauthorized,
    RateLimited,
    Busy,
    Capacity,
    InvalidCsrf,
    InvalidTicket,
    RandomUnavailable,
    VerifierUnavailable,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthorized | Self::InvalidCsrf | Self::InvalidTicket => "authentication failed",
            Self::RateLimited | Self::Capacity => "request limit reached",
            Self::Busy => "authentication busy",
            Self::RandomUnavailable | Self::VerifierUnavailable => "authentication unavailable",
        })
    }
}

impl std::error::Error for AuthError {}

impl AuthError {
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Unauthorized | Self::InvalidTicket => 401,
            Self::InvalidCsrf => 403,
            Self::RateLimited | Self::Busy | Self::Capacity => 429,
            Self::RandomUnavailable | Self::VerifierUnavailable => 503,
        }
    }
}

pub trait MonotonicClock: Send + Sync + 'static {
    fn now(&self) -> Instant;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone)]
pub struct PasswordVerifier {
    // password-hash 0.5 parses by borrowing the encoded PHC input. Keep an
    // owned, zeroizing copy and reparse for each verification rather than
    // storing a self-referential borrow or leaking the backing string.
    phc: Zeroizing<String>,
    argon2: Argon2<'static>,
}

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordVerifier([redacted])")
    }
}

impl PasswordVerifier {
    pub fn parse(phc_line: &str) -> Result<Self, AuthError> {
        let trimmed = phc_line
            .strip_suffix("\r\n")
            .or_else(|| phc_line.strip_suffix('\n'))
            .unwrap_or(phc_line);
        if trimmed.len() > 4096 || trimmed.contains(['\r', '\n']) {
            return Err(AuthError::VerifierUnavailable);
        }
        let parsed = PasswordHash::new(trimmed).map_err(|_| AuthError::VerifierUnavailable)?;
        if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(19) {
            return Err(AuthError::VerifierUnavailable);
        }
        let params =
            Params::new(65_536, 3, 4, Some(32)).map_err(|_| AuthError::VerifierUnavailable)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        validate_phc_costs(&parsed)?;
        Ok(Self {
            phc: Zeroizing::new(trimmed.to_owned()),
            argon2,
        })
    }

    pub fn load(path: &std::path::Path) -> Result<Self, AuthError> {
        let metadata = std::fs::metadata(path).map_err(|_| AuthError::VerifierUnavailable)?;
        if metadata.len() > 4096 || !metadata.is_file() {
            return Err(AuthError::VerifierUnavailable);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0
                || metadata.permissions().mode() & 0o400 == 0
            {
                return Err(AuthError::VerifierUnavailable);
            }
        }
        let mut line = std::fs::read_to_string(path).map_err(|_| AuthError::VerifierUnavailable)?;
        if line.lines().count() != 1 {
            line.zeroize();
            return Err(AuthError::VerifierUnavailable);
        }
        let verifier = Self::parse(&line);
        line.zeroize();
        verifier
    }

    fn verify(&self, password: &str) -> bool {
        PasswordHash::new(&self.phc).is_ok_and(|parsed| {
            self.argon2
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    }
}

fn validate_phc_costs(phc: &PasswordHash) -> Result<(), AuthError> {
    let get = |name: &'static str| {
        phc.params
            .get_decimal(name)
            .ok_or(AuthError::VerifierUnavailable)
    };
    if phc.params.iter().count() != 3 || get("m")? != 65_536 || get("t")? != 3 || get("p")? != 4 {
        return Err(AuthError::VerifierUnavailable);
    }
    let salt = phc.salt.ok_or(AuthError::VerifierUnavailable)?;
    let mut decoded_salt = [0u8; 16];
    let decoded_salt = salt
        .decode_b64(&mut decoded_salt)
        .map_err(|_| AuthError::VerifierUnavailable)?;
    if decoded_salt.len() != 16 {
        return Err(AuthError::VerifierUnavailable);
    }
    let hash = phc.hash.ok_or(AuthError::VerifierUnavailable)?;
    if hash.as_bytes().len() != 32 {
        return Err(AuthError::VerifierUnavailable);
    }
    Ok(())
}

#[derive(Clone)]
pub struct AuthManager {
    inner: Arc<Inner>,
}

struct Inner {
    verifier: PasswordVerifier,
    clock: Arc<dyn MonotonicClock>,
    login_rate: Mutex<TokenBucket>,
    hash_capacity: Arc<HashCapacity>,
    state: Mutex<State>,
}

impl fmt::Debug for AuthManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthManager").finish_non_exhaustive()
    }
}

#[derive(Default)]
struct State {
    sessions: HashMap<OpaqueToken, Session>,
    ticket_owners: HashMap<OpaqueToken, OpaqueToken>,
    websocket_slots: usize,
}

struct Session {
    csrf: OpaqueToken,
    created_at: Instant,
    last_seen: Instant,
    revocation: watch::Sender<Option<RevocationReason>>,
    ticket: Option<Ticket>,
}

struct Ticket {
    token: OpaqueToken,
    expires_at: Instant,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.csrf.zeroize();
        if let Some(mut ticket) = self.ticket.take() {
            ticket.token.zeroize();
        }
    }
}

impl AuthManager {
    pub fn new(verifier: PasswordVerifier) -> Self {
        Self::with_clock(verifier, Arc::new(SystemClock))
    }

    pub fn with_clock(verifier: PasswordVerifier, clock: Arc<dyn MonotonicClock>) -> Self {
        Self {
            inner: Arc::new(Inner {
                verifier,
                clock: clock.clone(),
                login_rate: Mutex::new(TokenBucket::new(clock.now())),
                hash_capacity: Arc::new(HashCapacity::default()),
                state: Mutex::new(State::default()),
            }),
        }
    }

    pub async fn login(
        &self,
        username: &str,
        password: String,
        existing_cookie: Option<&str>,
    ) -> Result<LoginSuccess, AuthError> {
        let mut password = Zeroizing::new(password);
        let now = self.inner.clock.now();
        if !mutex(&self.inner.login_rate).take(now) {
            password.zeroize();
            return Err(AuthError::RateLimited);
        }
        if password.len() > MAX_PASSWORD_BYTES {
            password.zeroize();
            return Err(AuthError::Unauthorized);
        }

        let admission = self.inner.hash_capacity.reserve()?;
        let permit = self
            .inner
            .hash_capacity
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AuthError::Busy)?;
        let verifier = self.inner.verifier.clone();
        let username = username.to_owned();
        let valid = tokio::task::spawn_blocking(move || {
            // Keep both bounds held until the CPU-bound worker actually exits,
            // including when its awaiting request is cancelled.
            let _permit = permit;
            let _admission = admission;
            let password_valid = verifier.verify(&password);
            username == OWNER_USERNAME && password_valid
        })
        .await
        .map_err(|_| AuthError::Busy)?;
        if !valid {
            return Err(AuthError::Unauthorized);
        }

        let cookie = OpaqueToken::random()?;
        let csrf = OpaqueToken::random()?;
        let (revocation, _) = watch::channel(None);
        let mut state = mutex(&self.inner.state);
        self.revoke_expired_locked(&mut state, now);

        let reauth_cookie = existing_cookie.and_then(OpaqueToken::from_hex);
        let reauth_key = reauth_cookie.filter(|token| state.sessions.contains_key(token));
        if let Some(old_cookie) = reauth_key.as_ref() {
            revoke_session(&mut state, old_cookie, RevocationReason::Reauthentication);
        } else if state.sessions.len() >= MAX_AUTH_SESSIONS {
            return Err(AuthError::Capacity);
        }

        state.sessions.insert(
            cookie.clone(),
            Session {
                csrf: csrf.clone(),
                created_at: now,
                last_seen: now,
                revocation,
                ticket: None,
            },
        );
        Ok(LoginSuccess {
            cookie: cookie.to_hex(),
            csrf_token: csrf.to_hex(),
        })
    }

    pub fn authenticate_http(
        &self,
        cookie_value: &str,
        csrf_value: Option<&str>,
        requires_csrf: bool,
    ) -> Result<(), AuthError> {
        let cookie = OpaqueToken::from_hex(cookie_value).ok_or(AuthError::Unauthorized)?;
        let now = self.inner.clock.now();
        let mut state = mutex(&self.inner.state);
        self.revoke_expired_locked(&mut state, now);
        let session = state
            .sessions
            .get_mut(&cookie)
            .ok_or(AuthError::Unauthorized)?;
        if requires_csrf {
            let candidate = csrf_value
                .and_then(OpaqueToken::from_hex)
                .ok_or(AuthError::InvalidCsrf)?;
            if !session.csrf.constant_time_eq(&candidate) {
                return Err(AuthError::InvalidCsrf);
            }
        }
        session.last_seen = now;
        Ok(())
    }

    pub fn issue_ticket(&self, cookie_value: &str, csrf_value: &str) -> Result<String, AuthError> {
        let cookie = OpaqueToken::from_hex(cookie_value).ok_or(AuthError::Unauthorized)?;
        let csrf = OpaqueToken::from_hex(csrf_value).ok_or(AuthError::InvalidCsrf)?;
        let token = OpaqueToken::random()?;
        let now = self.inner.clock.now();
        let mut state = mutex(&self.inner.state);
        self.revoke_expired_locked(&mut state, now);
        let session = state
            .sessions
            .get_mut(&cookie)
            .ok_or(AuthError::Unauthorized)?;
        if !session.csrf.constant_time_eq(&csrf) {
            return Err(AuthError::InvalidCsrf);
        }
        session.last_seen = now;
        if let Some(old) = session.ticket.take() {
            state.ticket_owners.remove(&old.token);
        }
        state.ticket_owners.insert(token.clone(), cookie.clone());
        let session = state
            .sessions
            .get_mut(&cookie)
            .ok_or(AuthError::Unauthorized)?;
        session.ticket = Some(Ticket {
            token: token.clone(),
            expires_at: now + WS_TICKET_LIFETIME,
        });
        Ok(token.to_hex())
    }

    pub fn reserve_websocket(&self, cookie_value: &str) -> Result<PendingWebSocket, AuthError> {
        let cookie = OpaqueToken::from_hex(cookie_value).ok_or(AuthError::Unauthorized)?;
        let now = self.inner.clock.now();
        let mut state = mutex(&self.inner.state);
        self.revoke_expired_locked(&mut state, now);
        let session = state
            .sessions
            .get_mut(&cookie)
            .ok_or(AuthError::Unauthorized)?;
        session.last_seen = now;
        if state.websocket_slots >= MAX_WEBSOCKETS {
            return Err(AuthError::Capacity);
        }
        state.websocket_slots += 1;
        Ok(PendingWebSocket {
            inner: Arc::clone(&self.inner),
            cookie,
            opened_at: now,
            slot_reserved: true,
        })
    }

    pub fn logout(&self, cookie_value: &str, csrf_value: &str) -> Result<(), AuthError> {
        let cookie = OpaqueToken::from_hex(cookie_value).ok_or(AuthError::Unauthorized)?;
        let csrf = OpaqueToken::from_hex(csrf_value).ok_or(AuthError::InvalidCsrf)?;
        let now = self.inner.clock.now();
        let mut state = mutex(&self.inner.state);
        self.revoke_expired_locked(&mut state, now);
        let session = state.sessions.get(&cookie).ok_or(AuthError::Unauthorized)?;
        if !session.csrf.constant_time_eq(&csrf) {
            return Err(AuthError::InvalidCsrf);
        }
        revoke_session(&mut state, &cookie, RevocationReason::Logout);
        Ok(())
    }

    pub fn revoke_all(&self, reason: RevocationReason) {
        let mut state = mutex(&self.inner.state);
        let cookies: Vec<_> = state.sessions.keys().cloned().collect();
        for cookie in cookies {
            revoke_session(&mut state, &cookie, reason);
        }
    }

    pub fn session_count(&self) -> usize {
        mutex(&self.inner.state).sessions.len()
    }

    pub fn websocket_slot_count(&self) -> usize {
        mutex(&self.inner.state).websocket_slots
    }

    pub async fn run_expiry_task(&self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(EXPIRY_POLL);
        loop {
            tokio::select! {
                _ = interval.tick() => self.sweep_expired(),
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        self.revoke_all(RevocationReason::Shutdown);
                        break;
                    }
                }
            }
        }
    }

    pub fn sweep_expired(&self) {
        let now = self.inner.clock.now();
        self.revoke_expired_locked(&mut mutex(&self.inner.state), now);
    }

    fn revoke_expired_locked(&self, state: &mut State, now: Instant) {
        let expired: Vec<_> = state
            .sessions
            .iter()
            .filter_map(|(cookie, session)| {
                if now.saturating_duration_since(session.created_at) >= SESSION_ABSOLUTE_TIMEOUT {
                    Some((cookie.clone(), RevocationReason::AbsoluteExpiry))
                } else if now.saturating_duration_since(session.last_seen) >= SESSION_IDLE_TIMEOUT {
                    Some((cookie.clone(), RevocationReason::IdleExpiry))
                } else {
                    None
                }
            })
            .collect();
        for (cookie, reason) in expired {
            revoke_session(state, &cookie, reason);
        }
        let expired_tickets: Vec<_> = state
            .ticket_owners
            .keys()
            .filter_map(|ticket| {
                let owner = state.ticket_owners.get(ticket)?;
                let session = state.sessions.get(owner)?;
                session
                    .ticket
                    .as_ref()
                    .filter(|item| now >= item.expires_at)
                    .map(|_| ticket.clone())
            })
            .collect();
        for ticket in expired_tickets {
            if let Some(cookie) = state.ticket_owners.remove(&ticket)
                && let Some(session) = state.sessions.get_mut(&cookie)
            {
                session.ticket = None;
            }
        }
    }
}

pub struct LoginSuccess {
    pub cookie: String,
    pub csrf_token: String,
}

impl LoginSuccess {
    pub fn set_cookie_header(&self) -> String {
        format!(
            "{SESSION_COOKIE_NAME}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
            self.cookie
        )
    }
}

impl fmt::Debug for LoginSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginSuccess([secrets redacted])")
    }
}

impl Drop for LoginSuccess {
    fn drop(&mut self) {
        self.cookie.zeroize();
        self.csrf_token.zeroize();
    }
}

pub struct PendingWebSocket {
    inner: Arc<Inner>,
    cookie: OpaqueToken,
    opened_at: Instant,
    slot_reserved: bool,
}

impl fmt::Debug for PendingWebSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingWebSocket([authority redacted])")
    }
}

impl PendingWebSocket {
    pub fn authenticate(mut self, ticket_value: &str) -> Result<AuthenticatedWebSocket, AuthError> {
        let now = self.inner.clock.now();
        if now.saturating_duration_since(self.opened_at) > WS_AUTHENTICATION_TIMEOUT {
            return Err(AuthError::InvalidTicket);
        }
        let ticket = OpaqueToken::from_hex(ticket_value).ok_or(AuthError::InvalidTicket)?;
        let mut state = mutex(&self.inner.state);
        self.revoke_expired_locked(&mut state, now);
        let owner = state
            .ticket_owners
            .get(&ticket)
            .ok_or(AuthError::InvalidTicket)?;
        if !owner.constant_time_eq(&self.cookie) {
            return Err(AuthError::InvalidTicket);
        }
        state.ticket_owners.remove(&ticket);
        let session = state
            .sessions
            .get_mut(&self.cookie)
            .ok_or(AuthError::Unauthorized)?;
        let valid = session.ticket.as_ref().is_some_and(|candidate| {
            candidate.token.constant_time_eq(&ticket) && now < candidate.expires_at
        });
        if !valid {
            session.ticket = None;
            return Err(AuthError::InvalidTicket);
        }
        session.ticket = None;
        let revocation = session.revocation.subscribe();
        drop(state);
        self.slot_reserved = false;
        Ok(AuthenticatedWebSocket {
            inner: Arc::clone(&self.inner),
            cookie: self.cookie.clone(),
            revocation,
            slot_reserved: true,
        })
    }

    fn revoke_expired_locked(&self, state: &mut State, now: Instant) {
        let manager = AuthManager {
            inner: Arc::clone(&self.inner),
        };
        manager.revoke_expired_locked(state, now);
    }
}

impl Drop for PendingWebSocket {
    fn drop(&mut self) {
        if self.slot_reserved {
            decrement_websocket_slots(&self.inner);
            self.slot_reserved = false;
        }
    }
}

pub struct AuthenticatedWebSocket {
    inner: Arc<Inner>,
    cookie: OpaqueToken,
    revocation: watch::Receiver<Option<RevocationReason>>,
    slot_reserved: bool,
}

impl fmt::Debug for AuthenticatedWebSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedWebSocket([authority redacted])")
    }
}

impl AuthenticatedWebSocket {
    pub fn session_revoked(&self) -> Option<RevocationReason> {
        *self.revocation.borrow()
    }

    pub async fn revoked(&mut self) -> RevocationReason {
        loop {
            if let Some(reason) = *self.revocation.borrow() {
                return reason;
            }
            if self.revocation.changed().await.is_err() {
                return RevocationReason::Shutdown;
            }
        }
    }

    pub fn session_is_active(&self) -> bool {
        let now = self.inner.clock.now();
        let mut state = mutex(&self.inner.state);
        let manager = AuthManager {
            inner: Arc::clone(&self.inner),
        };
        manager.revoke_expired_locked(&mut state, now);
        state.sessions.contains_key(&self.cookie) && self.session_revoked().is_none()
    }

    pub fn touch(&self) -> Result<(), AuthError> {
        if self.session_revoked().is_some() {
            return Err(AuthError::Unauthorized);
        }
        let now = self.inner.clock.now();
        let mut state = mutex(&self.inner.state);
        let manager = AuthManager {
            inner: Arc::clone(&self.inner),
        };
        manager.revoke_expired_locked(&mut state, now);
        let session = state
            .sessions
            .get_mut(&self.cookie)
            .ok_or(AuthError::Unauthorized)?;
        if self.session_revoked().is_some() {
            return Err(AuthError::Unauthorized);
        }
        session.last_seen = now;
        Ok(())
    }
}

impl Drop for AuthenticatedWebSocket {
    fn drop(&mut self) {
        if self.slot_reserved {
            decrement_websocket_slots(&self.inner);
            self.slot_reserved = false;
        }
    }
}

fn decrement_websocket_slots(inner: &Inner) {
    let mut state = mutex(&inner.state);
    state.websocket_slots = state.websocket_slots.saturating_sub(1);
}

fn revoke_session(state: &mut State, cookie: &OpaqueToken, reason: RevocationReason) {
    if let Some(mut session) = state.sessions.remove(cookie) {
        session.revocation.send_replace(Some(reason));
        if let Some(ticket) = session.ticket.take() {
            state.ticket_owners.remove(&ticket.token);
        }
    }
}

fn mutex<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone)]
struct OpaqueToken([u8; TOKEN_BYTES]);

impl OpaqueToken {
    fn random() -> Result<Self, AuthError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| AuthError::RandomUnavailable)?;
        Ok(Self(bytes))
    }

    fn from_hex(value: &str) -> Option<Self> {
        let bytes = value.as_bytes();
        if bytes.len() != TOKEN_HEX_BYTES {
            return None;
        }
        let mut token = [0u8; TOKEN_BYTES];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            token[index] = (high << 4) | low;
        }
        Some(Self(token))
    }

    fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(TOKEN_HEX_BYTES);
        for byte in self.0 {
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
        output
    }

    fn constant_time_eq(&self, other: &Self) -> bool {
        let mut difference = 0u8;
        for (left, right) in self.0.iter().zip(other.0.iter()) {
            difference |= left ^ right;
        }
        difference == 0
    }
}

impl PartialEq for OpaqueToken {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}
impl Eq for OpaqueToken {}
impl std::hash::Hash for OpaqueToken {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueToken([redacted])")
    }
}
impl Zeroize for OpaqueToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for OpaqueToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

struct HashCapacity {
    admitted: AtomicUsize,
    active: Arc<Semaphore>,
}

impl Default for HashCapacity {
    fn default() -> Self {
        Self {
            admitted: AtomicUsize::new(0),
            active: Arc::new(Semaphore::new(MAX_CONCURRENT_HASHES)),
        }
    }
}

impl HashCapacity {
    fn reserve(self: &Arc<Self>) -> Result<HashAdmission, AuthError> {
        let result = self
            .admitted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_HASH_ADMISSIONS).then_some(current + 1)
            });
        result.map_err(|_| AuthError::Busy)?;
        Ok(HashAdmission(Arc::clone(self)))
    }
}

struct HashAdmission(Arc<HashCapacity>);
impl Drop for HashAdmission {
    fn drop(&mut self) {
        self.0.admitted.fetch_sub(1, Ordering::AcqRel);
    }
}

struct TokenBucket {
    milli_tokens: u64,
    refill_remainder: u128,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(now: Instant) -> Self {
        Self {
            milli_tokens: LOGIN_BURST * 1000,
            refill_remainder: 0,
            last_refill: now,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill).as_nanos();
        let denominator = LOGIN_REFILL_PERIOD.as_nanos();
        let numerator = elapsed
            .saturating_mul((LOGIN_BURST * 1000) as u128)
            .saturating_add(self.refill_remainder);
        let refill = numerator / denominator;
        self.refill_remainder = numerator % denominator;
        self.milli_tokens =
            (self.milli_tokens as u128 + refill).min(LOGIN_BURST as u128 * 1000) as u64;
        if self.milli_tokens == LOGIN_BURST * 1000 {
            self.refill_remainder = 0;
        }
        self.last_refill = now;
        if self.milli_tokens < 1000 {
            false
        } else {
            self.milli_tokens -= 1000;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHasher, SaltString};

    struct TestClock(Mutex<Instant>);
    impl TestClock {
        fn new() -> Self {
            Self(Mutex::new(Instant::now()))
        }
        fn advance(&self, duration: Duration) {
            *mutex(&self.0) += duration;
        }
    }
    impl MonotonicClock for TestClock {
        fn now(&self) -> Instant {
            *mutex(&self.0)
        }
    }

    fn test_verifier() -> PasswordVerifier {
        let params = Params::new(65_536, 3, 4, Some(32)).expect("valid parameters");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::encode_b64(b"0123456789abcdef").expect("valid salt");
        let phc = argon2
            .hash_password(b"correct horse", &salt)
            .expect("hash password");
        PasswordVerifier::parse(&phc.to_string()).expect("strict verifier")
    }

    fn token(value: &LoginSuccess, csrf: bool) -> &str {
        if csrf {
            &value.csrf_token
        } else {
            &value.cookie
        }
    }

    #[tokio::test]
    async fn password_login_uses_one_owner_and_generic_failures() {
        let manager = AuthManager::new(test_verifier());
        let success = manager
            .login(OWNER_USERNAME, "correct horse".to_owned(), None)
            .await
            .expect("login");
        assert_eq!(success.cookie.len(), 64);
        assert_eq!(success.csrf_token.len(), 64);
        let cookie_header = success.set_cookie_header();
        assert!(cookie_header.starts_with("__Host-conman_session="));
        assert!(cookie_header.contains("Path=/"));
        assert!(cookie_header.contains("Secure"));
        assert!(cookie_header.contains("HttpOnly"));
        assert!(cookie_header.contains("SameSite=Strict"));
        assert!(!cookie_header.contains("Domain="));
        assert_eq!(validate_login_body_len(MAX_LOGIN_BODY_BYTES), Ok(()));
        assert_eq!(
            validate_login_body_len(MAX_LOGIN_BODY_BYTES + 1),
            Err(AuthError::Unauthorized)
        );
        let debug = format!("{success:?}");
        assert!(!debug.contains(&success.cookie));
        assert!(!debug.contains(&success.csrf_token));
        assert!(debug.contains("redacted"));
        let opaque = OpaqueToken::from_hex(&success.cookie).expect("generated token parses");
        let token_debug = format!("{opaque:?}");
        assert!(token_debug.contains("redacted"));
        assert!(!token_debug.contains(&success.cookie));
        assert_eq!(AuthError::Busy.http_status(), 429);
        assert_eq!(AuthError::Unauthorized.http_status(), 401);
        assert_eq!(
            manager.authenticate_http(token(&success, false), None, false),
            Ok(())
        );
        assert_eq!(
            manager
                .login("nobody", "correct horse".to_owned(), None)
                .await
                .unwrap_err(),
            AuthError::Unauthorized
        );
        assert_eq!(
            manager
                .login(OWNER_USERNAME, "wrong".to_owned(), None)
                .await
                .unwrap_err(),
            AuthError::Unauthorized
        );
        assert_eq!(
            manager
                .login(OWNER_USERNAME, "x".repeat(257), None)
                .await
                .unwrap_err(),
            AuthError::Unauthorized
        );
    }

    #[tokio::test]
    async fn second_login_is_independent_and_reauth_scopes_to_presented_cookie() {
        let manager = AuthManager::new(test_verifier());
        let first = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("first");
        let first_ticket = manager
            .issue_ticket(&first.cookie, &first.csrf_token)
            .expect("first ticket");
        let first_socket = manager
            .reserve_websocket(&first.cookie)
            .expect("first socket")
            .authenticate(&first_ticket)
            .expect("authenticate first socket");
        let second = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("second");
        assert_ne!(first.cookie, second.cookie);
        assert_eq!(manager.session_count(), 2);
        assert_eq!(
            manager.authenticate_http(token(&first, false), Some(token(&first, true)), true),
            Ok(())
        );

        let third = manager
            .login(OWNER_USERNAME, "correct horse".into(), Some(&first.cookie))
            .await
            .expect("reauth");
        assert_ne!(first.cookie, third.cookie);
        assert_eq!(
            first_socket.session_revoked(),
            Some(RevocationReason::Reauthentication)
        );
        assert_eq!(manager.session_count(), 2);
        assert_eq!(
            manager.authenticate_http(token(&second, false), Some(token(&second, true)), true),
            Ok(())
        );
        assert_eq!(
            manager.authenticate_http(token(&first, false), None, false),
            Err(AuthError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn csrf_ticket_and_pending_socket_limits_are_bounded() {
        let manager = AuthManager::new(test_verifier());
        let login = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("login");
        let wrong_csrf = "00".repeat(32);
        assert_eq!(
            manager.issue_ticket(&login.cookie, &wrong_csrf),
            Err(AuthError::InvalidCsrf)
        );
        let old = manager
            .issue_ticket(&login.cookie, &login.csrf_token)
            .expect("ticket");
        let new = manager
            .issue_ticket(&login.cookie, &login.csrf_token)
            .expect("replacement ticket");
        assert_ne!(old, new);
        let pending = manager.reserve_websocket(&login.cookie).expect("reserve");
        assert_eq!(manager.websocket_slot_count(), 1);
        let socket = pending.authenticate(&new).expect("one-use authenticate");
        assert!(matches!(
            manager
                .reserve_websocket(&login.cookie)
                .expect("second pending")
                .authenticate(&new),
            Err(AuthError::InvalidTicket)
        ));
        drop(socket);
        assert_eq!(manager.websocket_slot_count(), 0);
    }

    #[tokio::test]
    async fn websocket_capacity_includes_pending_upgrades_and_recovers_on_drop() {
        let manager = AuthManager::new(test_verifier());
        let login = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("login");
        let mut pending = Vec::new();
        for _ in 0..MAX_WEBSOCKETS {
            pending.push(
                manager
                    .reserve_websocket(&login.cookie)
                    .expect("under socket cap"),
            );
        }
        assert_eq!(manager.websocket_slot_count(), MAX_WEBSOCKETS);
        assert_eq!(
            manager.reserve_websocket(&login.cookie).err(),
            Some(AuthError::Capacity)
        );
        pending.pop();
        assert!(manager.reserve_websocket(&login.cookie).is_ok());
    }

    #[tokio::test]
    async fn logout_and_quiet_background_expiry_revoke_sockets() {
        let clock = Arc::new(TestClock::new());
        let manager = AuthManager::with_clock(test_verifier(), clock.clone());
        let login = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("login");
        let ticket = manager
            .issue_ticket(&login.cookie, &login.csrf_token)
            .expect("ticket");
        let mut socket = manager
            .reserve_websocket(&login.cookie)
            .expect("reserve")
            .authenticate(&ticket)
            .expect("authenticate");
        let (shutdown, receiver) = watch::channel(false);
        let task_manager = manager.clone();
        let task = tokio::spawn(async move { task_manager.run_expiry_task(receiver).await });
        clock.advance(SESSION_IDLE_TIMEOUT);
        tokio::time::sleep(EXPIRY_POLL + Duration::from_millis(20)).await;
        assert_eq!(socket.revoked().await, RevocationReason::IdleExpiry);
        assert!(!socket.session_is_active());
        shutdown.send(true).expect("shutdown signal");
        task.await.expect("expiry task");

        let second = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("second login");
        let ticket = manager
            .issue_ticket(&second.cookie, &second.csrf_token)
            .expect("ticket");
        let mut live = manager
            .reserve_websocket(&second.cookie)
            .expect("reserve")
            .authenticate(&ticket)
            .expect("authenticate");
        manager
            .logout(&second.cookie, &second.csrf_token)
            .expect("logout");
        assert_eq!(live.revoked().await, RevocationReason::Logout);
    }

    #[tokio::test]
    async fn absolute_expiry_and_shutdown_have_distinct_revocation_reasons() {
        let clock = Arc::new(TestClock::new());
        let manager = AuthManager::with_clock(test_verifier(), clock.clone());
        let login = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("login");
        let ticket = manager
            .issue_ticket(&login.cookie, &login.csrf_token)
            .expect("ticket");
        let socket = manager
            .reserve_websocket(&login.cookie)
            .expect("reserve")
            .authenticate(&ticket)
            .expect("authenticate");
        clock.advance(SESSION_ABSOLUTE_TIMEOUT);
        manager.sweep_expired();
        assert_eq!(
            socket.session_revoked(),
            Some(RevocationReason::AbsoluteExpiry)
        );

        let login = manager
            .login(OWNER_USERNAME, "correct horse".into(), None)
            .await
            .expect("new login");
        let ticket = manager
            .issue_ticket(&login.cookie, &login.csrf_token)
            .expect("ticket");
        let socket = manager
            .reserve_websocket(&login.cookie)
            .expect("reserve")
            .authenticate(&ticket)
            .expect("authenticate");
        manager.revoke_all(RevocationReason::Shutdown);
        assert_eq!(socket.session_revoked(), Some(RevocationReason::Shutdown));
    }

    #[tokio::test]
    async fn login_attempts_and_session_admission_are_limited_without_eviction() {
        let clock = Arc::new(TestClock::new());
        let manager = AuthManager::with_clock(test_verifier(), clock.clone());
        let mut issued = Vec::new();
        for index in 0..MAX_AUTH_SESSIONS {
            if index > 0 {
                clock.advance(Duration::from_secs(12));
            }
            issued.push(
                manager
                    .login(OWNER_USERNAME, "correct horse".into(), None)
                    .await
                    .expect("within cap"),
            );
        }
        clock.advance(Duration::from_secs(12));
        assert_eq!(
            manager
                .login(OWNER_USERNAME, "correct horse".into(), None)
                .await
                .unwrap_err(),
            AuthError::Capacity
        );
        assert_eq!(manager.session_count(), MAX_AUTH_SESSIONS);
        assert_eq!(
            manager.authenticate_http(&issued[0].cookie, Some(&issued[0].csrf_token), true),
            Ok(())
        );
    }

    #[test]
    fn limiter_is_a_five_token_bucket_refilling_over_one_minute() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(now);
        for _ in 0..5 {
            assert!(bucket.take(now));
        }
        assert!(!bucket.take(now));
        assert!(bucket.take(now + Duration::from_secs(12)));
        assert!(!bucket.take(now + Duration::from_secs(12)));
        assert!(bucket.take(now + Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn argon_admission_is_finite_and_cancel_releases_waiting_slot() {
        let capacity = Arc::new(HashCapacity::default());
        let mut reservations = Vec::new();
        for _ in 0..MAX_HASH_ADMISSIONS {
            reservations.push(capacity.reserve().expect("bounded admission"));
        }
        assert_eq!(capacity.reserve().err(), Some(AuthError::Busy));
        let first = capacity
            .active
            .clone()
            .try_acquire_owned()
            .expect("active hash 1");
        let second = capacity
            .active
            .clone()
            .try_acquire_owned()
            .expect("active hash 2");
        assert!(capacity.active.clone().try_acquire_owned().is_err());
        drop((first, second));
        drop(reservations.pop());
        assert!(capacity.reserve().is_ok());
    }

    #[test]
    fn phc_costs_and_output_lengths_are_fixed() {
        let good = test_verifier();
        assert!(good.verify("correct horse"));
        let params = Params::new(65_536, 3, 4, Some(32)).expect("params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::encode_b64(b"0123456789abcdef").expect("valid salt");
        let phc = argon2
            .hash_password(b"correct horse", &salt)
            .expect("hash")
            .to_string();
        let bad_cost = phc.replace("m=65536,t=3,p=4", "m=65535,t=3,p=4");
        assert_eq!(
            PasswordVerifier::parse(&bad_cost).err(),
            Some(AuthError::VerifierUnavailable)
        );

        let short_salt = SaltString::encode_b64(b"0123456789abcde").expect("valid short salt");
        let bad_salt = argon2
            .hash_password(b"correct horse", &short_salt)
            .expect("hash with short salt")
            .to_string();
        assert_eq!(
            PasswordVerifier::parse(&bad_salt).err(),
            Some(AuthError::VerifierUnavailable)
        );

        let short_output_params = Params::new(65_536, 3, 4, Some(31)).expect("valid parameters");
        let short_output_argon2 =
            Argon2::new(Algorithm::Argon2id, Version::V0x13, short_output_params);
        let bad_output = short_output_argon2
            .hash_password(b"correct horse", &salt)
            .expect("hash with short output")
            .to_string();
        assert_eq!(
            PasswordVerifier::parse(&bad_output).err(),
            Some(AuthError::VerifierUnavailable)
        );
    }
}
