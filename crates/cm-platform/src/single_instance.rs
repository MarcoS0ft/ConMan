//! Identity-scoped single-instance guard.
//!
//! An OS advisory lock on a persistent per-identity file is authoritative.
//! TCP is only the activation transport: the lock owner binds an ephemeral
//! loopback endpoint, publishes its port and full digest into a separate
//! unlocked endpoint file, and starts the responder synchronously. Keeping
//! publication separate is required because Windows blocks I/O on an
//! exclusively locked file. Stale files and unrelated sockets can therefore
//! never elect a second primary.

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Seek, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

const PROTOCOL_PREFIX: &str = "CONMAN-SINGLE-INSTANCE-V3";
const IO_TIMEOUT: Duration = Duration::from_millis(300);
const PUBLICATION_WAIT: Duration = Duration::from_secs(3);
const PUBLICATION_RETRY: Duration = Duration::from_millis(10);
const MAX_LINE_LEN: usize = 256;

#[derive(Clone, PartialEq, Eq)]
pub struct InstanceIdentity([u8; 32]);

impl std::fmt::Debug for InstanceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("InstanceIdentity")
            .field(&self.token())
            .finish()
    }
}

impl InstanceIdentity {
    /// Derive an identity without touching either selected target.
    pub fn from_paths(config_path: &Path, database_path: &Path) -> std::io::Result<Self> {
        let config_path = std::path::absolute(config_path)?;
        let database_path = std::path::absolute(database_path)?;
        let mut digest = Sha256::new();
        digest.update(b"conman-instance-identity-v1\0config\0");
        hash_os_path(&mut digest, &config_path);
        digest.update(b"\0database\0");
        hash_os_path(&mut digest, &database_path);
        Ok(Self(digest.finalize().into()))
    }

    fn token(&self) -> String {
        let mut token = String::with_capacity(64);
        for byte in self.0 {
            write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
        }
        token
    }
}

#[cfg(unix)]
fn hash_os_path(digest: &mut Sha256, path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    digest.update(path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn hash_os_path(digest: &mut Sha256, path: &Path) {
    use std::os::windows::ffi::OsStrExt as _;
    for unit in path.as_os_str().encode_wide() {
        let folded = match unit {
            0x0041..=0x005a => unit + u16::from(b'a' - b'A'),
            _ => unit,
        };
        digest.update(folded.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn hash_os_path(digest: &mut Sha256, path: &Path) {
    digest.update(path.as_os_str().to_string_lossy().as_bytes());
}

#[derive(Debug)]
pub enum AcquireOutcome {
    Acquired(InstanceHandle),
    AlreadyRunning,
    Unavailable(String),
}

/// The responder thread owns the advisory lock for this handle's lifetime.
#[derive(Debug)]
pub struct InstanceHandle {
    port: u16,
    activation_rx: Receiver<()>,
}

impl InstanceHandle {
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn into_activation_receiver(self) -> Receiver<()> {
        self.activation_rx
    }
}

#[must_use]
pub fn acquire(identity: &InstanceIdentity) -> AcquireOutcome {
    let runtime_dir = match instance_runtime_dir() {
        Ok(path) => path,
        Err(error) => {
            return AcquireOutcome::Unavailable(format!(
                "could not prepare the per-user instance runtime directory: {error}"
            ));
        }
    };
    acquire_in_dir(identity, &runtime_dir)
}

fn instance_runtime_dir() -> std::io::Result<PathBuf> {
    let base = dirs::runtime_dir()
        .or_else(dirs::data_local_dir)
        .ok_or_else(|| std::io::Error::other("no per-user runtime or local-data directory"))?;
    let conman = base.join("conman");
    ensure_private_directory(&conman)?;
    let instances = conman.join("instances");
    ensure_private_directory(&instances)?;
    Ok(instances)
}

fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("runtime path is not a real directory: {}", path.display()),
                ));
            }
        }
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn lock_path(runtime_dir: &Path, identity: &InstanceIdentity) -> PathBuf {
    runtime_dir.join(format!("{}.lock", identity.token()))
}

fn endpoint_path(runtime_dir: &Path, identity: &InstanceIdentity) -> PathBuf {
    runtime_dir.join(format!("{}.endpoint", identity.token()))
}

fn acquire_in_dir(identity: &InstanceIdentity, runtime_dir: &Path) -> AcquireOutcome {
    acquire_in_dir_with_hook(identity, runtime_dir, || {})
}

fn acquire_in_dir_with_hook(
    identity: &InstanceIdentity,
    runtime_dir: &Path,
    before_publication: impl FnOnce(),
) -> AcquireOutcome {
    if let Err(error) = ensure_private_directory(runtime_dir) {
        return AcquireOutcome::Unavailable(format!(
            "could not prepare instance runtime directory: {error}"
        ));
    }
    let path = lock_path(runtime_dir, identity);
    let endpoint = endpoint_path(runtime_dir, identity);
    let file = match crate::safe_lock::open_lock_file(&path) {
        Ok(file) => file,
        Err(error) => {
            return AcquireOutcome::Unavailable(format!(
                "could not safely open instance lock {}: {error}",
                path.display()
            ));
        }
    };
    match file.try_lock() {
        Ok(()) => become_primary(identity, file, &endpoint, before_publication),
        Err(std::fs::TryLockError::WouldBlock) => {
            wait_for_primary(identity, file, &endpoint, before_publication)
        }
        Err(std::fs::TryLockError::Error(error)) => AcquireOutcome::Unavailable(format!(
            "could not acquire instance lock {}: {error}",
            path.display()
        )),
    }
}

fn wait_for_primary(
    identity: &InstanceIdentity,
    file: fs::File,
    endpoint_path: &Path,
    before_publication: impl FnOnce(),
) -> AcquireOutcome {
    let deadline = Instant::now() + PUBLICATION_WAIT;
    let mut before_publication = Some(before_publication);
    loop {
        match file.try_lock() {
            Ok(()) => {
                return become_primary(
                    identity,
                    file,
                    endpoint_path,
                    before_publication.take().expect("hook consumed once"),
                );
            }
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(error)) => {
                return AcquireOutcome::Unavailable(format!(
                    "could not re-check instance lock ownership: {error}"
                ));
            }
        }

        if let Ok(Some(port)) = read_publication(endpoint_path, identity)
            && matches!(
                probe_existing(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), identity),
                ProbeOutcome::MatchingIdentity
            )
        {
            return AcquireOutcome::AlreadyRunning;
        }
        if Instant::now() >= deadline {
            return AcquireOutcome::Unavailable(
                "timed out waiting for the locked primary to publish a verified activation endpoint"
                    .to_owned(),
            );
        }
        std::thread::sleep(PUBLICATION_RETRY);
    }
}

fn become_primary(
    identity: &InstanceIdentity,
    lock_file: fs::File,
    endpoint_path: &Path,
    before_publication: impl FnOnce(),
) -> AcquireOutcome {
    before_publication();
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(listener) => listener,
        Err(error) => {
            return AcquireOutcome::Unavailable(format!(
                "could not bind the ephemeral activation endpoint: {error}"
            ));
        }
    };
    let port = match listener.local_addr() {
        Ok(address) => address.port(),
        Err(error) => {
            return AcquireOutcome::Unavailable(format!(
                "could not inspect the activation endpoint: {error}"
            ));
        }
    };
    if let Err(error) = write_publication(endpoint_path, identity, port) {
        return AcquireOutcome::Unavailable(format!(
            "could not publish the activation endpoint: {error}"
        ));
    }
    match start_responder(listener, identity.clone(), lock_file) {
        Ok(activation_rx) => AcquireOutcome::Acquired(InstanceHandle {
            port,
            activation_rx,
        }),
        Err(error) => AcquireOutcome::Unavailable(format!(
            "could not start the activation responder: {error}"
        )),
    }
}

fn write_publication(
    endpoint_path: &Path,
    identity: &InstanceIdentity,
    port: u16,
) -> std::io::Result<()> {
    let mut file = crate::safe_lock::open_lock_file(endpoint_path)?;
    file.set_len(0)?;
    file.rewind()?;
    file.write_all(format!("{PROTOCOL_PREFIX} ENDPOINT {} {port}\n", identity.token()).as_bytes())?;
    file.sync_data()
}

fn read_publication(
    endpoint_path: &Path,
    identity: &InstanceIdentity,
) -> std::io::Result<Option<u16>> {
    let mut file = crate::safe_lock::open_lock_file(endpoint_path)?;
    file.rewind()?;
    let mut bytes = Vec::new();
    file.take((MAX_LINE_LEN + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_LINE_LEN {
        return Ok(None);
    }
    let source = String::from_utf8_lossy(&bytes);
    let mut fields = source.split_whitespace();
    let token = identity.token();
    let valid = fields.next() == Some(PROTOCOL_PREFIX)
        && fields.next() == Some("ENDPOINT")
        && fields.next() == Some(token.as_str());
    let port = fields.next().and_then(|value| value.parse::<u16>().ok());
    if !valid || fields.next().is_some() {
        return Ok(None);
    }
    Ok(port.filter(|port| *port != 0))
}

fn start_responder(
    listener: TcpListener,
    identity: InstanceIdentity,
    lock_file: fs::File,
) -> std::io::Result<Receiver<()>> {
    let (activation_tx, activation_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    std::thread::Builder::new()
        .name("cm-platform-single-instance".to_owned())
        .spawn(move || {
            // Environment-blind worker; this handle is the authoritative lock.
            let _lock_file = lock_file;
            if ready_tx.send(()).is_err() {
                return;
            }
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                if handle_request(stream, &identity) == ExistingRequest::Activate
                    && activation_tx.send(()).is_err()
                {
                    break;
                }
            }
        })?;
    ready_rx.recv().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "activation responder exited before becoming ready",
        )
    })?;
    Ok(activation_rx)
}

enum ProbeOutcome {
    MatchingIdentity,
    Collision,
}

fn probe_existing(addr: SocketAddr, identity: &InstanceIdentity) -> ProbeOutcome {
    let mut stream = match TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
        Ok(stream) => stream,
        Err(_) => return ProbeOutcome::Collision,
    };
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return ProbeOutcome::Collision;
    }
    let token = identity.token();
    if stream
        .write_all(format!("{PROTOCOL_PREFIX} ACTIVATE {token}\n").as_bytes())
        .is_err()
    {
        return ProbeOutcome::Collision;
    }
    match read_bounded_line(&mut stream) {
        Ok(Some(reply)) if reply.trim_end() == format!("{PROTOCOL_PREFIX} OK {token}") => {
            ProbeOutcome::MatchingIdentity
        }
        _ => ProbeOutcome::Collision,
    }
}

fn read_bounded_line(reader: &mut impl Read) -> std::io::Result<Option<String>> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return Ok(if buffer.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&buffer).into_owned())
                });
            }
            Ok(_) if byte[0] == b'\n' => {
                return Ok(Some(String::from_utf8_lossy(&buffer).into_owned()));
            }
            Ok(_) => {
                buffer.push(byte[0]);
                if buffer.len() > MAX_LINE_LEN {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "handshake line exceeded the length bound",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingRequest {
    Activate,
    DifferentIdentity,
    Invalid,
}

fn handle_request(mut stream: TcpStream, identity: &InstanceIdentity) -> ExistingRequest {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return ExistingRequest::Invalid;
    }
    let Ok(Some(line)) = read_bounded_line(&mut stream) else {
        return ExistingRequest::Invalid;
    };
    let mut fields = line.split_whitespace();
    let candidate_identity =
        if fields.next() == Some(PROTOCOL_PREFIX) && fields.next() == Some("ACTIVATE") {
            fields.next()
        } else {
            None
        };
    if candidate_identity.is_none() || fields.next().is_some() {
        return ExistingRequest::Invalid;
    }
    let own_token = identity.token();
    if candidate_identity != Some(own_token.as_str()) {
        let _ = stream.write_all(format!("{PROTOCOL_PREFIX} DIFFERENT {own_token}\n").as_bytes());
        return ExistingRequest::DifferentIdentity;
    }
    if stream
        .write_all(format!("{PROTOCOL_PREFIX} OK {own_token}\n").as_bytes())
        .is_ok()
    {
        ExistingRequest::Activate
    } else {
        ExistingRequest::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn identity(label: &str) -> InstanceIdentity {
        InstanceIdentity(Sha256::digest(label.as_bytes()).into())
    }

    fn stop_handle(identity: &InstanceIdentity, handle: InstanceHandle) {
        let port = handle.port;
        drop(handle.activation_rx);
        assert!(matches!(
            probe_existing(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), identity),
            ProbeOutcome::MatchingIdentity
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                Ok(listener) => return drop(listener),
                Err(error)
                    if error.kind() == std::io::ErrorKind::AddrInUse
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("responder did not release port {port}: {error}"),
            }
        }
    }

    #[test]
    fn path_identity_is_stable_and_does_not_touch_targets() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("absent-config").join("conman.ini");
        let database = directory.path().join("absent-db").join("conman.sqlite");
        let first = InstanceIdentity::from_paths(&config, &database).unwrap();
        assert_eq!(
            first,
            InstanceIdentity::from_paths(&config, &database).unwrap()
        );
        assert_ne!(
            first,
            InstanceIdentity::from_paths(&config, Path::new("other")).unwrap()
        );
        let locks = directory.path().join("locks");
        let AcquireOutcome::Acquired(primary) = acquire_in_dir(&first, &locks) else {
            panic!("instance lock");
        };
        assert!(!config.parent().unwrap().exists());
        assert!(!database.parent().unwrap().exists());
        stop_handle(&first, primary);
    }

    #[cfg(windows)]
    #[test]
    fn path_identity_folds_case_insensitive_windows_spelling() {
        let upper = InstanceIdentity::from_paths(
            Path::new(r"C:\Users\ALICE\ConMan\CONMAN.ini"),
            Path::new(r"C:\Users\ALICE\ConMan\CONMAN.sqlite"),
        )
        .unwrap();
        let lower = InstanceIdentity::from_paths(
            Path::new(r"c:\users\alice\conman\conman.ini"),
            Path::new(r"c:\users\alice\conman\conman.sqlite"),
        )
        .unwrap();
        assert_eq!(upper, lower);
    }

    #[test]
    fn same_identity_secondary_activates_primary() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity("same");
        let AcquireOutcome::Acquired(primary) = acquire_in_dir(&identity, directory.path()) else {
            panic!("primary");
        };
        assert!(matches!(
            acquire_in_dir(&identity, directory.path()),
            AcquireOutcome::AlreadyRunning
        ));
        primary
            .activation_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        stop_handle(&identity, primary);
    }

    #[test]
    fn alternate_identities_coexist_without_activation() {
        let directory = tempfile::tempdir().unwrap();
        let first_id = identity("first");
        let second_id = identity("second");
        let AcquireOutcome::Acquired(first) = acquire_in_dir(&first_id, directory.path()) else {
            panic!()
        };
        let AcquireOutcome::Acquired(second) = acquire_in_dir(&second_id, directory.path()) else {
            panic!()
        };
        assert!(first.activation_rx.try_recv().is_err());
        assert!(second.activation_rx.try_recv().is_err());
        stop_handle(&first_id, first);
        stop_handle(&second_id, second);
    }

    #[test]
    fn concurrent_same_identity_has_exactly_one_primary() {
        for round in 0..32 {
            let directory = tempfile::tempdir().unwrap();
            let identity = identity(&format!("concurrent-{round}"));
            let barrier = Arc::new(Barrier::new(3));
            let spawn = |id: InstanceIdentity, barrier: Arc<Barrier>| {
                let path = directory.path().to_owned();
                std::thread::spawn(move || {
                    barrier.wait();
                    acquire_in_dir(&id, &path)
                })
            };
            let first = spawn(identity.clone(), barrier.clone());
            let second = spawn(identity.clone(), barrier.clone());
            barrier.wait();
            let mut primary = None;
            let mut secondary = 0;
            for outcome in [first.join().unwrap(), second.join().unwrap()] {
                match outcome {
                    AcquireOutcome::Acquired(handle) => primary = Some(handle),
                    AcquireOutcome::AlreadyRunning => secondary += 1,
                    AcquireOutcome::Unavailable(reason) => panic!("round {round}: {reason}"),
                }
            }
            assert_eq!(secondary, 1);
            let primary = primary.unwrap();
            primary
                .activation_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            stop_handle(&identity, primary);
        }
    }

    #[test]
    fn slow_primary_publication_never_allows_duplicate() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity("slow");
        let (locked_tx, locked_rx) = mpsc::sync_channel(0);
        let path = directory.path().to_owned();
        let first_id = identity.clone();
        let first = std::thread::spawn(move || {
            acquire_in_dir_with_hook(&first_id, &path, || {
                locked_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(250));
            })
        });
        locked_rx.recv().unwrap();
        let secondary = acquire_in_dir(&identity, directory.path());
        let AcquireOutcome::Acquired(primary) = first.join().unwrap() else {
            panic!()
        };
        assert!(matches!(secondary, AcquireOutcome::AlreadyRunning));
        primary
            .activation_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        stop_handle(&identity, primary);
    }

    #[test]
    fn stale_unlocked_publication_and_dropped_owner_recover() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity("stale");
        let path = endpoint_path(directory.path(), &identity);
        fs::write(
            &path,
            format!("{PROTOCOL_PREFIX} ENDPOINT {} 9\n", identity.token()),
        )
        .unwrap();
        let owner =
            crate::safe_lock::open_lock_file(&lock_path(directory.path(), &identity)).unwrap();
        owner.try_lock().unwrap();
        drop(owner);
        let AcquireOutcome::Acquired(primary) = acquire_in_dir(&identity, directory.path()) else {
            panic!()
        };
        assert_ne!(primary.port, 9);
        stop_handle(&identity, primary);
    }

    #[test]
    fn instance_lock_child_helper() {
        let Some(runtime_dir) = std::env::var_os("CONMAN_TEST_INSTANCE_CHILD_DIR") else {
            return;
        };
        let ready = std::env::var_os("CONMAN_TEST_INSTANCE_CHILD_READY").unwrap();
        let identity = identity("crash-recovery");
        let AcquireOutcome::Acquired(_primary) = acquire_in_dir(&identity, Path::new(&runtime_dir))
        else {
            panic!("child must own instance lock");
        };
        fs::write(ready, b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn killed_primary_releases_instance_lock_without_stale_cleanup() {
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("child-ready");
        let runtime_dir = directory.path().join("runtime");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("single_instance::tests::instance_lock_child_helper")
            .arg("--nocapture")
            .env("CONMAN_TEST_INSTANCE_CHILD_DIR", &runtime_dir)
            .env("CONMAN_TEST_INSTANCE_CHILD_READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !ready.is_file() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("instance child exited before readiness: {status}");
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();

        let identity = identity("crash-recovery");
        let AcquireOutcome::Acquired(primary) = acquire_in_dir(&identity, &runtime_dir) else {
            panic!("kernel must release killed primary's lock");
        };
        stop_handle(&identity, primary);
    }

    #[test]
    fn activation_child_helper() {
        let Some(runtime_dir) = std::env::var_os("CONMAN_TEST_ACTIVATION_CHILD_DIR") else {
            return;
        };
        let ready = std::env::var_os("CONMAN_TEST_ACTIVATION_CHILD_READY").unwrap();
        let activated = std::env::var_os("CONMAN_TEST_ACTIVATION_CHILD_ACTIVATED").unwrap();
        let identity = identity("process-activation");
        let AcquireOutcome::Acquired(primary) = acquire_in_dir(&identity, Path::new(&runtime_dir))
        else {
            panic!("child primary");
        };
        fs::write(ready, b"ready").unwrap();
        primary
            .activation_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("parent activation");
        fs::write(activated, b"activated").unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn process_level_secondary_reads_endpoint_while_lock_is_held() {
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().unwrap();
        let runtime_dir = directory.path().join("runtime");
        let ready = directory.path().join("ready");
        let activated = directory.path().join("activated");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("single_instance::tests::activation_child_helper")
            .arg("--nocapture")
            .env("CONMAN_TEST_ACTIVATION_CHILD_DIR", &runtime_dir)
            .env("CONMAN_TEST_ACTIVATION_CHILD_READY", &ready)
            .env("CONMAN_TEST_ACTIVATION_CHILD_ACTIVATED", &activated)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !ready.is_file() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("activation child exited before readiness: {status}");
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            acquire_in_dir(&identity("process-activation"), &runtime_dir),
            AcquireOutcome::AlreadyRunning
        ));
        let started = Instant::now();
        while !activated.is_file() {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn stale_or_foreign_endpoint_cannot_bypass_live_lock() {
        let directory = tempfile::tempdir().unwrap();
        let target_identity = identity("stale-locked");
        let foreign_identity = identity("foreign-endpoint");
        let foreign_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let foreign_port = foreign_listener.local_addr().unwrap().port();
        let foreign_guard = tempfile::tempfile().unwrap();
        let foreign_rx =
            start_responder(foreign_listener, foreign_identity.clone(), foreign_guard).unwrap();
        let path = lock_path(directory.path(), &target_identity);
        let owner = crate::safe_lock::open_lock_file(&path).unwrap();
        owner.try_lock().unwrap();
        write_publication(
            &endpoint_path(directory.path(), &target_identity),
            &target_identity,
            foreign_port,
        )
        .unwrap();
        let acquire_path = directory.path().to_owned();
        let acquire_id = target_identity.clone();
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            tx.send(acquire_in_dir(&acquire_id, &acquire_path)).unwrap()
        });
        assert!(rx.recv_timeout(Duration::from_millis(150)).is_err());
        owner.unlock().unwrap();
        drop(owner);
        let AcquireOutcome::Acquired(primary) = rx.recv_timeout(Duration::from_secs(2)).unwrap()
        else {
            panic!()
        };
        thread.join().unwrap();
        assert!(foreign_rx.try_recv().is_err());
        drop(foreign_rx);
        assert!(matches!(
            probe_existing(
                SocketAddr::from((Ipv4Addr::LOCALHOST, foreign_port)),
                &foreign_identity
            ),
            ProbeOutcome::MatchingIdentity
        ));
        stop_handle(&target_identity, primary);
    }

    #[cfg(unix)]
    #[test]
    fn hostile_lock_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let identity = identity("symlink");
        let target = directory.path().join("victim");
        fs::write(&target, "do not touch\n").unwrap();
        symlink(&target, lock_path(directory.path(), &identity)).unwrap();
        assert!(matches!(
            acquire_in_dir(&identity, directory.path()),
            AcquireOutcome::Unavailable(_)
        ));
        assert_eq!(fs::read_to_string(target).unwrap(), "do not touch\n");
    }

    #[cfg(unix)]
    #[test]
    fn hostile_endpoint_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let identity = identity("endpoint-symlink");
        let target = directory.path().join("victim");
        fs::write(&target, "do not touch\n").unwrap();
        symlink(&target, endpoint_path(directory.path(), &identity)).unwrap();
        assert!(matches!(
            acquire_in_dir(&identity, directory.path()),
            AcquireOutcome::Unavailable(_)
        ));
        assert_eq!(fs::read_to_string(target).unwrap(), "do not touch\n");
    }

    #[test]
    fn full_identity_is_required_by_handshake_and_publication() {
        let directory = tempfile::tempdir().unwrap();
        let primary_id = identity("primary");
        let other_id = identity("other");
        let AcquireOutcome::Acquired(primary) = acquire_in_dir(&primary_id, directory.path())
        else {
            panic!()
        };
        assert!(matches!(
            probe_existing(
                SocketAddr::from((Ipv4Addr::LOCALHOST, primary.port)),
                &other_id
            ),
            ProbeOutcome::Collision
        ));
        assert!(primary.activation_rx.try_recv().is_err());
        assert_eq!(
            read_publication(&endpoint_path(directory.path(), &primary_id), &other_id).unwrap(),
            None
        );
        stop_handle(&primary_id, primary);
    }

    #[test]
    fn bounded_reader_rejects_oversized_input() {
        let mut input = std::io::Cursor::new(vec![b'x'; MAX_LINE_LEN + 1]);
        assert!(read_bounded_line(&mut input).is_err());
    }
}
