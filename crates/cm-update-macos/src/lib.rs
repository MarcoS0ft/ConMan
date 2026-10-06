#![allow(unsafe_code)]
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
//! macOS Sparkle 2.9.4 adapter boundary.
//!
//! `cm-update` owns update policy and reduction. This crate only translates
//! commands to the main-actor Swift bridge and copies bounded callback facts
//! into a queue that the common controller can drain. It intentionally has no
//! Slint, session, credential, or release-selection logic.

use std::collections::VecDeque;
use std::ffi::{CStr, c_void};
use std::sync::Mutex;

const MAX_EVENTS: usize = 128;
const MAX_EVENT_STRING: usize = 512;
const MAX_ERROR_STRING: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparkleEvent {
    CheckStarted {
        generation: u64,
        manual: bool,
    },
    CandidateFound {
        generation: u64,
        revision: u64,
        version: String,
        display_version: String,
        release_notes_url: Option<String>,
        info_url: Option<String>,
    },
    NoCandidate {
        generation: u64,
    },
    DownloadStarted {
        generation: u64,
    },
    DownloadProgress {
        generation: u64,
        received: u64,
        total: u64,
    },
    Preparing {
        generation: u64,
        received: u64,
        total: u64,
    },
    ReadyToInstall {
        generation: u64,
        staging_token: u64,
    },
    Cancelled {
        generation: u64,
    },
    Failed {
        generation: u64,
        code: u32,
        message: String,
    },
    InstallStarted {
        generation: u64,
    },
    OpenReleasePage {
        generation: u64,
        version: String,
        display_version: String,
        release_notes_url: Option<String>,
        info_url: Option<String>,
    },
}

impl SparkleEvent {
    fn is_progress(&self) -> bool {
        matches!(self, Self::DownloadProgress { .. } | Self::Preparing { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparkleError {
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for SparkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sparkle bridge error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for SparkleError {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ConManSparkleConfig {
    channel: u32,
    automatic_download: u8,
    reserved: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ConManSparkleEvent {
    generation: u64,
    kind: u32,
    manual: u8,
    reserved: [u8; 3],
    received: u64,
    total: u64,
    revision: u64,
    staging_token: u64,
    version: *const i8,
    display_version: *const i8,
    release_notes_url: *const i8,
    info_url: *const i8,
    error_code: u32,
    error_message: *const i8,
}

#[repr(C)]
struct ConManSparkleError {
    code: u32,
    message: *mut i8,
    message_capacity: usize,
    message_length: usize,
}

type EventCallback = unsafe extern "C" fn(*mut c_void, *const ConManSparkleEvent);

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn conman_sparkle_create(
        config: *const ConManSparkleConfig,
        callback: Option<EventCallback>,
        context: *mut c_void,
        error: *mut ConManSparkleError,
    ) -> *mut c_void;
    fn conman_sparkle_start(handle: *mut c_void, error: *mut ConManSparkleError) -> bool;
    fn conman_sparkle_set_channel(
        handle: *mut c_void,
        channel: u32,
        error: *mut ConManSparkleError,
    ) -> bool;
    fn conman_sparkle_set_automatic_download(
        handle: *mut c_void,
        enabled: bool,
        error: *mut ConManSparkleError,
    ) -> bool;
    fn conman_sparkle_check(
        handle: *mut c_void,
        manual: bool,
        error: *mut ConManSparkleError,
    ) -> bool;
    fn conman_sparkle_cancel(handle: *mut c_void, error: *mut ConManSparkleError) -> bool;
    fn conman_sparkle_install_and_relaunch(
        handle: *mut c_void,
        error: *mut ConManSparkleError,
    ) -> bool;
    fn conman_sparkle_destroy(handle: *mut c_void);
}

struct CallbackState {
    events: Mutex<VecDeque<SparkleEvent>>,
}

impl CallbackState {
    fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(MAX_EVENTS)),
        }
    }

    fn push(&self, event: SparkleEvent) {
        let Ok(mut events) = self.events.lock() else {
            return;
        };
        if events.len() >= MAX_EVENTS {
            // Progress is replaceable; terminal facts are not. If a consumer
            // is stalled, discard an old progress event first. A queue full of
            // terminal events is retained intact to avoid hiding failure or
            // install handoff facts.
            if event.is_progress() {
                if let Some(index) = events.iter().position(SparkleEvent::is_progress) {
                    events.remove(index);
                } else {
                    return;
                }
            } else if let Some(index) = events.iter().position(SparkleEvent::is_progress) {
                events.remove(index);
            } else {
                return;
            }
        }
        events.push_back(event);
    }

    fn drain(&self) -> Vec<SparkleEvent> {
        let Ok(mut events) = self.events.lock() else {
            return Vec::new();
        };
        events.drain(..).collect()
    }
}

/// Copy one callback string before the Swift callback returns. Strings are
/// capped and control characters are removed so no arbitrary error or URL text
/// can escape into shared state.
unsafe fn copy_string(pointer: *const i8, limit: usize) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: Swift owns a NUL-terminated UTF-8 buffer for the duration of
    // this callback, as specified by the bridge contract. CStr stops at that
    // terminator before the bounded copy below.
    let bytes = unsafe { CStr::from_ptr(pointer).to_bytes() };
    let bytes = &bytes[..bytes.len().min(limit)];
    let safe = bytes
        .iter()
        .map(|byte| {
            if *byte < 0x20 || *byte == 0x7f {
                b'?'
            } else {
                *byte
            }
        })
        .collect::<Vec<_>>();
    Some(String::from_utf8_lossy(&safe).into_owned())
}

unsafe extern "C" fn event_callback(context: *mut c_void, event: *const ConManSparkleEvent) {
    if context.is_null() || event.is_null() {
        return;
    }
    // SAFETY: The Swift bridge guarantees that context remains valid until
    // destroy has returned and all callbacks have drained. The event pointer
    // and its string pointers are valid for this callback only and are copied
    // before returning.
    let state = unsafe { &*context.cast::<CallbackState>() };
    let event = unsafe { &*event };
    let version = unsafe { copy_string(event.version, MAX_EVENT_STRING) }.unwrap_or_default();
    let display_version =
        unsafe { copy_string(event.display_version, MAX_EVENT_STRING) }.unwrap_or_default();
    let release_notes_url = unsafe { copy_string(event.release_notes_url, MAX_EVENT_STRING) }
        .filter(|value| !value.is_empty());
    let info_url =
        unsafe { copy_string(event.info_url, MAX_EVENT_STRING) }.filter(|value| !value.is_empty());
    let error_message =
        unsafe { copy_string(event.error_message, MAX_ERROR_STRING) }.unwrap_or_default();
    let fact = match event.kind {
        1 => SparkleEvent::CheckStarted {
            generation: event.generation,
            manual: event.manual != 0,
        },
        2 => SparkleEvent::CandidateFound {
            generation: event.generation,
            revision: event.revision,
            version,
            display_version,
            release_notes_url,
            info_url,
        },
        3 => SparkleEvent::NoCandidate {
            generation: event.generation,
        },
        4 => SparkleEvent::DownloadStarted {
            generation: event.generation,
        },
        5 => SparkleEvent::DownloadProgress {
            generation: event.generation,
            received: event.received,
            total: event.total,
        },
        6 => SparkleEvent::Preparing {
            generation: event.generation,
            received: event.received,
            total: event.total,
        },
        7 => SparkleEvent::ReadyToInstall {
            generation: event.generation,
            staging_token: event.staging_token,
        },
        8 => SparkleEvent::Cancelled {
            generation: event.generation,
        },
        9 => SparkleEvent::Failed {
            generation: event.generation,
            code: event.error_code,
            message: error_message,
        },
        10 => SparkleEvent::InstallStarted {
            generation: event.generation,
        },
        11 => SparkleEvent::OpenReleasePage {
            generation: event.generation,
            version,
            display_version,
            release_notes_url,
            info_url,
        },
        _ => SparkleEvent::Failed {
            generation: event.generation,
            code: 103,
            message: "unknown Sparkle event kind".to_owned(),
        },
    };
    state.push(fact);
}

/// Main-actor Swift bridge plus a bounded, thread-safe callback queue.
#[cfg(target_os = "macos")]
pub struct MacosSparkleBackend {
    handle: *mut c_void,
    callback_state: Box<CallbackState>,
}

#[cfg(target_os = "macos")]
// SAFETY: Bridge entry points synchronously dispatch all Sparkle object access
// to AppKit's main actor. Rust only sends immutable command values and drains
// the independent callback queue. No Swift object is accessed from Rust.
unsafe impl Send for MacosSparkleBackend {}

#[cfg(target_os = "macos")]
impl MacosSparkleBackend {
    pub fn new(channel: u32, automatic_download: bool) -> Result<Self, SparkleError> {
        let mut callback_state = Box::new(CallbackState::new());
        let mut error = ErrorBuffer::new();
        let config = ConManSparkleConfig {
            channel,
            automatic_download: automatic_download as u8,
            reserved: [0; 3],
        };
        // SAFETY: The callback and context point to callback_state, which is
        // retained until the bridge is destroyed. Swift copies callback data
        // through this callback before returning.
        let handle = unsafe {
            conman_sparkle_create(
                &config,
                Some(event_callback),
                (&mut *callback_state).cast::<c_void>(),
                error.as_mut_ptr(),
            )
        };
        if handle.is_null() {
            drop(callback_state);
            return Err(error.finish());
        }
        Ok(Self {
            handle,
            callback_state,
        })
    }

    pub fn start(&mut self) -> Result<(), SparkleError> {
        self.call(|handle, error| unsafe { conman_sparkle_start(handle, error) })
    }

    pub fn set_channel(&mut self, channel: u32) -> Result<(), SparkleError> {
        self.call(|handle, error| unsafe { conman_sparkle_set_channel(handle, channel, error) })
    }

    pub fn set_automatic_download(&mut self, enabled: bool) -> Result<(), SparkleError> {
        self.call(|handle, error| unsafe {
            conman_sparkle_set_automatic_download(handle, enabled, error)
        })
    }

    pub fn check(&mut self, manual: bool) -> Result<(), SparkleError> {
        self.call(|handle, error| unsafe { conman_sparkle_check(handle, manual, error) })
    }

    pub fn cancel(&mut self) -> Result<(), SparkleError> {
        self.call(|handle, error| unsafe { conman_sparkle_cancel(handle, error) })
    }

    pub fn install_and_relaunch(&mut self) -> Result<(), SparkleError> {
        self.call(|handle, error| unsafe { conman_sparkle_install_and_relaunch(handle, error) })
    }

    pub fn drain_events(&self) -> Vec<SparkleEvent> {
        self.callback_state.drain()
    }

    fn call(
        &mut self,
        operation: impl FnOnce(*mut c_void, *mut ConManSparkleError) -> bool,
    ) -> Result<(), SparkleError> {
        let mut error = ErrorBuffer::new();
        if operation(self.handle, error.as_mut_ptr()) {
            Ok(())
        } else {
            Err(error.finish())
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosSparkleBackend {
    fn drop(&mut self) {
        // SAFETY: Drop is the sole owner of the opaque handle. The bridge's
        // destroy contract drains callbacks before returning, after which the
        // callback context can be reclaimed with the Box field.
        unsafe { conman_sparkle_destroy(self.handle) }
    }
}

#[cfg(target_os = "macos")]
struct ErrorBuffer {
    bytes: [i8; MAX_ERROR_STRING],
    error: ConManSparkleError,
}

#[cfg(target_os = "macos")]
impl ErrorBuffer {
    fn new() -> Self {
        let mut value = Self {
            bytes: [0; MAX_ERROR_STRING],
            error: ConManSparkleError {
                code: 0,
                message: ptr::null_mut(),
                message_capacity: MAX_ERROR_STRING,
                message_length: 0,
            },
        };
        value.error.message = value.bytes.as_mut_ptr();
        value
    }

    fn as_mut_ptr(&mut self) -> *mut ConManSparkleError {
        &mut self.error
    }

    fn finish(&self) -> SparkleError {
        let length = self.error.message_length.min(MAX_ERROR_STRING - 1);
        let bytes = self.bytes[..length]
            .iter()
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>();
        SparkleError {
            code: self.error.code,
            message: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Default)]
pub struct MacosSparkleBackend;

#[cfg(not(target_os = "macos"))]
impl MacosSparkleBackend {
    pub fn new(_channel: u32, _automatic_download: bool) -> Result<Self, SparkleError> {
        Err(SparkleError {
            code: 4,
            message: "Sparkle updates require macOS".to_owned(),
        })
    }

    pub fn drain_events(&self) -> Vec<SparkleEvent> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn callback_copies_borrowed_strings_and_maps_candidate() {
        let state = Box::new(CallbackState::new());
        let context = (&*state as *const CallbackState)
            .cast_mut()
            .cast::<c_void>();
        let version = CString::new("410").unwrap();
        let display = CString::new("0.1.0").unwrap();
        let notes = CString::new("https://example.invalid/notes").unwrap();
        let event = ConManSparkleEvent {
            generation: 7,
            kind: 2,
            manual: 1,
            reserved: [0; 3],
            received: 0,
            total: 42,
            revision: 410,
            staging_token: 0,
            version: version.as_ptr().cast(),
            display_version: display.as_ptr().cast(),
            release_notes_url: notes.as_ptr().cast(),
            info_url: ptr::null(),
            error_code: 0,
            error_message: ptr::null(),
        };
        unsafe { event_callback(context, &event) };
        drop(version);
        drop(display);
        drop(notes);
        let events = state.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            SparkleEvent::CandidateFound {
                generation: 7,
                revision: 410,
                version: "410".to_owned(),
                display_version: "0.1.0".to_owned(),
                release_notes_url: Some("https://example.invalid/notes".to_owned()),
                info_url: None,
            }
        );
    }

    #[test]
    fn progress_is_bounded_and_terminal_facts_are_retained() {
        let state = CallbackState::new();
        for index in 0..(MAX_EVENTS + 20) {
            state.push(SparkleEvent::DownloadProgress {
                generation: 1,
                received: index as u64,
                total: 100,
            });
        }
        state.push(SparkleEvent::Failed {
            generation: 1,
            code: 9,
            message: "failed".to_owned(),
        });
        let events = state.drain();
        assert!(events.len() <= MAX_EVENTS);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, SparkleEvent::Failed { .. }))
        );
    }

    #[test]
    fn unknown_event_kind_fails_closed() {
        let state = Box::new(CallbackState::new());
        let context = (&*state as *const CallbackState)
            .cast_mut()
            .cast::<c_void>();
        let event = ConManSparkleEvent {
            generation: 9,
            kind: 0xffff,
            manual: 0,
            reserved: [0; 3],
            received: 0,
            total: 0,
            revision: 0,
            staging_token: 0,
            version: ptr::null(),
            display_version: ptr::null(),
            release_notes_url: ptr::null(),
            info_url: ptr::null(),
            error_code: 0,
            error_message: ptr::null(),
        };
        unsafe { event_callback(context, &event) };
        assert_eq!(
            state.drain(),
            vec![SparkleEvent::Failed {
                generation: 9,
                code: 103,
                message: "unknown Sparkle event kind".to_owned(),
            }]
        );
    }

    #[test]
    fn callback_sanitizes_bounded_error_text() {
        let state = Box::new(CallbackState::new());
        let context = (&*state as *const CallbackState)
            .cast_mut()
            .cast::<c_void>();
        let message = CString::new("line one\nline two\t").unwrap();
        let event = ConManSparkleEvent {
            generation: 3,
            kind: 9,
            manual: 0,
            reserved: [0; 3],
            received: 0,
            total: 0,
            revision: 0,
            staging_token: 0,
            version: ptr::null(),
            display_version: ptr::null(),
            release_notes_url: ptr::null(),
            info_url: ptr::null(),
            error_code: 17,
            error_message: message.as_ptr().cast(),
        };
        unsafe { event_callback(context, &event) };
        assert_eq!(
            state.drain(),
            vec![SparkleEvent::Failed {
                generation: 3,
                code: 17,
                message: "line one?line two?".to_owned(),
            }]
        );
    }
}
