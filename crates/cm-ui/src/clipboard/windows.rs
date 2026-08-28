//! Bounded Windows OLE adapter for virtual-file clipboard sources (for
//! example, files redirected through an outer RDP session).

#![allow(unsafe_code)]

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use cm_core::ClipboardSnapshot;
use cm_platform::secure_temp::SecureClipboardRoot;
use windows::Win32::System::Com::{DVASPECT_CONTENT, FORMATETC, TYMED_HGLOBAL, TYMED_ISTREAM};
use windows::Win32::System::DataExchange::IsClipboardFormatAvailable;
use windows::Win32::System::DataExchange::{GetClipboardSequenceNumber, RegisterClipboardFormatW};
use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
use windows::Win32::System::Ole::{
    OleGetClipboard, OleInitialize, OleUninitialize, ReleaseStgMedium,
};
use windows::Win32::UI::Shell::FILEDESCRIPTORW;
use windows::core::w;

const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;

struct GlobalUnlockGuard(windows::Win32::Foundation::HGLOBAL);

impl Drop for GlobalUnlockGuard {
    fn drop(&mut self) {
        // SAFETY: each guard is created immediately after one successful
        // GlobalLock and is dropped exactly once.
        let _ = unsafe { GlobalUnlock(self.0) };
    }
}

pub(crate) struct VirtualMaterialization {
    pub sequence: u32,
    pub snapshot: ClipboardSnapshot,
    pub source_root: PathBuf,
}

pub(crate) struct VirtualTask {
    pub generation: u64,
    pub sequence: u32,
    pub cancel: Arc<AtomicBool>,
    receiver: std::sync::mpsc::Receiver<Result<VirtualMaterialization, ()>>,
}

pub(crate) enum VirtualTaskPoll {
    Pending,
    Finished(Result<VirtualMaterialization, ()>),
}

impl VirtualTask {
    pub(super) fn start(
        generation: u64,
        sequence: u32,
        root: Arc<SecureClipboardRoot>,
    ) -> Option<Self> {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let cleanup_root = Arc::clone(&root);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("clipboard-ole-reader".to_owned())
            .spawn(move || {
                if let Err(error) = sender.send(materialize(root, sequence, &worker_cancel))
                    && let Ok(materialized) = error.0
                {
                    let _ = cleanup_root.cleanup_staging_path(&materialized.source_root);
                }
            })
            .ok()?;
        drop(thread);
        Some(Self {
            generation,
            sequence,
            cancel,
            receiver,
        })
    }

    pub(super) fn poll(&self) -> VirtualTaskPoll {
        match self.receiver.try_recv() {
            Ok(result) => VirtualTaskPoll::Finished(result),
            Err(std::sync::mpsc::TryRecvError::Empty) => VirtualTaskPoll::Pending,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => VirtualTaskPoll::Finished(Err(())),
        }
    }
}

pub(crate) fn sequence() -> u32 {
    // SAFETY: this Win32 query has no preconditions.
    unsafe { GetClipboardSequenceNumber() }
}

pub(crate) fn virtual_formats_available() -> bool {
    // SAFETY: literal format names are valid and the availability queries
    // have no clipboard-open or thread-apartment requirement.
    let descriptor = unsafe { RegisterClipboardFormatW(w!("FileGroupDescriptorW")) };
    let contents = unsafe { RegisterClipboardFormatW(w!("FileContents")) };
    descriptor != 0
        && contents != 0
        && unsafe { IsClipboardFormatAvailable(descriptor) }.is_ok()
        && unsafe { IsClipboardFormatAvailable(contents) }.is_ok()
}

fn materialize(
    root: Arc<SecureClipboardRoot>,
    sequence: u32,
    cancel: &AtomicBool,
) -> Result<VirtualMaterialization, ()> {
    // SAFETY: initializes OLE for this dedicated STA thread and is balanced
    // below on every post-initialization path.
    unsafe { OleInitialize(None) }.map_err(|_| ())?;
    let result = materialize_initialized(&root, sequence, cancel);
    // SAFETY: paired with the successful OleInitialize above.
    unsafe { OleUninitialize() };
    result
}

fn materialize_initialized(
    root: &SecureClipboardRoot,
    sequence: u32,
    cancel: &AtomicBool,
) -> Result<VirtualMaterialization, ()> {
    if sequence == 0 || current_changed(sequence, cancel) {
        return Err(());
    }
    // SAFETY: OLE is initialized on this thread.
    let object = unsafe { OleGetClipboard() }.map_err(|_| ())?;
    // SAFETY: string literals are NUL-terminated and valid for the call.
    let descriptor_format = unsafe { RegisterClipboardFormatW(w!("FileGroupDescriptorW")) };
    let contents_format = unsafe { RegisterClipboardFormatW(w!("FileContents")) };
    if descriptor_format == 0 || contents_format == 0 {
        return Err(());
    }
    let descriptors_request = FORMATETC {
        cfFormat: descriptor_format as u16,
        ptd: std::ptr::null_mut(),
        dwAspect: DVASPECT_CONTENT.0,
        lindex: -1,
        tymed: TYMED_HGLOBAL.0 as u32,
    };
    // SAFETY: FORMATETC is fully initialized and remains live for the call.
    if unsafe { object.QueryGetData(&descriptors_request) }.is_err() {
        return Err(());
    }
    // SAFETY: the provider owns the returned STGMEDIUM until released below.
    let mut medium = unsafe { object.GetData(&descriptors_request) }.map_err(|_| ())?;
    let descriptors = read_descriptors(&medium);
    // SAFETY: releases exactly the medium returned by GetData.
    unsafe { ReleaseStgMedium(&mut medium) };
    let descriptors = descriptors?;

    let directory = root
        .create_source_directory(u64::from(sequence))
        .map_err(|_| ())?;
    let started = Instant::now();
    let mut paths = Vec::with_capacity(descriptors.len());
    for (index, (name, declared_size)) in descriptors.iter().enumerate() {
        if current_changed(sequence, cancel) || started.elapsed() >= Duration::from_secs(30 * 60) {
            let _ = root.cleanup_staging_path(directory.path());
            return Err(());
        }
        let partial = format!("{index}.partial");
        let mut output = match directory.create_new_file(&partial) {
            Ok(file) => file,
            Err(_) => {
                let _ = root.cleanup_staging_path(directory.path());
                return Err(());
            }
        };
        let request = FORMATETC {
            cfFormat: contents_format as u16,
            ptd: std::ptr::null_mut(),
            dwAspect: DVASPECT_CONTENT.0,
            lindex: index as i32,
            tymed: (TYMED_ISTREAM.0 | TYMED_HGLOBAL.0) as u32,
        };
        // SAFETY: provider validates the requested lindex/media.
        let mut content = match unsafe { object.GetData(&request) } {
            Ok(content) => content,
            Err(_) => {
                let _ = root.cleanup_staging_path(directory.path());
                return Err(());
            }
        };
        let copied = read_content(
            &content,
            &mut output,
            *declared_size,
            sequence,
            cancel,
            started,
        );
        // SAFETY: releases exactly the medium returned by GetData.
        unsafe { ReleaseStgMedium(&mut content) };
        if copied.is_err() || output.sync_all().is_err() {
            let _ = root.cleanup_staging_path(directory.path());
            return Err(());
        }
        drop(output);
        if directory.rename_leaf(&partial, name).is_err() {
            let _ = root.cleanup_staging_path(directory.path());
            return Err(());
        }
        paths.push(directory.path().join(name));
    }
    if current_changed(sequence, cancel) {
        let _ = root.cleanup_staging_path(directory.path());
        return Err(());
    }
    Ok(VirtualMaterialization {
        sequence,
        snapshot: ClipboardSnapshot::Files(paths),
        source_root: directory.path().to_path_buf(),
    })
}

fn read_descriptors(
    medium: &windows::Win32::System::Com::STGMEDIUM,
) -> Result<Vec<(String, u64)>, ()> {
    if medium.tymed != TYMED_HGLOBAL.0 as u32 {
        return Err(());
    }
    // SAFETY: union member matches tymed checked above.
    let global = unsafe { medium.u.hGlobal };
    // SAFETY: the HGLOBAL belongs to the live STGMEDIUM.
    let bytes = unsafe { GlobalSize(global) };
    let pointer = unsafe { GlobalLock(global) };
    if pointer.is_null() || bytes < 4 {
        return Err(());
    }
    let _unlock = GlobalUnlockGuard(global);
    // SAFETY: at least four bytes are locked above.
    let count = unsafe { std::ptr::read_unaligned(pointer.cast::<u32>()) } as usize;
    let required = 4usize
        .checked_add(
            count
                .checked_mul(std::mem::size_of::<FILEDESCRIPTORW>())
                .ok_or(())?,
        )
        .ok_or(())?;
    if count == 0 || count > MAX_FILES || required > bytes {
        return Err(());
    }
    let mut total = 0_u64;
    let mut names = std::collections::HashSet::with_capacity(count);
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: required-size validation above covers every descriptor.
        let descriptor = unsafe {
            std::ptr::read_unaligned(
                pointer
                    .cast::<u8>()
                    .add(4 + index * std::mem::size_of::<FILEDESCRIPTORW>())
                    .cast::<FILEDESCRIPTORW>(),
            )
        };
        // FILEDESCRIPTORW is packed, so copy the UTF-16 array without ever
        // creating an unaligned reference to the field.
        let file_name = unsafe { std::ptr::addr_of!(descriptor.cFileName).read_unaligned() };
        let descriptor_flags = unsafe { std::ptr::addr_of!(descriptor.dwFlags).read_unaligned() };
        let attributes =
            unsafe { std::ptr::addr_of!(descriptor.dwFileAttributes).read_unaligned() };
        let end = file_name.iter().position(|unit| *unit == 0).ok_or(())?;
        let name = String::from_utf16(&file_name[..end]).map_err(|_| ())?;
        if descriptor_flags & 0x0000_0040 == 0
            || attributes & 0x0000_0010 != 0
            || !valid_name(&name)
            || !names.insert(name.to_lowercase())
        {
            return Err(());
        }
        let size = (u64::from(descriptor.nFileSizeHigh) << 32) | u64::from(descriptor.nFileSizeLow);
        if size > MAX_FILE_BYTES {
            return Err(());
        }
        total = total.checked_add(size).ok_or(())?;
        if total > MAX_TOTAL_BYTES {
            return Err(());
        }
        result.push((name, size));
    }
    Ok(result)
}

fn read_content(
    medium: &windows::Win32::System::Com::STGMEDIUM,
    output: &mut std::fs::File,
    expected: u64,
    sequence: u32,
    cancel: &AtomicBool,
    total_started: Instant,
) -> Result<(), ()> {
    let mut written = 0_u64;
    if medium.tymed == TYMED_ISTREAM.0 as u32 {
        // SAFETY: union member matches tymed; cloning AddRefs the COM stream.
        let stream = unsafe { medium.u.pstm.as_ref().cloned() }.ok_or(())?;
        let mut buffer = vec![0_u8; CHUNK];
        let mut last_progress = Instant::now();
        while written < expected {
            if current_changed(sequence, cancel)
                || last_progress.elapsed() >= Duration::from_secs(60)
                || total_started.elapsed() >= Duration::from_secs(30 * 60)
            {
                return Err(());
            }
            let wanted = usize::try_from((expected - written).min(CHUNK as u64)).map_err(|_| ())?;
            let mut read = 0_u32;
            // SAFETY: buffer is writable for `wanted` bytes.
            unsafe { stream.Read(buffer.as_mut_ptr().cast(), wanted as u32, Some(&mut read)) }
                .ok()
                .map_err(|_| ())?;
            if read == 0 || read as usize > wanted {
                return Err(());
            }
            output.write_all(&buffer[..read as usize]).map_err(|_| ())?;
            written += u64::from(read);
            last_progress = Instant::now();
        }
    } else if medium.tymed == TYMED_HGLOBAL.0 as u32 {
        if current_changed(sequence, cancel)
            || total_started.elapsed() >= Duration::from_secs(30 * 60)
        {
            return Err(());
        }
        // SAFETY: union member matches tymed.
        let global = unsafe { medium.u.hGlobal };
        let size = unsafe { GlobalSize(global) };
        if size as u64 != expected {
            return Err(());
        }
        let pointer = unsafe { GlobalLock(global) };
        if pointer.is_null() {
            return Err(());
        }
        let _unlock = GlobalUnlockGuard(global);
        // SAFETY: GlobalSize bounds this live locked allocation.
        let data = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size) };
        let result = output.write_all(data).map_err(|_| ());
        result?;
        written = expected;
    } else {
        return Err(());
    }
    (written == expected).then_some(()).ok_or(())
}

fn current_changed(sequence: u32, cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::Relaxed) || self::sequence() != sequence
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.encode_utf16().count() <= 255
        && !name
            .chars()
            .any(|ch| ch == '\0' || ch.is_control() || ch == '/' || ch == '\\')
        && !name.ends_with(['.', ' '])
        && !is_windows_device_name(name)
}

fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_task_disconnection_is_terminal_not_permanent_pending() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(sender);
        let task = VirtualTask {
            generation: 1,
            sequence: 2,
            cancel: Arc::new(AtomicBool::new(false)),
            receiver,
        };
        assert!(matches!(task.poll(), VirtualTaskPoll::Finished(Err(()))));
    }

    #[test]
    fn virtual_descriptor_names_use_utf16_wire_limit_and_flat_policy() {
        assert!(valid_name("report.txt"));
        assert!(!valid_name("folder\\report.txt"));
        assert!(!valid_name("CON.txt"));
        assert!(!valid_name(&"😀".repeat(128)));
    }
}
