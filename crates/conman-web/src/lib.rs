//! Browser composition shell for ConMan.
//!
//! This W1 slice verifies the static browser identity and retains the shared
//! Slint window. It does not implement authentication, transport, an
//! application service, or workspace actions.

#[cfg(target_arch = "wasm32")]
use std::{cell::RefCell, rc::Rc};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[cfg(target_arch = "wasm32")]
use cm_ui::AppWindow;
#[cfg(target_arch = "wasm32")]
use slint::ComponentHandle;

#[cfg(target_arch = "wasm32")]
const BUILD_ID: &str = env!("CONMAN_BROWSER_BUILD_ID");
#[cfg(any(test, target_arch = "wasm32"))]
const WIRE_SCHEMA: u32 = 1;

#[cfg(target_arch = "wasm32")]
thread_local! {
    static APP_WINDOW: RefCell<Option<Rc<AppWindow>>> = const { RefCell::new(None) };
}

/// Mounts the inert W1 shell after static manifest preflight.
///
/// The HTML bootstrap passes the public manifest identity. The compiled build
/// identity is required at compile time and checked here again before any
/// Slint window is created. Repeated mounting is an error; a second window is
/// never silently created.
#[wasm_bindgen]
#[cfg(target_arch = "wasm32")]
pub fn start(manifest_build_id: &str, manifest_schema: u32) -> Result<(), JsValue> {
    validate_manifest_identity(BUILD_ID, manifest_build_id, manifest_schema)
        .map_err(|error| JsValue::from_str(error.message()))?;

    APP_WINDOW.with(|slot| {
        if slot.borrow().is_some() {
            return Err(JsValue::from_str("browser shell is already mounted"));
        }

        let window = AppWindow::new()
            .map_err(|error| JsValue::from_str(&format!("cannot create Slint window: {error}")))?;
        window
            .show()
            .map_err(|error| JsValue::from_str(&format!("cannot show Slint window: {error}")))?;

        // Retain the generated window wrapper for the browser document's full
        // lifetime. The DOM startup shield remains in place: no application
        // controller or editable workspace exists in W1.
        *slot.borrow_mut() = Some(Rc::new(window));
        // Winit creates the browser canvas and begins rendering from the
        // platform event loop. On wasm this hands control to the browser's
        // asynchronous event pump instead of blocking the JavaScript caller.
        slint::run_event_loop().map_err(|error| {
            JsValue::from_str(&format!("cannot start Slint event loop: {error}"))
        })?;
        Ok(())
    })
}

#[cfg(any(test, target_arch = "wasm32"))]
fn validate_manifest_identity(
    compiled_build_id: &str,
    manifest_build_id: &str,
    manifest_schema: u32,
) -> Result<(), ManifestIdentityError> {
    if !is_sha256_hex(compiled_build_id) {
        return Err(ManifestIdentityError::InvalidCompiledBuildId);
    }
    if manifest_schema != WIRE_SCHEMA {
        return Err(ManifestIdentityError::UnsupportedSchema);
    }
    if !is_sha256_hex(manifest_build_id) || manifest_build_id != compiled_build_id {
        return Err(ManifestIdentityError::BuildMismatch);
    }
    Ok(())
}

#[cfg(any(test, target_arch = "wasm32"))]
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestIdentityError {
    InvalidCompiledBuildId,
    UnsupportedSchema,
    BuildMismatch,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[cfg(target_arch = "wasm32")]
impl ManifestIdentityError {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidCompiledBuildId => "compiled browser build identity is invalid",
            Self::UnsupportedSchema => "unsupported gateway schema; reload the application",
            Self::BuildMismatch => "browser and gateway builds differ; reload the application",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ManifestIdentityError as Error, is_sha256_hex, validate_manifest_identity};

    const BUILD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_only_matching_schema_one_identity() {
        assert!(validate_manifest_identity(BUILD, BUILD, 1).is_ok());
    }

    #[test]
    fn rejects_build_and_schema_mismatches() {
        let different = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(
            validate_manifest_identity(BUILD, different, 1),
            Err(Error::BuildMismatch)
        );
        assert_eq!(
            validate_manifest_identity(BUILD, BUILD, 2),
            Err(Error::UnsupportedSchema)
        );
    }

    #[test]
    fn requires_lowercase_sha256_build_ids() {
        assert!(is_sha256_hex(BUILD));
        assert!(!is_sha256_hex(
            "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
        ));
        assert!(!is_sha256_hex("dev"));
    }
}
