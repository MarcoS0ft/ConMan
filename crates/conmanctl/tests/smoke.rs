#![forbid(unsafe_code)]

use std::process::Command;

fn conmanctl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_conmanctl"))
}

#[test]
fn version_is_machine_clean_and_uses_embedded_build_identity() {
    let output = conmanctl().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("conmanctl 0.1.0"));
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
}

#[test]
fn config_validation_json_has_no_decorative_output() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.conman");
    std::fs::write(&config, "theme = dark\n").unwrap();
    let output = conmanctl()
        .args(["--format", "json", "config", "validate"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(output.status.success());
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
}

#[test]
fn completion_is_a_raw_script_even_when_json_is_selected() {
    let output = conmanctl()
        .args(["--format", "json", "completion", "bash"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("_conmanctl_completion"));
    assert!(!stdout.trim_start().starts_with('"'));
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
}

#[test]
fn invalid_connection_id_is_a_usage_exit() {
    let output = conmanctl()
        .args(["connections", "show", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("positive integer")
    );
}

#[test]
fn hostile_argv_cannot_inject_terminal_controls_into_rich_errors() {
    let hostile = "--unknown\u{1b}]8;;https://example.invalid\u{7}\u{9d}\u{202e}";
    let output = conmanctl().arg(hostile).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    for forbidden in ['\u{1b}', '\u{7}', '\u{9d}', '\u{202e}'] {
        assert!(
            !stderr.contains(forbidden),
            "stderr retained injected control {forbidden:?}: {stderr:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn non_unicode_argv_is_a_clean_usage_error_not_a_panic() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let output = conmanctl()
        .arg(OsString::from_vec(vec![b'-', b'-', b'b', b'a', b'd', 0xff]))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("not valid Unicode"), "{stderr:?}");
    assert!(!stderr.contains("panicked"), "{stderr:?}");
}

#[test]
fn config_import_help_warns_about_automation_and_documents_acknowledgement() {
    let output = conmanctl()
        .args(["config", "import", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("automation"), "{stdout:?}");
    assert!(stdout.contains("--yes"), "{stdout:?}");
}

#[test]
fn automation_sensitive_config_requires_acknowledgement_before_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let selected = directory.path().join("config.conman");
    let source = directory.path().join("incoming.conman");
    std::fs::write(&selected, "theme = dark\n").unwrap();
    std::fs::write(&source, "theme = light\nautomation-enabled = true\n").unwrap();

    let refused = conmanctl()
        .arg("--config")
        .arg(&selected)
        .args(["config", "import"])
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        std::fs::read_to_string(&selected).unwrap(),
        "theme = dark\n"
    );
    let stderr = String::from_utf8(refused.stderr).unwrap();
    assert!(stderr.contains("automation"), "{stderr:?}");
    assert!(stderr.contains("--yes"), "{stderr:?}");

    let accepted = conmanctl()
        .arg("--config")
        .arg(&selected)
        .args(["config", "import"])
        .arg(&source)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(accepted.status.success(), "{accepted:?}");
    let stderr = String::from_utf8(accepted.stderr).unwrap();
    assert!(stderr.contains("automation"), "{stderr:?}");
    assert!(
        std::fs::read_to_string(&selected)
            .unwrap()
            .contains("automation-enabled = true")
    );
}

#[test]
fn ordinary_config_import_does_not_require_yes() {
    let directory = tempfile::tempdir().unwrap();
    let selected = directory.path().join("config.conman");
    let source = directory.path().join("incoming.conman");
    std::fs::write(&selected, "theme = dark\n").unwrap();
    std::fs::write(&source, "theme = light\n").unwrap();

    let output = conmanctl()
        .arg("--config")
        .arg(&selected)
        .args(["config", "import"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(&selected).unwrap(),
        "theme = light\n"
    );
}
