use std::process::Command;

#[test]
fn invalid_credential_overrides_do_not_leak_in_startup_diagnostics() {
    let secret = "credential-canary-never-print";
    for (name, value) in [
        ("RELAY_SERVER_AUTH", format!("key:{secret}")),
        ("RELAY_SERVER_WEBHOOK_CONFIG", format!(r#"["{secret}"]"#)),
        (
            "RELAY_SERVER_WEBHOOK_CONFIG",
            format!(r#"[{{"auth_token":"{secret}","url":false}}]"#),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_relay"))
            .arg("serve")
            .current_dir(directory.path())
            .env_clear()
            .env(name, value)
            .output()
            .unwrap();
        assert!(!output.status.success(), "invalid {name} must fail startup");
        let diagnostics = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !diagnostics.contains(secret),
            "credential leaked: {diagnostics}"
        );
        assert!(
            diagnostics.contains(name),
            "missing actionable field name: {diagnostics}"
        );
    }
}
