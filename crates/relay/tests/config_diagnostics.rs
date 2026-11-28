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

#[test]
fn fallback_webhook_loader_does_not_log_parser_input() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = Output(Arc::new(Mutex::new(Vec::new())));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let name = "RELAY_SERVER_WEBHOOK_CONFIG";
    let previous = std::env::var_os(name);
    std::env::set_var(name, r#"["credential-canary-never-print"]"#);
    let result =
        tracing::subscriber::with_default(subscriber, relay::webhook::load_webhook_configs);
    match previous {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
    assert!(result.is_none());
    let diagnostics = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(diagnostics.contains(name));
    assert!(!diagnostics.contains("credential-canary-never-print"));
}
