use crate::auxiliaries::{command, ADDR_SIZE};

#[test]
fn gen_key() {
    let addr = "fpqqmiwzqiv63jczrshh4qcmlxw6gujcai3arobq23wikt7hk7ojadid.onion";
    let dir = tempfile::TempDir::new().unwrap();
    let dir_path = dir.path();
    let o = format!(r#"storage.state_dir="{}""#, dir_path.to_str().unwrap());
    let mut cmd = command();
    cmd.args([
        "-c",
        "./tests/testcases/hsc/conf/hsc.toml",
        "-o",
        &o,
        "hsc",
        "key",
        "get",
        "--batch",
        "--key-type=service-discovery",
        "--output",
        "-",
    ]);
    cmd.write_stdin(addr);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("descriptor:x25519:"));

    let keystore_path = dir_path
        .join("keystore")
        .join("client")
        .join(&addr[..ADDR_SIZE]);
    // Assert new private key has been generated
    assert_eq!(
        keystore_path
            .read_dir()
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .file_name(),
        "ks_hsc_desc_enc.x25519_private"
    );
}

#[test]
fn generate_then_rotate() {
    let addr = "fpqqmiwzqiv63jczrshh4qcmlxw6gujcai3arobq23wikt7hk7ojadid.onion";
    let dir = tempfile::TempDir::new().unwrap();
    let dir_path = dir.path();
    let o = format!(r#"storage.state_dir="{}""#, dir_path.to_str().unwrap());
    let mut cmd = command();
    cmd.args([
        "-c",
        "./tests/testcases/hsc/conf/hsc.toml",
        "-o",
        &o,
        "hsc",
        "key",
        "get",
        "--batch",
        "--key-type=service-discovery",
        "--output",
        "-",
    ]);
    cmd.write_stdin(addr);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let descriptor = String::from_utf8(output.stdout).unwrap();
    assert!(descriptor.contains("descriptor:x25519:"));

    let mut cmd = command();
    cmd.args(["-o", &o, "hsc", "key", "rotate", "--batch", "--output", "-"]);
    cmd.write_stdin(addr);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let rotated_descriptor = String::from_utf8(output.stdout).unwrap();
    assert!(rotated_descriptor.contains("descriptor:x25519:"));

    // Assert key has been rotated
    assert_ne!(descriptor, rotated_descriptor);

    let keystore_path = dir_path
        .join("keystore")
        .join("client")
        .join(&addr[..ADDR_SIZE]);
    // Assert new private key has been generated
    assert_eq!(
        keystore_path
            .read_dir()
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .file_name(),
        "ks_hsc_desc_enc.x25519_private"
    );
}

#[test]
fn generate_then_remove() {
    let addr = "fpqqmiwzqiv63jczrshh4qcmlxw6gujcai3arobq23wikt7hk7ojadid.onion";
    let dir = tempfile::TempDir::new().unwrap();
    let dir_path = dir.path();
    let o = format!(r#"storage.state_dir="{}""#, dir_path.to_str().unwrap());
    let mut cmd = command();
    cmd.args([
        "-c",
        "./tests/testcases/hsc/conf/hsc.toml",
        "-o",
        &o,
        "hsc",
        "key",
        "get",
        "--batch",
        "--key-type=service-discovery",
        "--output",
        "-",
    ]);
    cmd.write_stdin(addr);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("descriptor:x25519:"));

    let mut cmd = command();
    cmd.args(["-o", &o, "hsc", "key", "remove", "--batch"]);
    cmd.write_stdin(addr);
    cmd.assert().success();

    let keystore_path = dir_path
        .join("keystore")
        .join("client")
        .join(&addr[..ADDR_SIZE]);
    let entries = keystore_path.read_dir().unwrap().flatten();
    // Assert key has been removed
    assert_eq!(entries.count(), 0);
}
