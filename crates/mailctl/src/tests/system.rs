//! Tests for the file handling of the system backend.

use super::*;

/// A fresh, empty directory for one test.
fn scratch(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!(
        "mailctl-test-{name}-{}-{:x}",
        std::process::id(),
        SystemBackend.random()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| Error::Config(e.to_string()))?;
    Ok(dir)
}

fn entries(dir: &Path) -> Result<Vec<String>, Error> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| Error::Config(e.to_string()))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

#[test]
fn writes_privately_and_leaves_no_temporary_file() -> Result<(), Error> {
    let dir = scratch("write")?;
    let path = dir.join("sub/config.toml");
    SystemBackend.write_file(&path, "a = 1\n")?;
    SystemBackend.write_file(&path, "a = 2\n")?;
    assert_eq!(
        SystemBackend.read_optional(&path)?.as_deref(),
        Some("a = 2\n")
    );
    assert_eq!(entries(&dir.join("sub"))?, vec!["config.toml".to_owned()]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .map_err(|e| Error::Config(e.to_string()))?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[cfg(unix)]
#[test]
fn writes_through_a_symlink() -> Result<(), Error> {
    let dir = scratch("symlink")?;
    let real = dir.join("dotfiles-config.toml");
    std::fs::write(&real, "a = 1\n").map_err(|e| Error::Config(e.to_string()))?;
    let link = dir.join("config.toml");
    std::os::unix::fs::symlink(&real, &link).map_err(|e| Error::Config(e.to_string()))?;
    SystemBackend.write_file(&link, "a = 2\n")?;
    let meta = std::fs::symlink_metadata(&link).map_err(|e| Error::Config(e.to_string()))?;
    assert!(meta.file_type().is_symlink());
    assert_eq!(
        SystemBackend.read_optional(&real)?.as_deref(),
        Some("a = 2\n")
    );
    assert_eq!(
        entries(&dir)?,
        vec!["config.toml".to_owned(), "dotfiles-config.toml".to_owned()]
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn keychain_refuses_control_characters_before_running_security() {
    let result = SystemBackend.keychain_store(
        "mailctl",
        "alice",
        &Secret::new("one\nadd-generic-password -s x -a y -w z".into()),
    );
    assert!(matches!(result, Err(Error::Secret { .. })), "{result:?}");
}

#[test]
fn reads_the_configured_default_path() -> Result<(), Error> {
    let dir = scratch("read")?;
    let path = dir.join("c.toml");
    SystemBackend.write_file(&path, "x = 1\n")?;
    assert_eq!(SystemBackend.read_config(Some(&path))?, "x = 1\n");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
