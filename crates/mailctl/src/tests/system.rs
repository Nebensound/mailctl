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
fn reads_the_configured_default_path() -> Result<(), Error> {
    let dir = scratch("read")?;
    let path = dir.join("c.toml");
    SystemBackend.write_file(&path, "x = 1\n")?;
    assert_eq!(SystemBackend.read_config(Some(&path))?, "x = 1\n");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn reads_configuration_and_optional_files() -> Result<(), Error> {
    let dir = scratch("read-files")?;
    let missing = dir.join("missing.toml");
    assert!(matches!(
        SystemBackend.read_config(Some(&missing)),
        Err(Error::Config(m)) if m.contains("missing.toml")
    ));
    assert_eq!(SystemBackend.read_optional(&missing)?, None);
    // A directory cannot be read as a file.
    assert!(matches!(
        SystemBackend.read_optional(&dir),
        Err(Error::Config(_))
    ));
    assert_eq!(SystemBackend.config_path(Some(&missing))?, missing);
    let default = SystemBackend.config_path(None)?;
    assert!(
        default.ends_with(".config/mailctl/config.toml"),
        "{}",
        default.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn failed_writes_are_reported_and_leave_nothing_behind() -> Result<(), Error> {
    let dir = scratch("write-fail")?;
    // The parent "directory" is a file.
    let file = dir.join("plain");
    std::fs::write(&file, "x").map_err(|e| Error::Config(e.to_string()))?;
    assert!(matches!(
        SystemBackend.write_file(&file.join("config.toml"), "a = 1\n"),
        Err(Error::Config(_))
    ));
    // The target is a directory: the rename fails and the temporary file goes.
    let occupied = dir.join("occupied");
    std::fs::create_dir_all(occupied.join("inside")).map_err(|e| Error::Config(e.to_string()))?;
    assert!(matches!(
        SystemBackend.write_file(&occupied, "a = 1\n"),
        Err(Error::Config(_))
    ));
    assert_eq!(
        entries(&dir)?,
        vec!["occupied".to_owned(), "plain".to_owned()]
    );
    #[cfg(unix)]
    {
        // A dangling symlink cannot be resolved.
        let dangling = dir.join("dangling.toml");
        std::os::unix::fs::symlink(dir.join("nowhere/config.toml"), &dangling)
            .map_err(|e| Error::Config(e.to_string()))?;
        assert!(matches!(
            SystemBackend.write_file(&dangling, "a = 1\n"),
            Err(Error::Config(_))
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn clock_and_randomness() {
    assert!(SystemBackend.unix_time() > 1_700_000_000);
    assert_ne!(SystemBackend.random(), SystemBackend.random());
    assert!(
        SystemBackend
            .secrets()
            .env("MAILCTL_SURELY_UNSET_VARIABLE")
            .is_none()
    );
}
