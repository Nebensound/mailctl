//! The real [`Backend`]: files, environment, macOS keychain, network.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::adapters::{imap::ImapStore, net::SystemNet, smtp::SmtpSender};
use crate::cli::Backend;
use crate::config::{
    AccountConfig, Secret, SecretLookup, keychain_password, keychain_store_command,
};
use crate::discover::Net;
use crate::error::Error;
use crate::store::{MailSender, MailStore};

/// Backend for production use.
#[derive(Debug, Default)]
pub struct SystemBackend;

// Coverage: runs the macOS `security` tool and reads the process environment.
#[cfg_attr(coverage_nightly, coverage(off))]
impl SecretLookup for SystemBackend {
    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn keychain(&self, service: &str, account: &str) -> Result<String, String> {
        let output = Command::new("security")
            .args(["find-generic-password", "-s", service, "-a", account, "-g"])
            .output()
            .map_err(|e| format!("cannot run `security`: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "keychain item {service}/{account} not readable: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        keychain_password(&String::from_utf8_lossy(&output.stderr))
    }
}

impl Backend for SystemBackend {
    fn read_config(&self, path: Option<&PathBuf>) -> Result<String, Error> {
        self.config_path(path).and_then(|path| {
            std::fs::read_to_string(&path)
                .map_err(|e| Error::Config(format!("{}: {e}", path.display())))
        })
    }

    // Coverage: reads a file or standard input; the plan itself is tested in `plan`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_plan(&self, path: &Path) -> Result<String, Error> {
        if path.as_os_str() == "-" {
            return self.read_stdin();
        }
        std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidInput(format!("{}: {e}", path.display())))
    }

    fn secrets(&self) -> &dyn SecretLookup {
        self
    }

    fn connect(
        &self,
        account: &AccountConfig,
        secret: &Secret,
    ) -> Result<Box<dyn MailStore>, Error> {
        Ok(Box::new(ImapStore::connect(account, secret)?))
    }

    fn sender(
        &self,
        account: &AccountConfig,
        secret: &Secret,
    ) -> Result<Box<dyn MailSender>, Error> {
        SmtpSender::new(account, secret).map(|sender| Box::new(sender) as Box<dyn MailSender>)
    }

    fn unix_time(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn random(&self) -> u64 {
        use std::hash::{BuildHasher as _, Hasher as _};
        // Every `RandomState` is seeded from the operating system's randomness.
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    }

    fn config_path(&self, explicit: Option<&PathBuf>) -> Result<PathBuf, Error> {
        match explicit {
            Some(path) => Ok(path.clone()),
            None => std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".config/mailctl/config.toml"))
                .ok_or(Error::Config("HOME is not set; pass --config".into())),
        }
    }

    fn read_optional(&self, path: &Path) -> Result<Option<String>, Error> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Config(format!("{}: {e}", path.display()))),
        }
    }

    fn write_file(&self, path: &Path, text: &str) -> Result<(), Error> {
        let fail = |e: std::io::Error| Error::Config(format!("{}: {e}", path.display()));
        // Write through a symlink (e.g. into a dotfiles repository) instead of
        // replacing it with a regular file.
        let target = match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                std::fs::canonicalize(path).map_err(fail)?
            }
            _ => path.to_path_buf(),
        };
        let dir = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(fail)?;
        // A unique name in the same directory, created exclusively and
        // readable only by the owner from the start.
        let name = target
            .file_name()
            .map_or(String::from("config"), |n| n.to_string_lossy().into_owned());
        let temp = dir.join(format!(
            ".{name}.{}.{:016x}.tmp",
            std::process::id(),
            self.random()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let written = options.open(&temp).and_then(|mut file| {
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
        });
        let result = written.and_then(|()| std::fs::rename(&temp, &target));
        if result.is_err() {
            // Best effort: do not leave the temporary file behind.
            let _ = std::fs::remove_file(&temp);
        }
        result.map_err(fail)
    }

    // Coverage: needs an interactive terminal.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prompt_line(&self, question: &str, default: Option<&str>) -> Result<Option<String>, Error> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        let shown = default.map_or_else(
            || format!("{question}: "),
            |d| format!("{question} [{d}]: "),
        );
        std::io::stderr()
            .write_all(shown.as_bytes())
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        Ok(Some(line.trim_end_matches(['\r', '\n']).to_owned()))
    }

    // Coverage: needs an interactive terminal.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prompt_password(&self, prompt: &str) -> Result<Option<Secret>, Error> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        rpassword::prompt_password(prompt)
            .map(|p| Some(Secret::new(p)))
            .map_err(|e| Error::InvalidInput(e.to_string()))
    }

    // Coverage: reads the process's standard input.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_stdin(&self) -> Result<String, Error> {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| Error::InvalidInput(format!("stdin: {e}")))?;
        Ok(text)
    }

    // Coverage: runs the macOS `security` tool; the command is `config::keychain_store_command`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn keychain_store(&self, service: &str, account: &str, secret: &Secret) -> Result<(), Error> {
        let command = keychain_store_command(service, account, secret)?;
        let fail = |reason: String| Error::Secret {
            account: account.to_owned(),
            reason,
        };
        let mut child = Command::new("security")
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| fail(format!("cannot run `security`: {e}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| fail("no stdin for `security`".into()))?
            .write_all(command.as_bytes())
            .map_err(|e| fail(e.to_string()))?;
        let output = child.wait_with_output().map_err(|e| fail(e.to_string()))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() && stderr.trim().is_empty() {
            Ok(())
        } else {
            Err(fail(format!("keychain write failed: {}", stderr.trim())))
        }
    }

    // Coverage: runs the macOS `security` tool.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn keychain_delete(&self, service: &str, account: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::Secret {
            account: account.to_owned(),
            reason,
        };
        let output = Command::new("security")
            .args(["delete-generic-password", "-s", service, "-a", account])
            .output()
            .map_err(|e| fail(e.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(fail(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }

    // Coverage: returns the real network.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn net(&self) -> Box<dyn Net> {
        Box::new(SystemNet::default())
    }

    fn check_smtp(&self, account: &AccountConfig, secret: &Secret) -> Result<(), Error> {
        SmtpSender::new(account, secret).and_then(|sender| sender.check())
    }
}

#[cfg(test)]
#[path = "../tests/system.rs"]
mod tests;
