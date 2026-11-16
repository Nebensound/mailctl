//! The real [`Backend`]: files, environment, macOS keychain, network.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::adapters::{imap::ImapStore, net::SystemNet, smtp::SmtpSender};
use crate::cli::Backend;
use crate::config::{AccountConfig, Secret, SecretLookup};
use crate::discover::Net;
use crate::error::Error;
use crate::store::{MailSender, MailStore};

/// Backend for production use.
#[derive(Debug, Default)]
pub struct SystemBackend;

impl SecretLookup for SystemBackend {
    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn keychain(&self, service: &str, account: &str) -> Result<String, String> {
        let output = Command::new("security")
            .args(["find-generic-password", "-s", service, "-a", account, "-w"])
            .output()
            .map_err(|e| format!("cannot run `security`: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "keychain item {service}/{account} not readable: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let password =
            String::from_utf8(output.stdout).map_err(|_| "password is not UTF-8".to_owned())?;
        Ok(password.trim_end_matches('\n').to_owned())
    }
}

impl Backend for SystemBackend {
    fn read_config(&self, path: Option<&PathBuf>) -> Result<String, Error> {
        let path = match path {
            Some(p) => p.clone(),
            None => std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".config/mailctl/config.toml"))
                .ok_or_else(|| Error::Config("HOME is not set; pass --config".into()))?,
        };
        std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }

    fn read_plan(&self, path: &Path) -> Result<String, Error> {
        if path.as_os_str() == "-" {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .map_err(|e| Error::InvalidInput(format!("stdin: {e}")))?;
            return Ok(text);
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
        Ok(Box::new(SmtpSender::new(account, secret)?))
    }

    fn unix_time(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn config_path(&self, explicit: Option<&PathBuf>) -> Result<PathBuf, Error> {
        match explicit {
            Some(path) => Ok(path.clone()),
            None => std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".config/mailctl/config.toml"))
                .ok_or_else(|| Error::Config("HOME is not set; pass --config".into())),
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(fail)?;
        }
        let temp = path.with_extension("toml.tmp");
        std::fs::write(&temp, text).map_err(fail)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
                .map_err(fail)?;
        }
        std::fs::rename(&temp, path).map_err(fail)
    }

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

    fn prompt_password(&self, prompt: &str) -> Result<Option<Secret>, Error> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        rpassword::prompt_password(prompt)
            .map(|p| Some(Secret::new(p)))
            .map_err(|e| Error::InvalidInput(e.to_string()))
    }

    fn read_stdin(&self) -> Result<String, Error> {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| Error::InvalidInput(format!("stdin: {e}")))?;
        Ok(text)
    }

    fn keychain_store(&self, service: &str, account: &str, secret: &Secret) -> Result<(), Error> {
        let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let command = format!(
            "add-generic-password -U -s {} -a {} -w {}\n",
            quote(service),
            quote(account),
            quote(secret.expose())
        );
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

    fn net(&self) -> Box<dyn Net> {
        Box::new(SystemNet::default())
    }

    fn check_smtp(&self, account: &AccountConfig, secret: &Secret) -> Result<(), Error> {
        SmtpSender::new(account, secret)?.check()
    }
}
