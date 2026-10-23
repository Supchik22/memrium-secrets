//! `memrium_secrets`: the desktop's secret service. On the session bus it is `org.freedesktop.secrets` (what libsecret,
//! browsers, Telegram, git-credential-libsecret ... talk to); on the system bus it is a NetworkManager secret agent that
//! keeps Wi-Fi/VPN passwords in the same vault, under the same attributes nm-applet uses.
//!
//! The vault opens by itself with a key file, or (after `memrium_secrets passphrase`) asks for a passphrase through
//! `$MEMRIUM_ASKPASS <message>` (prints the answer on stdout) the first time something needs a secret.

mod agent;
mod service;

use memrium_secrets::{Unlock, Vault};
use std::path::PathBuf;
use std::sync::{atomic::AtomicU64, Mutex};

pub struct Shared {
    pub file: PathBuf,
    pub key_file: PathBuf,
    /// `None` while locked (a passphrase vault that was not unlocked yet)
    pub vault: Mutex<Option<Vault>>,
    pub sessions: Mutex<Vec<String>>,
    pub aliases: Mutex<std::collections::BTreeMap<String, String>>,
    pub next: AtomicU64,
    /// the session-bus connection serving the objects, once it is up
    pub session: std::sync::OnceLock<zbus::Connection>,
    /// object paths `service::sync` put on the bus (so it can take them off again)
    pub registered: Mutex<std::collections::BTreeSet<String>>,
}

impl Shared {
    /// Runs `f` on the store, and saves it when `f` says it changed something. `None` while locked.
    pub fn with_store<R>(&self, f: impl FnOnce(&mut memrium_secrets::Store) -> (R, bool)) -> Option<R> {
        let mut guard = self.vault.lock().ok()?;
        let vault = guard.as_mut()?;
        let (r, changed) = f(&mut vault.store);
        if changed {
            if let Err(e) = vault.save() {
                eprintln!("secrets: cannot save the vault: {e}");
            }
        }
        Some(r)
    }

    pub fn locked(&self) -> bool {
        self.vault.lock().map_or(true, |v| v.is_none())
    }

    /// Makes the bus objects match the store (after something else than a bus call changed it).
    pub fn resync(self: &std::sync::Arc<Self>) {
        if let Some(conn) = self.session.get() {
            zbus::block_on(service::sync(conn.object_server(), self));
        }
    }

    pub fn fresh(&self) -> u64 {
        self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Asks the user with the askpass program; `None` when they cancel or there is no program.
    pub fn ask(&self, message: &str) -> Option<String> {
        let program = std::env::var("MEMRIUM_ASKPASS").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "memrium_askpass".into());
        let out = std::process::Command::new(program).arg(message).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::inherit()).output().ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        let text = text.strip_suffix('\n').unwrap_or(&text).to_string();
        (out.status.success() && !text.is_empty()).then_some(text)
    }

    /// Opens a locked passphrase vault, asking for the phrase. Blocking (the key derivation takes a moment).
    pub fn unlock(self: &std::sync::Arc<Self>, message: &str) -> bool {
        if !self.locked() {
            return true;
        }
        let Some(pass) = self.ask(message) else { return false };
        match Vault::open(&self.file, Unlock::Passphrase(&pass)) {
            Ok(mut v) => {
                // the default collection always exists
                if v.store.collection("login").is_none() {
                    v.store.ensure("login", "Login");
                    let _ = v.save();
                }
                if let Ok(mut g) = self.vault.lock() {
                    *g = Some(v);
                }
                true
            }
            Err(e) => {
                eprintln!("secrets: cannot unlock: {e}");
                false
            }
        }
    }
}

fn data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p| p.is_absolute()).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share"))).unwrap_or_else(|| PathBuf::from("."));
    base.join("memrium")
}

/// `memrium_secrets passphrase`: switches the vault to a passphrase (read from the terminal), or back with `keyfile`.
fn change_mode(shared: &Shared, args: &[String]) -> Result<(), String> {
    let mut vault = match Vault::kind(&shared.file) {
        Some(true) => {
            let old = prompt("Current passphrase: ")?;
            Vault::open(&shared.file, Unlock::Passphrase(&old)).map_err(|e| e.to_string())?
        }
        Some(false) => Vault::open(&shared.file, Unlock::KeyFile(&shared.key_file)).map_err(|e| e.to_string())?,
        None => Vault::create(&shared.file, Unlock::KeyFile(&shared.key_file)).map_err(|e| e.to_string())?,
    };
    match args.first().map(String::as_str) {
        Some("passphrase") => {
            let a = prompt("New passphrase: ")?;
            if a.is_empty() || a != prompt("Again: ")? {
                return Err("the passphrases differ or are empty".into());
            }
            vault.rekey(Unlock::Passphrase(&a)).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&shared.key_file);
            println!("the vault now needs a passphrase");
        }
        _ => {
            vault.rekey(Unlock::KeyFile(&shared.key_file)).map_err(|e| e.to_string())?;
            println!("the vault now opens by itself (key file {})", shared.key_file.display());
        }
    }
    Ok(())
}

fn prompt(text: &str) -> Result<String, String> {
    use std::io::Write;
    print!("{text}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn main() {
    let dir = data_dir();
    let shared = std::sync::Arc::new(Shared {
        file: dir.join("vault.bin"),
        key_file: dir.join("vault.key"),
        vault: Mutex::new(None),
        sessions: Mutex::new(Vec::new()),
        aliases: Mutex::new(std::collections::BTreeMap::from([("default".to_string(), "login".to_string())])),
        next: AtomicU64::new(1),
        session: std::sync::OnceLock::new(),
        registered: Mutex::new(std::collections::BTreeSet::new()),
    });
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("passphrase" | "keyfile")) {
        if let Err(e) = change_mode(&shared, &args) {
            eprintln!("memrium_secrets: {e}");
            std::process::exit(1);
        }
        return;
    }
    // a vault that needs no passphrase is open from the start; a new one is made
    match Vault::kind(&shared.file) {
        Some(true) => eprintln!("secrets: the vault needs its passphrase (asked when first used)"),
        kind => {
            let opened = if kind.is_some() { Vault::open(&shared.file, Unlock::KeyFile(&shared.key_file)) } else { Vault::create(&shared.file, Unlock::KeyFile(&shared.key_file)) };
            match opened {
                Ok(mut v) => {
                    // the default collection always exists
                    if v.store.collection("login").is_none() {
                        v.store.ensure("login", "Login");
                        let _ = v.save();
                    }
                    *shared.vault.lock().unwrap() = Some(v);
                }
                Err(e) => {
                    eprintln!("secrets: cannot open {}: {e}", shared.file.display());
                    std::process::exit(1);
                }
            }
        }
    }
    let session = match service::serve(shared.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("secrets: cannot serve org.freedesktop.secrets: {e} (is another keyring running?)");
            std::process::exit(1);
        }
    };
    let _ = shared.session.set(session.clone());
    eprintln!("secrets: serving org.freedesktop.secrets");
    // the NetworkManager agent is optional: a machine without NetworkManager still gets the service
    let _system = match agent::serve(shared.clone()) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("secrets: no NetworkManager agent: {e}");
            None
        }
    };
    // the service ends with the session bus it was started on
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let ping = zbus::block_on(session.call_method(Some("org.freedesktop.DBus"), "/org/freedesktop/DBus", Some("org.freedesktop.DBus"), "GetId", &()));
        if ping.is_err() {
            eprintln!("secrets: the session bus is gone, leaving");
            return;
        }
    }
}
