//! The secret store of the desktop: collections of items (a label, attributes to look it up by, a secret), kept in one
//! file sealed with XChaCha20-Poly1305. The key is either made from a passphrase (Argon2id) or read from a key file that
//! only its owner can open. The D-Bus services in `main.rs` (`org.freedesktop.secrets` and the NetworkManager agent) are
//! thin wrappers over this.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"MRMVT1";
const HEADER: usize = 6 + 1 + 16 + 24;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// not a vault file, or damaged
    Format,
    /// the key does not open the file
    Key,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Format => write!(f, "not a vault file"),
            Error::Key => write!(f, "wrong passphrase or key"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

/// How the file's key is had.
pub enum Unlock<'a> {
    /// a passphrase typed by the user
    Passphrase(&'a str),
    /// a random key in a file (0600), made when missing
    KeyFile(&'a Path),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub id: u64,
    pub label: String,
    pub attrs: BTreeMap<String, String>,
    pub secret: Vec<u8>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

impl Item {
    /// every wanted attribute is present with the same value
    pub fn matches(&self, want: &BTreeMap<String, String>) -> bool {
        want.iter().all(|(k, v)| self.attrs.get(k) == Some(v))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Collection {
    /// the name in D-Bus paths (letters, digits, `_`)
    pub id: String,
    pub label: String,
    pub items: Vec<Item>,
    pub next_id: u64,
    pub created: u64,
    pub modified: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Store {
    pub collections: Vec<Collection>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A name that is safe inside an object path.
pub fn path_safe(s: &str) -> String {
    let id: String = s.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if id.is_empty() { "_".into() } else { id }
}

impl Store {
    pub fn collection(&self, id: &str) -> Option<&Collection> {
        self.collections.iter().find(|c| c.id == id)
    }

    pub fn collection_mut(&mut self, id: &str) -> Option<&mut Collection> {
        self.collections.iter_mut().find(|c| c.id == id)
    }

    /// A collection of this name, made when missing.
    pub fn ensure(&mut self, id: &str, label: &str) -> &mut Collection {
        if self.collection(id).is_none() {
            let t = now();
            self.collections.push(Collection { id: id.into(), label: label.into(), items: Vec::new(), next_id: 1, created: t, modified: t });
        }
        self.collection_mut(id).unwrap()
    }

    /// A free collection id near `want`.
    pub fn free_id(&self, want: &str) -> String {
        let base = path_safe(want);
        let mut id = base.clone();
        let mut n = 2;
        while self.collection(&id).is_some() {
            id = format!("{base}_{n}");
            n += 1;
        }
        id
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut o = Zeroizing::new(Vec::new());
        put_u32(&mut o, self.collections.len() as u32);
        for c in &self.collections {
            put_str(&mut o, &c.id);
            put_str(&mut o, &c.label);
            o.extend(c.next_id.to_le_bytes());
            o.extend(c.created.to_le_bytes());
            o.extend(c.modified.to_le_bytes());
            put_u32(&mut o, c.items.len() as u32);
            for i in &c.items {
                o.extend(i.id.to_le_bytes());
                put_str(&mut o, &i.label);
                put_str(&mut o, &i.content_type);
                o.extend(i.created.to_le_bytes());
                o.extend(i.modified.to_le_bytes());
                put_u32(&mut o, i.attrs.len() as u32);
                for (k, v) in &i.attrs {
                    put_str(&mut o, k);
                    put_str(&mut o, v);
                }
                put_u32(&mut o, i.secret.len() as u32);
                o.extend(&i.secret);
            }
        }
        o
    }

    pub fn decode(b: &[u8]) -> Option<Store> {
        let mut r = Reader { b, at: 0 };
        let mut store = Store::default();
        for _ in 0..r.u32()? {
            let id = r.string()?;
            let label = r.string()?;
            let (next_id, created, modified) = (r.u64()?, r.u64()?, r.u64()?);
            let mut items = Vec::new();
            for _ in 0..r.u32()? {
                let item_id = r.u64()?;
                let label = r.string()?;
                let content_type = r.string()?;
                let (created, modified) = (r.u64()?, r.u64()?);
                let mut attrs = BTreeMap::new();
                for _ in 0..r.u32()? {
                    attrs.insert(r.string()?, r.string()?);
                }
                let n = r.u32()? as usize;
                let secret = r.take(n)?.to_vec();
                items.push(Item { id: item_id, label, attrs, secret, content_type, created, modified });
            }
            store.collections.push(Collection { id, label, items, next_id, created, modified });
        }
        (r.at == b.len()).then_some(store)
    }
}

fn put_u32(o: &mut Vec<u8>, n: u32) {
    o.extend(n.to_le_bytes());
}

fn put_str(o: &mut Vec<u8>, s: &str) {
    put_u32(o, s.len() as u32);
    o.extend(s.as_bytes());
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn string(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system has no random source");
    b
}

/// 64 MiB, 3 passes: a guess costs the same on a thief's machine as it does here.
fn argon(m_kib: u32) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m_kib, 3, 1, Some(32)).expect("argon2 parameters"))
}

fn read_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, Error> {
    match std::fs::read(path) {
        Ok(b) if b.len() == 32 => Ok(Zeroizing::new(b.try_into().unwrap())),
        Ok(_) => Err(Error::Format),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = Zeroizing::new(random::<32>());
            write_private(path, &*key)?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

/// Writes through a temporary file that only the owner can open, so the contents are never readable by others.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

pub struct Vault {
    path: PathBuf,
    kdf: u8,
    salt: [u8; 16],
    argon_kib: u32,
    key: Zeroizing<[u8; 32]>,
    pub store: Store,
}

const KDF_KEYFILE: u8 = 0;
const KDF_ARGON: u8 = 1;
pub const ARGON_KIB: u32 = 64 * 1024;

impl Vault {
    /// Makes an empty vault and writes it.
    pub fn create(path: &Path, unlock: Unlock) -> Result<Vault, Error> {
        Vault::create_with(path, unlock, ARGON_KIB)
    }

    fn create_with(path: &Path, unlock: Unlock, argon_kib: u32) -> Result<Vault, Error> {
        let salt = random::<16>();
        let (kdf, key) = Vault::key_for(&unlock, &salt, argon_kib)?;
        let mut v = Vault { path: path.into(), kdf, salt, argon_kib, key, store: Store::default() };
        v.save()?;
        Ok(v)
    }

    pub fn open(path: &Path, unlock: Unlock) -> Result<Vault, Error> {
        Vault::open_with(path, unlock, ARGON_KIB)
    }

    fn open_with(path: &Path, unlock: Unlock, argon_kib: u32) -> Result<Vault, Error> {
        let file = std::fs::read(path)?;
        if file.len() < HEADER || &file[..6] != MAGIC {
            return Err(Error::Format);
        }
        let kdf = file[6];
        let salt: [u8; 16] = file[7..23].try_into().unwrap();
        let (want, key) = Vault::key_for(&unlock, &salt, argon_kib)?;
        if want != kdf {
            return Err(Error::Key);
        }
        let plain = XChaCha20Poly1305::new(key.as_slice().into())
            .decrypt(XNonce::from_slice(&file[23..HEADER]), Payload { msg: &file[HEADER..], aad: &file[..23] })
            .map_err(|_| Error::Key)?;
        let plain = Zeroizing::new(plain);
        let store = Store::decode(&plain).ok_or(Error::Format)?;
        Ok(Vault { path: path.into(), kdf, salt, argon_kib, key, store })
    }

    /// What a file of this kind is unlocked with (so a UI knows whether to ask for a passphrase).
    pub fn kind(path: &Path) -> Option<bool> {
        let mut head = [0u8; 7];
        std::io::Read::read_exact(&mut std::fs::File::open(path).ok()?, &mut head).ok()?;
        (&head[..6] == MAGIC).then_some(head[6] == KDF_ARGON)
    }

    fn key_for(unlock: &Unlock, salt: &[u8; 16], argon_kib: u32) -> Result<(u8, Zeroizing<[u8; 32]>), Error> {
        match unlock {
            Unlock::KeyFile(p) => Ok((KDF_KEYFILE, read_key_file(p)?)),
            Unlock::Passphrase(pw) => {
                let mut key = Zeroizing::new([0u8; 32]);
                argon(argon_kib).hash_password_into(pw.as_bytes(), salt, key.as_mut_slice()).map_err(|_| Error::Key)?;
                Ok((KDF_ARGON, key))
            }
        }
    }

    pub fn save(&mut self) -> Result<(), Error> {
        let mut head = Vec::with_capacity(HEADER);
        head.extend(MAGIC);
        head.push(self.kdf);
        head.extend(self.salt);
        let nonce = random::<24>();
        let sealed = XChaCha20Poly1305::new(self.key.as_slice().into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &self.store.encode(), aad: &head })
            .map_err(|_| Error::Format)?;
        head.extend(nonce);
        head.extend(sealed);
        write_private(&self.path, &head)?;
        Ok(())
    }

    /// Changes how the file is unlocked; the items stay.
    pub fn rekey(&mut self, unlock: Unlock) -> Result<(), Error> {
        self.salt = random::<16>();
        let (kdf, key) = Vault::key_for(&unlock, &self.salt, self.argon_kib)?;
        self.kdf = kdf;
        self.key = key;
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("memrium-secrets-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> Store {
        let mut s = Store::default();
        let c = s.ensure("login", "Login");
        c.items.push(Item {
            id: 1,
            label: "Wi-Fi: Home".into(),
            attrs: BTreeMap::from([("ssid".to_string(), "Home".to_string()), ("xdg:schema".to_string(), "org.freedesktop.NetworkManager.Connection".to_string())]),
            secret: b"hunter2\0\xff".to_vec(),
            content_type: "text/plain".into(),
            created: 1,
            modified: 2,
        });
        c.next_id = 2;
        s
    }

    #[test]
    fn a_store_survives_encoding() {
        let s = sample();
        assert_eq!(Store::decode(&s.encode()), Some(s));
    }

    #[test]
    fn damaged_or_truncated_input_is_refused() {
        let enc = sample().encode();
        for n in [0, 3, enc.len() / 2, enc.len() - 1] {
            assert_eq!(Store::decode(&enc[..n]), None);
        }
        let mut longer = enc.to_vec();
        longer.push(0);
        assert_eq!(Store::decode(&longer), None);
    }

    #[test]
    fn a_key_file_vault_reopens_and_the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("keyfile");
        let (file, key) = (d.join("vault.bin"), d.join("vault.key"));
        let mut v = Vault::create(&file, Unlock::KeyFile(&key)).unwrap();
        v.store = sample();
        v.save().unwrap();
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        let raw = std::fs::read(&file).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"hunter2"), "the secret must not be readable in the file");
        assert_eq!(Vault::open(&file, Unlock::KeyFile(&key)).unwrap().store, sample());
        assert_eq!(Vault::kind(&file), Some(false));
    }

    #[test]
    fn a_passphrase_vault_rejects_a_wrong_phrase_and_rekeys() {
        let d = dir("pass");
        let (file, key) = (d.join("vault.bin"), d.join("vault.key"));
        // a small memory cost keeps the test fast
        let mut v = Vault::create_with(&file, Unlock::Passphrase("correct horse"), 64).unwrap();
        v.store = sample();
        v.save().unwrap();
        assert_eq!(Vault::kind(&file), Some(true));
        assert!(matches!(Vault::open_with(&file, Unlock::Passphrase("wrong"), 64), Err(Error::Key)));
        assert!(matches!(Vault::open_with(&file, Unlock::KeyFile(&key), 64), Err(Error::Key)));
        let mut v = Vault::open_with(&file, Unlock::Passphrase("correct horse"), 64).unwrap();
        assert_eq!(v.store, sample());
        v.rekey(Unlock::KeyFile(&key)).unwrap();
        assert!(matches!(Vault::open_with(&file, Unlock::Passphrase("correct horse"), 64), Err(Error::Key)));
        assert_eq!(Vault::open_with(&file, Unlock::KeyFile(&key), 64).unwrap().store, sample());
    }

    #[test]
    fn a_flipped_byte_is_detected() {
        let d = dir("flip");
        let (file, key) = (d.join("vault.bin"), d.join("vault.key"));
        let mut v = Vault::create(&file, Unlock::KeyFile(&key)).unwrap();
        v.store = sample();
        v.save().unwrap();
        for at in [8, 30, std::fs::metadata(&file).unwrap().len() as usize - 1] {
            let mut raw = std::fs::read(&file).unwrap();
            raw[at] ^= 1;
            let copy = d.join("copy.bin");
            std::fs::write(&copy, raw).unwrap();
            assert!(Vault::open(&copy, Unlock::KeyFile(&key)).is_err());
        }
    }

    #[test]
    fn item_lookup_needs_every_attribute() {
        let s = sample();
        let item = &s.collection("login").unwrap().items[0];
        assert!(item.matches(&BTreeMap::from([("ssid".to_string(), "Home".to_string())])));
        assert!(!item.matches(&BTreeMap::from([("ssid".to_string(), "Other".to_string())])));
        assert!(!item.matches(&BTreeMap::from([("missing".to_string(), "x".to_string())])));
        assert!(item.matches(&BTreeMap::new()));
    }

    #[test]
    fn collection_ids_are_path_safe_and_unique() {
        let mut s = Store::default();
        assert_eq!(path_safe("my wallet/é"), "my_wallet__");
        s.ensure("work", "Work");
        assert_eq!(s.free_id("work"), "work_2");
    }
}
