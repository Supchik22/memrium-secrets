//! `org.freedesktop.secrets`: the Secret Service API over the vault. Sessions use the `plain` transfer (the bus is the
//! user's own); items are looked up by attributes.

use crate::Shared;
use memrium_secrets::{now, Item, Store};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use zbus::{
    connection::Builder,
    interface,
    object_server::SignalEmitter,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
    Connection, ObjectServer,
};

pub const BUS: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
const NONE: &str = "/";

#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretError {
    #[zbus(error)]
    ZBus(zbus::Error),
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
}

/// `(session, parameters, value, content_type)`
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

fn op(s: impl AsRef<str>) -> OwnedObjectPath {
    OwnedObjectPath::try_from(s.as_ref().to_string()).expect("a valid object path")
}

fn coll_path(cid: &str) -> OwnedObjectPath {
    op(format!("{ROOT}/collection/{cid}"))
}

fn item_path(cid: &str, id: u64) -> OwnedObjectPath {
    op(format!("{ROOT}/collection/{cid}/{id}"))
}

/// `(collection, item)` of an item path, `(collection, None)` of a collection path.
fn parse(path: &str) -> Option<(String, Option<u64>)> {
    let rest = path.strip_prefix(ROOT)?.strip_prefix("/collection/")?;
    match rest.split_once('/') {
        None => Some((rest.to_string(), None)),
        Some((c, i)) => Some((c.to_string(), Some(i.parse().ok()?))),
    }
}

fn session_ok(shared: &Shared, session: &str) -> bool {
    shared.sessions.lock().map_or(false, |s| s.iter().any(|p| p == session))
}

fn secret_of(session: &str, item: &Item) -> Secret {
    (op(session), Vec::new(), item.secret.clone(), item.content_type.clone())
}

/// Every item in `store` that carries all of `want`, as `(collection, item)`.
fn search(store: &Store, want: &BTreeMap<String, String>) -> Vec<(String, u64)> {
    store.collections.iter().flat_map(|c| c.items.iter().filter(|i| i.matches(want)).map(move |i| (c.id.clone(), i.id))).collect()
}

/// Makes the objects on the bus match the store: new collections and items appear, those that are gone leave.
pub async fn sync(server: &ObjectServer, shared: &Arc<Shared>) {
    let list: Vec<(String, Vec<u64>)> = shared.with_store(|s| (s.collections.iter().map(|c| (c.id.clone(), c.items.iter().map(|i| i.id).collect())).collect(), false)).unwrap_or_default();
    let mut paths = std::collections::BTreeSet::new();
    for (cid, ids) in list {
        let _ = server.at(coll_path(&cid), Collection { shared: shared.clone(), id: cid.clone() }).await;
        paths.insert(coll_path(&cid).to_string());
        for id in ids {
            let _ = server.at(item_path(&cid, id), ItemObj { shared: shared.clone(), coll: cid.clone(), id }).await;
            paths.insert(item_path(&cid, id).to_string());
        }
    }
    let old = match shared.registered.lock() {
        Ok(mut r) => std::mem::replace(&mut *r, paths.clone()),
        Err(_) => return,
    };
    for gone in old.difference(&paths) {
        match parse(gone) {
            Some((c, None)) => drop(server.remove::<Collection, _>(coll_path(&c)).await),
            Some((c, Some(id))) => drop(server.remove::<ItemObj, _>(item_path(&c, id)).await),
            None => {}
        }
    }
}

struct Service {
    shared: Arc<Shared>,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(&self, algorithm: String, _input: Value<'_>, #[zbus(object_server)] server: &ObjectServer) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        if algorithm != "plain" {
            return Err(zbus::fdo::Error::NotSupported(format!("the session algorithm {algorithm} is not supported, use plain")));
        }
        let path = format!("{ROOT}/session/s{}", self.shared.fresh());
        server.at(path.as_str(), SessionObj { shared: self.shared.clone(), path: path.clone() }).await?;
        if let Ok(mut s) = self.shared.sessions.lock() {
            s.push(path.clone());
        }
        let empty = OwnedValue::try_from(Value::from("")).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok((empty, op(path)))
    }

    async fn create_collection(&self, properties: HashMap<String, OwnedValue>, alias: String, #[zbus(object_server)] server: &ObjectServer) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let label = properties.get("org.freedesktop.Secret.Collection.Label").and_then(|v| <&str>::try_from(v).ok()).unwrap_or("Collection").to_string();
        if self.shared.locked() {
            return Err(SecretError::IsLocked("the vault is locked".into()));
        }
        // an alias that names a collection that exists returns it
        let existing = (!alias.is_empty()).then(|| self.shared.aliases.lock().ok().and_then(|a| a.get(&alias).cloned())).flatten();
        let cid = match existing.filter(|c| self.shared.with_store(|s| (s.collection(c).is_some(), false)).unwrap_or(false)) {
            Some(c) => c,
            None => {
                let cid = self.shared.with_store(|s| {
                    let id = s.free_id(&if alias.is_empty() { label.clone() } else { alias.clone() });
                    s.ensure(&id, &label);
                    (id, true)
                });
                let cid = cid.ok_or_else(|| SecretError::IsLocked("the vault is locked".into()))?;
                if !alias.is_empty() {
                    if let Ok(mut a) = self.shared.aliases.lock() {
                        a.insert(alias, cid.clone());
                    }
                }
                server.at(coll_path(&cid), Collection { shared: self.shared.clone(), id: cid.clone() }).await?;
                cid
            }
        };
        Ok((coll_path(&cid), op(NONE)))
    }

    /// The items are sealed while the vault is locked, so a search has to open it first.
    async fn search_items(&self, attributes: BTreeMap<String, String>, #[zbus(object_server)] server: &ObjectServer) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        if self.shared.locked() {
            let shared = self.shared.clone();
            if blocking::unblock(move || shared.unlock("Unlock the secret vault")).await {
                sync(server, &self.shared).await;
            }
        }
        let found = self.shared.with_store(|s| (search(s, &attributes), false));
        match found {
            Some(list) => (list.into_iter().map(|(c, i)| item_path(&c, i)).collect(), Vec::new()),
            None => (Vec::new(), Vec::new()),
        }
    }

    /// Unlocking asks for the passphrase in a prompt; a vault with no passphrase is always open.
    async fn unlock(&self, objects: Vec<OwnedObjectPath>, #[zbus(object_server)] server: &ObjectServer) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        if !self.shared.locked() {
            return Ok((objects, op(NONE)));
        }
        let path = format!("{ROOT}/prompt/p{}", self.shared.fresh());
        server.at(path.as_str(), PromptObj { shared: self.shared.clone(), path: path.clone(), objects }).await?;
        Ok((Vec::new(), op(path)))
    }

    /// A vault that opens by itself has nothing to lock; a passphrase vault forgets its key.
    fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        if crate::Vault::kind(&self.shared.file) == Some(true) {
            if let Ok(mut v) = self.shared.vault.lock() {
                *v = None;
            }
            return (objects, op(NONE));
        }
        (Vec::new(), op(NONE))
    }

    fn get_secrets(&self, items: Vec<OwnedObjectPath>, session: ObjectPath<'_>) -> Result<HashMap<OwnedObjectPath, Secret>, SecretError> {
        if !session_ok(&self.shared, session.as_str()) {
            return Err(SecretError::NoSession("no such session".into()));
        }
        let out = self
            .shared
            .with_store(|s| {
                let mut out = HashMap::new();
                for p in items {
                    if let Some((c, Some(id))) = parse(p.as_str()) {
                        if let Some(i) = s.collection(&c).and_then(|c| c.items.iter().find(|i| i.id == id)) {
                            out.insert(p.clone(), secret_of(session.as_str(), i));
                        }
                    }
                }
                (out, false)
            })
            .ok_or_else(|| SecretError::IsLocked("the vault is locked".into()))?;
        Ok(out)
    }

    fn read_alias(&self, name: String) -> OwnedObjectPath {
        match self.shared.aliases.lock().ok().and_then(|a| a.get(&name).cloned()) {
            Some(c) => coll_path(&c),
            None => op(NONE),
        }
    }

    fn set_alias(&self, name: String, collection: OwnedObjectPath) {
        if let Ok(mut a) = self.shared.aliases.lock() {
            match parse(collection.as_str()) {
                Some((c, None)) => {
                    a.insert(name, c);
                }
                _ => {
                    a.remove(&name);
                }
            }
        }
    }

    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        self.shared.with_store(|s| (s.collections.iter().map(|c| coll_path(&c.id)).collect(), false)).unwrap_or_default()
    }
}

struct Collection {
    shared: Arc<Shared>,
    id: String,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    async fn delete(&self, #[zbus(object_server)] server: &ObjectServer) -> Result<OwnedObjectPath, SecretError> {
        let ids = self
            .shared
            .with_store(|s| {
                let ids: Vec<u64> = s.collection(&self.id).map(|c| c.items.iter().map(|i| i.id).collect()).unwrap_or_default();
                s.collections.retain(|c| c.id != self.id);
                (ids, true)
            })
            .ok_or_else(|| SecretError::IsLocked("the vault is locked".into()))?;
        for id in ids {
            let _ = server.remove::<ItemObj, _>(item_path(&self.id, id)).await;
        }
        let _ = server.remove::<Collection, _>(coll_path(&self.id)).await;
        Ok(op(NONE))
    }

    fn search_items(&self, attributes: BTreeMap<String, String>) -> Vec<OwnedObjectPath> {
        self.shared.with_store(|s| (search(s, &attributes).into_iter().filter(|(c, _)| *c == self.id).map(|(c, i)| item_path(&c, i)).collect(), false)).unwrap_or_default()
    }

    async fn create_item(&self, properties: HashMap<String, OwnedValue>, secret: Secret, replace: bool, #[zbus(object_server)] server: &ObjectServer) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        if !session_ok(&self.shared, secret.0.as_str()) {
            return Err(SecretError::NoSession("no such session".into()));
        }
        let label = properties.get("org.freedesktop.Secret.Item.Label").and_then(|v| <&str>::try_from(v).ok()).unwrap_or("").to_string();
        let attrs: BTreeMap<String, String> = properties.get("org.freedesktop.Secret.Item.Attributes").and_then(|v| HashMap::<String, String>::try_from(v.try_clone().ok()?).ok()).map(|m| m.into_iter().collect()).unwrap_or_default();
        let (value, content_type) = (secret.2, if secret.3.is_empty() { "text/plain".to_string() } else { secret.3 });
        let (id, fresh) = self
            .shared
            .with_store(|s| {
                let Some(c) = s.collection_mut(&self.id) else { return (None, false) };
                let t = now();
                if replace {
                    // an item with exactly these attributes is the one to replace
                    if let Some(i) = c.items.iter_mut().find(|i| i.attrs == attrs) {
                        (i.label, i.secret, i.content_type, i.modified) = (label.clone(), value.clone(), content_type.clone(), t);
                        return (Some((i.id, false)), true);
                    }
                }
                let id = c.next_id;
                c.next_id += 1;
                c.items.push(Item { id, label: label.clone(), attrs: attrs.clone(), secret: value.clone(), content_type: content_type.clone(), created: t, modified: t });
                c.modified = t;
                (Some((id, true)), true)
            })
            .ok_or_else(|| SecretError::IsLocked("the vault is locked".into()))?
            .ok_or_else(|| SecretError::NoSuchObject("no such collection".into()))?;
        if fresh {
            server.at(item_path(&self.id, id), ItemObj { shared: self.shared.clone(), coll: self.id.clone(), id }).await?;
        }
        Ok((item_path(&self.id, id), op(NONE)))
    }

    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        self.shared.with_store(|s| (s.collection(&self.id).map(|c| c.items.iter().map(|i| item_path(&c.id, i.id)).collect()).unwrap_or_default(), false)).unwrap_or_default()
    }

    #[zbus(property)]
    fn label(&self) -> String {
        self.shared.with_store(|s| (s.collection(&self.id).map(|c| c.label.clone()).unwrap_or_default(), false)).unwrap_or_else(|| self.id.clone())
    }

    #[zbus(property)]
    fn set_label(&self, label: String) {
        self.shared.with_store(|s| {
            if let Some(c) = s.collection_mut(&self.id) {
                c.label = label;
                c.modified = now();
            }
            ((), true)
        });
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.shared.locked()
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        self.shared.with_store(|s| (s.collection(&self.id).map_or(0, |c| c.created), false)).unwrap_or(0)
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.shared.with_store(|s| (s.collection(&self.id).map_or(0, |c| c.modified), false)).unwrap_or(0)
    }
}

struct ItemObj {
    shared: Arc<Shared>,
    coll: String,
    id: u64,
}

impl ItemObj {
    /// Reads the item, or changes it and saves.
    fn read<R>(&self, f: impl FnOnce(&Item) -> R) -> Option<R> {
        self.shared.with_store(|s| (s.collection(&self.coll).and_then(|c| c.items.iter().find(|i| i.id == self.id)).map(f), false)).flatten()
    }

    fn edit(&self, f: impl FnOnce(&mut Item)) {
        self.shared.with_store(|s| {
            if let Some(i) = s.collection_mut(&self.coll).and_then(|c| c.items.iter_mut().find(|i| i.id == self.id)) {
                f(i);
                i.modified = now();
            }
            ((), true)
        });
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemObj {
    async fn delete(&self, #[zbus(object_server)] server: &ObjectServer) -> Result<OwnedObjectPath, SecretError> {
        self.shared
            .with_store(|s| {
                if let Some(c) = s.collection_mut(&self.coll) {
                    c.items.retain(|i| i.id != self.id);
                }
                ((), true)
            })
            .ok_or_else(|| SecretError::IsLocked("the vault is locked".into()))?;
        let _ = server.remove::<ItemObj, _>(item_path(&self.coll, self.id)).await;
        Ok(op(NONE))
    }

    fn get_secret(&self, session: ObjectPath<'_>) -> Result<(Secret,), SecretError> {
        if !session_ok(&self.shared, session.as_str()) {
            return Err(SecretError::NoSession("no such session".into()));
        }
        if self.shared.locked() {
            return Err(SecretError::IsLocked("the vault is locked".into()));
        }
        self.read(|i| (secret_of(session.as_str(), i),)).ok_or_else(|| SecretError::NoSuchObject("no such item".into()))
    }

    fn set_secret(&self, secret: Secret) -> Result<(), SecretError> {
        if !session_ok(&self.shared, secret.0.as_str()) {
            return Err(SecretError::NoSession("no such session".into()));
        }
        if self.shared.locked() {
            return Err(SecretError::IsLocked("the vault is locked".into()));
        }
        self.edit(|i| {
            i.secret = secret.2;
            if !secret.3.is_empty() {
                i.content_type = secret.3;
            }
        });
        Ok(())
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.shared.locked()
    }

    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        self.read(|i| i.attrs.clone().into_iter().collect()).unwrap_or_default()
    }

    #[zbus(property)]
    fn set_attributes(&self, attrs: HashMap<String, String>) {
        self.edit(|i| i.attrs = attrs.into_iter().collect());
    }

    #[zbus(property)]
    fn label(&self) -> String {
        self.read(|i| i.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    fn set_label(&self, label: String) {
        self.edit(|i| i.label = label);
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        self.read(|i| i.created).unwrap_or(0)
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        self.read(|i| i.modified).unwrap_or(0)
    }
}

struct SessionObj {
    shared: Arc<Shared>,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionObj {
    async fn close(&self, #[zbus(object_server)] server: &ObjectServer) {
        if let Ok(mut s) = self.shared.sessions.lock() {
            s.retain(|p| *p != self.path);
        }
        let _ = server.remove::<SessionObj, _>(self.path.as_str()).await;
    }
}

struct PromptObj {
    shared: Arc<Shared>,
    path: String,
    objects: Vec<OwnedObjectPath>,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObj {
    /// Returns at once; the answer comes with `Completed` once the passphrase was asked and tried.
    async fn prompt(&self, _window_id: String, #[zbus(connection)] conn: &Connection) {
        let (shared, path, objects) = (self.shared.clone(), self.path.clone(), self.objects.clone());
        let spawner = conn.clone();
        let conn = conn.clone();
        let task = async move {
            let s2 = shared.clone();
            let opened = blocking::unblock(move || s2.unlock("Unlock the secret vault")).await;
            let server = conn.object_server();
            if opened {
                sync(server, &shared).await;
            }
            let result = OwnedValue::try_from(Value::from(if opened { objects } else { Vec::new() })).unwrap_or_else(|_| OwnedValue::from(0u8));
            if let Ok(e) = SignalEmitter::new(&conn, path.as_str()) {
                let _ = PromptObj::completed(&e, !opened, Value::from(result)).await;
            }
            let _ = server.remove::<PromptObj, _>(path.as_str()).await;
        };
        self.executor_spawn(&spawner, task);
    }

    async fn dismiss(&self, #[zbus(object_server)] server: &ObjectServer) {
        let _ = server.remove::<PromptObj, _>(self.path.as_str()).await;
    }

    #[zbus(signal)]
    async fn completed(emitter: &SignalEmitter<'_>, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
}

impl PromptObj {
    fn executor_spawn(&self, conn: &Connection, task: impl std::future::Future<Output = ()> + Send + 'static) {
        conn.executor().spawn(task, "secret prompt").detach();
    }
}

pub fn serve(shared: Arc<Shared>) -> zbus::Result<Connection> {
    zbus::block_on(async {
        let conn = Builder::session()?.name(BUS)?.serve_at(ROOT, Service { shared: shared.clone() })?.build().await?;
        let server = conn.object_server();
        // the alias path libsecret uses for the default collection
        let default = shared.aliases.lock().ok().and_then(|a| a.get("default").cloned()).unwrap_or_else(|| "login".into());
        server.at(coll_path(&default), Collection { shared: shared.clone(), id: default.clone() }).await?;
        server.at(format!("{ROOT}/aliases/default"), Collection { shared: shared.clone(), id: default }).await?;
        sync(server, &shared).await;
        Ok(conn)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_paths_round_trip() {
        assert_eq!(parse(coll_path("login").as_str()), Some(("login".into(), None)));
        assert_eq!(parse(item_path("login", 7).as_str()), Some(("login".into(), Some(7))));
        assert_eq!(parse("/org/freedesktop/secrets/collection/login/x"), None);
        assert_eq!(parse("/elsewhere"), None);
    }
}
