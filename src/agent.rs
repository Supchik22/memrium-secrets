//! A NetworkManager secret agent: NetworkManager asks it for the passwords of connections whose secrets are "agent
//! owned" (`psk-flags=1`), tells it to keep the ones it learned, and to forget them. They live in the vault under the
//! attributes nm-applet uses, so a vault shared with GNOME's keyring tools stays readable.

use crate::Shared;
use memrium_secrets::{now, Item};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use zbus::{
    connection::Builder,
    interface,
    zvariant::{ObjectPath, OwnedValue, Value},
    Connection,
};

const SCHEMA: &str = "org.freedesktop.NetworkManager.Connection";
const IDENTIFIER: &str = "io.github.supchik22.Memrium.SecretAgent";
const FLAG_ALLOW_INTERACTION: u32 = 0x1;
const FLAG_REQUEST_NEW: u32 = 0x2;
const FLAG_ONLY_SYSTEM: u32 = 0x8000_0000;

/// The secret properties of each setting NetworkManager can ask about.
const SECRET_KEYS: &[(&str, &[&str])] = &[
    ("802-11-wireless-security", &["psk", "wep-key0", "wep-key1", "wep-key2", "wep-key3", "leap-password"]),
    ("802-1x", &["password", "private-key-password", "phase2-private-key-password", "pin"]),
    ("pppoe", &["password"]),
    ("gsm", &["password", "pin"]),
    ("cdma", &["password"]),
    ("wireguard", &["private-key"]),
];

type ConnDict = HashMap<String, HashMap<String, OwnedValue>>;

#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "org.freedesktop.NetworkManager.SecretAgent.Error")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NoSecrets(String),
    UserCanceled(String),
    InvalidConnection(String),
}

fn keys_of(setting: &str) -> &'static [&'static str] {
    SECRET_KEYS.iter().find(|(s, _)| *s == setting).map_or(&[], |(_, k)| *k)
}

fn text(conn: &ConnDict, setting: &str, key: &str) -> Option<String> {
    <&str>::try_from(conn.get(setting)?.get(key)?).ok().map(str::to_string)
}

/// `(uuid, id)` of the connection.
fn who(conn: &ConnDict) -> Option<(String, String)> {
    let uuid = text(conn, "connection", "uuid")?;
    Some((uuid.clone(), text(conn, "connection", "id").unwrap_or(uuid)))
}

fn attrs(uuid: &str, setting: &str, key: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("xdg:schema".into(), SCHEMA.into()), ("connection-uuid".into(), uuid.into()), ("setting-name".into(), setting.into()), ("setting-key".into(), key.into())])
}

/// The secret the user is asked for when none is kept.
fn primary(conn: &ConnDict, setting: &str) -> &'static str {
    if setting == "802-11-wireless-security" && text(conn, setting, "key-mgmt").as_deref() == Some("none") {
        return "wep-key0";
    }
    keys_of(setting).first().copied().unwrap_or("password")
}

fn load(shared: &Shared, uuid: &str, setting: &str, key: &str) -> Option<String> {
    let want = attrs(uuid, setting, key);
    shared.with_store(|s| (s.collection("login").and_then(|c| c.items.iter().find(|i| i.matches(&want))).and_then(|i| String::from_utf8(i.secret.clone()).ok()), false)).flatten()
}

fn store(shared: &Arc<Shared>, id: &str, uuid: &str, setting: &str, key: &str, secret: &str) {
    let want = attrs(uuid, setting, key);
    let label = format!("Network secret for {id}/{setting}/{key}");
    shared.with_store(|s| {
        let c = s.ensure("login", "Login");
        let t = now();
        if let Some(i) = c.items.iter_mut().find(|i| i.attrs == want) {
            (i.label, i.secret, i.modified) = (label, secret.as_bytes().to_vec(), t);
        } else {
            let item_id = c.next_id;
            c.next_id += 1;
            c.items.push(Item { id: item_id, label, attrs: want, secret: secret.as_bytes().to_vec(), content_type: "text/plain".into(), created: t, modified: t });
        }
        ((), true)
    });
    shared.resync();
}

struct Agent {
    shared: Arc<Shared>,
}

#[interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl Agent {
    async fn get_secrets(&self, connection: ConnDict, _connection_path: ObjectPath<'_>, setting_name: String, _hints: Vec<String>, flags: u32) -> Result<ConnDict, AgentError> {
        let (uuid, id) = who(&connection).ok_or_else(|| AgentError::InvalidConnection("the connection has no uuid".into()))?;
        if flags & FLAG_ONLY_SYSTEM != 0 || keys_of(&setting_name).is_empty() {
            return Err(AgentError::NoSecrets("this agent keeps no secrets of that kind".into()));
        }
        let interactive = flags & FLAG_ALLOW_INTERACTION != 0;
        let primary = primary(&connection, &setting_name);
        let (shared, setting) = (self.shared.clone(), setting_name.clone());
        // everything below may wait for the user, so it runs off the bus thread
        let answer = blocking::unblock(move || -> Result<(String, String), AgentError> {
            if shared.locked() && !(interactive && shared.unlock("Unlock the secret vault")) {
                return Err(AgentError::NoSecrets("the vault is locked".into()));
            }
            // a password NetworkManager asks to replace was refused: it is not offered again
            if flags & FLAG_REQUEST_NEW == 0 {
                for key in keys_of(&setting) {
                    if let Some(v) = load(&shared, &uuid, &setting, key) {
                        return Ok(((*key).to_string(), v));
                    }
                }
            }
            if !interactive {
                return Err(AgentError::NoSecrets("no secret is kept and the user may not be asked".into()));
            }
            let what = if flags & FLAG_REQUEST_NEW != 0 { "The password was not accepted. Password for" } else { "Password for" };
            match shared.ask(&format!("{what} {id}")) {
                Some(v) => {
                    store(&shared, &id, &uuid, &setting, primary, &v);
                    Ok((primary.to_string(), v))
                }
                None => Err(AgentError::UserCanceled("the password was not given".into())),
            }
        })
        .await?;
        let value = OwnedValue::try_from(Value::from(answer.1)).map_err(|e| AgentError::ZBus(e.into()))?;
        Ok(HashMap::from([(setting_name, HashMap::from([(answer.0, value)]))]))
    }

    fn cancel_get_secrets(&self, _connection_path: ObjectPath<'_>, _setting_name: String) {}

    async fn save_secrets(&self, connection: ConnDict, _connection_path: ObjectPath<'_>) -> Result<(), AgentError> {
        let (uuid, id) = who(&connection).ok_or_else(|| AgentError::InvalidConnection("the connection has no uuid".into()))?;
        let shared = self.shared.clone();
        blocking::unblock(move || {
            for (setting, keys) in SECRET_KEYS {
                for key in *keys {
                    if let Some(v) = text(&connection, setting, key).filter(|v| !v.is_empty()) {
                        store(&shared, &id, &uuid, setting, key, &v);
                    }
                }
            }
        })
        .await;
        Ok(())
    }

    async fn delete_secrets(&self, connection: ConnDict, _connection_path: ObjectPath<'_>) -> Result<(), AgentError> {
        let (uuid, _) = who(&connection).ok_or_else(|| AgentError::InvalidConnection("the connection has no uuid".into()))?;
        let shared = self.shared.clone();
        blocking::unblock(move || {
            shared.with_store(|s| {
                if let Some(c) = s.collection_mut("login") {
                    c.items.retain(|i| !(i.attrs.get("xdg:schema").map(String::as_str) == Some(SCHEMA) && i.attrs.get("connection-uuid") == Some(&uuid)));
                }
                ((), true)
            });
            shared.resync();
        })
        .await;
        Ok(())
    }
}

async fn register(conn: &Connection) -> zbus::Result<()> {
    conn.call_method(Some("org.freedesktop.NetworkManager"), "/org/freedesktop/NetworkManager/AgentManager", Some("org.freedesktop.NetworkManager.AgentManager"), "Register", &IDENTIFIER).await?;
    eprintln!("secrets: registered as a NetworkManager agent");
    Ok(())
}

pub fn serve(shared: Arc<Shared>) -> zbus::Result<Connection> {
    if std::env::var_os("MEMRIUM_NO_NM_AGENT").is_some() {
        return Err(zbus::Error::Failure("MEMRIUM_NO_NM_AGENT is set".into()));
    }
    zbus::block_on(async {
        let test = std::env::var_os("MEMRIUM_NM_TEST_BUS").is_some();
        let builder = if test { Builder::session()?.name(IDENTIFIER)? } else { Builder::system()? };
        let conn = builder.serve_at("/org/freedesktop/NetworkManager/SecretAgent", Agent { shared })?.build().await?;
        if test {
            return Ok(conn);
        }
        register(&conn).await?;
        // NetworkManager forgets its agents when it restarts: register again when it comes back
        let again = conn.clone();
        conn.executor()
            .spawn(
                async move {
                    use futures_util::StreamExt;
                    let Ok(bus) = zbus::fdo::DBusProxy::new(&again).await else { return };
                    let Ok(mut changes) = bus.receive_name_owner_changed_with_args(&[(0, "org.freedesktop.NetworkManager")]).await else { return };
                    while let Some(change) = changes.next().await {
                        if change.args().is_ok_and(|a| a.new_owner().is_some()) {
                            let _ = register(&again).await;
                        }
                    }
                },
                "nm agent re-register",
            )
            .detach();
        Ok(conn)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(key_mgmt: &str) -> ConnDict {
        let v = |s: &str| OwnedValue::try_from(Value::from(s)).unwrap();
        HashMap::from([
            ("connection".to_string(), HashMap::from([("uuid".to_string(), v("u-1")), ("id".to_string(), v("Home"))])),
            ("802-11-wireless-security".to_string(), HashMap::from([("key-mgmt".to_string(), v(key_mgmt))])),
        ])
    }

    #[test]
    fn the_connection_is_known_by_uuid_and_name() {
        assert_eq!(who(&conn("wpa-psk")), Some(("u-1".into(), "Home".into())));
        assert_eq!(who(&HashMap::new()), None);
    }

    #[test]
    fn the_password_asked_for_depends_on_the_security() {
        assert_eq!(primary(&conn("wpa-psk"), "802-11-wireless-security"), "psk");
        assert_eq!(primary(&conn("none"), "802-11-wireless-security"), "wep-key0");
        assert_eq!(primary(&conn("wpa-eap"), "802-1x"), "password");
    }

    #[test]
    fn attributes_match_what_nm_applet_writes() {
        let a = attrs("u-1", "802-11-wireless-security", "psk");
        assert_eq!(a.get("xdg:schema").map(String::as_str), Some("org.freedesktop.NetworkManager.Connection"));
        assert_eq!(a.len(), 4);
    }
}
