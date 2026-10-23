# memrium-secrets

The secret service of the [Memrium](https://github.com/Supchik22/memrium-desktop) desktop.

- `memrium_secrets`: `org.freedesktop.secrets` on the session bus (what libsecret, browsers, Telegram or
  git-credential-libsecret talk to) and a NetworkManager secret agent on the system bus, over one vault encrypted with
  ChaCha20-Poly1305 (key from a key file, or from a passphrase through Argon2).
- `memrium_askpass`: a small Chebrium window that asks for one password and prints it on stdout. The vault runs it to ask for the
  passphrase.

```
cargo run --release --bin memrium_secrets
```

License: MIT.
