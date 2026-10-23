//! Memrium Askpass: a small window that asks for one password and prints it on stdout (nothing on Esc, Cancel or when the
//! window is closed; the exit code tells). `memrium_secrets` runs it to unlock the vault and to ask for network passwords:
//! `memrium_askpass "Password for Home"`.

use chebrium::app::{self, App, Config, Host};
use chebrium::draw::Align;
use chebrium::input::{Key, KeyMods};
use chebrium::ui::Ui;
use std::sync::{Arc, Mutex};

struct Ask {
    message: String,
    value: String,
    started: bool,
    answer: Arc<Mutex<Option<String>>>,
}

impl App for Ask {
    fn draw(&mut self, ui: &mut Ui<'_>, size: [f32; 2], host: &mut Host) {
        let (w, ink) = (size[0], ui.ink);
        // the field is always being typed in: a click elsewhere or Esc only ends one edit
        if !self.started || !ui.editing() {
            ui.begin_edit("password", &self.value);
            self.started = true;
        }
        ui.glyph(34.0, 38.0, 22.0, "lock", ink, 0.9);
        ui.text(58.0, 44.0, &self.message, 14.5, true, ink, 0.95, Align::Left);
        let field = [24.0, 70.0, w - 48.0, 36.0];
        let entered = ui.password_field(field, "password", &mut self.value);
        let cancel = [w - 24.0 - 96.0 - 8.0 - 96.0, size[1] - 24.0 - 32.0, 96.0, 32.0];
        let ok = [w - 24.0 - 96.0, size[1] - 24.0 - 32.0, 96.0, 32.0];
        let pressed = ui.button(ok, "OK", true);
        if ui.button(cancel, "Cancel", false) {
            host.quit = true;
        } else if (entered || pressed) && !self.value.is_empty() {
            *self.answer.lock().unwrap() = Some(std::mem::take(&mut self.value));
            host.quit = true;
        }
    }

    fn key(&mut self, key: Key, _mods: KeyMods, host: &mut Host) {
        if key == Key::Esc {
            host.quit = true;
        }
    }
}

fn main() {
    let message = std::env::args().nth(1).unwrap_or_else(|| "Password".into());
    let answer = Arc::new(Mutex::new(None));
    let mut config = Config::new("Memrium Secrets", "memrium-askpass").size(420, 180);
    config.resizable = false;
    app::run(config, Ask { message, value: String::new(), started: false, answer: answer.clone() });
    let taken = answer.lock().unwrap().take();
    match taken {
        Some(pw) => println!("{pw}"),
        None => std::process::exit(1),
    }
}
