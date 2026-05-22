use crate::error::{LocalPassError, Result};
use std::thread;
use std::time::Duration;

pub fn copy_and_clear_after(password: String, seconds: u64) -> Result<()> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|error| LocalPassError::Message(error.to_string()))?;
    clipboard
        .set_text(password.clone())
        .map_err(|error| LocalPassError::Message(error.to_string()))?;

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let _ = clipboard.set_text(String::new());
        }
    });

    Ok(())
}
