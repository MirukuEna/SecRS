use crate::ui::app::App;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub async fn handle_key_events(key_event: KeyEvent, app: &mut App) -> anyhow::Result<()> {
    match key_event.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.quit();
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            if key_event.modifiers == KeyModifiers::CONTROL {
                app.quit();
            }
        }
        KeyCode::Tab => {
            // Cycle tabs
            app.active_tab = (app.active_tab + 1) % 3; // Assuming 3 tabs
        }
        _ => {}
    }
    Ok(())
}
