pub mod app;
pub mod handler;
pub mod tui;
pub mod ui;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::manager::{SecurityConfig, SecurityManager};

pub async fn run(
    config: Arc<RwLock<SecurityConfig>>,
    manager: Arc<RwLock<SecurityManager>>,
) -> Result<()> {
    // TUI initialization logic will go here
    let mut app = app::App::new(config, manager);
    let backend = ratatui::backend::CrosstermBackend::new(std::io::stderr());
    let terminal = ratatui::Terminal::new(backend)?;
    let events = tui::EventHandler::new(250);
    let mut tui = tui::Tui::new(terminal, events);

    // Register TUI log listener
    {
        let manager_write = app.manager.write().await;
        let sender = tui.events.sender();
        manager_write
            .register_listener(move |msg| {
                let _ = sender.send(tui::Event::Log(msg));
            })
            .await;
    }

    tui.init()?;

    while app.running {
        tui.draw(&mut app)?;

        match tui.events.next().await? {
            tui::Event::Tick => app.tick().await,
            tui::Event::Key(key) => {
                if key.code == crossterm::event::KeyCode::Char('s') {
                    // Trigger simulation
                    let manager_clone = app.manager.clone();
                    tokio::spawn(async move {
                        let mut manager = manager_clone.write().await;
                        let _ = manager
                            .process_security_event(
                                crate::core::manager::SecurityEvent::CommandExecution {
                                    command: "rm -rf / --no-preserve-root".to_string(),
                                    user: "intruder".to_string(),
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                    success: false,
                                },
                            )
                            .await;
                    });
                }
                handler::handle_key_events(key, &mut app).await?
            }
            tui::Event::Mouse(_) => {}
            tui::Event::Resize(_, _) => {}
            tui::Event::Log(msg) => {
                app.logs.push(msg);
                if app.logs.len() > 100 {
                    app.logs.remove(0);
                }
            }
        }
    }

    tui.exit()?;
    Ok(())
}
