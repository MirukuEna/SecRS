// use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::manager::{SecurityConfig, SecurityManager};

pub type AppResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use sysinfo::{CpuRefreshKind, RefreshKind, System};

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub config: Arc<RwLock<SecurityConfig>>,
    pub manager: Arc<RwLock<SecurityManager>>,
    pub active_tab: usize,
    pub logs: Vec<String>,
    pub system: System,
}

impl App {
    pub fn new(config: Arc<RwLock<SecurityConfig>>, manager: Arc<RwLock<SecurityManager>>) -> Self {
        let system =
            System::new_with_specifics(RefreshKind::new().with_cpu(CpuRefreshKind::everything()));
        Self {
            running: true,
            config,
            manager,
            active_tab: 0,
            logs: Vec::new(),
            system,
        }
    }

    pub async fn tick(&mut self) {
        self.system.refresh_cpu();
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}
