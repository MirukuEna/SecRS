use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Tabs},
    Frame,
};

use crate::ui::app::App;

pub fn render(app: &mut App, frame: &mut Frame) {
    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Footer
            ]
            .as_ref(),
        )
        .split(frame.size());

    render_header(app, frame, chunks[0]);
    render_content(app, frame, chunks[1]);
    render_footer(app, frame, chunks[2]);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let titles = vec!["Monitor", "Logs", "Config"]
        .iter()
        .map(|t| {
            let (first, rest) = t.split_at(1);
            Line::from(vec![
                Span::styled(first, Style::default().fg(Color::Yellow)),
                Span::styled(rest, Style::default().fg(Color::Green)),
            ])
        })
        .collect::<Vec<Line>>();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("SecRS Dashboard"),
        )
        .select(app.active_tab)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Yellow),
        );

    frame.render_widget(tabs, area);
}

fn render_content(app: &mut App, frame: &mut Frame, area: Rect) {
    match app.active_tab {
        0 => render_monitor(app, frame, area),
        1 => render_logs(app, frame, area),
        2 => render_config(app, frame, area),
        _ => {}
    }
}

pub fn render_monitor(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);

    let activity_logs: Vec<ListItem> = app
        .logs
        .iter()
        .rev()
        .filter(|log| {
            log.contains("[SCAN]")
                || log.contains("[PROC]")
                || log.contains("[NET]")
                || log.contains("Monitoring")
        })
        .take(20)
        .map(|log| {
            ListItem::new(Line::from(Span::styled(
                log,
                Style::default().fg(Color::Cyan),
            )))
        })
        .collect();

    let threat_logs: Vec<ListItem> = app
        .logs
        .iter()
        .rev()
        .filter(|log| {
            !log.contains("[SCAN]")
                && !log.contains("[PROC]")
                && !log.contains("[NET]")
                && !log.contains("Monitoring")
        })
        .take(10)
        .map(|log| {
            ListItem::new(Line::from(Span::styled(
                log,
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            )))
        })
        .collect();

    let left_block = List::new(activity_logs).block(
        Block::default()
            .title("Live System Activity")
            .borders(Borders::ALL),
    );

    let right_block = List::new(threat_logs).block(
        Block::default()
            .title("Active Threats")
            .borders(Borders::ALL),
    );

    frame.render_widget(left_block, chunks[0]);
    frame.render_widget(right_block, chunks[1]);

    // Real CPU Usage
    let cpu_usage = app.system.global_cpu_info().cpu_usage();
    let gauge = Gauge::default()
        .block(Block::default().title("CPU Usage").borders(Borders::ALL))
        .gauge_style(
            Style::default()
                .fg(Color::Magenta)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .percent(cpu_usage as u16);

    let gauge_area = Rect {
        x: chunks[0].x + 1,
        y: chunks[0].y + 1,
        width: chunks[0].width - 2,
        height: 3,
    };

    frame.render_widget(gauge, gauge_area);
}

fn render_logs(app: &mut App, frame: &mut Frame, area: Rect) {
    let logs: Vec<ListItem> = app
        .logs
        .iter()
        .map(|log| {
            let content = Line::from(Span::raw(log));
            ListItem::new(content)
        })
        .collect();

    let logs_list = List::new(logs)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Security Logs"),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(logs_list, area);
}

fn render_config(_app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title("Configuration")
        .borders(Borders::ALL);
    frame.render_widget(block, area);
}

fn render_footer(_app: &App, frame: &mut Frame, area: Rect) {
    let text = Line::from(vec![
        Span::raw("Press "),
        Span::styled(
            "q",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" to exit, "),
        Span::styled(
            "Tab",
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" to switch tabs"),
    ]);

    let paragraph = Paragraph::new(text).block(Block::default().borders(Borders::ALL));

    frame.render_widget(paragraph, area);
}
