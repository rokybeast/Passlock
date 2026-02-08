use super::super::app::App;
use super::super::colors::GruvboxColors;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn draw_search_pwd(f: &mut Frame, size: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(size);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::blue()))
        .title("═══ SEARCH PASSWORDS ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, size);
    let title = Paragraph::new("Search by name, username, URL, or tags")
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    let search = Paragraph::new(format!("Search: {}", app.search_query)).style(
        Style::default()
            .fg(GruvboxColors::green())
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(search, chunks[1]);
    if app.entry_disp.is_empty() && !app.search_query.is_empty() {
        let empty = Paragraph::new("[ No matches found ]")
            .style(Style::default().fg(GruvboxColors::gray()))
            .alignment(Alignment::Center);
        f.render_widget(empty, chunks[2]);
    } else if !app.entry_disp.is_empty() {
        let items: Vec<ListItem> = app
            .entry_disp
            .iter()
            .map(|entry| {
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("• ", Style::default().fg(GruvboxColors::orange())),
                        Span::styled(
                            &entry.n,
                            Style::default()
                                .fg(GruvboxColors::yellow())
                                .add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("  User: ", Style::default().fg(GruvboxColors::gray())),
                        Span::styled(&entry.u, Style::default().fg(GruvboxColors::blue())),
                    ]),
                    Line::from(vec![
                        Span::styled("  Pass: ", Style::default().fg(GruvboxColors::gray())),
                        Span::styled(&entry.p, Style::default().fg(GruvboxColors::green())),
                    ]),
                ];
                if !entry.tags.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("  Tags: ", Style::default().fg(GruvboxColors::gray())),
                        Span::styled(
                            entry.tags.join(", "),
                            Style::default().fg(GruvboxColors::orange()),
                        ),
                    ]));
                }
                lines.push(Line::from(""));
                ListItem::new(lines)
            })
            .collect();
        let list = List::new(items).block(Block::default().borders(Borders::NONE));
        f.render_widget(list, chunks[2]);
    }
    let help = Paragraph::new("Type to search │ Enter: View results │ Esc: Back")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}

pub fn draw_gen_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(60, 50, size);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::aqua()))
        .title("═══ GENERATE PASSWORD ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, area);
    let title = Paragraph::new("Enter password length (4-64)")
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    let length_input = Paragraph::new(format!(
        "Length: {}",
        if app.input_buffer.is_empty() {
            "16"
        } else {
            &app.input_buffer
        }
    ))
    .style(
        Style::default()
            .fg(GruvboxColors::green())
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(length_input, chunks[1]);
    if !app.gen_pwd.is_empty() {
        let generated = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "Generated Password:",
                Style::default().fg(GruvboxColors::gray()),
            )),
            Line::from(""),
            Line::from(Span::styled(
                &app.gen_pwd,
                Style::default()
                    .fg(GruvboxColors::green())
                    .add_modifier(Modifier::BOLD),
            )),
        ])
        .alignment(Alignment::Center);
        f.render_widget(generated, chunks[2]);
    }
    let help = Paragraph::new("Enter: Generate │ Esc: Back")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[4]);
}

pub fn draw_filter_tags(f: &mut Frame, size: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(size);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::purple()))
        .title("═══ FILTER BY TAG ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, size);
    let title = if let Some(ref tag) = app.active_tf {
        format!("Filtering by: [{}] ({} entries)", tag, app.entry_disp.len())
    } else {
        "Select a tag to filter".to_string()
    };
    let title_widget = Paragraph::new(title)
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title_widget, chunks[0]);
    if app.all_tags.is_empty() {
        let empty = Paragraph::new("[ No tags available - Add tags to your passwords first ]")
            .style(Style::default().fg(GruvboxColors::gray()))
            .alignment(Alignment::Center);
        f.render_widget(empty, chunks[1]);
    } else {
        let mut items = vec![ListItem::new(Line::from(vec![
            Span::styled(
                if app.select_tf == 0 { "▶ " } else { "  " },
                Style::default().fg(GruvboxColors::yellow()),
            ),
            Span::styled(
                format!(
                    "All ({} total)",
                    app.vault.as_ref().map_or(0, |v| v.e.len())
                ),
                if app.select_tf == 0 {
                    Style::default()
                        .fg(GruvboxColors::green())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(GruvboxColors::fg())
                },
            ),
        ]))];
        for (idx, (tag, count)) in app.all_tags.iter().enumerate() {
            let is_selected = idx + 1 == app.select_tf;
            let prefix = if is_selected { "▶ " } else { "  " };
            items.push(ListItem::new(Line::from(vec![
                Span::styled(prefix, Style::default().fg(GruvboxColors::yellow())),
                Span::styled(
                    format!("[{tag}] ({count} entries)"),
                    if is_selected {
                        Style::default()
                            .fg(GruvboxColors::orange())
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(GruvboxColors::fg())
                    },
                ),
            ])));
        }
        let list = List::new(items).block(Block::default().borders(Borders::NONE));
        f.render_widget(list, chunks[1]);
    }
    if app.active_tf.is_some() {
        let filter_info = Paragraph::new("Press V to view filtered passwords")
            .style(Style::default().fg(GruvboxColors::aqua()))
            .alignment(Alignment::Center);
        f.render_widget(filter_info, chunks[2]);
    }
    let help = Paragraph::new("↑/↓: Navigate │ Enter: Apply │ V: View │ Esc: Back")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}
