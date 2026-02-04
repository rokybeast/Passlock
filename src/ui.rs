use crate::crypto;
use crate::models::{Entry, Vault, PasswordHistory};
use crate::storage;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::collections::HashMap;

struct GruvboxColors;
impl GruvboxColors {
    fn bg0() -> Color { Color::Rgb(40, 40, 40) }
    fn _bg1() -> Color { Color::Rgb(60, 56, 54) }
    fn _bg2() -> Color { Color::Rgb(80, 73, 69) }
    fn fg() -> Color { Color::Rgb(235, 219, 178) }
    fn red() -> Color { Color::Rgb(251, 73, 52) }
    fn green() -> Color { Color::Rgb(184, 187, 38) }
    fn yellow() -> Color { Color::Rgb(250, 189, 47) }
    fn blue() -> Color { Color::Rgb(131, 165, 152) }
    fn purple() -> Color { Color::Rgb(211, 134, 155) }
    fn aqua() -> Color { Color::Rgb(142, 192, 124) }
    fn orange() -> Color { Color::Rgb(254, 128, 25) }
    fn gray() -> Color { Color::Rgb(146, 131, 116) }
}

#[derive(Clone, PartialEq)]
enum Screen {
    VaultCheck,
    CreateVault,
    UnlockVault,
    MainMenu,
    ViewPasswords,
    AddPassword,
    EditPassword,
    ViewHistory,
    SearchPassword,
    GeneratePassword,
    DeletePassword,
    FilterByTag,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq)]
enum InputField {
    None,
    Password,
    PasswordConfirm,
    Name,
    Username,
    Pass,
    Url,
    Notes,
    Tags,
    Search,
    Length,
    DeleteIndex,
}

#[allow(dead_code)]
struct App {
    screen: Screen,
    vault: Option<Vault>,
    master_pwd: String,
    selected_menu: usize,
    selected_section: usize,
    selected_entry: usize,
    input_field: InputField,
    input_buffer: String,
    input_buffer2: String,
    msg: String,
    msg_type: MessageType,
    entry_disp: Vec<Entry>,
    search_query: String,
    gen_pwd: String,
    scroll_offset: usize,
    n_entry_name: String,
    n_entry_user: String,
    n_entry_pass: String,
    n_entry_url: String,
    n_entry_notes: String,
    n_entry_tags: Vec<String>,
    tag_input: String,
    add_fi: usize,
    all_tags: Vec<(String, usize)>,
    select_tf: usize,
    active_tf: Option<String>,
    edit_eid: String,
}

#[derive(Clone, PartialEq)]
enum MessageType {
    None,
    Success,
    Error,
    Info,
}

impl App {
    fn new() -> Self {
        Self {
            screen: Screen::VaultCheck,
            vault: None,
            master_pwd: String::new(),
            selected_menu: 0,
            selected_section: 0,
            selected_entry: 0,
            input_field: InputField::None,
            input_buffer: String::new(),
            input_buffer2: String::new(),
            msg: String::new(),
            msg_type: MessageType::None,
            entry_disp: Vec::new(),
            search_query: String::new(),
            gen_pwd: String::new(),
            scroll_offset: 0,
            n_entry_name: String::new(),
            n_entry_user: String::new(),
            n_entry_pass: String::new(),
            n_entry_url: String::new(),
            n_entry_notes: String::new(),
            n_entry_tags: Vec::new(),
            tag_input: String::new(),
            add_fi: 0,
            all_tags: Vec::new(),
            select_tf: 0,
            active_tf: None,
            edit_eid: String::new(),
        }
    }

    fn check_vault(&mut self) {
        if storage::vt_exi() {
            self.screen = Screen::UnlockVault;
            self.input_field = InputField::Password;
        } else {
            self.screen = Screen::CreateVault;
            self.input_field = InputField::Password;
            self.set_msg("No vault found. Create one to get started!", MessageType::Info);
        }
    }

    fn create_vault(&mut self) {
        if self.input_buffer.len() < 4 {
            self.set_msg("Password too short (min 4 chars)", MessageType::Error);
            return;
        }
        if self.input_buffer != self.input_buffer2 {
            self.set_msg("Passwords don't match!", MessageType::Error);
            return;
        }
        let salt = crypto::gen_salt();
        let vault = Vault::new(salt);
        match storage::svv(&vault, &self.input_buffer) {
            Ok(_) => {
                self.master_pwd = self.input_buffer.clone();
                self.vault = Some(vault);
                self.screen = Screen::MainMenu;
                self.input_buffer.clear();
                self.input_buffer2.clear();
                self.input_field = InputField::None;
                self.set_msg("Vault created successfully!", MessageType::Success);
            }
            Err(e) => {
                self.set_msg(&format!("Failed to create vault: {}", e), MessageType::Error);
            }
        }
    }

    fn unlock_vault(&mut self) {
        match storage::ld_vt(&self.input_buffer) {
            Ok(vault) => {
                self.master_pwd = self.input_buffer.clone();
                self.vault = Some(vault);
                self.screen = Screen::MainMenu;
                self.input_buffer.clear();
                self.input_field = InputField::None;
                self.set_msg("Vault unlocked!", MessageType::Success);
                self.load_at();
                // Initialize entry_disp with all entries
                if let Some(ref vault) = self.vault {
                    self.entry_disp = vault.e.clone();
                }
            }
            Err(_) => {
                self.set_msg("Wrong password!", MessageType::Error);
            }
        }
    }

    fn add_entry(&mut self) {
        if self.n_entry_name.is_empty() || self.n_entry_user.is_empty() || self.n_entry_pass.is_empty() {
            self.set_msg("Name, Username, and Password are required!", MessageType::Error);
            return;
        }
        let now = crate::get_timestamp();
        let entry = Entry {
            id: crate::generate_uuid(),
            n: self.n_entry_name.clone(),
            u: self.n_entry_user.clone(),
            p: self.n_entry_pass.clone(),
            url: if self.n_entry_url.is_empty() { None } else { Some(self.n_entry_url.clone()) },
            nt: if self.n_entry_notes.is_empty() { None } else { Some(self.n_entry_notes.clone()) },
            t: now,
            tags: self.n_entry_tags.clone(),
            history: Vec::new(),
            last_modified: now,
        };
        if let Some(ref mut vault) = self.vault {
            vault.e.push(entry);
            if let Err(e) = storage::svv(vault, &self.master_pwd) {
                self.set_msg(&format!("Failed to save: {}", e), MessageType::Error);
            } else {
                self.set_msg("Password added successfully!", MessageType::Success);
                self.ca_form();
                self.screen = Screen::MainMenu;
                self.load_at();
                // Update entry_disp to include the new entry
                if let Some(ref vault) = self.vault {
                    self.entry_disp = vault.e.clone();
                }
            }
        }
    }

    fn edit_entry(&mut self) {
        if self.n_entry_name.is_empty() || self.n_entry_user.is_empty() || self.n_entry_pass.is_empty() {
            self.set_msg("Name, Username, and Password are required!", MessageType::Error);
            return;
        }
        if let Some(ref mut vault) = self.vault {
            if let Some(entry) = vault.e.iter_mut().find(|e| e.id == self.edit_eid) {
                let now = crate::get_timestamp();
                if entry.p != self.n_entry_pass {
                    if entry.history.len() >= 5 {
                        entry.history.remove(0);
                    }
                    entry.history.push(PasswordHistory {
                        password: entry.p.clone(),
                        changed_at: now,
                    });
                }
                entry.n = self.n_entry_name.clone();
                entry.u = self.n_entry_user.clone();
                entry.p = self.n_entry_pass.clone();
                entry.url = if self.n_entry_url.is_empty() { None } else { Some(self.n_entry_url.clone()) };
                entry.nt = if self.n_entry_notes.is_empty() { None } else { Some(self.n_entry_notes.clone()) };
                entry.tags = self.n_entry_tags.clone();
                entry.last_modified = now;
                
                if let Err(e) = storage::svv(vault, &self.master_pwd) {
                    self.set_msg(&format!("Failed to save: {}", e), MessageType::Error);
                } else {
                    self.set_msg("Entry updated successfully!", MessageType::Success);
                    self.ca_form();
                    self.screen = Screen::MainMenu;
                    self.load_at();
                    // Update entry_disp to reflect changes
                    if let Some(ref vault) = self.vault {
                        self.entry_disp = vault.e.clone();
                    }
                }
            }
        }
    }

    fn load_efe(&mut self, entry_id: String) {
        if let Some(ref vault) = self.vault {
            if let Some(entry) = vault.e.iter().find(|e| e.id == entry_id) {
                self.edit_eid = entry.id.clone();
                self.n_entry_name = entry.n.clone();
                self.n_entry_user = entry.u.clone();
                self.n_entry_pass = entry.p.clone();
                self.n_entry_url = entry.url.clone().unwrap_or_default();
                self.n_entry_notes = entry.nt.clone().unwrap_or_default();
                self.n_entry_tags = entry.tags.clone();
                self.add_fi = 0;
                self.screen = Screen::EditPassword;
            }
        }
    }

    fn delete_entry(&mut self, index: usize) {
        if let Some(ref mut vault) = self.vault {
            if index < vault.e.len() {
                let removed = vault.e.remove(index);
                if let Err(e) = storage::svv(vault, &self.master_pwd) {
                    self.set_msg(&format!("Failed to save: {}", e), MessageType::Error);
                } else {
                    self.set_msg(&format!("Deleted '{}'", removed.n), MessageType::Success);
                    self.screen = Screen::MainMenu;
                    self.load_at();
                    // Update entry_disp to remove the deleted entry
                    if let Some(ref vault) = self.vault {
                        self.entry_disp = vault.e.clone();
                    }
                }
            } else {
                self.set_msg("Invalid entry number!", MessageType::Error);
            }
        }
    }

    fn search_entries(&mut self) {
        if let Some(ref vault) = self.vault {
            let query = self.search_query.to_lowercase();
            if query.is_empty() {
                self.entry_disp = vault.e.clone();
            } else {
                self.entry_disp = vault
                    .e
                    .iter()
                    .filter(|e| {
                        e.n.to_lowercase().contains(&query)
                            || e.u.to_lowercase().contains(&query)
                            || e.url.as_ref().map_or(false, |u| u.to_lowercase().contains(&query))
                            || e.tags.iter().any(|t| t.to_lowercase().contains(&query))
                    })
                    .cloned()
                    .collect();
            }
        }
    }

    fn gen_pwd(&mut self) {
        let len = self.input_buffer.parse::<usize>().unwrap_or(16).max(4).min(64);
        self.gen_pwd = crypto::gen_pwd(len);
    }

    fn set_msg(&mut self, msg: &str, msg_type: MessageType) {
        self.msg = msg.to_string();
        self.msg_type = msg_type;
    }

    fn ca_form(&mut self) {
        self.n_entry_name.clear();
        self.n_entry_user.clear();
        self.n_entry_pass.clear();
        self.n_entry_url.clear();
        self.n_entry_notes.clear();
        self.n_entry_tags.clear();
        self.tag_input.clear();
        self.add_fi = 0;
        self.edit_eid.clear();
    }

    fn add_tag(&mut self) {
        let tag = self.tag_input.trim().to_lowercase();
        if !tag.is_empty() && !self.n_entry_tags.contains(&tag.to_string()) {
            self.n_entry_tags.push(tag.to_string());
            self.tag_input.clear();
        }
    }

    fn remove_tag(&mut self, index: usize) {
        if index < self.n_entry_tags.len() {
            self.n_entry_tags.remove(index);
        }
    }

    fn load_at(&mut self) {
        if let Some(ref vault) = self.vault {
            let mut tag_map: HashMap<String, usize> = HashMap::new();
            for entry in &vault.e {
                for tag in &entry.tags {
                    *tag_map.entry(tag.clone()).or_insert(0) += 1;
                }
            }
            self.all_tags = tag_map.into_iter().collect();
            self.all_tags.sort_by(|a, b| b.1.cmp(&a.1));
        }
    }

    fn filter_bt(&mut self, tag: Option<String>) {
        self.active_tf = tag.clone();
        if let Some(ref vault) = self.vault {
            if let Some(filter_tag) = tag {
                self.entry_disp = vault
                    .e
                    .iter()
                    .filter(|e| e.tags.contains(&filter_tag))
                    .cloned()
                    .collect();
            } else {
                // Clear filter - show all entries
                self.entry_disp = vault.e.clone();
            }
        }
    }

    fn get_ta(&self, timestamp: u64) -> String {
        let now = crate::get_timestamp();
        let diff = now.saturating_sub(timestamp);
        let days = diff / 86400;
        if days == 0 {
            "Today".to_string()
        } else if days == 1 {
            "1 day ago".to_string()
        } else if days < 30 {
            format!("{} days ago", days)
        } else if days < 365 {
            let months = days / 30;
            if months == 1 {
                "1 month ago".to_string()
            } else {
                format!("{} months ago", months)
            }
        } else {
            let years = days / 365;
            if years == 1 {
                "1 year ago".to_string()
            } else {
                format!("{} years ago", years)
            }
        }
    }
}

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    app.check_vault();
    let res = run_app(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    if let Err(err) = res {
        println!("Error: {:?}", err);
    }
    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match app.screen {
                    Screen::VaultCheck => {}
                    Screen::CreateVault => handle_cvi(app, key.code),
                    Screen::UnlockVault => handle_uvi(app, key.code),
                    Screen::MainMenu => {
                        if handle_mmi(app, key.code) {
                            return Ok(());
                        }
                    }
                    Screen::ViewPasswords => handle_vpi(app, key.code),
                    Screen::AddPassword => handle_api(app, key.code),
                    Screen::EditPassword => handle_epi(app, key.code),
                    Screen::ViewHistory => handle_vhi(app, key.code),
                    Screen::SearchPassword => handle_si(app, key.code),
                    Screen::GeneratePassword => handle_gi(app, key.code),
                    Screen::DeletePassword => handle_di(app, key.code),
                    Screen::FilterByTag => handle_tfi(app, key.code),
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let size = f.size();
    match app.screen {
        Screen::VaultCheck => draw_loading(f, size),
        Screen::CreateVault => draw_create_vault(f, size, app),
        Screen::UnlockVault => draw_unlock_vault(f, size, app),
        Screen::MainMenu => draw_main_menu(f, size, app),
        Screen::ViewPasswords => draw_view_pwds(f, size, app),
        Screen::AddPassword => draw_add_pwd(f, size, app),
        Screen::EditPassword => draw_edit_pwd(f, size, app),
        Screen::ViewHistory => draw_history(f, size, app),
        Screen::SearchPassword => draw_search_pwd(f, size, app),
        Screen::GeneratePassword => draw_gen_pwd(f, size, app),
        Screen::DeletePassword => draw_del_pwd(f, size, app),
        Screen::FilterByTag => draw_filter_tags(f, size, app),
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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

fn draw_loading(f: &mut Frame, size: Rect) {
    let area = centered_rect(50, 30, size);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::yellow()))
        .title(" PASSLOCK ")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    let text = Paragraph::new("Initializing vault...")
        .block(block)
        .alignment(Alignment::Center)
        .style(Style::default().fg(GruvboxColors::fg()));
    f.render_widget(Clear, area);
    f.render_widget(text, area);
}

fn draw_create_vault(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(65, 70, size);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3), Constraint::Length(1), Constraint::Length(3),
            Constraint::Length(3), Constraint::Length(3), Constraint::Length(1),
            Constraint::Length(3), Constraint::Min(2), Constraint::Length(3),
        ])
        .split(area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::orange()))
        .title("═══ CREATE VAULT ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, area);
    let title = Paragraph::new("Create your master password")
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    let pwd_text = format!("Password: {}", "•".repeat(app.input_buffer.len()));
    let pwd_style = if app.input_field == InputField::Password {
        Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(GruvboxColors::gray())
    };
    let password_input = Paragraph::new(pwd_text).style(pwd_style);
    f.render_widget(password_input, chunks[2]);
    if !app.input_buffer.is_empty() && app.input_field == InputField::Password {
        let strength = crypto::calc_pwd_strength(&app.input_buffer);
        let strength_color = match strength.strength.as_str() {
            "Weak" => GruvboxColors::red(),
            "Fair" => GruvboxColors::orange(),
            "Good" => GruvboxColors::yellow(),
            "Strong" => GruvboxColors::green(),
            _ => GruvboxColors::gray(),
        };
        let bar_width = (35 * strength.percentage) / 100;
        let empty_width = 35 - bar_width;
        let bar = format!("[{}{}] {}% - {}", 
            "█".repeat(bar_width as usize),
            "─".repeat(empty_width as usize),
            strength.percentage,
            strength.strength
        );
        let strength_display = Paragraph::new(bar)
            .style(Style::default().fg(strength_color))
            .alignment(Alignment::Center);
        f.render_widget(strength_display, chunks[3]);
        if !strength.feedback.is_empty() {
            let feedback_text = format!("↳ {}", strength.feedback.join(", "));
            let feedback = Paragraph::new(feedback_text)
                .style(Style::default().fg(GruvboxColors::gray()))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true });
            f.render_widget(feedback, chunks[4]);
        }
    }
    let confirm_text = format!("Confirm: {}", "•".repeat(app.input_buffer2.len()));
    let confirm_style = if app.input_field == InputField::PasswordConfirm {
        Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(GruvboxColors::gray())
    };
    let confirm_input = Paragraph::new(confirm_text).style(confirm_style);
    f.render_widget(confirm_input, chunks[6]);
    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(GruvboxColors::green()),
            MessageType::Error => Style::default().fg(GruvboxColors::red()),
            MessageType::Info => Style::default().fg(GruvboxColors::blue()),
            MessageType::None => Style::default().fg(GruvboxColors::fg()),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center);
        f.render_widget(msg, chunks[7]);
    }
    let help = Paragraph::new("Tab: Switch | Enter: Create | Esc: Quit")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[8]);
}

fn draw_unlock_vault(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(60, 40, size);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3), Constraint::Length(1), Constraint::Length(3),
            Constraint::Min(2), Constraint::Length(3),
        ])
        .split(area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::aqua()))
        .title("═══ UNLOCK VAULT ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, area);
    let title = Paragraph::new("Enter your master password")
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    let pwd_text = format!("Password: {}", "•".repeat(app.input_buffer.len()));
    let password_input = Paragraph::new(pwd_text)
        .style(Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD));
    f.render_widget(password_input, chunks[2]);
    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(GruvboxColors::green()),
            MessageType::Error => Style::default().fg(GruvboxColors::red()),
            MessageType::Info => Style::default().fg(GruvboxColors::blue()),
            MessageType::None => Style::default().fg(GruvboxColors::fg()),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center);
        f.render_widget(msg, chunks[3]);
    }
    let help = Paragraph::new("Enter: Unlock | Esc: Quit")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[4]);
}

fn draw_main_menu(f: &mut Frame, size: Rect, app: &App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(5), Constraint::Min(10), Constraint::Length(3)])
        .split(size);
    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::yellow()))
        .style(Style::default().bg(GruvboxColors::bg0()));
    let vault_info = if let Some(ref vault) = app.vault {
        let tag_count = app.all_tags.len();
        let disp_count = app.entry_disp.len();
        let total_count = vault.e.len();
        let filter_indicator = if disp_count != total_count {
            format!(" (Filtered: {})", disp_count)
        } else {
            String::new()
        };
        vec![
            Line::from(vec![
                Span::styled("█▓▒░ PASSLOCK ░▒▓█", Style::default().fg(GruvboxColors::orange()).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Vault: ", Style::default().fg(GruvboxColors::gray())),
                Span::styled("UNLOCKED ", Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD)),
                Span::styled("│ ", Style::default().fg(GruvboxColors::gray())),
                Span::styled(format!("{} passwords{} ", total_count, filter_indicator), Style::default().fg(GruvboxColors::blue())),
                Span::styled("│ ", Style::default().fg(GruvboxColors::gray())),
                Span::styled(format!("{} tags", tag_count), Style::default().fg(GruvboxColors::purple())),
            ]),
        ]
    } else {
        vec![
            Line::from(Span::styled("PASSLOCK", Style::default().fg(GruvboxColors::red()))),
            Line::from(""),
            Line::from("No vault loaded"),
        ]
    };
    let header = Paragraph::new(vault_info)
        .block(header_block)
        .alignment(Alignment::Center);
    f.render_widget(header, main_layout[0]);
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .margin(0)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_layout[1]);
    let left_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::green()))
        .title("═══ PASSWORDS ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    let left_items = vec![
        ("1", "View All", "Browse vault"),
        ("2", "Add New", "Create entry"),
        ("3", "Search", "Find passwords"),
    ];
    let left_list: Vec<ListItem> = left_items
        .iter()
        .enumerate()
        .map(|(i, (num, title, desc))| {
            let is_selected = app.selected_section == 0 && i == app.selected_menu;
            let style = if is_selected {
                Style::default().fg(GruvboxColors::yellow()).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(GruvboxColors::fg())
            };
            let prefix = if is_selected { "▶ " } else { "  " };
            let lines = vec![
                Line::from(vec![
                    Span::styled(prefix, Style::default().fg(GruvboxColors::yellow())),
                    Span::styled(format!("[{}] ", num), Style::default().fg(GruvboxColors::orange())),
                    Span::styled(*title, style),
                ]),
                Line::from(vec![
                    Span::raw("     "),
                    Span::styled(*desc, Style::default().fg(GruvboxColors::gray())),
                ]),
                Line::from(""),
            ];
            ListItem::new(lines)
        })
        .collect();
    let left = List::new(left_list).block(left_block);
    f.render_widget(left, content_layout[0]);
    let right_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::purple()))
        .title("═══ TOOLS ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    let right_items = vec![
        ("4", "Filter Tags", "Sort by tags"),
        ("5", "Generate", "Random password"),
        ("6", "Delete", "Remove entry"),
        ("7", "Exit", "Lock & quit"),
    ];
    let right_list: Vec<ListItem> = right_items
        .iter()
        .enumerate()
        .map(|(i, (num, title, desc))| {
            let is_selected = app.selected_section == 1 && i == app.selected_menu - 3;
            let style = if is_selected {
                Style::default().fg(GruvboxColors::yellow()).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(GruvboxColors::fg())
            };
            let prefix = if is_selected { "▶ " } else { "  " };
            let lines = vec![
                Line::from(vec![
                    Span::styled(prefix, Style::default().fg(GruvboxColors::yellow())),
                    Span::styled(format!("[{}] ", num), Style::default().fg(GruvboxColors::orange())),
                    Span::styled(*title, style),
                ]),
                Line::from(vec![
                    Span::raw("     "),
                    Span::styled(*desc, Style::default().fg(GruvboxColors::gray())),
                ]),
                Line::from(""),
            ];
            ListItem::new(lines)
        })
        .collect();
    let right = List::new(right_list).block(right_block);
    f.render_widget(right, content_layout[1]);
    if !app.msg.is_empty() {
        let msg_area = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(3)])
            .split(main_layout[1])[1];
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(GruvboxColors::green()),
            MessageType::Error => Style::default().fg(GruvboxColors::red()),
            MessageType::Info => Style::default().fg(GruvboxColors::blue()),
            MessageType::None => Style::default().fg(GruvboxColors::fg()),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        f.render_widget(msg, msg_area);
    }
    let help_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::gray()))
        .style(Style::default().bg(GruvboxColors::bg0()));
    let help = Paragraph::new("↑/↓: Navigate  │  ←/→: Switch section  │  Enter: Select  │  Esc: Exit")
        .block(help_block)
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, main_layout[2]);
}

fn draw_view_pwds(f: &mut Frame, size: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(3)])
        .split(size);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::green()))
        .title("═══ PASSWORDS ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block.clone(), size);
    
    // Show filter status if active
    let filter_status = if let Some(ref tag) = app.active_tf {
        format!(" (Filtered by: {})", tag)
    } else if !app.search_query.is_empty() {
        format!(" (Search: {})", app.search_query)
    } else {
        String::new()
    };
    
    let title = Paragraph::new(format!("Total: {} entries{} | Press E to edit, H for history", app.entry_disp.len(), filter_status))
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    
    if app.entry_disp.is_empty() {
        let empty = if app.active_tf.is_some() || !app.search_query.is_empty() {
            "[ No matching entries found ]"
        } else {
            "[ No passwords saved yet ]"
        };
        let empty_paragraph = Paragraph::new(empty)
            .style(Style::default().fg(GruvboxColors::gray()))
            .alignment(Alignment::Center);
        f.render_widget(empty_paragraph, chunks[1]);
    } else {
        let items: Vec<ListItem> = app
            .entry_disp
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let is_selected = i == app.selected_entry;
                let prefix = if is_selected { "▶ " } else { "  " };
                let time_ago = app.get_ta(entry.last_modified);
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled(prefix, Style::default().fg(GruvboxColors::yellow())),
                        Span::styled(format!("[{}] ", i + 1), Style::default().fg(GruvboxColors::orange())),
                        Span::styled(&entry.n, 
                            if is_selected {
                                Style::default().fg(GruvboxColors::yellow()).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(GruvboxColors::yellow())
                            }
                        ),
                        Span::styled(format!("  (Modified: {})", time_ago), Style::default().fg(GruvboxColors::gray())),
                    ]),
                    Line::from(vec![
                        Span::raw("     "),
                        Span::styled("├─ User: ", Style::default().fg(GruvboxColors::gray())),
                        Span::styled(&entry.u, Style::default().fg(GruvboxColors::blue())),
                    ]),
                    Line::from(vec![
                        Span::raw("     "),
                        Span::styled("├─ Pass: ", Style::default().fg(GruvboxColors::gray())),
                        Span::styled(&entry.p, Style::default().fg(GruvboxColors::green())),
                    ]),
                ];
                if let Some(ref url) = entry.url {
                    lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled("├─ URL:  ", Style::default().fg(GruvboxColors::gray())),
                        Span::styled(url, Style::default().fg(GruvboxColors::aqua())),
                    ]));
                }
                if !entry.history.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled(format!("├─ History: {} changes", entry.history.len()), 
                            Style::default().fg(GruvboxColors::purple())),
                    ]));
                }
                if !entry.tags.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled("└─ Tags: ", Style::default().fg(GruvboxColors::gray())),
                        Span::styled(entry.tags.join(", "), Style::default().fg(GruvboxColors::orange())),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled("└─", Style::default().fg(GruvboxColors::gray()))
                    ]));
                }
                lines.push(Line::from(""));
                ListItem::new(lines)
            })
            .collect();
        let list = List::new(items).block(Block::default().borders(Borders::NONE));
        f.render_widget(list, chunks[1]);
    }
    let help = Paragraph::new("↑/↓: Navigate │ E: Edit │ H: History │ F: Clear filter │ Esc: Back")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[2]);
}

fn draw_add_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(80, 85, size);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2), Constraint::Length(1), Constraint::Length(2), Constraint::Length(2),
            Constraint::Length(2), Constraint::Length(2), Constraint::Length(2), Constraint::Length(2),
            Constraint::Length(2), Constraint::Length(3), Constraint::Length(4), Constraint::Min(1), Constraint::Length(2),
        ])
        .split(area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::green()))
        .title("═══ ADD NEW PASSWORD ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, area);
    let title = Paragraph::new("Fill in the details below")
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    let active_style = Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD);
    let inactive_style = Style::default().fg(GruvboxColors::gray());
    let name_field = Paragraph::new(format!("Name: {}", app.n_entry_name))
        .style(if app.add_fi == 0 { active_style } else { inactive_style });
    f.render_widget(name_field, chunks[2]);
    let user_field = Paragraph::new(format!("Username: {}", app.n_entry_user))
        .style(if app.add_fi == 1 { active_style } else { inactive_style });
    f.render_widget(user_field, chunks[3]);
    let pass_field = Paragraph::new(format!("Password: {}", app.n_entry_pass))
        .style(if app.add_fi == 2 { active_style } else { inactive_style });
    f.render_widget(pass_field, chunks[4]);
    if !app.n_entry_pass.is_empty() && app.add_fi == 2 {
        let strength = crypto::calc_pwd_strength(&app.n_entry_pass);
        let strength_color = match strength.strength.as_str() {
            "Weak" => GruvboxColors::red(),
            "Fair" => GruvboxColors::orange(),
            "Good" => GruvboxColors::yellow(),
            "Strong" => GruvboxColors::green(),
            _ => GruvboxColors::gray(),
        };
        let bar_width = (35 * strength.percentage) / 100;
        let empty_width = 35 - bar_width;
        let bar = format!("[{}{}] {}% - {}", 
            "█".repeat(bar_width as usize),
            "─".repeat(empty_width as usize),
            strength.percentage,
            strength.strength
        );
        let strength_display = Paragraph::new(bar)
            .style(Style::default().fg(strength_color))
            .alignment(Alignment::Center);
        f.render_widget(strength_display, chunks[5]);
        if !strength.feedback.is_empty() {
            let feedback_text = format!("↳ {}", strength.feedback.join(", "));
            let feedback = Paragraph::new(feedback_text)
                .style(Style::default().fg(GruvboxColors::gray()))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true });
            f.render_widget(feedback, chunks[6]);
        }
    }
    let url_field = Paragraph::new(format!("URL (optional): {}", app.n_entry_url))
        .style(if app.add_fi == 3 { active_style } else { inactive_style });
    f.render_widget(url_field, chunks[7]);
    let tags_text = if app.add_fi == 4 {
        format!("Tags: {} ← Enter to add", app.tag_input)
    } else {
        "Tags: (Tab to focus)".to_string()
    };
    let tags_input = Paragraph::new(tags_text)
        .style(if app.add_fi == 4 { active_style } else { inactive_style })
        .wrap(Wrap { trim: true });
    f.render_widget(tags_input, chunks[8]);
    if !app.n_entry_tags.is_empty() {
        let tags_display = app.n_entry_tags
            .iter()
            .enumerate()
            .map(|(i, tag)| format!("[{}]{} ", i + 1, tag))
            .collect::<Vec<_>>()
            .join(" ");
        let tags_widget = Paragraph::new(format!("Added: {}", tags_display))
            .style(Style::default().fg(GruvboxColors::orange()))
            .wrap(Wrap { trim: true });
        f.render_widget(tags_widget, chunks[9]);
    }
    let notes = Paragraph::new(format!("Notes:\n{}", app.n_entry_notes))
        .style(if app.add_fi == 5 { active_style } else { inactive_style })
        .wrap(Wrap { trim: false });
    f.render_widget(notes, chunks[10]);
    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(GruvboxColors::green()),
            MessageType::Error => Style::default().fg(GruvboxColors::red()),
            MessageType::Info => Style::default().fg(GruvboxColors::blue()),
            MessageType::None => Style::default().fg(GruvboxColors::fg()),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center);
        f.render_widget(msg, chunks[11]);
    }
    let help = Paragraph::new("Tab: Next field │ Enter: Add tag/Save │ 1-9: Remove tag │ Esc: Cancel")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[12]);
}

fn draw_edit_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(80, 85, size);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2), Constraint::Length(1), Constraint::Length(2), Constraint::Length(2),
            Constraint::Length(2), Constraint::Length(2), Constraint::Length(2), Constraint::Length(2),
            Constraint::Length(2), Constraint::Length(3), Constraint::Length(4), Constraint::Min(1), Constraint::Length(2),
        ])
        .split(area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::orange()))
        .title("═══ EDIT PASSWORD ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, area);
    let title = Paragraph::new("Edit entry details (password changes are tracked)")
        .style(Style::default().fg(GruvboxColors::yellow()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    let active_style = Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD);
    let inactive_style = Style::default().fg(GruvboxColors::gray());
    let name_field = Paragraph::new(format!("Name: {}", app.n_entry_name))
        .style(if app.add_fi == 0 { active_style } else { inactive_style });
    f.render_widget(name_field, chunks[2]);
    let user_field = Paragraph::new(format!("Username: {}", app.n_entry_user))
        .style(if app.add_fi == 1 { active_style } else { inactive_style });
    f.render_widget(user_field, chunks[3]);
    let pass_field = Paragraph::new(format!("Password: {}", app.n_entry_pass))
        .style(if app.add_fi == 2 { active_style } else { inactive_style });
    f.render_widget(pass_field, chunks[4]);
    if !app.n_entry_pass.is_empty() && app.add_fi == 2 {
        let strength = crypto::calc_pwd_strength(&app.n_entry_pass);
        let strength_color = match strength.strength.as_str() {
            "Weak" => GruvboxColors::red(),
            "Fair" => GruvboxColors::orange(),
            "Good" => GruvboxColors::yellow(),
            "Strong" => GruvboxColors::green(),
            _ => GruvboxColors::gray(),
        };
        let bar_width = (35 * strength.percentage) / 100;
        let empty_width = 35 - bar_width;
        let bar = format!("[{}{}] {}% - {}", 
            "█".repeat(bar_width as usize),
            "─".repeat(empty_width as usize),
            strength.percentage,
            strength.strength
        );
        let strength_display = Paragraph::new(bar)
            .style(Style::default().fg(strength_color))
            .alignment(Alignment::Center);
        f.render_widget(strength_display, chunks[5]);
        if !strength.feedback.is_empty() {
            let feedback_text = format!("↳ {}", strength.feedback.join(", "));
            let feedback = Paragraph::new(feedback_text)
                .style(Style::default().fg(GruvboxColors::gray()))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true });
            f.render_widget(feedback, chunks[6]);
        }
    }
    let url_field = Paragraph::new(format!("URL: {}", app.n_entry_url))
        .style(if app.add_fi == 3 { active_style } else { inactive_style });
    f.render_widget(url_field, chunks[7]);
    let tags_text = if app.add_fi == 4 {
        format!("Tags: {} ← Enter to add", app.tag_input)
    } else {
        "Tags: (Tab to focus)".to_string()
    };
    let tags_input = Paragraph::new(tags_text)
        .style(if app.add_fi == 4 { active_style } else { inactive_style })
        .wrap(Wrap { trim: true });
    f.render_widget(tags_input, chunks[8]);
    if !app.n_entry_tags.is_empty() {
        let tags_display = app.n_entry_tags
            .iter()
            .enumerate()
            .map(|(i, tag)| format!("[{}]{} ", i + 1, tag))
            .collect::<Vec<_>>()
            .join(" ");
        let tags_widget = Paragraph::new(format!("Tags: {}", tags_display))
            .style(Style::default().fg(GruvboxColors::orange()))
            .wrap(Wrap { trim: true });
        f.render_widget(tags_widget, chunks[9]);
    }
    let notes = Paragraph::new(format!("Notes:\n{}", app.n_entry_notes))
        .style(if app.add_fi == 5 { active_style } else { inactive_style })
        .wrap(Wrap { trim: false });
    f.render_widget(notes, chunks[10]);
    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(GruvboxColors::green()),
            MessageType::Error => Style::default().fg(GruvboxColors::red()),
            MessageType::Info => Style::default().fg(GruvboxColors::blue()),
            MessageType::None => Style::default().fg(GruvboxColors::fg()),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center);
        f.render_widget(msg, chunks[11]);
    }
    let help = Paragraph::new("Tab: Next │ Enter: Add tag/Save │ 1-9: Remove tag │ Esc: Cancel")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[12]);
}

fn draw_history(f: &mut Frame, size: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(3)])
        .split(size);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::purple()))
        .title("═══ PASSWORD HISTORY ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, size);
    if let Some(ref vault) = app.vault {
        if app.selected_entry < app.entry_disp.len() {
            // Get the entry from entry_disp
            let entry = &app.entry_disp[app.selected_entry];
            // Find the same entry in vault by ID
            if let Some(vault_entry) = vault.e.iter().find(|e| e.id == entry.id) {
                let title = Paragraph::new(format!("History for: {} (Last 5 changes)", vault_entry.n))
                    .style(Style::default().fg(GruvboxColors::yellow()))
                    .alignment(Alignment::Center);
                f.render_widget(title, chunks[0]);
                if vault_entry.history.is_empty() {
                    let empty = Paragraph::new("[ No password changes recorded ]")
                        .style(Style::default().fg(GruvboxColors::gray()))
                        .alignment(Alignment::Center);
                    f.render_widget(empty, chunks[1]);
                } else {
                    let items: Vec<ListItem> = vault_entry
                        .history
                        .iter()
                        .rev()
                        .enumerate()
                        .map(|(i, hist)| {
                            let time_ago = app.get_ta(hist.changed_at);
                            let lines = vec![
                                Line::from(vec![
                                    Span::styled(format!("[{}] ", i + 1), Style::default().fg(GruvboxColors::purple())),
                                    Span::styled(&hist.password, Style::default().fg(GruvboxColors::green())),
                                ]),
                                Line::from(vec![
                                    Span::raw("    "),
                                    Span::styled(format!("Changed: {}", time_ago), Style::default().fg(GruvboxColors::gray())),
                                ]),
                                Line::from(""),
                            ];
                            ListItem::new(lines)
                        })
                        .collect();
                    let list = List::new(items).block(Block::default().borders(Borders::NONE));
                    f.render_widget(list, chunks[1]);
                }
            }
        }
    }
    let help = Paragraph::new("Esc: Back")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[2]);
}

fn draw_filter_tags(f: &mut Frame, size: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(3), Constraint::Length(3)])
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
                Style::default().fg(GruvboxColors::yellow())
            ),
            Span::styled(
                format!("All ({} total)", app.vault.as_ref().map_or(0, |v| v.e.len())),
                if app.select_tf == 0 {
                    Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(GruvboxColors::fg())
                }
            ),
        ]))];
        for (idx, (tag, count)) in app.all_tags.iter().enumerate() {
            let is_selected = idx + 1 == app.select_tf;
            let prefix = if is_selected { "▶ " } else { "  " };
            items.push(ListItem::new(Line::from(vec![
                Span::styled(prefix, Style::default().fg(GruvboxColors::yellow())),
                Span::styled(
                    format!("[{}] ({} entries)", tag, count),
                    if is_selected {
                        Style::default().fg(GruvboxColors::orange()).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(GruvboxColors::fg())
                    }
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

fn draw_search_pwd(f: &mut Frame, size: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(5), Constraint::Length(3)])
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
    let search = Paragraph::new(format!("Search: {}", app.search_query))
        .style(Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD));
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
                        Span::styled(&entry.n, Style::default().fg(GruvboxColors::yellow()).add_modifier(Modifier::BOLD)),
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
                        Span::styled(entry.tags.join(", "), Style::default().fg(GruvboxColors::orange())),
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

fn draw_gen_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(60, 50, size);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Length(6), Constraint::Min(1), Constraint::Length(3)])
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
    let length_input = Paragraph::new(format!("Length: {}", if app.input_buffer.is_empty() { "16" } else { &app.input_buffer }))
        .style(Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD));
    f.render_widget(length_input, chunks[1]);
    if !app.gen_pwd.is_empty() {
        let generated = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("Generated Password:", Style::default().fg(GruvboxColors::gray()))),
            Line::from(""),
            Line::from(Span::styled(&app.gen_pwd, Style::default().fg(GruvboxColors::green()).add_modifier(Modifier::BOLD))),
        ])
        .alignment(Alignment::Center);
        f.render_widget(generated, chunks[2]);
    }
    let help = Paragraph::new("Enter: Generate │ Esc: Back")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[4]);
}

fn draw_del_pwd(f: &mut Frame, size: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(3), Constraint::Length(3)])
        .split(size);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GruvboxColors::red()))
        .title("═══ DELETE PASSWORD ═══")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(GruvboxColors::bg0()));
    f.render_widget(block, size);
    let title = Paragraph::new("⚠ Enter the number of the entry to delete")
        .style(Style::default().fg(GruvboxColors::orange()))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);
    // Use entry_disp for deletion when filtered
    let empty_vec = Vec::new();
    let entries_to_display = if app.entry_disp.is_empty() {
        app.vault.as_ref().map(|v| &v.e).unwrap_or(&empty_vec)
    } else {
        &app.entry_disp
    };
    
    if entries_to_display.is_empty() {
        let empty = Paragraph::new("[ No passwords to delete ]")
            .style(Style::default().fg(GruvboxColors::gray()))
            .alignment(Alignment::Center);
        f.render_widget(empty, chunks[1]);
    } else {
        let items: Vec<ListItem> = entries_to_display
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("[{}] ", i + 1), Style::default().fg(GruvboxColors::red())),
                    Span::styled(&entry.n, Style::default().fg(GruvboxColors::fg())),
                ]))
            })
            .collect();
        let list = List::new(items).block(Block::default().borders(Borders::NONE));
        f.render_widget(list, chunks[1]);
    }
    let input = Paragraph::new(format!("Entry number: {}", app.input_buffer))
        .style(Style::default().fg(GruvboxColors::red()).add_modifier(Modifier::BOLD));
    f.render_widget(input, chunks[2]);
    let help = Paragraph::new("Type number │ Enter: Delete │ Esc: Cancel")
        .style(Style::default().fg(GruvboxColors::gray()))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}

fn handle_cvi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            if app.input_field == InputField::Password {
                app.input_buffer.push(c);
            } else if app.input_field == InputField::PasswordConfirm {
                app.input_buffer2.push(c);
            }
        }
        KeyCode::Backspace => {
            if app.input_field == InputField::Password {
                app.input_buffer.pop();
            } else if app.input_field == InputField::PasswordConfirm {
                app.input_buffer2.pop();
            }
        }
        KeyCode::Tab => {
            app.input_field = if app.input_field == InputField::Password {
                InputField::PasswordConfirm
            } else {
                InputField::Password
            };
        }
        KeyCode::Enter => {
            app.create_vault();
        }
        KeyCode::Esc => {
            std::process::exit(0);
        }
        _ => {}
    }
}

fn handle_uvi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            app.input_buffer.push(c);
        }
        KeyCode::Backspace => {
            app.input_buffer.pop();
        }
        KeyCode::Enter => {
            app.unlock_vault();
        }
        KeyCode::Esc => {
            std::process::exit(0);
        }
        _ => {}
    }
}

fn handle_mmi(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Up => {
            if app.selected_menu > 0 {
                app.selected_menu -= 1;
                if app.selected_menu < 3 {
                    app.selected_section = 0;
                } else {
                    app.selected_section = 1;
                }
            }
        }
        KeyCode::Down => {
            if app.selected_menu < 6 {
                app.selected_menu += 1;
                if app.selected_menu < 3 {
                    app.selected_section = 0;
                } else {
                    app.selected_section = 1;
                }
            }
        }
        KeyCode::Left => {
            app.selected_section = 0;
            if app.selected_menu > 2 {
                app.selected_menu = 0;
            }
        }
        KeyCode::Right => {
            app.selected_section = 1;
            if app.selected_menu < 3 {
                app.selected_menu = 3;
            }
        }
        KeyCode::Char('1') => { 
            app.screen = Screen::ViewPasswords; 
            app.msg.clear(); 
            // Reset any active filters
            app.active_tf = None;
            app.search_query.clear();
            if let Some(ref vault) = app.vault {
                app.entry_disp = vault.e.clone();
            }
        }
        KeyCode::Char('2') => { app.screen = Screen::AddPassword; app.ca_form(); app.msg.clear(); }
        KeyCode::Char('3') => { 
            app.screen = Screen::SearchPassword; 
            app.search_query.clear(); 
            app.entry_disp.clear(); 
            app.msg.clear(); 
        }
        KeyCode::Char('4') => { 
            app.screen = Screen::FilterByTag; 
            app.select_tf = 0; 
            app.filter_bt(None); 
            app.msg.clear(); 
        }
        KeyCode::Char('5') => { app.screen = Screen::GeneratePassword; app.input_buffer = String::from("16"); app.gen_pwd.clear(); app.msg.clear(); }
        KeyCode::Char('6') => { 
            app.screen = Screen::DeletePassword; 
            app.input_buffer.clear(); 
            app.msg.clear(); 
            // Use filtered entries for deletion if filter is active
            if app.entry_disp.is_empty() {
                if let Some(ref vault) = app.vault {
                    app.entry_disp = vault.e.clone();
                }
            }
        }
        KeyCode::Char('7') => return true,
        KeyCode::Enter => {
            app.msg.clear();
            match app.selected_menu {
                0 => { 
                    app.screen = Screen::ViewPasswords; 
                    app.active_tf = None;
                    app.search_query.clear();
                    if let Some(ref vault) = app.vault {
                        app.entry_disp = vault.e.clone();
                    }
                }
                1 => { app.screen = Screen::AddPassword; app.ca_form(); }
                2 => { 
                    app.screen = Screen::SearchPassword; 
                    app.search_query.clear(); 
                    app.entry_disp.clear(); 
                }
                3 => { app.screen = Screen::FilterByTag; app.select_tf = 0; app.filter_bt(None); }
                4 => { app.screen = Screen::GeneratePassword; app.input_buffer = String::from("16"); app.gen_pwd.clear(); }
                5 => { 
                    app.screen = Screen::DeletePassword; 
                    app.input_buffer.clear(); 
                    // Use filtered entries for deletion if filter is active
                    if app.entry_disp.is_empty() {
                        if let Some(ref vault) = app.vault {
                            app.entry_disp = vault.e.clone();
                        }
                    }
                }
                6 => return true,
                _ => {}
            }
        }
        KeyCode::Esc => return true,
        _ => {}
    }
    false
}

fn handle_vpi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.selected_entry > 0 {
                app.selected_entry -= 1;
            }
        }
        KeyCode::Down => {
            if app.selected_entry < app.entry_disp.len().saturating_sub(1) {
                app.selected_entry += 1;
            }
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            if app.selected_entry < app.entry_disp.len() {
                let entry_id = app.entry_disp[app.selected_entry].id.clone();
                app.load_efe(entry_id);
            }
        }
        KeyCode::Char('h') | KeyCode::Char('H') => {
            if app.selected_entry < app.entry_disp.len() {
                app.screen = Screen::ViewHistory;
            }
        }
        KeyCode::Char('f') | KeyCode::Char('F') => {
            // Clear all filters
            app.active_tf = None;
            app.search_query.clear();
            if let Some(ref vault) = app.vault {
                app.entry_disp = vault.e.clone();
            }
            app.selected_entry = 0;
            app.set_msg("Filters cleared", MessageType::Success);
        }
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
            app.selected_entry = 0;
        }
        _ => {}
    }
}

fn handle_api(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            match app.add_fi {
                0 => app.n_entry_name.push(c),
                1 => app.n_entry_user.push(c),
                2 => app.n_entry_pass.push(c),
                3 => app.n_entry_url.push(c),
                4 => {
                    if !c.is_ascii_digit() {
                        app.tag_input.push(c);
                    } else if let Some(digit) = c.to_digit(10) {
                        let idx = (digit as usize).saturating_sub(1);
                        app.remove_tag(idx);
                    }
                }
                5 => app.n_entry_notes.push(c),
                _ => {}
            }
        }
        KeyCode::Backspace => {
            match app.add_fi {
                0 => { app.n_entry_name.pop(); }
                1 => { app.n_entry_user.pop(); }
                2 => { app.n_entry_pass.pop(); }
                3 => { app.n_entry_url.pop(); }
                4 => {
                    if app.tag_input.is_empty() && !app.n_entry_tags.is_empty() {
                        app.n_entry_tags.pop();
                    } else {
                        app.tag_input.pop();
                    }
                }
                5 => { app.n_entry_notes.pop(); }
                _ => {}
            }
        }
        KeyCode::Tab => {
            app.add_fi = (app.add_fi + 1) % 6;
        }
        KeyCode::Enter => {
            if app.add_fi == 4 {
                app.add_tag();
            } else if app.add_fi == 5 {
                app.n_entry_notes.push('\n');
            } else {
                app.add_entry();
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
            app.ca_form();
        }
        _ => {}
    }
}

fn handle_epi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            match app.add_fi {
                0 => app.n_entry_name.push(c),
                1 => app.n_entry_user.push(c),
                2 => app.n_entry_pass.push(c),
                3 => app.n_entry_url.push(c),
                4 => {
                    if !c.is_ascii_digit() {
                        app.tag_input.push(c);
                    } else if let Some(digit) = c.to_digit(10) {
                        let idx = (digit as usize).saturating_sub(1);
                        app.remove_tag(idx);
                    }
                }
                5 => app.n_entry_notes.push(c),
                _ => {}
            }
        }
        KeyCode::Backspace => {
            match app.add_fi {
                0 => { app.n_entry_name.pop(); }
                1 => { app.n_entry_user.pop(); }
                2 => { app.n_entry_pass.pop(); }
                3 => { app.n_entry_url.pop(); }
                4 => {
                    if app.tag_input.is_empty() && !app.n_entry_tags.is_empty() {
                        app.n_entry_tags.pop();
                    } else {
                        app.tag_input.pop();
                    }
                }
                5 => { app.n_entry_notes.pop(); }
                _ => {}
            }
        }
        KeyCode::Tab => {
            app.add_fi = (app.add_fi + 1) % 6;
        }
        KeyCode::Enter => {
            if app.add_fi == 4 {
                app.add_tag();
            } else if app.add_fi == 5 {
                app.n_entry_notes.push('\n');
            } else {
                app.edit_entry();
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
            app.ca_form();
        }
        _ => {}
    }
}

fn handle_vhi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.screen = Screen::ViewPasswords;
        }
        _ => {}
    }
}

fn handle_si(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            app.search_query.push(c);
            app.search_entries();
        }
        KeyCode::Backspace => {
            app.search_query.pop();
            app.search_entries();
        }
        KeyCode::Enter => {
            app.screen = Screen::ViewPasswords;
        }
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
        }
        _ => {}
    }
}

fn handle_gi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) if c.is_ascii_digit() => {
            app.input_buffer.push(c);
        }
        KeyCode::Backspace => {
            app.input_buffer.pop();
        }
        KeyCode::Enter => {
            app.gen_pwd();
        }
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
        }
        _ => {}
    }
}

fn handle_di(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) if c.is_ascii_digit() => {
            app.input_buffer.push(c);
        }
        KeyCode::Backspace => {
            app.input_buffer.pop();
        }
        KeyCode::Enter => {
            if let Ok(idx) = app.input_buffer.parse::<usize>() {
                if idx > 0 && idx <= app.entry_disp.len() {
                    let entry_id = app.entry_disp[idx - 1].id.clone();
                    // Find the actual index in the vault
                    if let Some(ref vault) = app.vault {
                        if let Some(vault_idx) = vault.e.iter().position(|e| e.id == entry_id) {
                            app.delete_entry(vault_idx);
                        } else {
                            app.set_msg("Entry not found in vault!", MessageType::Error);
                        }
                    }
                } else {
                    app.set_msg("Invalid entry number!", MessageType::Error);
                }
            } else {
                app.set_msg("Please enter a valid number!", MessageType::Error);
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
        }
        _ => {}
    }
}

fn handle_tfi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.select_tf > 0 {
                app.select_tf -= 1;
            }
        }
        KeyCode::Down => {
            if app.select_tf < app.all_tags.len() {
                app.select_tf += 1;
            }
        }
        KeyCode::Enter => {
            if app.select_tf == 0 {
                app.filter_bt(None);
                app.set_msg("Showing all entries", MessageType::Success);
            } else if app.select_tf <= app.all_tags.len() {
                let tag = app.all_tags[app.select_tf - 1].0.clone();
                app.filter_bt(Some(tag.clone()));
                app.set_msg(&format!("Filtered by tag: {}", tag), MessageType::Success);
            }
        }
        KeyCode::Char('v') | KeyCode::Char('V') => {
            if !app.entry_disp.is_empty() {
                app.selected_entry = 0;
                app.screen = Screen::ViewPasswords;
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
        }
        _ => {}
    }
}

pub fn _clr() {}
pub fn _banner() {}
pub fn _info(_: &str) {}
pub fn _ok(_: &str) {}
pub fn _err(_: &str) {}
pub fn _warn(_: &str) {}
pub fn _sep() {}
pub fn _menu() {}
pub fn _inp(_: &str) -> String { String::new() }
pub fn _sec_inp(_: &str) -> String { String::new() }
pub fn _pause() {}