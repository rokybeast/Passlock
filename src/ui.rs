use crate::crypto;
use crate::models::{Entry, Vault};
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

#[derive(Clone, PartialEq)]
enum Screen {
    VaultCheck,
    CreateVault,
    UnlockVault,
    MainMenu,
    ViewPasswords,
    AddPassword,
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
    selected_tag_filter: usize,
    active_tag_filter: Option<String>,
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
            selected_tag_filter: 0,
            active_tag_filter: None,
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
                self.load_all_tags();
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

        let entry = Entry {
            id: crate::generate_uuid(),
            n: self.n_entry_name.clone(),
            u: self.n_entry_user.clone(),
            p: self.n_entry_pass.clone(),
            url: if self.n_entry_url.is_empty() { None } else { Some(self.n_entry_url.clone()) },
            nt: if self.n_entry_notes.is_empty() { None } else { Some(self.n_entry_notes.clone()) },
            t: crate::get_timestamp(),
            tags: self.n_entry_tags.clone(),
        };

        if let Some(ref mut vault) = self.vault {
            vault.e.push(entry);
            
            if let Err(e) = storage::svv(vault, &self.master_pwd) {
                self.set_msg(&format!("Failed to save: {}", e), MessageType::Error);
            } else {
                self.set_msg("Password added successfully!", MessageType::Success);
                self.ca_form();
                self.screen = Screen::MainMenu;
                self.load_all_tags();
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
                    self.load_all_tags();
                }
            } else {
                self.set_msg("Invalid entry number!", MessageType::Error);
            }
        }
    }

    fn search_entries(&mut self) {
        if let Some(ref vault) = self.vault {
            let query = self.search_query.to_lowercase();
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

    fn load_all_tags(&mut self) {
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

    fn filter_by_tag(&mut self, tag: Option<String>) {
        self.active_tag_filter = tag.clone();
        
        if let Some(ref vault) = self.vault {
            if let Some(filter_tag) = tag {
                self.entry_disp = vault
                    .e
                    .iter()
                    .filter(|e| e.tags.contains(&filter_tag))
                    .cloned()
                    .collect();
            } else {
                self.entry_disp = vault.e.clone();
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
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error: {:?}", err);
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()> {
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
        .border_style(Style::default().fg(Color::Rgb(80, 120, 150)))
        .title(" PASSLOCK ")
        .title_alignment(Alignment::Center);

    let text = Paragraph::new("Initializing vault...")
        .block(block)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Rgb(150, 170, 190)));

    f.render_widget(Clear, area);
    f.render_widget(text, area);
}

fn draw_create_vault(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(60, 65, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" CREATE VAULT ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let title = Paragraph::new("Create your master password")
        .style(Style::default().fg(Color::Rgb(140, 160, 180)))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    let pwd_text = if app.input_field == InputField::Password {
        format!("Password: {}", "•".repeat(app.input_buffer.len()))
    } else {
        format!("Password: {}", "•".repeat(app.input_buffer.len()))
    };
    
    let pwd_style = if app.input_field == InputField::Password {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    
    let password_input = Paragraph::new(pwd_text)
        .style(pwd_style);
    f.render_widget(password_input, chunks[1]);

    if !app.input_buffer.is_empty() && app.input_field == InputField::Password {
        let strength = crypto::calc_pwd_strength(&app.input_buffer);
        
        let strength_color = match strength.strength.as_str() {
            "Weak" => Color::Rgb(180, 80, 80),
            "Fair" => Color::Rgb(180, 140, 80),
            "Good" => Color::Rgb(100, 140, 180),
            "Strong" => Color::Rgb(100, 160, 120),
            _ => Color::Rgb(120, 120, 120),
        };
        
        let bar_width = (30 * strength.percentage) / 100;
        let empty_width = 30 - bar_width;
        let bar = format!("[{}{}] {}% {}", 
            "━".repeat(bar_width as usize),
            "─".repeat(empty_width as usize),
            strength.percentage,
            strength.strength
        );
        
        let strength_display = Paragraph::new(bar)
            .style(Style::default().fg(strength_color))
            .alignment(Alignment::Center);
        f.render_widget(strength_display, chunks[2]);
        
        if !strength.feedback.is_empty() {
            let feedback_text = strength.feedback.join(", ");
            let feedback = Paragraph::new(format!("Tip: {}", feedback_text))
                .style(Style::default().fg(Color::Rgb(100, 110, 120)))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true });
            f.render_widget(feedback, chunks[3]);
        }
    }

    let confirm_text = if app.input_field == InputField::PasswordConfirm {
        format!("Confirm: {}", "•".repeat(app.input_buffer2.len()))
    } else {
        format!("Confirm: {}", "•".repeat(app.input_buffer2.len()))
    };
    
    let confirm_style = if app.input_field == InputField::PasswordConfirm {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    
    let confirm_input = Paragraph::new(confirm_text)
        .style(confirm_style);
    f.render_widget(confirm_input, chunks[4]);

    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(Color::Rgb(100, 160, 120)),
            MessageType::Error => Style::default().fg(Color::Rgb(180, 90, 90)),
            MessageType::Info => Style::default().fg(Color::Rgb(100, 140, 180)),
            MessageType::None => Style::default().fg(Color::Rgb(140, 150, 160)),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center);
        f.render_widget(msg, chunks[5]);
    }

    let help = Paragraph::new("Tab: Switch | Enter: Create | Esc: Quit")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[6]);
}

fn draw_unlock_vault(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(60, 40, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" UNLOCK VAULT ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let title = Paragraph::new("Enter your master password")
        .style(Style::default().fg(Color::Rgb(140, 160, 180)))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    let pwd_text = format!("Password: {}", "•".repeat(app.input_buffer.len()));
    let password_input = Paragraph::new(pwd_text)
        .style(Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD));
    f.render_widget(password_input, chunks[1]);

    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(Color::Rgb(100, 160, 120)),
            MessageType::Error => Style::default().fg(Color::Rgb(180, 90, 90)),
            MessageType::Info => Style::default().fg(Color::Rgb(100, 140, 180)),
            MessageType::None => Style::default().fg(Color::Rgb(140, 150, 160)),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center);
        f.render_widget(msg, chunks[2]);
    }

    let help = Paragraph::new("Enter: Unlock | Esc: Quit")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}

fn draw_main_menu(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(70, 60, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" PASSLOCK ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let vault_info = if let Some(ref vault) = app.vault {
        let tag_count = app.all_tags.len();
        format!("Vault unlocked  |  {} passwords  |  {} tags", vault.e.len(), tag_count)
    } else {
        "No vault loaded".to_string()
    };
    
    let info = Paragraph::new(vault_info)
        .style(Style::default().fg(Color::Rgb(140, 160, 180)))
        .alignment(Alignment::Center);
    f.render_widget(info, chunks[0]);

    let menu_items = vec![
        "View All Passwords",
        "Add New Password",
        "Search Passwords",
        "Filter by Tag",
        "Generate Password",
        "Delete Password",
        "Exit",
    ];

    let items: Vec<ListItem> = menu_items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let style = if i == app.selected_menu {
                Style::default()
                    .fg(Color::Rgb(180, 200, 220))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Rgb(140, 150, 160))
            };
            
            let prefix = if i == app.selected_menu { " > " } else { "   " };
            ListItem::new(format!("{}{}", prefix, item)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::NONE));
    
    f.render_widget(list, chunks[1]);

    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(Color::Rgb(100, 160, 120)),
            MessageType::Error => Style::default().fg(Color::Rgb(180, 90, 90)),
            MessageType::Info => Style::default().fg(Color::Rgb(100, 140, 180)),
            MessageType::None => Style::default().fg(Color::Rgb(140, 150, 160)),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        f.render_widget(msg, chunks[2]);
    }

    let help = Paragraph::new("↑/↓: Navigate | Enter: Select | Esc: Back")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}

fn draw_view_pwds(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(90, 80, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" ALL PASSWORDS ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    if let Some(ref vault) = app.vault {
        let title = Paragraph::new(format!("Total: {} passwords", vault.e.len()))
            .style(Style::default().fg(Color::Rgb(140, 160, 180)))
            .alignment(Alignment::Center);
        f.render_widget(title, chunks[0]);

        if vault.e.is_empty() {
            let empty = Paragraph::new("No passwords saved yet")
                .style(Style::default().fg(Color::Rgb(100, 110, 120)))
                .alignment(Alignment::Center);
            f.render_widget(empty, chunks[1]);
        } else {
            let items: Vec<ListItem> = vault
                .e
                .iter()
                .enumerate()
                .map(|(i, entry)| {
                    let mut lines = vec![
                        Line::from(vec![
                            Span::styled(
                                format!("[{}] ", i + 1),
                                Style::default().fg(Color::Rgb(100, 140, 180)),
                            ),
                            Span::styled(
                                &entry.n,
                                Style::default().fg(Color::Rgb(140, 180, 160)).add_modifier(Modifier::BOLD),
                            ),
                        ]),
                        Line::from(vec![
                            Span::raw("    User: "),
                            Span::styled(&entry.u, Style::default().fg(Color::Rgb(160, 170, 180))),
                        ]),
                        Line::from(vec![
                            Span::raw("    Pass: "),
                            Span::styled(&entry.p, Style::default().fg(Color::Rgb(140, 150, 180))),
                        ]),
                    ];

                    if let Some(ref url) = entry.url {
                        lines.push(Line::from(vec![
                            Span::raw("    URL:  "),
                            Span::styled(url, Style::default().fg(Color::Rgb(100, 130, 160))),
                        ]));
                    }

                    if let Some(ref notes) = entry.nt {
                        lines.push(Line::from(vec![
                            Span::raw("    Note: "),
                            Span::styled(notes, Style::default().fg(Color::Rgb(110, 120, 130))),
                        ]));
                    }

                    if !entry.tags.is_empty() {
                        lines.push(Line::from(vec![
                            Span::raw("    Tags: "),
                            Span::styled(
                                entry.tags.join(", "),
                                Style::default().fg(Color::Rgb(120, 180, 140))
                            ),
                        ]));
                    }

                    lines.push(Line::from(""));

                    ListItem::new(lines)
                })
                .collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::NONE));
            
            f.render_widget(list, chunks[1]);
        }
    }

    let help = Paragraph::new("Esc: Back to menu")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[2]);
}

fn draw_add_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(75, 82, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" ADD NEW PASSWORD ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let title = Paragraph::new("Fill in the details")
        .style(Style::default().fg(Color::Rgb(140, 160, 180)))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    let name_style = if app.add_fi == 0 {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    let name_field = Paragraph::new(format!("Name: {}", app.n_entry_name))
        .style(name_style);
    f.render_widget(name_field, chunks[1]);

    let user_style = if app.add_fi == 1 {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    let user_field = Paragraph::new(format!("Username: {}", app.n_entry_user))
        .style(user_style);
    f.render_widget(user_field, chunks[2]);

    let pass_style = if app.add_fi == 2 {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    let pass_field = Paragraph::new(format!("Password: {}", app.n_entry_pass))
        .style(pass_style);
    f.render_widget(pass_field, chunks[3]);

    if !app.n_entry_pass.is_empty() && app.add_fi == 2 {
        let strength = crypto::calc_pwd_strength(&app.n_entry_pass);
        
        let strength_color = match strength.strength.as_str() {
            "Weak" => Color::Rgb(180, 80, 80),
            "Fair" => Color::Rgb(180, 140, 80),
            "Good" => Color::Rgb(100, 140, 180),
            "Strong" => Color::Rgb(100, 160, 120),
            _ => Color::Rgb(120, 120, 120),
        };
        
        let bar_width = (30 * strength.percentage) / 100;
        let empty_width = 30 - bar_width;
        let bar = format!("[{}{}] {}% {}", 
            "━".repeat(bar_width as usize),
            "─".repeat(empty_width as usize),
            strength.percentage,
            strength.strength
        );
        
        let strength_display = Paragraph::new(bar)
            .style(Style::default().fg(strength_color))
            .alignment(Alignment::Center);
        f.render_widget(strength_display, chunks[4]);
        
        if !strength.feedback.is_empty() {
            let feedback_text = strength.feedback.join(", ");
            let feedback = Paragraph::new(format!("Tip: {}", feedback_text))
                .style(Style::default().fg(Color::Rgb(100, 110, 120)))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true });
            f.render_widget(feedback, chunks[5]);
        }
    }

    let url_style = if app.add_fi == 3 {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    let url_field = Paragraph::new(format!("URL (optional): {}", app.n_entry_url))
        .style(url_style);
    f.render_widget(url_field, chunks[6]);

    let tags_input_style = if app.add_fi == 4 {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    let tags_input_text = if app.add_fi == 4 {
        format!("Tags: {} (Enter to add, Backspace to remove)", app.tag_input)
    } else {
        "Tags: (Tab to focus)".to_string()
    };
    let tags_input = Paragraph::new(tags_input_text)
        .style(tags_input_style)
        .wrap(Wrap { trim: true });
    f.render_widget(tags_input, chunks[7]);

    if !app.n_entry_tags.is_empty() {
        let tags_display = app.n_entry_tags
            .iter()
            .enumerate()
            .map(|(i, tag)| format!("[{}] {}", i + 1, tag))
            .collect::<Vec<_>>()
            .join("  ");
        
        let tags_widget = Paragraph::new(format!("Added: {}", tags_display))
            .style(Style::default().fg(Color::Rgb(120, 180, 140)))
            .wrap(Wrap { trim: true });
        f.render_widget(tags_widget, chunks[8]);
    }

    let notes_style = if app.add_fi == 5 {
        Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Rgb(140, 150, 160))
    };
    let notes = Paragraph::new(format!("Notes (optional):\n{}", app.n_entry_notes))
        .style(notes_style)
        .wrap(Wrap { trim: false });
    f.render_widget(notes, chunks[9]);

    if !app.msg.is_empty() {
        let msg_style = match app.msg_type {
            MessageType::Success => Style::default().fg(Color::Rgb(100, 160, 120)),
            MessageType::Error => Style::default().fg(Color::Rgb(180, 90, 90)),
            MessageType::Info => Style::default().fg(Color::Rgb(100, 140, 180)),
            MessageType::None => Style::default().fg(Color::Rgb(140, 150, 160)),
        };
        let msg = Paragraph::new(app.msg.as_str())
            .style(msg_style)
            .alignment(Alignment::Center);
        f.render_widget(msg, chunks[10]);
    }

    let help = Paragraph::new("Tab: Next | Enter: Add tag/Save | 1-9: Remove tag | Esc: Cancel")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[11]);
}

fn draw_filter_tags(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(80, 70, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" FILTER BY TAG ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let title = if let Some(ref tag) = app.active_tag_filter {
        format!("Filtering by: {} ({} entries)", tag, app.entry_disp.len())
    } else {
        "Select a tag to filter".to_string()
    };
    
    let title_widget = Paragraph::new(title)
        .style(Style::default().fg(Color::Rgb(140, 160, 180)))
        .alignment(Alignment::Center);
    f.render_widget(title_widget, chunks[0]);

    if app.all_tags.is_empty() {
        let empty = Paragraph::new("No tags available. Add tags to your passwords first!")
            .style(Style::default().fg(Color::Rgb(100, 110, 120)))
            .alignment(Alignment::Center);
        f.render_widget(empty, chunks[1]);
    } else {
        let mut items = vec![ListItem::new(Line::from(vec![
            Span::styled(
                if app.selected_tag_filter == 0 { " > " } else { "   " },
                Style::default().fg(Color::Rgb(120, 180, 140))
            ),
            Span::styled(
                format!("All ({} total)", app.vault.as_ref().map_or(0, |v| v.e.len())),
                if app.selected_tag_filter == 0 {
                    Style::default().fg(Color::Rgb(180, 200, 220)).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Rgb(140, 150, 160))
                }
            ),
        ]))];

        for (idx, (tag, count)) in app.all_tags.iter().enumerate() {
            let is_selected = idx + 1 == app.selected_tag_filter;
            let prefix = if is_selected { " > " } else { "   " };
            
            items.push(ListItem::new(Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::Rgb(120, 180, 140))),
                Span::styled(
                    format!("{} ({})", tag, count),
                    if is_selected {
                        Style::default().fg(Color::Rgb(180, 200, 220)).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Rgb(140, 150, 160))
                    }
                ),
            ])));
        }

        let list = List::new(items)
            .block(Block::default().borders(Borders::NONE));
        
        f.render_widget(list, chunks[1]);
    }

    if app.active_tag_filter.is_some() {
        let filter_info = Paragraph::new("Press V to view filtered passwords")
            .style(Style::default().fg(Color::Rgb(120, 180, 140)))
            .alignment(Alignment::Center);
        f.render_widget(filter_info, chunks[2]);
    }

    let help = Paragraph::new("↑/↓: Navigate | Enter: Apply Filter | V: View | Esc: Back")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}

fn draw_search_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(80, 70, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" SEARCH PASSWORDS ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let title = Paragraph::new("Search by name, username, URL, or tags")
        .style(Style::default().fg(Color::Rgb(140, 160, 180)))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    let search = Paragraph::new(format!("Search: {}", app.search_query))
        .style(Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD));
    f.render_widget(search, chunks[1]);

    if app.entry_disp.is_empty() && !app.search_query.is_empty() {
        let empty = Paragraph::new("No matches found")
            .style(Style::default().fg(Color::Rgb(100, 110, 120)))
            .alignment(Alignment::Center);
        f.render_widget(empty, chunks[2]);
    } else if !app.entry_disp.is_empty() {
        let items: Vec<ListItem> = app
            .entry_disp
            .iter()
            .map(|entry| {
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled(&entry.n, Style::default().fg(Color::Rgb(140, 180, 160)).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(vec![
                        Span::raw("  User: "),
                        Span::styled(&entry.u, Style::default().fg(Color::Rgb(160, 170, 180))),
                    ]),
                    Line::from(vec![
                        Span::raw("  Pass: "),
                        Span::styled(&entry.p, Style::default().fg(Color::Rgb(140, 150, 180))),
                    ]),
                ];
                
                if !entry.tags.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("  Tags: "),
                        Span::styled(
                            entry.tags.join(", "),
                            Style::default().fg(Color::Rgb(120, 180, 140))
                        ),
                    ]));
                }
                
                lines.push(Line::from(""));

                ListItem::new(lines)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::NONE));
        
        f.render_widget(list, chunks[2]);
    }

    let help = Paragraph::new("Type to search | Esc: Back")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[3]);
}

fn draw_gen_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(60, 50, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(5),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(90, 100, 130)))
        .title(" GENERATE PASSWORD ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let title = Paragraph::new("Enter password length (4-64)")
        .style(Style::default().fg(Color::Rgb(140, 160, 180)))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    let length_input = Paragraph::new(format!("Length: {}", if app.input_buffer.is_empty() { "16" } else { &app.input_buffer }))
        .style(Style::default().fg(Color::Rgb(120, 180, 140)).add_modifier(Modifier::BOLD));
    f.render_widget(length_input, chunks[1]);

    if !app.gen_pwd.is_empty() {
        let generated = Paragraph::new(vec![
            Line::from(""),
            Line::from("Generated Password:"),
            Line::from(""),
            Line::from(Span::styled(
                &app.gen_pwd,
                Style::default().fg(Color::Rgb(140, 180, 160)).add_modifier(Modifier::BOLD),
            )),
        ])
        .alignment(Alignment::Center);
        f.render_widget(generated, chunks[2]);
    }

    let help = Paragraph::new("Enter: Generate | Esc: Back")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[4]);
}

fn draw_del_pwd(f: &mut Frame, size: Rect, app: &App) {
    let area = centered_rect(80, 70, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(160, 90, 90)))
        .title(" DELETE PASSWORD ")
        .title_alignment(Alignment::Center);

    f.render_widget(block, area);

    let title = Paragraph::new("Enter the number of the entry to delete")
        .style(Style::default().fg(Color::Rgb(180, 140, 140)))
        .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    if let Some(ref vault) = app.vault {
        if vault.e.is_empty() {
            let empty = Paragraph::new("No passwords to delete")
                .style(Style::default().fg(Color::Rgb(100, 110, 120)))
                .alignment(Alignment::Center);
            f.render_widget(empty, chunks[1]);
        } else {
            let items: Vec<ListItem> = vault
                .e
                .iter()
                .enumerate()
                .map(|(i, entry)| {
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!("[{}] ", i + 1),
                            Style::default().fg(Color::Rgb(160, 90, 90)),
                        ),
                        Span::styled(&entry.n, Style::default().fg(Color::Rgb(140, 150, 160))),
                    ]))
                })
                .collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::NONE));
            
            f.render_widget(list, chunks[1]);
        }
    }

    let input = Paragraph::new(format!("Entry number: {}", app.input_buffer))
        .style(Style::default().fg(Color::Rgb(160, 90, 90)).add_modifier(Modifier::BOLD));
    f.render_widget(input, chunks[2]);

    let help = Paragraph::new("Type number | Enter: Delete | Esc: Cancel")
        .style(Style::default().fg(Color::Rgb(90, 100, 110)))
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
            }
        }
        KeyCode::Down => {
            if app.selected_menu < 6 {
                app.selected_menu += 1;
            }
        }
        KeyCode::Enter => {
            app.msg.clear();
            match app.selected_menu {
                0 => app.screen = Screen::ViewPasswords,
                1 => {
                    app.screen = Screen::AddPassword;
                    app.ca_form();
                }
                2 => {
                    app.screen = Screen::SearchPassword;
                    app.search_query.clear();
                    app.entry_disp.clear();
                }
                3 => {
                    app.screen = Screen::FilterByTag;
                    app.selected_tag_filter = 0;
                    app.filter_by_tag(None);
                }
                4 => {
                    app.screen = Screen::GeneratePassword;
                    app.input_buffer = String::from("16");
                    app.gen_pwd.clear();
                }
                5 => {
                    app.screen = Screen::DeletePassword;
                    app.input_buffer.clear();
                }
                6 => return true,
                _ => {}
            }
        }
        KeyCode::Esc => {
            return true;
        }
        _ => {}
    }
    false
}

fn handle_vpi(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.screen = Screen::MainMenu;
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
                if idx > 0 {
                    app.delete_entry(idx - 1);
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
            if app.selected_tag_filter > 0 {
                app.selected_tag_filter -= 1;
            }
        }
        KeyCode::Down => {
            if app.selected_tag_filter < app.all_tags.len() {
                app.selected_tag_filter += 1;
            }
        }
        KeyCode::Enter => {
            if app.selected_tag_filter == 0 {
                app.filter_by_tag(None);
            } else if app.selected_tag_filter <= app.all_tags.len() {
                let tag = app.all_tags[app.selected_tag_filter - 1].0.clone();
                app.filter_by_tag(Some(tag));
            }
        }
        KeyCode::Char('v') | KeyCode::Char('V') => {
            if app.active_tag_filter.is_some() && !app.entry_disp.is_empty() {
                app.screen = Screen::ViewPasswords;
            }
        }
        KeyCode::Esc => {
            app.active_tag_filter = None;
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