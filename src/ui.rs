use colored::*;
use std::io::{self, Write};

pub fn clr() {
    clearscreen::clear().unwrap();
}

pub fn banner() {
    println!("{}", "╔═══════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                                       ║".bright_cyan());
    println!("{}     {}      {}", "║".bright_cyan(), "PASSLOCK v0.1".bright_white().bold(), "               ║".bright_cyan());
    println!("{}   {}   {}", "║".bright_cyan(), "secure password manager".bright_black(), "          ║".bright_cyan());
    println!("{}", "║                                       ║".bright_cyan());
    println!("{}", "╚═══════════════════════════════════════╝".bright_cyan());
    println!();
}

pub fn sep() {
    println!("{}", "───────────────────────────────────────".bright_black());
}

pub fn menu() {
    sep();
    println!("  {}  list all passwords", "[1]".bright_green().bold());
    println!("  {}  add new password", "[2]".bright_green().bold());
    println!("  {}  search password", "[3]".bright_green().bold());
    println!("  {}  generate password", "[4]".bright_green().bold());
    println!("  {}  delete password", "[5]".bright_green().bold());
    println!("  {}  exit", "[0]".bright_red().bold());
    sep();
}

pub fn inp(prompt: &str) -> String {
    print!("{} ", prompt.bright_yellow());
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

pub fn sec_inp(prompt: &str) -> String {
    print!("{} ", prompt.bright_yellow());
    io::stdout().flush().unwrap();
    rpassword::read_password().unwrap_or_default()
}

pub fn ok(msg: &str) {
    println!("{} {}", "✓".bright_green().bold(), msg.bright_white());
}

pub fn err(msg: &str) {
    println!("{} {}", "✗".bright_red().bold(), msg.bright_white());
}

pub fn info(msg: &str) {
    println!("{} {}", "→".bright_blue().bold(), msg.bright_white());
}

pub fn warn(msg: &str) {
    println!("{} {}", "!".bright_yellow().bold(), msg.bright_white());
}

pub fn pause() {
    println!();
    print!("{}", "press enter to continue...".bright_black());
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
}