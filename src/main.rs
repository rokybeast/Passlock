mod crypto;
mod storage;
mod models;
mod ui;

use models::{Entry, Vault};
use std::time::{SystemTime, UNIX_EPOCH};
use colored::Colorize;

fn main() {
    ui::clr();
    ui::banner();
    
    let pwd = if storage::vault_exists() {
        ui::info("vault found - enter master password");
        ui::sec_inp("password:")
    } else {
        ui::info("no vault found - creating new one");
        let p1 = ui::sec_inp("new password:");
        let p2 = ui::sec_inp("confirm:");
        
        if p1 != p2 {
            ui::err("passwords dont match");
            return;
        }
        
        let salt = crypto::gen_salt();
        let v = Vault::new(salt);
        
        if let Err(e) = storage::save_vault(&v, &p1) {
            ui::err(&format!("failed to create vault: {}", e));
            return;
        }
        
        ui::ok("vault created successfully");
        p1
    };
    
    let mut v = match storage::load_vault(&pwd) {
        Ok(vault) => {
            ui::ok("vault unlocked");
            vault
        }
        Err(e) => {
            ui::err(&format!("failed to unlock: {}", e));
            return;
        }
    };
    
    loop {
        ui::clr();
        ui::banner();
        ui::menu();
        
        let choice = ui::inp("choice:");
        
        match choice.as_str() {
            "1" => list_all(&v),
            "2" => add_entry(&mut v, &pwd),
            "3" => search(&v),
            "4" => gen_password(),
            "5" => delete_entry(&mut v, &pwd),
            "0" => {
                ui::ok("goodbye");
                break;
            }
            _ => ui::err("invalid choice"),
        }
        
        ui::pause();
    }
}

fn list_all(v: &Vault) {
    ui::clr();
    ui::banner();
    ui::info(&format!("total entries: {}", v.e.len()));
    ui::sep();
    
    if v.e.is_empty() {
        ui::warn("no passwords saved yet");
        return;
    }
    
    for (i, e) in v.e.iter().enumerate() {
        println!();
        println!("  {} {}", format!("[{}]", i + 1).bright_cyan().bold(), e.n.bright_white().bold());
        println!("      user: {}", e.u.bright_black());
        println!("      pass: {}", e.p.bright_green());
        if let Some(url) = &e.url {
            println!("       url: {}", url.bright_blue());
        }
        if let Some(nt) = &e.nt {
            println!("     notes: {}", nt.bright_black());
        }
    }
}

fn add_entry(v: &mut Vault, pwd: &str) {
    ui::clr();
    ui::banner();
    ui::info("add new password");
    ui::sep();
    
    let n = ui::inp("name:");
    let u = ui::inp("username:");
    let p = ui::inp("password (or 'g' to generate):");
    
    let p = if p == "g" || p == "G" {
        let len: usize = ui::inp("length (default 16):").parse().unwrap_or(16);
        let gen = crypto::gen_pwd(len);
        ui::ok(&format!("generated: {}", gen.bright_green()));
        gen
    } else {
        p
    };
    
    let url = ui::inp("url (optional):");
    let nt = ui::inp("notes (optional):");
    
    let e = Entry {
        id: uuid(),
        n,
        u,
        p,
        url: if url.is_empty() { None } else { Some(url) },
        nt: if nt.is_empty() { None } else { Some(nt) },
        t: now(),
    };
    
    v.e.push(e);
    
    if let Err(e) = storage::save_vault(v, pwd) {
        ui::err(&format!("failed to save: {}", e));
    } else {
        ui::ok("password saved");
    }
}

fn search(v: &Vault) {
    ui::clr();
    ui::banner();
    ui::info("search passwords");
    ui::sep();
    
    let q = ui::inp("search:").to_lowercase();
    let mut found = Vec::new();
    
    for e in &v.e {
        if e.n.to_lowercase().contains(&q) 
            || e.u.to_lowercase().contains(&q)
            || e.url.as_ref().map_or(false, |u| u.to_lowercase().contains(&q)) {
            found.push(e);
        }
    }
    
    if found.is_empty() {
        ui::warn("no matches found");
        return;
    }
    
    ui::ok(&format!("found {} match(es)", found.len()));
    ui::sep();
    
    for e in found {
        println!();
        println!("  {}", e.n.bright_white().bold());
        println!("      user: {}", e.u.bright_black());
        println!("      pass: {}", e.p.bright_green());
        if let Some(url) = &e.url {
            println!("       url: {}", url.bright_blue());
        }
    }
}

fn gen_password() {
    ui::clr();
    ui::banner();
    ui::info("password generator");
    ui::sep();
    
    let len: usize = ui::inp("length:").parse().unwrap_or(16);
    let pwd = crypto::gen_pwd(len);
    
    println!();
    ui::ok("generated password:");
    println!();
    println!("      {}", pwd.bright_green().bold());
    println!();
}

fn delete_entry(v: &mut Vault, pwd: &str) {
    ui::clr();
    ui::banner();
    ui::info("delete password");
    ui::sep();
    
    if v.e.is_empty() {
        ui::warn("no passwords to delete");
        return;
    }
    
    for (i, e) in v.e.iter().enumerate() {
        println!("  {} {}", format!("[{}]", i + 1).bright_cyan(), e.n.bright_white());
    }
    
    println!();
    let choice = ui::inp("entry number:");
    
    if let Ok(idx) = choice.parse::<usize>() {
        if idx > 0 && idx <= v.e.len() {
            let removed = v.e.remove(idx - 1);
            
            if let Err(e) = storage::save_vault(v, pwd) {
                ui::err(&format!("failed to save: {}", e));
            } else {
                ui::ok(&format!("deleted '{}'", removed.n));
            }
        } else {
            ui::err("invalid number");
        }
    } else {
        ui::err("invalid input");
    }
}

fn uuid() -> String {
    use rand::Rng;
    let mut r = rand::thread_rng();
    format!("{:x}", r.gen::<u128>())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}