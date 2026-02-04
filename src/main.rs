mod crypto;
mod models;
mod storage;
mod ui;

use models::Vault;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 3 && args[1] == "create" {
        let pwd = &args[2];

        if storage::vt_exi() {
            eprintln!("Error: vault already exists");
            std::process::exit(1);
        }

        let salt = crypto::gen_salt();
        let v = Vault::new(salt);

        match storage::svv(&v, pwd) {
            Ok(_) => {
                let temp_path = storage::gtp_path();
                if let Ok(json) = serde_json::to_string(&v) {
                    let _ = std::fs::write(&temp_path, json);
                }
                println!("✓ vault created");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }

    if args.len() >= 3 && args[1] == "unlock" {
        let pwd = &args[2];

        match storage::ld_vt(pwd) {
            Ok(vault) => {
                let temp_path = storage::gtp_path();
                if let Ok(json) = serde_json::to_string(&vault) {
                    if std::fs::write(&temp_path, json).is_ok() {
                        println!("✓ vault unlocked");
                        std::process::exit(0);
                    }
                }
                eprintln!("Error: failed to write temp file");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }

    if args.len() >= 3 && args[1] == "sync" {
        let pwd = &args[2];

        let temp_path = storage::gtp_path();
        if let Ok(data) = std::fs::read_to_string(&temp_path) {
            if let Ok(vault) = serde_json::from_str::<Vault>(&data) {
                if let Err(e) = storage::svv(&vault, pwd) {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
                println!("✓ synced to vault");
                std::process::exit(0);
            }
        }
        eprintln!("Error: failed to read temp file");
        std::process::exit(1);
    }

    if let Err(e) = ui::run_tui() {
        eprintln!("Error running TUI: {e}");
        std::process::exit(1);
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

pub fn generate_uuid() -> String {
    uuid()
}

pub fn get_timestamp() -> u64 {
    now()
}
