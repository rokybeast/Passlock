use crate::vault_ffi;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordStrength {
    pub score: i32,
    pub strength: String,
    pub percentage: i32,
    pub feedback: Vec<String>,
}

pub fn init_crypto() -> Result<(), String> {
    vault_ffi::init()
}

pub fn cleanup() {
    vault_ffi::cleanup();
}

pub fn gen_salt() -> String {
    match vault_ffi::generate_salt() {
        Ok(salt_bytes) => hex::encode(salt_bytes),
        Err(_) => {
            let mut rng = rand::thread_rng();
            let salt_bytes: Vec<u8> = (0..vault_ffi::SALT_LENGTH).map(|_| rng.gen()).collect();
            hex::encode(salt_bytes)
        }
    }
}

pub fn enc(data: &[u8], pwd: &str, salt_hex: &str) -> Result<Vec<u8>, String> {
    let salt = hex::decode(salt_hex).map_err(|_| "Invalid salt hex")?;
    vault_ffi::encrypt_data(data, pwd, &salt)
}

pub fn dec(data: &[u8], pwd: &str, salt_hex: &str) -> Result<Vec<u8>, String> {
    let salt = hex::decode(salt_hex).map_err(|_| "Invalid salt hex")?;
    vault_ffi::decrypt_data(data, pwd, &salt)
}

pub fn gen_pwd(len: usize) -> String {
    let chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..chars.len());
            chars.chars().nth(idx).unwrap()
        })
        .collect()
}

pub fn calc_pwd_strength(password: &str) -> PasswordStrength {
    let mut score = 0;
    let mut feedback = Vec::new();
    let length = password.len();

    if length >= 8 {
        score += 1;
    }
    if length >= 12 {
        score += 1;
    }
    if length >= 16 {
        score += 1;
    }
    if length < 8 {
        feedback.push("Use at least 8 characters".to_string());
    }

    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

    if has_lower {
        score += 1;
    } else {
        feedback.push("Add lowercase letters".to_string());
    }

    if has_upper {
        score += 1;
    } else {
        feedback.push("Add uppercase letters".to_string());
    }

    if has_digit {
        score += 1;
    } else {
        feedback.push("Add numbers".to_string());
    }

    if has_special {
        score += 1;
    } else {
        feedback.push("Add special characters".to_string());
    }

    let lower_pwd = password.to_lowercase();
    let common_patterns = ["123", "abc", "password", "qwerty", "admin"];
    for pattern in &common_patterns {
        if lower_pwd.contains(pattern) {
            score -= 2;
            feedback.push("Avoid common patterns".to_string());
            break;
        }
    }

    if length >= 20 {
        score += 1;
    }

    if score < 0 {
        score = 0;
    }

    let (strength, percentage) = match score {
        0..=2 => ("Weak", 25),
        3..=4 => ("Fair", 50),
        5..=6 => ("Good", 75),
        _ => ("Strong", 100),
    };

    PasswordStrength {
        score,
        strength: strength.to_string(),
        percentage,
        feedback,
    }
}

#[allow(dead_code)]
pub fn secure_wipe(data: &mut [u8]) {
    vault_ffi::secure_zero(data);
}
