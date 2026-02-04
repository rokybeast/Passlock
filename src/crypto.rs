use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;
use std::ffi::CString;

extern "C" {
    fn xor_buf(d: *mut u8, len: usize, k: *const u8, klen: usize);
    fn gen_rand(buf: *mut u8, n: usize) -> i32;
    fn hash_str(s: *const libc::c_char) -> libc::c_ulong;
    fn sec_zero(p: *mut libc::c_void, n: usize);
}

#[allow(dead_code)]
pub struct PwdStrength {
    pub score: i32,
    pub strength: String,
    pub percentage: i32,
    pub feedback: Vec<String>,
}

pub fn calc_pwd_strength(pwd: &str) -> PwdStrength {
    let mut score = 0;
    let mut feedback = Vec::new();
    
    let length = pwd.len();
    
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
    
    let has_lower = pwd.chars().any(|c| c.is_lowercase());
    let has_upper = pwd.chars().any(|c| c.is_uppercase());
    let has_digit = pwd.chars().any(|c| c.is_ascii_digit());
    let has_special = pwd.chars().any(|c| "!@#$%^&*()_+-=[]{};\':\"\\|,.<>/?".contains(c));
    
    let mut variety_count = 0;
    if has_lower {
        variety_count += 1;
    } else {
        feedback.push("Add lowercase letters".to_string());
    }
    
    if has_upper {
        variety_count += 1;
    } else {
        feedback.push("Add uppercase letters".to_string());
    }
    
    if has_digit {
        variety_count += 1;
    } else {
        feedback.push("Add numbers".to_string());
    }
    
    if has_special {
        variety_count += 1;
    } else {
        feedback.push("Add special characters".to_string());
    }
    
    score += variety_count;
    
    let common_patterns = vec!["123", "abc", "pwd", "qwerty", "admin"];
    let lower_password = pwd.to_lowercase();
    for pattern in common_patterns {
        if lower_password.contains(pattern) {
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
    
    let (strength, percentage) = if score <= 2 {
        ("Weak".to_string(), 25)
    } else if score <= 4 {
        ("Fair".to_string(), 50)
    } else if score <= 6 {
        ("Good".to_string(), 75)
    } else {
        ("Strong".to_string(), 100)
    };
    
    PwdStrength {
        score,
        strength,
        percentage,
        feedback,
    }
}

pub fn gen_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}

pub fn der_k(pwd: &str, salt: &str) -> Result<[u8; 32], String> {
    let s = SaltString::from_b64(salt).map_err(|e| e.to_string())?;
    let h = Argon2::default()
        .hash_password(pwd.as_bytes(), &s)
        .map_err(|e| e.to_string())?;
    let hash_str = h.hash.ok_or("no hash")?;
    let mut k = [0u8; 32];
    let dcd = hash_str.as_bytes();
    let len = dcd.len().min(32);
    k[..len].copy_from_slice(&dcd[..len]);
    Ok(k)
}

pub fn enc(data: &str, pwd: &str, salt: &str) -> Result<String, String> {
    let k = der_k(pwd, salt)?;
    let c = Aes256Gcm::new(&k.into());
    let mut n_bytes = [0u8; 12];
    unsafe { gen_rand(n_bytes.as_mut_ptr(), 12) };
    let n = Nonce::from(n_bytes);
    let mut data_bytes = data.as_bytes().to_vec();
    let pwd_c = CString::new(pwd).unwrap();
    let h = unsafe { hash_str(pwd_c.as_ptr()) };
    let xor_k = h.to_le_bytes();
    unsafe {
        xor_buf(data_bytes.as_mut_ptr(), data_bytes.len(), 
                xor_k.as_ptr(), xor_k.len());
    }
    let ct = c.encrypt(&n, data_bytes.as_slice())
        .map_err(|e| e.to_string())?;
    let mut result = n_bytes.to_vec();
    result.extend_from_slice(&ct);
    unsafe { sec_zero(k.as_ptr() as *mut libc::c_void, k.len()) };
    Ok(general_purpose::STANDARD.encode(result))
}

pub fn dec(enc_data: &str, pwd: &str, salt: &str) -> Result<String, String> {
    let k = der_k(pwd, salt)?;
    let c = Aes256Gcm::new(&k.into());
    let data = general_purpose::STANDARD.decode(enc_data)
        .map_err(|e| e.to_string())?;
    if data.len() < 12 {
        return Err("invalid data".into());
    }
    let (n_bytes, ct) = data.split_at(12);
    let n_bytes: [u8; 12] = n_bytes.try_into().map_err(|_| "invalid nonce")?;
    let n = Nonce::from(n_bytes);
    let mut pt = c.decrypt(&n, ct)
        .map_err(|_| "decryption failed - wrong pwd?")?;
    let pwd_c = CString::new(pwd).unwrap();
    let h = unsafe { hash_str(pwd_c.as_ptr()) };
    let xor_k = h.to_le_bytes();
    unsafe {
        xor_buf(pt.as_mut_ptr(), pt.len(), 
                xor_k.as_ptr(), xor_k.len());
    }
    unsafe { sec_zero(k.as_ptr() as *mut libc::c_void, k.len()) };
    String::from_utf8(pt).map_err(|e| e.to_string())
}

pub fn gen_pwd(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let mut r = rand::thread_rng();
    (0..len)
        .map(|_| {
            let i = r.gen_range(0..CHARS.len());
            CHARS[i] as char
        })
        .collect()
}