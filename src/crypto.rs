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
        .map_err(|_| "decryption failed - wrong password?")?;
    
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
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"; //needs more
    let mut r = rand::thread_rng();
    (0..len)
        .map(|_| {
            let i = r.gen_range(0..CHARS.len());
            CHARS[i] as char
        })
        .collect()
}