use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;

const VAULT_SUCCESS: c_int = 0;
const VAULT_ERROR_AUTH: c_int = -4;
pub const SALT_LENGTH: usize = 16;

#[link(name = "vault_engine", kind = "static")]
extern "C" {
    fn vault_init() -> c_int;
    fn vault_cleanup();

    fn vault_encrypt(
        plaintext: *const c_uchar,
        plaintext_len: usize,
        password: *const c_char,
        password_len: usize,
        salt: *const c_uchar,
        ciphertext_out: *mut *mut c_uchar,
        ciphertext_len_out: *mut usize,
    ) -> c_int;

    fn vault_decrypt(
        ciphertext: *const c_uchar,
        ciphertext_len: usize,
        password: *const c_char,
        password_len: usize,
        salt: *const c_uchar,
        plaintext_out: *mut *mut c_uchar,
        plaintext_len_out: *mut usize,
    ) -> c_int;

    fn vault_gen_salt(salt: *mut c_uchar, salt_len: usize) -> c_int;

    fn vault_free_buffer(buf: *mut c_uchar);

    fn vault_secure_zero(ptr: *mut c_uchar, len: usize);
}

pub fn init() -> Result<(), String> {
    unsafe {
        if vault_init() == VAULT_SUCCESS {
            Ok(())
        } else {
            Err("Failed to initialize vault engine".to_string())
        }
    }
}

pub fn cleanup() {
    unsafe {
        vault_cleanup();
    }
}

pub fn generate_salt() -> Result<Vec<u8>, String> {
    let mut salt = vec![0u8; SALT_LENGTH];
    unsafe {
        if vault_gen_salt(salt.as_mut_ptr(), SALT_LENGTH) == VAULT_SUCCESS {
            Ok(salt)
        } else {
            Err("Failed to generate salt".to_string())
        }
    }
}

pub fn encrypt_data(plaintext: &[u8], password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    if salt.len() != SALT_LENGTH {
        return Err(format!(
            "Invalid salt length: expected {}, got {}",
            SALT_LENGTH,
            salt.len()
        ));
    }

    let password_cstr = CString::new(password).map_err(|_| "Invalid password string")?;

    let mut ciphertext_ptr: *mut c_uchar = ptr::null_mut();
    let mut ciphertext_len: usize = 0;

    unsafe {
        let result = vault_encrypt(
            plaintext.as_ptr(),
            plaintext.len(),
            password_cstr.as_ptr(),
            password.len(),
            salt.as_ptr(),
            &mut ciphertext_ptr,
            &mut ciphertext_len,
        );

        if result == VAULT_SUCCESS {
            let ciphertext = std::slice::from_raw_parts(ciphertext_ptr, ciphertext_len).to_vec();
            vault_free_buffer(ciphertext_ptr);
            Ok(ciphertext)
        } else {
            if !ciphertext_ptr.is_null() {
                vault_free_buffer(ciphertext_ptr);
            }
            Err("Encryption failed".to_string())
        }
    }
}

pub fn decrypt_data(ciphertext: &[u8], password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    if salt.len() != SALT_LENGTH {
        return Err(format!(
            "Invalid salt length: expected {}, got {}",
            SALT_LENGTH,
            salt.len()
        ));
    }

    let password_cstr = CString::new(password).map_err(|_| "Invalid password string")?;

    let mut plaintext_ptr: *mut c_uchar = ptr::null_mut();
    let mut plaintext_len: usize = 0;

    unsafe {
        let result = vault_decrypt(
            ciphertext.as_ptr(),
            ciphertext.len(),
            password_cstr.as_ptr(),
            password.len(),
            salt.as_ptr(),
            &mut plaintext_ptr,
            &mut plaintext_len,
        );

        if result == VAULT_SUCCESS {
            let plaintext = std::slice::from_raw_parts(plaintext_ptr, plaintext_len).to_vec();
            vault_free_buffer(plaintext_ptr);
            Ok(plaintext)
        } else {
            if !plaintext_ptr.is_null() {
                vault_free_buffer(plaintext_ptr);
            }
            if result == VAULT_ERROR_AUTH {
                Err("Wrong password".to_string())
            } else {
                Err("Decryption failed".to_string())
            }
        }
    }
}

pub fn secure_zero(data: &mut [u8]) {
    unsafe {
        vault_secure_zero(data.as_mut_ptr(), data.len());
    }
}
