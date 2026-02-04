use crate::crypto;
use crate::models::Vault;
use std::fs;
use std::path::PathBuf;

fn vt_p() -> PathBuf {
    let home = dirs::home_dir().expect("no home");
    home.join(".passlock.vault")
}

fn tmp_p() -> PathBuf {
    let home = dirs::home_dir().expect("no home");
    home.join(".passlock.temp")
}

pub fn svv(v: &Vault, pwd: &str) -> Result<(), String> {
    let j = serde_json::to_string(v).map_err(|e| e.to_string())?;
    let j_bytes = j.as_bytes();

    let enc_d = crypto::enc(j_bytes, pwd, &v.s)?;

    let salt_bytes = hex::decode(&v.s).map_err(|_| "Invalid salt")?;
    let mut final_data = Vec::new();
    final_data.extend_from_slice(&salt_bytes);
    final_data.extend_from_slice(&enc_d);

    fs::write(vt_p(), final_data).map_err(|e| e.to_string())?;

    let tmp_j = serde_json::to_string(v).map_err(|e| e.to_string())?;
    fs::write(tmp_p(), tmp_j).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn ld_vt(pwd: &str) -> Result<Vault, String> {
    let data = fs::read(vt_p()).map_err(|_| "vault not found")?;

    if data.len() < 16 {
        return Err("corrupt vault".to_string());
    }

    let salt_bytes = &data[0..16];
    let enc_data = &data[16..];
    let salt = hex::encode(salt_bytes);

    let dec_data = crypto::dec(enc_data, pwd, &salt)?;
    let dec_str = String::from_utf8(dec_data).map_err(|_| "invalid data")?;

    let v: Vault = serde_json::from_str(&dec_str).map_err(|e| e.to_string())?;

    let tmp_j = serde_json::to_string(&v).map_err(|e| e.to_string())?;
    fs::write(tmp_p(), tmp_j).map_err(|e| e.to_string())?;

    Ok(v)
}

pub fn vt_exi() -> bool {
    vt_p().exists()
}
