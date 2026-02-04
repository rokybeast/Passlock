use crate::crypto::enc;
use crate::models::Vault;
use std::fs;
use std::path::PathBuf;

pub fn gtv_path() -> PathBuf {
    let mut p = dirs::home_dir().expect("cant find home");
    p.push(".passlock.vault");
    p
}

pub fn gtp_path() -> PathBuf {
    let mut p = dirs::home_dir().expect("cant find home");
    p.push(".passlock.temp");
    p
}

pub fn svv(v: &Vault, pwd: &str) -> Result<(), String> {
    let j = serde_json::to_string(v).map_err(|e| e.to_string())?;
    let enc_d = enc(&j, pwd, &v.s)?;

    let final_d = format!("{}:{}", v.s, enc_d);

    let p = gtv_path();
    fs::write(p, final_d).map_err(|e| e.to_string())?;

    let temp_p = gtp_path();
    let tempd = serde_json::to_string(v).map_err(|e| e.to_string())?;
    fs::write(temp_p, tempd).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn ld_vt(pwd: &str) -> Result<Vault, String> {
    let p = gtv_path();

    if !p.exists() {
        return Err("no vault found".into());
    }

    let data = fs::read_to_string(p).map_err(|e| e.to_string())?;

    let parts: Vec<&str> = data.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("invalid vault format".into());
    }

    let salt = parts[0];
    let enc_d = parts[1];

    let dec_data = crate::crypto::dec(enc_d, pwd, salt)?;
    let v: Vault = serde_json::from_str(&dec_data).map_err(|e| e.to_string())?;

    let temp_p = gtp_path();
    let tempd = serde_json::to_string(&v).map_err(|e| e.to_string())?;
    fs::write(temp_p, tempd).ok();

    Ok(v)
}

pub fn vt_exi() -> bool {
    gtv_path().exists()
}
