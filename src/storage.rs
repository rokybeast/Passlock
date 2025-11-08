use crate::crypto::enc;
use crate::models::Vault;
use std::fs;
use std::path::PathBuf;

pub fn getvp() -> PathBuf {
    let mut p = dirs::home_dir().expect("cant find home");
    p.push(".passlock.vault");
    p
}

pub fn save_vault(v: &Vault, pwd: &str) -> Result<(), String> {
    let j = serde_json::to_string(v).map_err(|e| e.to_string())?;
    let enc_data = enc(&j, pwd, &v.s)?;
    
    let final_data = format!("{}:{}", v.s, enc_data);
    
    let p = getvp();
    fs::write(p, final_data).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn load_vault(pwd: &str) -> Result<Vault, String> {
    let p = getvp();
    
    if !p.exists() {
        return Err("no vault found".into());
    }
    
    let data = fs::read_to_string(p).map_err(|e| e.to_string())?;
    
    let parts: Vec<&str> = data.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("invalid vault format".into());
    }
    
    let salt = parts[0];
    let enc_data = parts[1];
    
    let dec_data = crate::crypto::dec(enc_data, pwd, salt)?;
    let v: Vault = serde_json::from_str(&dec_data).map_err(|e| e.to_string())?;
    
    Ok(v)
}

pub fn vault_exists() -> bool {
    getvp().exists()
}