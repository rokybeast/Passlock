use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String,
    pub n: String,
    pub u: String,
    pub p: String,
    pub url: Option<String>,
    pub nt: Option<String>,
    pub t: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub e: Vec<Entry>,
    pub s: String,
}

impl Vault {
    pub fn new(s: String) -> Self {
        Self { e: Vec::new(), s }
    }
}