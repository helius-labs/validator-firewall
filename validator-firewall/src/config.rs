use cidr::Ipv4Cidr;
use serde::Deserialize;
use std::path::PathBuf;

#[allow(dead_code)] //Used in Debug
#[derive(Deserialize, Debug)]
pub struct NameAddressPair {
    pub name: String,
    pub ip: Ipv4Cidr,
}

#[derive(Deserialize, Debug)]
pub struct StaticOverrides {
    pub allow: Vec<NameAddressPair>,
    pub deny: Vec<NameAddressPair>,
}

pub fn load_static_overrides(path: PathBuf) -> Result<StaticOverrides, anyhow::Error> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let overrides = serde_yaml::from_reader(reader)?;
    Ok(overrides)
}
