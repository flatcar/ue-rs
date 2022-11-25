use std::borrow::Cow;
use std::fmt;

use hard_xml::{XmlWrite};

#[macro_use]
mod uuid;
pub use self::uuid::*;


#[allow(dead_code)]
#[derive(Debug)]
pub enum OmahaInstallSource {
    OnDemand,
    Scheduler
}

impl fmt::Display for OmahaInstallSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OmahaInstallSource::OnDemand => f.write_str("ondemand"),
            OmahaInstallSource::Scheduler => f.write_str("scheduler")
        }
    }
}

#[derive(XmlWrite)]
#[xml(tag = "os")]
pub struct OmahaOsTag<'a> {
    #[xml(attr = "platform")]
    pub platform: Cow<'a, str>,

    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(attr = "sp")]
    pub service_pack: Cow<'a, str>
}

#[derive(XmlWrite)]
#[xml(tag = "updatecheck")]
pub struct OmahaAppUpdateCheck;

#[derive(XmlWrite)]
#[xml(tag = "app")]
pub struct OmahaAppTag<'a> {
    #[xml(attr = "appid")]
    pub id: OmahaUuid,

    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(attr = "track")]
    pub track: Cow<'a, str>,

    #[xml(attr = "bootid")]
    pub boot_id: Option<OmahaUuid>,

    #[xml(attr = "oem")]
    pub oem: Option<Cow<'a, str>>,

    #[xml(attr = "oemversion")]
    pub oem_version: Option<Cow<'a, str>>,

    #[xml(attr = "machineid")]
    pub machine_id: Cow<'a, str>,

    #[xml(child = "updatecheck")]
    pub update_check: Option<OmahaAppUpdateCheck>
}

#[derive(XmlWrite)]
#[xml(tag = "request")]
pub struct OmahaRequest<'a> {
    #[xml(attr = "protocol")]
    pub protocol_version: Cow<'a, str>,

    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(attr = "updaterversion")]
    pub updater_version: Cow<'a, str>,

    #[xml(attr = "installsource")]
    pub install_source: OmahaInstallSource,

    #[xml(attr = "ismachine")]
    pub is_machine: usize,

    #[xml(child = "os")]
    pub os: OmahaOsTag<'a>,

    #[xml(child = "app")]
    pub apps: Vec<OmahaAppTag<'a>>
}
