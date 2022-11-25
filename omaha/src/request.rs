use std::borrow::Cow;
use std::fmt;

use hard_xml::XmlWrite;

use crate as omaha;


#[allow(dead_code)]
#[derive(Debug)]
pub enum InstallSource {
    OnDemand,
    Scheduler
}

impl fmt::Display for InstallSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InstallSource::OnDemand => f.write_str("ondemand"),
            InstallSource::Scheduler => f.write_str("scheduler")
        }
    }
}

#[derive(XmlWrite)]
#[xml(tag = "os")]
pub struct Os<'a> {
    #[xml(attr = "platform")]
    pub platform: Cow<'a, str>,

    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(attr = "sp")]
    pub service_pack: Cow<'a, str>
}

#[derive(XmlWrite)]
#[xml(tag = "updatecheck")]
pub struct AppUpdateCheck;

#[derive(XmlWrite)]
#[xml(tag = "app")]
pub struct App<'a> {
    #[xml(attr = "appid")]
    pub id: omaha::Uuid,

    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(attr = "track")]
    pub track: Cow<'a, str>,

    #[xml(attr = "bootid")]
    pub boot_id: Option<omaha::Uuid>,

    #[xml(attr = "oem")]
    pub oem: Option<Cow<'a, str>>,

    #[xml(attr = "oemversion")]
    pub oem_version: Option<Cow<'a, str>>,

    #[xml(attr = "machineid")]
    pub machine_id: Cow<'a, str>,

    #[xml(child = "updatecheck")]
    pub update_check: Option<AppUpdateCheck>
}

#[derive(XmlWrite)]
#[xml(tag = "request")]
pub struct Request<'a> {
    #[xml(attr = "protocol")]
    pub protocol_version: Cow<'a, str>,

    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(attr = "updaterversion")]
    pub updater_version: Cow<'a, str>,

    #[xml(attr = "installsource")]
    pub install_source: InstallSource,

    #[xml(attr = "ismachine")]
    pub is_machine: usize,

    #[xml(child = "os")]
    pub os: Os<'a>,

    #[xml(child = "app")]
    pub apps: Vec<App<'a>>
}
