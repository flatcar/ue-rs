use std::borrow::Cow;
use std::str::FromStr;
use std::fmt;
use std::fmt::Debug;
use url::Url;
use crate::uuid::braced_uuid;

use hard_xml::{XmlError, XmlRead, XmlReader, XmlResult};
use hard_xml::xmlparser::{ElementEnd, Token};
use crate::{FileSize, Sha1Digest, Sha256Digest, Error, sha1_from_str, sha256_from_str};
use crate::Error::{UnknownActionEvent, UnknownSuccessAction};

#[derive(XmlRead, Debug)]
#[xml(tag = "package")]
pub struct Package<'a> {
    #[xml(attr = "name")]
    pub name: Cow<'a, str>,

    #[xml(attr = "hash", with = "sha1_from_str")]
    pub hash: Option<Sha1Digest>,

    #[xml(attr = "size")]
    pub size: FileSize,

    #[xml(attr = "required")]
    pub required: bool,

    #[xml(attr = "hash_sha256", with = "sha256_from_str")]
    pub hash_sha256: Option<Sha256Digest>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ActionEvent {
    PreInstall,
    Install,
    PostInstall,
    Update,
}

impl fmt::Display for ActionEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ActionEvent::PreInstall => f.write_str("preinstall"),
            ActionEvent::Install => f.write_str("install"),
            ActionEvent::PostInstall => f.write_str("postinstall"),
            ActionEvent::Update => f.write_str("update"),
        }
    }
}

impl FromStr for ActionEvent {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "preinstall" => ActionEvent::PreInstall,
            "install" => ActionEvent::Install,
            "postinstall" => ActionEvent::PostInstall,
            "update" => ActionEvent::Update,

            _ => return Err(UnknownActionEvent(s.to_string())),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SuccessAction {
    Default,
    ExitSilently,
    ExitSilentlyOnLaunchCommand,
}

impl fmt::Display for SuccessAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SuccessAction::Default => f.write_str("default"),
            SuccessAction::ExitSilently => f.write_str("exitsilently"),
            SuccessAction::ExitSilentlyOnLaunchCommand => f.write_str("exitsilentlyonlaunchcmd"),
        }
    }
}

impl FromStr for SuccessAction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "default" => SuccessAction::Default,
            "exitsilently" => SuccessAction::ExitSilently,
            "exitsilentlyonlaunchcmd" => SuccessAction::ExitSilentlyOnLaunchCommand,

            _ => return Err(UnknownSuccessAction(s.to_string())),
        })
    }
}

#[derive(XmlRead, Debug)]
#[xml(tag = "action")]
pub struct Action {
    #[xml(attr = "event")]
    pub event: ActionEvent,

    #[xml(attr = "sha256", with = "sha256_from_str")]
    pub sha256: Sha256Digest,

    #[xml(attr = "DisablePayloadBackoff")]
    pub disable_payload_backoff: Option<bool>,

    #[xml(attr = "successaction")]
    pub success_action: Option<SuccessAction>,
}

// for Manifest and UpdateCheck, we've customised the XmlRead implementation (using `cargo expand`
// and inlining) so that we can flatten the `packages`, `actions`, and `urls` container tags.
// this lets us do `update_check.urls[n]` instead of `update_check.urls.urls[n]`.
// just nicer to use.

#[derive(XmlRead, Debug)]
#[xml(tag = "manifest")]
pub struct Manifest<'a> {
    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(child = "packages")]
    pub packages: Vec<Package<'a>>,

    #[xml(child = "actions")]
    pub actions: Vec<Action>,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Default))]
pub struct Urls(Vec<Url>);

impl std::ops::Deref for Urls {
    type Target = Vec<Url>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Urls {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> IntoIterator for &'a Urls {
    type Item = &'a Url;
    type IntoIter = std::slice::Iter<'a, Url>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> hard_xml::XmlRead<'a> for Urls {
    fn from_reader(reader: &mut XmlReader<'a>) -> XmlResult<Self> {
        let mut urls = Vec::new();

        reader.read_till_element_start("urls")?;
        while (reader.find_attribute()?).is_some() {}

        if let Ok(Token::ElementEnd {
            end: ElementEnd::Empty,
            ..
        }) = reader.next().ok_or(XmlError::MissingField {
            name: "urls".to_owned(),
            field: "url".to_string(),
        })? {
            return Ok(Self(urls));
        }

        while let Some(tag) = reader.find_element_start(Some("urls"))? {
            match tag {
                "url" => {
                    reader.read_till_element_start("url")?;
                    while let Some((k, v)) = reader.find_attribute()? {
                        if k == "codebase" {
                            urls.push(Url::from_str(&v).map_err(|e| XmlError::FromStr(e.into()))?);
                        }
                    }
                    reader.read_to_end("url")?;
                }
                other => {
                    reader.next();
                    reader.read_to_end(other)?;
                }
            }
        }

        Ok(Self(urls))
    }
}

#[derive(XmlRead, Debug)]
#[xml(tag = "updatecheck")]
pub struct UpdateCheck<'a> {
    #[xml(attr = "status")]
    pub status: Cow<'a, str>,

    #[xml(child = "urls")]
    pub urls: Urls,

    #[xml(child = "manifest")]
    pub manifest: Manifest<'a>,
}

#[derive(XmlRead, Debug)]
#[xml(tag = "app")]
pub struct App<'a> {
    #[xml(attr = "appid", with = "braced_uuid")]
    pub id: uuid::Uuid,

    #[xml(attr = "status")]
    pub status: Cow<'a, str>,

    #[xml(child = "updatecheck")]
    pub update_check: UpdateCheck<'a>,
}

#[derive(XmlRead, Debug)]
#[xml(tag = "response")]
pub struct Response<'a> {
    #[xml(attr = "protocol")]
    pub protocol_version: Cow<'a, str>,

    #[xml(child = "app")]
    pub apps: Vec<App<'a>>,
}

#[cfg(test)]
mod tests {
    use url::Url;
    use hard_xml::{XmlRead, XmlReader};
    use crate::response::{App, Manifest, UpdateCheck, Urls};

    const TEST_UUID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    fn parse_urls_from_str(s: &str) -> Urls {
        Urls::from_reader(&mut XmlReader::new(s)).unwrap()
    }

    #[test]
    fn parse_empty_urls_self_closing() {
        let xml = r#"<urls/>"#;
        let urls = parse_urls_from_str(xml);
        assert!(urls.is_empty());
    }

    #[test]
    fn parse_empty_urls() {
        let xml = r#"<urls></urls>"#;
        let urls = parse_urls_from_str(xml);
        let exp = Urls(vec![]);
        assert_eq!(urls, exp);
    }

    #[test]
    fn parse_single_url() {
        let xml = "<urls><url codebase=\"https://example.net\"/></urls>";
        let urls = parse_urls_from_str(xml);
        let exp = Urls(vec![Url::parse("https://example.net").unwrap()]);
        assert_eq!(urls, exp);
    }

    #[test]
    fn ignore_invalid_url_attrs() {
        let xml = "<urls><url bad-attr=\"\"/></urls>";
        let urls = parse_urls_from_str(xml);
        let exp = Urls::default();
        assert_eq!(urls, exp);

        let xml = "<urls><url codebase=\"https://example.org\" bad-attr=\"\"/></urls>";
        let urls = parse_urls_from_str(xml);
        let exp = Urls(vec![Url::parse("https://example.org").unwrap()]);
        assert_eq!(urls, exp);
    }

    #[test]
    fn parse_multiple_urls() {
        let xml = "<urls><url codebase=\"https://example.net/1\"/><url codebase=\"https://example.net/2\"/></urls>";
        let urls = parse_urls_from_str(xml);
        let exp = Urls(vec![
            Url::parse("https://example.net/1").unwrap(),
            Url::parse("https://example.net/2").unwrap(),
        ]);
        assert_eq!(urls, exp);
    }

    #[test]
    fn app_xml_read() {
        let xml = format!(
            "<app appid=\"{{{}}}\" status=\"\"><updatecheck status=\"\"><manifest version=\"\"/><urls></urls></updatecheck></app>",
            TEST_UUID
        );
        let app = App::from_str(xml.as_str()).unwrap();
        let exp = App {
            id: uuid::uuid!(TEST_UUID),
            status: Default::default(),
            update_check: UpdateCheck {
                status: Default::default(),
                urls: Urls::default(),
                manifest: Manifest {
                    version: Default::default(),
                    packages: vec![],
                    actions: vec![],
                },
            },
        };
        assert_eq!(app.id, exp.id);
    }
}
