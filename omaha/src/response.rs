use std::borrow::Cow;
use std::str::FromStr;
use std::fmt;
use std::fmt::Debug;
use url::Url;
use crate::uuid::braced_uuid;

use hard_xml::{XmlError, XmlRead, XmlReader, XmlResult};
use hard_xml::xmlparser::{ElementEnd, Token};
use crate::{Sha1Digest, Sha256Digest, Error, sha1_from_str, sha256_from_str};
use crate::Error::{UnknownActionEvent, UnknownSuccessAction};

#[derive(XmlRead, Debug)]
#[xml(tag = "response")]
pub struct Response<'a> {
    #[xml(attr = "protocol")]
    pub protocol_version: Cow<'a, str>,

    #[xml(child = "app")]
    pub apps: Vec<App<'a>>,
}

#[derive(XmlRead, Debug)]
#[xml(tag = "app")]
#[cfg_attr(test, derive(PartialEq, Default))]
pub struct App<'a> {
    #[xml(attr = "appid", with = "braced_uuid")]
    pub id: uuid::Uuid,

    #[xml(attr = "status")]
    pub status: Cow<'a, str>,

    #[xml(child = "updatecheck")]
    pub update_check: UpdateCheck<'a>,
}

#[derive(XmlRead, Debug)]
#[xml(tag = "updatecheck")]
#[cfg_attr(test, derive(PartialEq, Default))]
pub struct UpdateCheck<'a> {
    #[xml(attr = "status")]
    pub status: Cow<'a, str>,

    #[xml(child = "urls")]
    pub urls: Urls,

    #[xml(child = "manifest")]
    pub manifest: Manifest<'a>,
}

/// A wrapper struct for `Vec<url::Url>`.
///
/// Since we cannot derive or define `XmlRead` on `url::Url`, and need to use a
/// `Vec<url::Url>` field in the `UpdateCheck` struct, it is easier to use a
/// new type struct to implement `XmlRead` only for this, and let `UpdateCheck`
/// make full use of deriving the required trait.
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

// TODO: this is the same behaviour as the old XmlRead implementation for the
//       UpdateCheck struct, but is it definitely correct? This will allow <url>
//       and <urls> elements with unknown attributes -- just ignoring them.
//       Should this instead cause an XmlError here?
/// Custom implementation for the `hard_xml::XmlRead` trait to extract `<url>`
/// elements with a `codebase=""` attribute within and enclosing `<urls>`.
impl<'a> hard_xml::XmlRead<'a> for Urls {
    fn from_reader(reader: &mut XmlReader<'a>) -> XmlResult<Self> {
        const URLS_OUTER_TAG: &str = "urls";
        const URL_INNER_TAG: &str = "url";

        let mut urls = Vec::new();

        reader.read_till_element_start(URLS_OUTER_TAG)?;
        while (reader.find_attribute()?).is_some() {}

        if let Ok(Token::ElementEnd {
            end: ElementEnd::Empty,
            ..
        }) = reader.next().ok_or(XmlError::MissingField {
            name: URLS_OUTER_TAG.to_owned(),
            field: URL_INNER_TAG.to_string(),
        })? {
            return Ok(Self(urls));
        }

        while let Some(tag) = reader.find_element_start(Some(URLS_OUTER_TAG))? {
            if tag == URL_INNER_TAG {
                reader.read_till_element_start(URL_INNER_TAG)?;
                while let Some(("codebase", v)) = reader.find_attribute()? {
                    urls.push(Url::from_str(&v).map_err(|e| XmlError::FromStr(e.into()))?);
                }
            } else {
                reader.next();
            }
            reader.read_to_end(tag)?;
        }

        Ok(Self(urls))
    }
}

#[derive(XmlRead, Debug)]
#[xml(tag = "manifest")]
#[cfg_attr(test, derive(PartialEq, Default))]
pub struct Manifest<'a> {
    #[xml(attr = "version")]
    pub version: Cow<'a, str>,

    #[xml(child = "packages")]
    pub packages: Vec<Package<'a>>,

    #[xml(child = "actions")]
    pub actions: Vec<Action>,
}

#[derive(XmlRead, Debug)]
#[xml(tag = "package")]
#[cfg_attr(test, derive(PartialEq, Default))]
pub struct Package<'a> {
    #[xml(attr = "name")]
    pub name: Cow<'a, str>,

    #[xml(attr = "hash", with = "sha1_from_str")]
    pub hash: Option<Sha1Digest>,

    #[xml(attr = "size")]
    pub size: usize,

    #[xml(attr = "required")]
    pub required: bool,

    #[xml(attr = "hash_sha256", with = "sha256_from_str")]
    pub hash_sha256: Option<Sha256Digest>,
}

#[derive(XmlRead, Debug)]
#[xml(tag = "action")]
#[cfg_attr(test, derive(PartialEq))]
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fmt::Debug;
    use url::Url;
    use hard_xml::XmlRead;
    use crate::response::{App, Package, Urls};
    use crate::{Hasher, Sha1, Sha256};

    const TEST_UUID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    fn test_xml_read<'a, T>(s: &'a str, exp: T)
    where
        T: Debug + PartialEq + XmlRead<'a>,
    {
        assert_eq!(T::from_str(s).unwrap(), exp);
    }

    #[test]
    fn parse_empty_urls_self_closing() {
        test_xml_read("<urls/>", Urls::default());
    }

    #[test]
    fn parse_empty_urls() {
        test_xml_read("<urls></urls>", Urls::default());
    }

    #[test]
    fn parse_single_url() {
        const URL: &str = "https://example.net";

        test_xml_read(
            format!("<urls><url codebase=\"{URL}\"/></urls>").as_str(),
            Urls(vec![Url::parse(URL).unwrap()]),
        )
    }

    #[test]
    fn ignore_invalid_url_attrs() {
        const URL: &str = "https://example.net";

        test_xml_read("<urls><url bad-attr=\"\"/></urls>", Urls::default());
        test_xml_read(
            format!("<urls><url codebase=\"{URL}\" bad-attr=\"\"/></urls>").as_str(),
            Urls(vec![Url::parse(URL).unwrap()]),
        );
    }

    #[test]
    fn parse_multiple_urls() {
        const URL_1: &str = "https://example.net/1";
        const URL_2: &str = "https://example.net/2";

        test_xml_read(
            format!("<urls><url codebase=\"{URL_1}\"/><url codebase=\"{URL_2}\"/></urls>").as_str(),
            Urls(vec![Url::parse(URL_1).unwrap(), Url::parse(URL_2).unwrap()]),
        );
    }

    #[test]
    fn package_xml_read_no_hashes() {
        const NAME: &str = "name";
        const SIZE: usize = 0;
        const REQUIRED: bool = false;

        test_xml_read(
            format!("<package name=\"{NAME}\" size=\"{SIZE}\" required=\"{REQUIRED}\"/>").as_str(),
            Package {
                name: Cow::Borrowed(NAME),
                size: SIZE,
                required: REQUIRED,
                ..Package::default()
            },
        );
    }

    #[test]
    fn package_xml_read_hashes() {
        const NAME: &str = "name";
        const SHA1_STR: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
        const SIZE: usize = 1;
        const REQUIRED: bool = false;
        const SHA256_STR: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        test_xml_read(
            format!("<package name=\"{NAME}\" hash=\"{SHA1_STR}\" size=\"{SIZE}\" required=\"{REQUIRED}\" hash_sha256=\"{SHA256_STR}\"/>",).as_str(),
            Package {
                name: Cow::Borrowed(NAME),
                hash: Some(Sha1::try_from_hex_string(SHA1_STR).unwrap()),
                size: SIZE,
                required: REQUIRED,
                hash_sha256: Some(Sha256::try_from_hex_string(SHA256_STR).unwrap()),
            },
        )
    }

    #[test]
    fn app_xml_read() {
        test_xml_read(
            format!("<app appid=\"{{{TEST_UUID}}}\" status=\"\"><updatecheck status=\"\"><manifest version=\"\"/><urls></urls></updatecheck></app>",).as_str(),
            App {
                id: uuid::uuid!(TEST_UUID),
                ..App::default()
            },
        );
    }
}
