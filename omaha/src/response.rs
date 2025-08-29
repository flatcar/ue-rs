use std::borrow::Cow;
use std::str::FromStr;
use std::fmt;

use hard_xml::XmlRead;
use url::Url;

use crate::{FileSize, Uuid, Sha1Digest, Sha256Digest};

mod sha256_from_str {
    use crate::{Hasher, Sha256, Sha256Digest};

    #[inline]
    pub(crate) fn from_str(s: &str) -> Result<Sha256Digest, String> {
        <Sha256 as Hasher>::try_from_hex_string(s)
    }
}

mod sha1_from_str {
    use crate::{Hasher, Sha1, Sha1Digest};

    #[inline]
    pub(crate) fn from_str(s: &str) -> Result<Sha1Digest, String> {
        <Sha1 as Hasher>::try_from_hex_string(s)
    }
}

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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "preinstall" => ActionEvent::PreInstall,
            "install" => ActionEvent::Install,
            "postinstall" => ActionEvent::PostInstall,
            "update" => ActionEvent::Update,

            _ => return Err(format!("unknown success action \"{s}\"")),
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "default" => SuccessAction::Default,
            "exitsilently" => SuccessAction::ExitSilently,
            "exitsilentlyonlaunchcmd" => SuccessAction::ExitSilentlyOnLaunchCommand,

            _ => return Err(format!("unknown success action \"{s}\"")),
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

#[derive(Debug)]
pub struct Manifest<'a> {
    pub version: Cow<'a, str>,
    pub packages: Vec<Package<'a>>,
    pub actions: Vec<Action>,
}

impl<'__input: 'a, 'a> hard_xml::XmlRead<'__input> for Manifest<'a> {
    fn from_reader(reader: &mut hard_xml::XmlReader<'__input>) -> hard_xml::XmlResult<Self> {
        use hard_xml::xmlparser::{ElementEnd, Token};
        use hard_xml::XmlError;
        let mut __self_version = None;
        let mut __self_packages = Vec::new();
        let mut __self_actions = Vec::new();
        reader.read_till_element_start("manifest")?;

        while let Some((k, v)) = reader.find_attribute()? {
            if k == "version" {
                __self_version = Some(v);
            }
        }

        if let Ok(Token::ElementEnd {
            end: ElementEnd::Empty,
            ..
        }) = reader.next().ok_or(XmlError::MissingField {
            name: "Manifest".to_owned(),
            field: "version".to_owned(),
        })? {
            return Ok(Manifest {
                version: __self_version.ok_or(XmlError::MissingField {
                    name: "Manifest".to_owned(),
                    field: "version".to_owned(),
                })?,
                packages: __self_packages,
                actions: __self_actions,
            });
        }

        while let Some(tag) = reader.find_element_start(Some("manifest"))? {
            match tag {
                "packages" => {
                    reader.read_till_element_start("packages")?;

                    while (reader.find_attribute()?).is_some() {}

                    if let Ok(Token::ElementEnd {
                        end: ElementEnd::Empty,
                        ..
                    }) = reader.next().ok_or(XmlError::MissingField {
                        name: "Manifest".to_owned(),
                        field: "version".to_owned(),
                    })? {
                        continue;
                    }

                    while let Some(__tag) = reader.find_element_start(Some("packages"))? {
                        match __tag {
                            "package" => {
                                __self_packages.push(<Package<'a> as hard_xml::XmlRead>::from_reader(reader)?);
                            }

                            tag => {
                                reader.next();
                                reader.read_to_end(tag)?;
                            }
                        }
                    }
                }

                "actions" => {
                    reader.read_till_element_start("actions")?;

                    while (reader.find_attribute()?).is_some() {}

                    if let Ok(Token::ElementEnd {
                        end: ElementEnd::Empty,
                        ..
                    }) = reader.next().ok_or(XmlError::MissingField {
                        name: "Manifest".to_owned(),
                        field: "version".to_owned(),
                    })? {
                        continue;
                    }

                    while let Some(__tag) = reader.find_element_start(Some("actions"))? {
                        match __tag {
                            "action" => {
                                __self_actions.push(<Action as hard_xml::XmlRead>::from_reader(reader)?);
                            }

                            tag => {
                                reader.next();
                                reader.read_to_end(tag)?;
                            }
                        }
                    }
                }

                tag => {
                    reader.next();
                    reader.read_to_end(tag)?;
                }
            }
        }

        Ok(Manifest {
            version: __self_version.ok_or(XmlError::MissingField {
                name: "Manifest".to_owned(),
                field: "version".to_owned(),
            })?,
            packages: __self_packages,
            actions: __self_actions,
        })
    }
}
#[derive(Debug)]
pub struct UpdateCheck<'a> {
    pub status: Cow<'a, str>,
    pub urls: Vec<Url>,

    pub manifest: Manifest<'a>,
}

impl<'__input: 'a, 'a> hard_xml::XmlRead<'__input> for UpdateCheck<'a> {
    fn from_reader(reader: &mut hard_xml::XmlReader<'__input>) -> hard_xml::XmlResult<Self> {
        use hard_xml::xmlparser::{ElementEnd, Token};
        use hard_xml::XmlError;
        let mut __self_status = None;
        let mut __self_manifest = None;
        let mut __self_urls = Vec::new();

        reader.read_till_element_start("updatecheck")?;

        while let Some((k, v)) = reader.find_attribute()? {
            if k == "status" {
                __self_status = Some(v);
            }
        }

        if let Ok(Token::ElementEnd {
            end: ElementEnd::Empty,
            ..
        }) = reader.next().ok_or(XmlError::MissingField {
            name: "UpdateCheck".to_owned(),
            field: "manifest".to_owned(),
        })? {
            return Ok(UpdateCheck {
                status: __self_status.ok_or(XmlError::MissingField {
                    name: "UpdateCheck".to_owned(),
                    field: "status".to_owned(),
                })?,
                urls: __self_urls,
                manifest: __self_manifest.ok_or(XmlError::MissingField {
                    name: "UpdateCheck".to_owned(),
                    field: "manifest".to_owned(),
                })?,
            });
        }

        while let Some(__tag) = reader.find_element_start(Some("updatecheck"))? {
            match __tag {
                "urls" => {
                    reader.read_till_element_start("urls")?;

                    while (reader.find_attribute()?).is_some() {}
                    if let Ok(Token::ElementEnd {
                        end: ElementEnd::Empty,
                        ..
                    }) = reader.next().ok_or(XmlError::MissingField {
                        name: "UpdateCheck".to_owned(),
                        field: "manifest".to_owned(),
                    })? {
                        continue;
                    }

                    while let Some(__tag) = reader.find_element_start(Some("urls"))? {
                        match __tag {
                            "url" => {
                                reader.read_till_element_start("url")?;
                                while let Some((k, v)) = reader.find_attribute()? {
                                    if k == "codebase" {
                                        __self_urls.push(Url::from_str(&v).map_err(|e| XmlError::FromStr(e.into()))?)
                                    }
                                }

                                reader.read_to_end("url")?;
                            }

                            tag => {
                                reader.next();
                                reader.read_to_end(tag)?;
                            }
                        }
                    }
                }

                "manifest" => {
                    __self_manifest = Some(<Manifest<'_> as hard_xml::XmlRead>::from_reader(reader)?);
                }

                tag => {
                    reader.next();
                    reader.read_to_end(tag)?;
                }
            }
        }

        Ok(UpdateCheck {
            status: __self_status.ok_or(XmlError::MissingField {
                name: "UpdateCheck".to_owned(),
                field: "status".to_owned(),
            })?,
            urls: __self_urls,
            manifest: __self_manifest.ok_or(XmlError::MissingField {
                name: "UpdateCheck".to_owned(),
                field: "manifest".to_owned(),
            })?,
        })
    }
}

#[derive(XmlRead, Debug)]
#[xml(tag = "app")]
pub struct App<'a> {
    #[xml(attr = "appid")]
    pub id: Uuid,

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
