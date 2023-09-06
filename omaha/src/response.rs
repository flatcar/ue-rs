use std::borrow::Cow;
use std::str::FromStr;
use std::fmt;

use hard_xml::XmlRead;
use url::Url;

use crate as omaha;
use self::omaha::{Sha1, Sha256};

// for Manifest and UpdateCheck, we've customised the XmlRead implementation (using `cargo expand`
// and inlining) so that we can flatten the `packages`, `actions`, and `urls` container tags.
// this lets us do `update_check.urls[n]` instead of `update_check.urls.urls[n]`.
// just nicer to use.

#[derive(Debug)]
// #[xml(tag = "package")]
pub struct Package<'a> {
    // #[xml(attr = "name")]
    pub name: Cow<'a, str>,

    // #[xml(attr = "hash")]
    pub hash: Option<omaha::Hash<Sha1>>,

    // #[xml(attr = "size")]
    pub size: omaha::FileSize,

    // #[xml(attr = "required")]
    pub required: bool,

    // #[xml(attr = "hash_sha256")]
    pub hash_sha256: Option<omaha::Hash<Sha256>>,
}

impl<'__input: 'a, 'a> hard_xml::XmlRead<'__input> for Package<'a> {
    fn from_reader(
        reader: &mut hard_xml::XmlReader<'__input>,
    ) -> hard_xml::XmlResult<Self> {
        use hard_xml::xmlparser::{ElementEnd, Token};
        use hard_xml::XmlError;
        let mut __self_name = None;
        let mut __self_hash = None;
        let mut __self_size = None;
        let mut __self_required = None;
        let mut __self_hash_sha256 = None;
        reader.read_till_element_start("package")?;
        while let Some((__key, __value)) = reader.find_attribute()? {
            match __key {
                "name" => {
                    __self_name = Some(__value);
                }
                "hash" => {
                    __self_hash = Some(
                        <omaha::Hash<Sha1> as std::str::FromStr>::from_str(&__value)
                            .map_err(|e| XmlError::FromStr(e.into()))?,
                    );
                }
                "size" => {
                    __self_size = Some(
                        <omaha::FileSize as std::str::FromStr>::from_str(&__value)
                            .map_err(|e| XmlError::FromStr(e.into()))?,
                    );
                }
                "required" => {
                    __self_required = Some(
                        match &*__value {
                            "t" | "true" | "y" | "yes" | "on" | "1" => true,
                            "f" | "false" | "n" | "no" | "off" | "0" => false,
                            _ => {
                                <bool as std::str::FromStr>::from_str(&__value)
                                    .map_err(|e| XmlError::FromStr(e.into()))?
                            }
                        },
                    );
                }
                "hash_sha256" => {
                    __self_hash_sha256 = Some(<omaha::Hash<Sha256>>::from_hex(&__value)
                            .map_err(|e| XmlError::FromStr(e.into()))?,
                    );
                }
                _key => {}
            }
        }
        if let Token::ElementEnd { end: ElementEnd::Empty, .. }
            = reader.next().unwrap()?
        {
            let __res = Package {
                name: __self_name
                    .ok_or(XmlError::MissingField {
                        name: "Package".to_owned(),
                        field: "name".to_owned(),
                    })?,
                hash: __self_hash,
                size: __self_size
                    .ok_or(XmlError::MissingField {
                        name: "Package".to_owned(),
                        field: "size".to_owned(),
                    })?,
                required: __self_required
                    .ok_or(XmlError::MissingField {
                        name: "Package".to_owned(),
                        field: "required".to_owned(),
                    })?,
                hash_sha256: __self_hash_sha256,
            };
            return Ok(__res);
        }
        while let Some(__tag) = reader.find_element_start(Some("package"))? {
            match __tag {
                tag => {
                    reader.next();
                    reader.read_to_end(tag)?;
                }
            }
        }
        let __res = Package {
            name: __self_name
                .ok_or(XmlError::MissingField {
                    name: "Package".to_owned(),
                    field: "name".to_owned(),
                })?,
            hash: __self_hash,
            size: __self_size
                .ok_or(XmlError::MissingField {
                    name: "Package".to_owned(),
                    field: "size".to_owned(),
                })?,
            required: __self_required
                .ok_or(XmlError::MissingField {
                    name: "Package".to_owned(),
                    field: "required".to_owned(),
                })?,
            hash_sha256: __self_hash_sha256,
        };
        return Ok(__res);
    }
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

            _ => return Err(format!("unknown success action \"{}\"", s)),
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

            _ => return Err(format!("unknown success action \"{}\"", s)),
        })
    }
}

#[derive(XmlRead, Debug)]
#[xml(tag = "action")]
pub struct Action {
    #[xml(attr = "event")]
    pub event: ActionEvent,

    #[xml(attr = "sha256")]
    pub sha256: omaha::Hash<Sha256>,

    #[xml(attr = "DisablePayloadBackoff")]
    pub disable_payload_backoff: Option<bool>,

    #[xml(attr = "successaction")]
    pub success_action: Option<SuccessAction>,
}

#[derive(Debug)]
pub struct Manifest<'a> {
    pub version: Cow<'a, str>,
    pub packages: Vec<Package<'a>>,
    pub actions: Vec<Action>,
}

impl<'__input: 'a, 'a> hard_xml::XmlRead<'__input> for Manifest<'a> {
    #[rustfmt::skip]
    fn from_reader(
        reader: &mut hard_xml::XmlReader<'__input>,
    ) -> hard_xml::XmlResult<Self> {
        use hard_xml::xmlparser::{ElementEnd, Token};
        use hard_xml::XmlError;
        let mut __self_version = None;
        let mut __self_packages = Vec::new();
        let mut __self_actions = Vec::new();
        reader.read_till_element_start("manifest")?;

        while let Some((k, v)) = reader.find_attribute()? {
            match k {
                "version" => __self_version = Some(v),
                _ => ()
            }
        }

        if let Token::ElementEnd { end: ElementEnd::Empty, .. }
            = reader.next().unwrap()?
        {
            return Ok(Manifest {
                version: __self_version
                    .ok_or(XmlError::MissingField {
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

                    while let Some(_) = reader.find_attribute()? {}

                    if let Token::ElementEnd { end: ElementEnd::Empty, .. }
                        = reader.next().unwrap()?
                    {
                        continue;
                    }

                    while let Some(__tag) = reader.find_element_start(Some("packages"))?
                    {
                        match __tag {
                            "package" => {
                                __self_packages
                                    .push(<Package<'a> as hard_xml::XmlRead>::from_reader(reader)?);
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

                    while let Some(_) = reader.find_attribute()? {}

                    if let Token::ElementEnd { end: ElementEnd::Empty, .. }
                        = reader.next().unwrap()?
                    {
                        continue;
                    }

                    while let Some(__tag) = reader.find_element_start(Some("actions"))?
                    {
                        match __tag {
                            "action" => {
                                __self_actions
                                    .push(<Action as hard_xml::XmlRead>::from_reader(reader)?);
                            }

                            tag => {
                                reader.next();
                                reader.read_to_end(tag)?;
                            }
                        }
                    }
                },

                tag => {
                    reader.next();
                    reader.read_to_end(tag)?;
                }
            }
        }

        return Ok(Manifest {
            version: __self_version
                .ok_or(XmlError::MissingField {
                    name: "Manifest".to_owned(),
                    field: "version".to_owned(),
                })?,
                packages: __self_packages,
                actions: __self_actions,
        });
    }
}
#[derive(Debug)]
pub struct UpdateCheck<'a> {
    pub status: Cow<'a, str>,
    pub urls: Vec<Url>,

    pub manifest: Manifest<'a>,
}

impl<'__input: 'a, 'a> hard_xml::XmlRead<'__input> for UpdateCheck<'a> {
    #[rustfmt::skip]
    fn from_reader(
        reader: &mut hard_xml::XmlReader<'__input>,
    ) -> hard_xml::XmlResult<Self> {
        use hard_xml::xmlparser::{ElementEnd, Token};
        use hard_xml::XmlError;
        let mut __self_status = None;
        let mut __self_manifest = None;
        let mut __self_urls = Vec::new();

        reader.read_till_element_start("updatecheck")?;

        while let Some((k, v)) = reader.find_attribute()? {
            match k {
                "status" => __self_status = Some(v),
                _ => {}
            }
        }

        if let Token::ElementEnd { end: ElementEnd::Empty, .. }
            = reader.next().unwrap()?
        {
            return Ok(UpdateCheck {
                status: __self_status
                    .ok_or(XmlError::MissingField {
                        name: "UpdateCheck".to_owned(),
                        field: "status".to_owned(),
                    })?,
                urls: __self_urls,
                manifest: __self_manifest
                    .ok_or(XmlError::MissingField {
                        name: "UpdateCheck".to_owned(),
                        field: "manifest".to_owned(),
                    })?,
            });
        }

        while let Some(__tag) = reader.find_element_start(Some("updatecheck"))? {
            match __tag {
                "urls" => {
                    reader.read_till_element_start("urls")?;

                    while let Some(_) = reader.find_attribute()? {}
                    if let Token::ElementEnd { end: ElementEnd::Empty, .. }
                        = reader.next().unwrap()?
                    {
                        continue;
                    }

                    while let Some(__tag) = reader.find_element_start(Some("urls"))? {
                        match __tag {
                            "url" => {
                                reader.read_till_element_start("url")?;
                                while let Some((k, v)) = reader.find_attribute()? {
                                    match k {
                                        "codebase" => {
                                            __self_urls.push(
                                                Url::from_str(&v)
                                                    .map_err(|e| XmlError::FromStr(e.into()))?,
                                            )
                                        }

                                        _ => {}
                                    }
                                }

                                reader.read_to_end("url")?;
                            },

                            tag => {
                                reader.next();
                                reader.read_to_end(tag)?;
                            }
                        }
                    }
                }

                "manifest" => {
                    __self_manifest = Some(
                        <Manifest<'_> as hard_xml::XmlRead>::from_reader(reader)?,
                    );
                }

                tag => {
                    reader.next();
                    reader.read_to_end(tag)?;
                }
            }
        }

        return Ok(UpdateCheck {
            status: __self_status
                .ok_or(XmlError::MissingField {
                    name: "UpdateCheck".to_owned(),
                    field: "status".to_owned(),
                })?,
            urls: __self_urls,
            manifest: __self_manifest
                .ok_or(XmlError::MissingField {
                    name: "UpdateCheck".to_owned(),
                    field: "manifest".to_owned(),
                })?,
        });
    }
}

#[derive(XmlRead, Debug)]
#[xml(tag = "app")]
pub struct App<'a> {
    #[xml(attr = "appid")]
    pub id: omaha::Uuid,

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
