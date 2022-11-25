use std::borrow::Cow;

use hard_xml::XmlRead;
use url::Url;

use crate as omaha;
use omaha::{Sha1, Sha256};


// for Manifest and UpdateCheck, we've customised the XmlRead implementation (using `cargo expand`
// and inlining) so that we can flatten the `packages`, `actions`, and `urls` container tags.
// this lets us do `update_check.urls[n]` instead of `update_check.urls.urls[n]`.
// just nicer to use.

#[derive(XmlRead, Debug)]
#[xml(tag = "package")]
pub struct Package<'a> {
    #[xml(attr = "name")]
    pub name: Cow<'a, str>,

    #[xml(attr = "hash")]
    pub hash: omaha::Hash<Sha1>,

    #[xml(attr = "size")]
    pub size: usize,

    #[xml(attr = "required")]
    pub required: bool
}

#[derive(XmlRead, Debug)]
#[xml(tag = "action")]
pub struct Action<'a> {
    #[xml(attr = "event")]
    pub event: Cow<'a, str>,

    #[xml(attr = "sha256")]
    pub sha256: omaha::Hash<Sha256>,

    #[xml(attr = "DisablePayloadBackoff")]
    pub disable_payload_backoff: Option<bool>,
}

#[derive(Debug)]
pub struct Manifest<'a> {
    pub version: Cow<'a, str>,
    pub packages: Vec<Package<'a>>,
    pub actions: Vec<Action<'a>>,
}

impl<'__input: 'a, 'a> hard_xml::XmlRead<'__input> for Manifest<'a> {
    fn from_reader(
        reader: &mut hard_xml::XmlReader<'__input>,
    ) -> hard_xml::XmlResult<Self> {
        use hard_xml::xmlparser::{ElementEnd, Token};
        use hard_xml::XmlError;
        let mut __self_version = None;
        let mut __self_packages = Vec::new();
        let mut __self_actions = Vec::new();
        reader.read_till_element_start("manifest")?;
        while let Some((__key, __value)) = reader.find_attribute()? {
            match __key {
                "version" => {
                    __self_version = Some(__value);
                }
                _ => {}
            }
        }
        if let Token::ElementEnd { end: ElementEnd::Empty, .. }
            = reader.next().unwrap()?
        {
            let __res = Manifest {
                version: __self_version
                    .ok_or(XmlError::MissingField {
                        name: "Manifest".to_owned(),
                        field: "version".to_owned(),
                    })?,
                packages: __self_packages,
                actions: __self_actions,
            };
            return Ok(__res);
        }
        while let Some(__tag) = reader.find_element_start(Some("manifest"))? {
            match __tag {
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
                                    .push(<Action<'a> as hard_xml::XmlRead>::from_reader(reader)?);
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
        let __res = Manifest {
            version: __self_version
                .ok_or(XmlError::MissingField {
                    name: "Manifest".to_owned(),
                    field: "version".to_owned(),
                })?,
                packages: __self_packages,
                actions: __self_actions,
        };
        return Ok(__res);
    }
}
#[derive(Debug)]
pub struct UpdateCheck<'a> {
    pub status: Cow<'a, str>,
    pub urls: Vec<Url>,

    pub manifest: Manifest<'a>,
}

impl<'__input: 'a, 'a> hard_xml::XmlRead<'__input> for UpdateCheck<'a> {
    fn from_reader(
        reader: &mut hard_xml::XmlReader<'__input>,
    ) -> hard_xml::XmlResult<Self> {
        use hard_xml::xmlparser::{ElementEnd, Token};
        use hard_xml::XmlError;
        let mut __self_status = None;
        let mut __self_manifest = None;
        let mut __self_urls = Vec::new();

        reader.read_till_element_start("updatecheck")?;

        while let Some((__key, __value)) = reader.find_attribute()? {
            match __key {
                "status" => {
                    __self_status = Some(__value);
                }
                _ => {}
            }
        }

        if let Token::ElementEnd { end: ElementEnd::Empty, .. }
            = reader.next().unwrap()?
        {
            let __res = UpdateCheck {
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
            };
            return Ok(__res);
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
                                while let Some((__key, __value)) = reader.find_attribute()? {
                                    match __key {
                                        "codebase" => {
                                            __self_urls.push(
                                                <Url as std::str::FromStr>::from_str(&__value)
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

        let __res = UpdateCheck {
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
        };

        return Ok(__res);
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
    pub apps: Vec<App<'a>>
}
