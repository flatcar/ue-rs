use crate::types::StrictMode;
use crate::utils::Context;
use syn::Attribute;
use syn::Error;
use syn::Lit;
use syn::{LitStr, ExprPath};
use syn::Meta;
use syn::NestedMeta;

pub(crate) struct Container {
    pub(crate) tags: Vec<LitStr>,
    pub(crate) strict_mode: StrictMode,
}

impl Container {
    pub(crate) fn parse(ctx: &mut Context, attrs: Vec<Attribute>) -> Self {
        let mut tags = Vec::new();
        let mut strict_mode = StrictMode::empty();

        for meta in attrs.iter().filter_map(get_xml_meta).flatten() {
            match meta {
                NestedMeta::Meta(Meta::NameValue(m)) if m.path.is_ident("tag") => {
                    if let Lit::Str(lit) = m.lit {
                        tags.push(lit);
                    } else {
                        ctx.push_spanned_error(m.lit, "expected a string literal");
                    }
                }

                NestedMeta::Meta(Meta::List(m)) if m.path.is_ident("strict") => {
                    for nested in m.nested {
                        match nested {
                            NestedMeta::Meta(Meta::Path(path)) => {
                                if path.is_ident("unknown_attribute") {
                                    strict_mode |= StrictMode::UNKNOWN_ATTRIBUTE;
                                } else if path.is_ident("unknown_element") {
                                    strict_mode |= StrictMode::UNKNOWN_ELEMENT;
                                } else {
                                    ctx.push_spanned_error(
                                        path,
                                        "unsupported argument to `strict`",
                                    );
                                }
                            }
                            _ => {
                                ctx.push_spanned_error(nested, "unsupported meta type in `strict`")
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        Self { tags, strict_mode }
    }
}

pub(crate) struct Field {
    pub(crate) default: bool,
    pub(crate) attr_tag: Option<LitStr>,
    pub(crate) child_tags: Vec<LitStr>,
    pub(crate) is_text: bool,
    pub(crate) flatten_text_tag: Option<LitStr>,
    pub(crate) is_cdata: bool,
    pub(crate) with: Option<ExprPath>,
}

impl Field {
    pub(crate) fn parse(context: &mut Context, attrs: Vec<Attribute>) -> Self {
        let mut default = false;
        let mut attr_tag = None;
        let mut child_tags = Vec::new();
        let mut is_text = false;
        let mut flatten_text_tag = None;
        let mut is_cdata = false;
        let mut with = None;

        // TODO can this be handled more cleanly?
        for meta in attrs.iter().filter_map(get_xml_meta).flatten() {
            match meta {
                NestedMeta::Meta(Meta::Path(p)) if p.is_ident("default") => {
                    if default {
                        context.push(Error::new_spanned(p, "duplicate `default` attribute"));
                    } else {
                        default = true;
                    }
                }
                NestedMeta::Meta(Meta::NameValue(m)) if m.path.is_ident("attr") => {
                    if let Lit::Str(lit) = m.lit {
                        if attr_tag.is_some() {
                            context.push(Error::new_spanned(m.path, "duplicate `attr` attribute"));
                        } else if is_text {
                            context.push(Error::new_spanned(
                                m.path,
                                "`attr` attribute and `text` attribute is disjoint",
                            ));
                        } else if is_cdata {
                            context.push(Error::new_spanned(
                                m.path,
                                "`attr` attribute and `cdata` attribute is disjoint",
                            ))
                        } else if !child_tags.is_empty() {
                            context.push(Error::new_spanned(
                                m.path,
                                "`attr` attribute and `child` attribute is disjoint",
                            ));
                        } else if flatten_text_tag.is_some() {
                            context.push(Error::new_spanned(
                                m.path,
                                "`attr` attribute and `flatten_text` attribute is disjoint",
                            ));
                        } else {
                            attr_tag = Some(lit);
                        }
                    } else {
                        context.push(Error::new_spanned(m.lit, "expected a string literal"));
                    }
                }
                NestedMeta::Meta(Meta::Path(ref p)) if p.is_ident("text") => {
                    if is_text {
                        context.push(Error::new_spanned(p, "Duplicate `text` attribute."));
                    } else if attr_tag.is_some() {
                        context.push(Error::new_spanned(
                            p,
                            "`text` attribute and `attr` attribute is disjoint.",
                        ));
                    } else if !child_tags.is_empty() {
                        context.push(Error::new_spanned(
                            p,
                            "`text` attribute and `child` attribute is disjoint.",
                        ));
                    } else if flatten_text_tag.is_some() {
                        context.push(Error::new_spanned(
                            p,
                            "`text` attribute and `flatten_text` attribute is disjoint.",
                        ));
                    } else {
                        is_text = true;
                    }
                }
                NestedMeta::Meta(Meta::Path(ref p)) if p.is_ident("cdata") => {
                    if is_cdata {
                        context.push(Error::new_spanned(p, "Duplicate `cdata` attribute."));
                    } else if attr_tag.is_some() {
                        context.push(Error::new_spanned(
                            p,
                            "`text` attribute and `attr` attribute is disjoint.",
                        ));
                    } else if !child_tags.is_empty() {
                        context.push(Error::new_spanned(
                            p,
                            "`text` attribute and `child` attribute is disjoint.",
                        ));
                    } else {
                        is_cdata = true;
                    }
                }
                NestedMeta::Meta(Meta::NameValue(m)) if m.path.is_ident("child") => {
                    if let Lit::Str(lit) = m.lit {
                        if is_text {
                            context.push(Error::new_spanned(
                                m.path,
                                "`child` attribute and `text` attribute is disjoint.",
                            ));
                        } else if attr_tag.is_some() {
                            context.push(Error::new_spanned(
                                m.path,
                                "`child` attribute and `attr` attribute is disjoint.",
                            ));
                        } else if is_cdata {
                            context.push(Error::new_spanned(
                                m.path,
                                "`child` attribute and `cdata` attribute is disjoint.",
                            ))
                        } else if flatten_text_tag.is_some() {
                            context.push(Error::new_spanned(
                                m.path,
                                "`child` attribute and `flatten_text` attribute is disjoint.",
                            ));
                        } else {
                            child_tags.push(lit);
                        }
                    } else {
                        context.push(Error::new_spanned(m.lit, "Expected a string literal."));
                    }
                }
                NestedMeta::Meta(Meta::NameValue(m)) if m.path.is_ident("flatten_text") => {
                    if let Lit::Str(lit) = m.lit {
                        if is_text {
                            context.push(Error::new_spanned(
                                m.path,
                                "`flatten_text` attribute and `text` attribute is disjoint.",
                            ));
                        } else if !child_tags.is_empty() {
                            context.push(Error::new_spanned(
                                m.path,
                                "`flatten_text` attribute and `child` attribute is disjoint.",
                            ));
                        } else if attr_tag.is_some() {
                            context.push(Error::new_spanned(
                                m.path,
                                "`flatten_text` attribute and `attr` attribute is disjoint.",
                            ));
                        } else if flatten_text_tag.is_some() {
                            context.push(Error::new_spanned(
                                m.path,
                                "Duplicate `flatten_text` attribute.",
                            ));
                        } else {
                            flatten_text_tag = Some(lit);
                        }
                    } else {
                        context.push(Error::new_spanned(m.lit, "Expected a string literal."));
                    }
                }
                NestedMeta::Meta(Meta::NameValue(m)) if m.path.is_ident("with") => {
                    if let Lit::Str(lit) = m.lit {
                        match lit.parse() {
                            Ok(w) => with = Some(w),
                            Err(e) => context.push(e),
                        };
                    } else {
                        context.push(Error::new_spanned(m.lit, "Expected a string literal."));
                    }
                },
                _ => (),
            }
        }

        Self {
            default,
            attr_tag,
            child_tags,
            is_text,
            flatten_text_tag,
            is_cdata,
            with,
        }
    }
}

pub(crate) fn get_xml_meta(attr: &Attribute) -> Option<impl Iterator<Item = NestedMeta>> {
    if attr.path.is_ident("xml") {
        match attr.parse_meta() {
            Ok(Meta::List(meta)) => Some(meta.nested.into_iter()),
            _ => None,
        }
    } else {
        None
    }
}
