use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{spanned::Spanned, *};

use crate::{
    attrs,
    utils::{elide_type_lifetimes, Context},
};
use bitflags::bitflags;

type Result<T, E = Vec<syn::Error>> = std::result::Result<T, E>;

pub enum Element {
    Struct { name: Ident, fields: Fields },
    Enum { name: Ident, variants: Vec<Fields> },
}

pub enum Fields {
    /// Named fields of a struct or struct variant
    ///
    /// ```ignore
    /// #[xml(tag = "$tag")]
    /// struct $name {
    ///     $( $fields )*
    /// }
    /// ```
    ///
    /// ```ignore
    /// enum Foo {
    ///     #[xml(tag = "$tag")]
    ///     $name {
    ///         $( $fields )*
    ///     }
    /// }
    /// ```
    Named {
        tag: LitStr,
        strict: StrictMode,
        name: Ident,
        fields: Vec<Field>,
    },
    /// Newtype struct or newtype variant
    ///
    /// ```ignore
    /// #[xml($(tag = "$tags",)*)]
    /// struct $name($ty);
    /// ```
    ///
    /// ```ignore
    /// enum Foo {
    ///     #[xml($(tag = "$tags",)*)]
    ///     $name($ty)
    /// }
    /// ```
    Newtype {
        tags: Vec<LitStr>,
        name: Ident,
        ty: Box<Type>,
    },
}

pub enum Field {
    /// Arrtibute Field
    ///
    /// ```ignore
    /// struct Foo {
    ///     #[xml(attr = "$tag", $default)]
    ///     $name: $ty,
    /// }
    /// ```
    Attribute {
        name: TokenStream,
        bind: Ident,
        ty: Type,
        with: Option<ExprPath>,
        tag: LitStr,
        default: bool,
    },
    /// Child(ren) Field
    ///
    /// ```ignore
    /// struct Foo {
    ///     #[xml(child = "$tag", child = "$tag", $default)]
    ///     $name: $ty,
    /// }
    /// ```
    Child {
        name: TokenStream,
        bind: Ident,
        ty: Type,
        with: Option<ExprPath>,
        default: bool,
        tags: Vec<LitStr>,
    },
    /// Text Field
    ///
    /// ```ignore
    /// struct Foo {
    ///     #[xml(text, $default)]
    ///     $name: $ty,
    /// }
    /// ```
    Text {
        name: TokenStream,
        bind: Ident,
        ty: Type,
        with: Option<ExprPath>,
        is_cdata: bool,
    },
    /// Flatten Text
    ///
    /// ```ignore
    /// struct Foo {
    ///     #[xml(flatten_text = "$tag", $default)]
    ///     $name: $ty,
    /// }
    /// ```
    FlattenText {
        name: TokenStream,
        bind: Ident,
        ty: Type,
        with: Option<ExprPath>,
        default: bool,
        tag: LitStr,
        is_cdata: bool,
    },
}

pub enum Type {
    // Cow<'a, str>
    CowStr,
    // Option<Cow<'a, str>>
    OptionCowStr,
    // Vec<Cow<'a, str>>
    VecCowStr,
    // T
    T(syn::Type),
    // Option<T>
    OptionT(syn::Type),
    // Vec<T>
    VecT(syn::Type),
    // bool
    Bool,
    // Vec<bool>
    VecBool,
    // Option<bool>
    OptionBool,
}

impl Element {
    pub fn parse(input: DeriveInput) -> Result<Element> {
        let mut ctx = Context::default();

        let element = match input.data {
            Data::Struct(data) => Element::Struct {
                name: input.ident.clone(),
                fields: Fields::parse(&mut ctx, data.fields, input.attrs, input.ident),
            },
            Data::Enum(data) => Element::Enum {
                name: input.ident,
                variants: data
                    .variants
                    .into_iter()
                    .map(|variant| {
                        Fields::parse(&mut ctx, variant.fields, variant.attrs, variant.ident)
                    })
                    .collect(),
            },
            Data::Union(_) => {
                return Err(vec![syn::Error::new_spanned(
                    input,
                    "hard-xml doesn't support union",
                )]);
            }
        };

        ctx.check().map(|_| element)
    }
}

impl Fields {
    pub fn parse(
        ctx: &mut Context,
        mut fields: syn::Fields,
        attrs: Vec<Attribute>,
        name: Ident,
    ) -> Fields {
        // Finding `tag` attribute
        let attrs::Container {
            mut tags,
            strict_mode,
        } = attrs::Container::parse(ctx, attrs);

        if tags.is_empty() {
            ctx.push_spanned_error(&name, "missing `tag` attribute");
        }

        // Special handling for newtypes, which can have multiple tags
        if let syn::Fields::Unnamed(ref mut fields) = fields {
            if is_new_type(fields) {
                let ty = fields.unnamed.pop().unwrap().into_value().ty;
                let ty = Box::new(Type::parse(ty));

                return Fields::Newtype { tags, name, ty };
            }
        }

        let fields = match fields {
            syn::Fields::Unit => Vec::new(),

            syn::Fields::Unnamed(fields) => fields
                .unnamed
                .into_iter()
                .enumerate()
                .filter_map(|(index, field)| {
                    let index = syn::Index::from(index);
                    let bind = format_ident!("__self_{}", index);

                    Field::parse(ctx, quote!(#index), bind, field)
                })
                .collect(),

            syn::Fields::Named(_) => fields
                .into_iter()
                .filter_map(|field| {
                    let name = field.ident.clone().unwrap();
                    let bind = format_ident!("__self_{}", name);

                    Field::parse(ctx, quote!(#name), bind, field)
                })
                .collect(),
        };

        // TODO should extraneous tags be an error?
        let tag = if !tags.is_empty() {
            tags.swap_remove(0)
        } else {
            LitStr::new("", Span::call_site())
        };

        Fields::Named {
            tag,
            strict: strict_mode,
            name,
            fields,
        }
    }
}

fn is_new_type(fields: &FieldsUnnamed) -> bool {
    fields.unnamed.len() == 1
        && fields.unnamed[0]
            .attrs
            .iter()
            .all(|attr| attrs::get_xml_meta(attr).is_none())
}

impl Field {
    pub fn parse(
        ctx: &mut Context,
        name: TokenStream,
        bind: Ident,
        field: syn::Field,
    ) -> Option<Field> {
        let span = field.span();

        let mut attrs = attrs::Field::parse(ctx, field.attrs);
        let with = attrs.with.take();
        let kind = FieldKind::from_attributes(ctx, attrs, span)?;

        let span = field.ty.span();
        let ty = Type::parse(field.ty);

        kind.into_field(ctx, name, bind, ty, with, span)
    }
}

enum FieldKind {
    Attribute(LitStr, bool),
    Child(Vec<LitStr>, bool),
    FlattenText {
        tag: LitStr,
        cdata: bool,
        default: bool,
    },
    Text(bool),
}

impl FieldKind {
    fn into_field(
        self,
        ctx: &mut Context,
        name: TokenStream,
        bind: Ident,
        ty: Type,
        with: Option<ExprPath>,
        span: Span,
    ) -> Option<Field> {
        self.verify_type(ctx, &ty, span).then(|| match self {
            FieldKind::Attribute(tag, default) => Field::Attribute {
                name,
                bind,
                ty,
                with,
                tag,
                default,
            },
            FieldKind::Child(tags, default) => Field::Child {
                name,
                bind,
                ty,
                with,
                default,
                tags,
            },
            FieldKind::FlattenText {
                tag,
                cdata,
                default,
            } => Field::FlattenText {
                name,
                bind,
                ty,
                with,
                default,
                tag,
                is_cdata: cdata,
            },
            FieldKind::Text(cdata) => Field::Text {
                name,
                bind,
                ty,
                with,
                is_cdata: cdata,
            },
        })
    }

    fn from_attributes(ctx: &mut Context, attrs: attrs::Field, span: Span) -> Option<Self> {
        let attrs::Field {
            attr_tag,
            child_tags,
            flatten_text_tag,
            is_text,
            ..
        } = attrs;

        match (attr_tag, child_tags.as_slice(), flatten_text_tag, is_text) {
            (Some(tag), &[], None, false) => Some(Self::Attribute(tag, attrs.default)),
            (None, &[_, ..], None, false) => Some(Self::Child(child_tags, attrs.default)),
            (None, &[], Some(tag), false) => Some(Self::FlattenText {
                tag,
                cdata: attrs.is_cdata,
                default: attrs.default,
            }),
            (None, &[], None, true) => Some(Self::Text(attrs.is_cdata)),

            (None, &[], None, false) => {
                ctx.push_new_error(
                    span,
                    "field should have one of `attr`, `child`, `text` or `flatten_text` attribute",
                );
                None
            }
            _ => {
                ctx.push_new_error(
                    span,
                    "the attributes `attr`, `child`, `text` and `flatten_text` are mutually exclusive",
                );
                None
            }
        }
    }

    fn verify_type(&self, ctx: &mut Context, ty: &Type, span: Span) -> bool {
        match self {
            FieldKind::Attribute(_, _) if ty.is_vec() => {
                ctx.push_new_error(span, "`attr` attribute doesn't support Vec");
                false
            }
            FieldKind::Child(_, _)
                if !matches!(ty, Type::OptionT(_) | Type::T(_) | Type::VecT(_)) =>
            {
                ctx.push_new_error(
                    span,
                    "`child` attribute only supports Vec<T>, Option<T>, and T",
                );
                false
            }
            FieldKind::Text(_) if ty.is_vec() => {
                ctx.push_new_error(span, "`text` attribute doesn't support Vec");
                false
            }

            _ => true,
        }
    }
}

impl Type {
    pub fn is_option(&self) -> bool {
        matches!(
            self,
            Type::OptionCowStr | Type::OptionT(_) | Type::OptionBool
        )
    }

    pub fn is_vec(&self) -> bool {
        matches!(self, Type::VecCowStr | Type::VecT(_) | Type::VecBool)
    }

    fn parse(mut ty: syn::Type) -> Self {
        fn is_vec(ty: &syn::Type) -> Option<&syn::Type> {
            let path = match ty {
                syn::Type::Path(ty) => &ty.path,
                _ => return None,
            };
            let seg = path.segments.last()?;
            let args = match &seg.arguments {
                PathArguments::AngleBracketed(bracketed) => &bracketed.args,
                _ => return None,
            };
            if seg.ident == "Vec" && args.len() == 1 {
                match args[0] {
                    GenericArgument::Type(ref arg) => Some(arg),
                    _ => None,
                }
            } else {
                None
            }
        }

        fn is_option(ty: &syn::Type) -> Option<&syn::Type> {
            let path = match ty {
                syn::Type::Path(ty) => &ty.path,
                _ => return None,
            };
            let seg = path.segments.last()?;
            let args = match &seg.arguments {
                PathArguments::AngleBracketed(bracketed) => &bracketed.args,
                _ => return None,
            };
            if seg.ident == "Option" && args.len() == 1 {
                match &args[0] {
                    GenericArgument::Type(arg) => Some(arg),
                    _ => None,
                }
            } else {
                None
            }
        }

        fn is_cow_str(ty: &syn::Type) -> bool {
            let path = match ty {
                syn::Type::Path(ty) => &ty.path,
                _ => return false,
            };
            let seg = match path.segments.last() {
                Some(seg) => seg,
                None => return false,
            };
            let args = match &seg.arguments {
                PathArguments::AngleBracketed(bracketed) => &bracketed.args,
                _ => return false,
            };
            if seg.ident == "Cow" && args.len() == 2 {
                match &args[1] {
                    GenericArgument::Type(syn::Type::Path(ty)) => ty.path.is_ident("str"),
                    _ => false,
                }
            } else {
                false
            }
        }

        fn is_bool(ty: &syn::Type) -> bool {
            matches!(ty, syn::Type::Path(ty) if ty.path.is_ident("bool"))
        }

        elide_type_lifetimes(&mut ty);

        if let Some(ty) = is_vec(&ty) {
            if is_cow_str(ty) {
                Type::VecCowStr
            } else if is_bool(ty) {
                Type::VecBool
            } else {
                Type::VecT(ty.clone())
            }
        } else if let Some(ty) = is_option(&ty) {
            if is_cow_str(ty) {
                Type::OptionCowStr
            } else if is_bool(ty) {
                Type::OptionBool
            } else {
                Type::OptionT(ty.clone())
            }
        } else if is_cow_str(&ty) {
            Type::CowStr
        } else if is_bool(&ty) {
            Type::Bool
        } else {
            Type::T(ty)
        }
    }
}

bitflags! {
    pub struct StrictMode: u8 {
        const UNKNOWN_ATTRIBUTE = 0b0000_0001;
        const UNKNOWN_ELEMENT = 0b0000_0010;
    }
}
