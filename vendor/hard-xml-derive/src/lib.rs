#![recursion_limit = "256"]

#![allow(clippy::all)]

extern crate proc_macro;

mod attrs;
mod read;
mod types;
mod utils;
mod write;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};
use types::Element;

#[proc_macro_derive(XmlRead, attributes(xml))]
pub fn derive_xml_read(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let generics = &input.generics;

    let params = &generics.params;

    let where_clause = &generics.where_clause;

    let input_lifetime = utils::gen_input_lifetime(generics);

    let mut params_with_input_lifetime = generics.params.clone();

    params_with_input_lifetime.insert(0, input_lifetime.into());

    let element = match Element::parse(input.clone()) {
        Ok(element) => element,
        Err(errors) => {
            return errors
                .into_iter()
                .map(syn::Error::into_compile_error)
                .collect::<proc_macro2::TokenStream>()
                .into()
        }
    };
    let impl_read = read::impl_read(element);

    let gen = quote! {
        impl <#params_with_input_lifetime> hard_xml::XmlRead<'__input> for #name <#params>
            #where_clause
        {
            fn from_reader(
                mut reader: &mut hard_xml::XmlReader<'__input>
            ) -> hard_xml::XmlResult<Self> {
                use hard_xml::xmlparser::{ElementEnd, Token, Tokenizer};
                use hard_xml::XmlError;
                #impl_read
            }
        }
    };

    gen.into()
}

#[proc_macro_derive(XmlWrite, attributes(xml))]
pub fn derive_xml_write(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let generics = &input.generics;

    let params = &generics.params;

    let where_clause = &generics.where_clause;

    let element = match Element::parse(input.clone()) {
        Ok(element) => element,
        Err(errors) => {
            return errors
                .into_iter()
                .map(syn::Error::into_compile_error)
                .collect::<proc_macro2::TokenStream>()
                .into()
        }
    };
    let impl_write = write::impl_write(element);

    let gen = quote! {
        impl <#params> hard_xml::XmlWrite for #name <#params>
            #where_clause
        {
            fn to_writer<W: std::io::Write>(
                &self,
                mut writer: &mut hard_xml::XmlWriter<W>
            ) -> hard_xml::XmlResult<()> {
                #impl_write

                Ok(())
            }
        }
    };

    gen.into()
}
