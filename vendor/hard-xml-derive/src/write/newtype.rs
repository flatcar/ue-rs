use proc_macro2::TokenStream;
use quote::quote;

pub fn write(name: TokenStream) -> TokenStream {
    quote! {
        hard_xml::log_start_writing!(#name);

        __inner.to_writer(writer)?;

        hard_xml::log_finish_writing!(#name);
    }
}
