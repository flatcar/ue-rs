use proc_macro2::Span;
use quote::ToTokens;
use std::fmt::Display;
use syn::Error;

#[derive(Default)]
pub struct Context {
    pub(crate) errors: Vec<Error>,
}

impl Context {
    pub(crate) fn check(self) -> Result<(), Vec<Error>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    pub(crate) fn push(&mut self, error: Error) {
        self.errors.push(error)
    }

    pub(crate) fn push_new_error<T>(&mut self, span: Span, message: T)
    where
        T: Display,
    {
        self.push(Error::new(span, message))
    }

    pub(crate) fn push_spanned_error<T, U>(&mut self, tokens: T, message: U)
    where
        T: ToTokens,
        U: Display,
    {
        self.push(Error::new_spanned(tokens, message))
    }
}
