mod elide_lifetime;
mod errors;
mod input_lifetime;

pub use elide_lifetime::elide_type_lifetimes;
pub use errors::Context;
pub use input_lifetime::gen_input_lifetime;
