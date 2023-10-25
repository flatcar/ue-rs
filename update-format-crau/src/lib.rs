pub mod delta_update;
mod generated;
pub mod verify_sig;

pub mod proto {
    pub use super::generated::update_metadata::*;
}
