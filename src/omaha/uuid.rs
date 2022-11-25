use std::fmt;

use ::uuid::Uuid as WrappedUuid;

// the only reason we're wrapping the upstream Uuid type here is so that Display formats it in
// "braced" form in the XML document.
#[repr(transparent)]
pub struct Uuid(WrappedUuid);

impl Uuid {
    #[inline]
    pub const fn from_uuid(uuid: WrappedUuid) -> Self {
        Uuid(uuid)
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self.0.as_braced(), f)
    }
}

impl From<WrappedUuid> for Uuid {
    #[inline]
    fn from(uuid: WrappedUuid) -> Self {
        Uuid::from_uuid(uuid)
    }
}

#[macro_export]
macro_rules! uuid {
    ($uuid:literal) => {{
        omaha::Uuid::from_uuid(::uuid::uuid!($uuid))
    }};
}
