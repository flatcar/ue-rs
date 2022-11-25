use std::fmt;

use uuid::Uuid;
pub use uuid::uuid;

// the only reason we're wrapping the upstream Uuid type here is so that Display formats it in
// "braced" form in the XML document.
#[repr(transparent)]
pub struct OmahaUuid(Uuid);

impl OmahaUuid {
    #[inline]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        OmahaUuid(uuid)
    }
}

impl fmt::Display for OmahaUuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self.0.as_braced(), f)
    }
}

impl From<Uuid> for OmahaUuid {
    #[inline]
    fn from(uuid: Uuid) -> Self {
        OmahaUuid::from_uuid(uuid)
    }
}

macro_rules! omaha_uuid {
    ($uuid:literal) => {{
        OmahaUuid::from_uuid(uuid!($uuid))
    }};
}
