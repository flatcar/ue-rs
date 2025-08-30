pub(crate) mod braced_uuid {
    #[inline]
    pub(crate) fn to_str(u: &uuid::Uuid) -> String {
        u.braced().to_string()
    }

    type Err = crate::Error;

    pub(crate) fn from_str(s: &str) -> Result<uuid::Uuid, Err> {
        let unbraced = s.strip_prefix('{').unwrap_or(s).strip_suffix('}').unwrap_or(s);
        uuid::Uuid::parse_str(unbraced).map_err(crate::Error::ParseUuid)
    }
}
