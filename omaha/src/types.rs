use std::str;

#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
#[cfg_attr(test, derive(PartialEq, Default))]
pub struct FileSize(usize);

impl FileSize {
    #[inline]
    pub fn from_bytes(bytes: usize) -> Self {
        Self(bytes)
    }

    #[inline]
    pub fn bytes(&self) -> usize {
        self.0
    }
}

impl str::FromStr for FileSize {
    type Err = crate::Error;

    fn from_str(x: &str) -> Result<Self, Self::Err> {
        usize::from_str(x).map(Self).map_err(crate::Error::ParseFileSize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        const TEST_SIZE: usize = 1048576_usize;

        assert_eq!(FileSize::from_bytes(TEST_SIZE).bytes(), TEST_SIZE);
    }
}
