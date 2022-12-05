use std::str;

#[derive(Debug)]
#[repr(transparent)]
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
    type Err = <usize as str::FromStr>::Err;

    fn from_str(x: &str) -> Result<Self, Self::Err> {
        usize::from_str(x).map(Self)
    }
}
