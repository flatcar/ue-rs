use std::io::{Read, Seek, SeekFrom};
use std::error::Error;
use std::fs;

use protobuf::Message;

use update_format_crau::proto;


const DELTA_UPDATE_HEADER_SIZE: u64 = 4 + 8 + 8;

#[derive(Debug)]
struct DeltaUpdateFileHeader {
    magic: [u8; 4],
    file_format_version: u64,
    manifest_size: u64
}

impl DeltaUpdateFileHeader {
    #[inline]
    fn translate_offset(&self, offset: u64) -> u64 {
        DELTA_UPDATE_HEADER_SIZE + self.manifest_size + offset
    }
}

fn read_delta_update_header(f: &mut dyn Read) -> Result<DeltaUpdateFileHeader, Box<dyn Error>> {
    let mut header = DeltaUpdateFileHeader {
        magic: [0; 4],
        file_format_version: 0,
        manifest_size: 0
    };

    f.read_exact(&mut header.magic)?;
    if &header.magic != b"CrAU" {
        return Err("bad file magic".into());
    }

    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    header.file_format_version = u64::from_be_bytes(buf);
    if header.file_format_version != 1 {
        return Err("unsupported file format version".into());
    }

    f.read_exact(&mut buf)?;
    header.manifest_size = u64::from_be_bytes(buf);

    Ok(header)
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).expect("missing path (second argument)");

    let mut f = fs::File::open(path)?;
    let header = read_delta_update_header(&mut f)?;

    let manifest_bytes = {
        let mut buf = vec![0u8; header.manifest_size as usize];
        f.read_exact(&mut buf)?;
        buf.into_boxed_slice()
    };

    let manifest =
        proto::DeltaArchiveManifest::parse_from_bytes(&manifest_bytes)?;

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // !!! signature offsets are from the END of the manifest !!!
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // this may also be the case for the InstallOperations
    // use header.translate_offset()

    let signatures_bytes = match (manifest.signatures_offset, manifest.signatures_size) {
        (Some(sig_offset), Some(sig_size)) => {
            f.seek(SeekFrom::Start(header.translate_offset(sig_offset)))?;

            let mut buf = vec![0u8; sig_size as usize];
            f.read_exact(&mut buf)?;
            Some(buf.into_boxed_slice())
        },
        _ => None
    };

    let signatures = match signatures_bytes {
        Some(ref bytes) => Some(proto::Signatures::parse_from_bytes(bytes)?),
        None => None
    };

    println!("{:?}", signatures);

    Ok(())
}
