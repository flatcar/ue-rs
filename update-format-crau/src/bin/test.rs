use std::error::Error;
use std::io::Read;
use std::fs;

use protobuf::Message;

use update_format_crau::proto;


#[derive(Debug)]
struct DeltaUpdateFileHeader {
    magic: [u8; 4],
    file_format_version: u64
}

fn read_delta_update_header(f: &mut dyn Read) -> Result<DeltaUpdateFileHeader, Box<dyn Error>> {
    let mut header = DeltaUpdateFileHeader {
        magic: [0; 4],
        file_format_version: 0
    };

    f.read_exact(&mut header.magic)?;

    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    header.file_format_version = u64::from_be_bytes(buf);

    Ok(header)
}

fn check_header_invariants(header: &DeltaUpdateFileHeader) -> Result<(), Box<dyn Error>>
{
    if &header.magic != b"CrAU" {
        return Err("bad file magic".into());
    }

    if header.file_format_version != 1 {
        return Err("unsupported file format version".into());
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).expect("missing path (second argument)");

    let mut f = fs::File::open(path)?;
    let header = read_delta_update_header(&mut f)?;
    check_header_invariants(&header)?;

    let manifest_size = {
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf)?;
        u64::from_be_bytes(buf)
    };

    println!("{:?}, {}", header, manifest_size);

    let manifest_bytes = {
        let mut buf = vec![0u8; manifest_size as usize];
        f.read_exact(&mut buf)?;
        buf
    };

    let manifest =
        proto::DeltaArchiveManifest::parse_from_bytes(&manifest_bytes)?;

    println!("{:?}", manifest);

    Ok(())
}
