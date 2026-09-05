use std::collections::HashMap;

use crate::errors::PyInstallerError;

use crate::utils::helper::{
    read_u32_be
};

use crate::utils::zlib::{
    decompress_zlib
};

use crate::pyinstaller::consts::{
    SIGNATURE,
};
use crate::pyinstaller::structs::{
    PyinstHeader,
    PyinstEntry
};



pub fn get_files(data: &[u8], toc: &[PyinstEntry]) -> HashMap<String, Vec<u8>> {

    let mut result = HashMap::new();

    for entry in toc {
        let content = &data[(entry.offset) as usize .. (entry.offset + entry.compressed_size) as usize];

        let uncompressed = if entry.compression_flag == 1 {
            decompress_zlib(content, entry.uncompressed_size as usize).expect("ERROR MANAGE")
        } else {
            content.to_vec()
        };
                
        result.insert(entry.name.clone(), uncompressed);
    };

    result
    
}

pub fn parse_toc(data: &[u8], header: &PyinstHeader, header_pos: usize) -> Vec<PyinstEntry> {

    let overlay_offset = header_pos + size_of::<PyinstHeader>() - header.package_size as usize;
    let toc_pos = overlay_offset + header.toc_offset as usize;

    let mut bytes_read: usize = 0;
    let mut toc: Vec<PyinstEntry> = Vec::new();
    toc.reserve(header.toc_size as usize);

    while bytes_read < header.toc_size as usize {
        let size = read_u32_be(&data[toc_pos + bytes_read..toc_pos + bytes_read + 4]);
        let entry = &data[toc_pos + bytes_read..toc_pos + bytes_read + size as usize];

        let offset = overlay_offset as u32 + read_u32_be(&entry[4..8]);
        let compressed_size = read_u32_be(&entry[8..12]);
        let uncompressed_size = read_u32_be(&entry[12..16]);
        let compression_flag = entry[16];
        let type_ = entry[17];

        let len = entry[17..].iter().position(|&b| b == 0).unwrap_or(entry[17..].len());
        let name = std::str::from_utf8(&entry[18..18 + (len - 1)]).ok().expect("ERROR MANAGE"); // ERROR MANAGE

        bytes_read += size as usize;

        toc.push(
            PyinstEntry {
                size: size,
                offset: offset,
                compressed_size: compressed_size,
                uncompressed_size: uncompressed_size,
                compression_flag: compression_flag,
                type_: type_,
                name: name.to_owned()
            }
        );

    }

    toc
}

pub fn get_header(data: &[u8], header_offset: usize) -> Result<PyinstHeader, PyInstallerError> {

    let offseted = &data[header_offset..];

    if offseted.len() < 24 {
        return Err(PyInstallerError::InvalidPyinstallerArchive);
    }

    let mut signature = [0u8; 8];
    signature.copy_from_slice(&offseted[0..8]);

    let mut python_libname = [0u8; 64];
    python_libname.copy_from_slice(&offseted[24..88]);


    Ok(PyinstHeader {
        signature: signature,
        package_size: read_u32_be(&offseted[8..12]),
        toc_offset: read_u32_be(&offseted[12..16]),
        toc_size: read_u32_be(&offseted[16..20]),
        python_version: read_u32_be(&offseted[20..24]),
        python_libname: python_libname
    })
}

pub fn get_tail_bytes(data: &[u8], header_offset: usize) -> usize {
    data.get(header_offset + size_of::<PyinstHeader>()..)
        .map_or(0, |tail| tail.len())
}

pub fn find_header(data: &[u8]) -> Result<usize, PyInstallerError> {

    if data.len() < SIGNATURE.len() {

        Err(PyInstallerError::BufferTooSmall)

    } else {

        data.windows(SIGNATURE.len())
            .rposition(|w| w == SIGNATURE)
            .ok_or(PyInstallerError::InvalidPyinstallerArchive)
    }

}


pub fn is_pyinstaller(data: &[u8]) -> bool {
    data.len() >= SIGNATURE.len() && data.windows(SIGNATURE.len())
        .rposition(|w| w == SIGNATURE)
        .is_some()
}

