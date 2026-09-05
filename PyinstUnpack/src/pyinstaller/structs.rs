
#[allow(dead_code)]
#[derive(Debug)]
pub struct PyinstHeader {
    pub signature: [u8; 8],
    pub package_size: u32,
    pub toc_offset: u32,
    pub toc_size: u32,
    pub python_version: u32,
    pub python_libname: [u8; 64]
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PyinstEntry {
    pub size: u32,
    pub offset: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub compression_flag: u8,
    pub type_: u8,
    pub name: String
}