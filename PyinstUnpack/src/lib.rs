pub mod pyinstaller;
pub mod errors;
mod utils;

#[pyo3::pymodule]
mod _native {
    use std::collections::HashMap;
    use pyo3::prelude::*;
    use crate::pyinstaller::decompiler::{
        find_header,
        is_pyinstaller,
        get_header,
        parse_toc,
        get_files
    };


    #[pyfunction]
    fn unpack(buffer: &[u8]) -> PyResult<(HashMap<String, Vec<u8>>, (u8, u8))> {
        if !is_pyinstaller(buffer) {
            return Err(pyo3::exceptions::PyValueError::new_err("Not a PyInstaller archive"));
        };
    
        let header_offset = find_header(buffer).unwrap();
        let header = get_header(buffer, header_offset).unwrap();
        let toc = parse_toc(buffer, &header, header_offset);
        let files = get_files(buffer, &toc);

        let s = header.python_version.to_string();

        let major = s[0..1].parse::<u8>().unwrap();
        let minor = s[1..].parse::<u8>().unwrap();
        Ok((files, (major, minor)))
    }
}
