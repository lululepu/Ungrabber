use std::fs;
use PyinstUnpack::pyinstaller::decompiler::{
    find_header, get_header, is_pyinstaller
};

use PyinstUnpack::errors::PyInstallerError;


#[test]
fn test_is_pyinstaller() {
    let pyinstaller = fs::read("tests/pyinstaller_archive").unwrap();
    let non_pyinstaller = fs::read("tests/non_pyinstaller").unwrap();
    let empty = fs::read("tests/empty").unwrap();

    assert_eq!(is_pyinstaller(&pyinstaller), true);
    assert_eq!(is_pyinstaller(&non_pyinstaller), false);
    assert_eq!(is_pyinstaller(&empty), false);
}

#[test]
fn test_find_header() {
    let pyinstaller = fs::read("tests/pyinstaller_archive").unwrap();

    let offset = find_header(&pyinstaller).unwrap();
    assert!(offset < pyinstaller.len());
}

#[test]
fn test_find_header_errors() {
    let non_pyinstaller = fs::read("tests/non_pyinstaller").unwrap();
    let empty = fs::read("tests/empty").unwrap();

    assert_eq!(
        find_header(&non_pyinstaller),
        Err(PyInstallerError::InvalidPyinstallerArchive)
    );

    assert_eq!(
        find_header(&empty),
        Err(PyInstallerError::BufferTooSmall)
    );
}

#[test]
fn test_get_header() {
    let pyinstaller = fs::read("tests/pyinstaller_archive").unwrap();

    get_header(&pyinstaller, find_header(&pyinstaller).unwrap()).unwrap();
}