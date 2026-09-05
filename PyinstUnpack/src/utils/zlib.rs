use libdeflater::{Decompressor};

pub fn decompress_zlib(data: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
    let mut decompressor = Decompressor::new();

    let mut output = vec![0u8; expected_size];

    let actual_size = decompressor.zlib_decompress(data, &mut output)
        .map_err(|e| format!("Decompression error: {:?}", e))?;

    output.truncate(actual_size);
    Ok(output)
}
