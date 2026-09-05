

pub fn read_u32_be(slice: &[u8]) -> u32 {
    let bytes: [u8; 4] = slice.try_into().expect("slice length verified");
    u32::from_be_bytes(bytes)
}