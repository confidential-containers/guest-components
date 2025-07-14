use rand::Rng;

pub fn random_bytes<const N: usize>() -> Vec<u8> {
    let mut buffer = vec![0u8; N];
    rand::rng().fill(&mut buffer[..]);
    buffer
}
