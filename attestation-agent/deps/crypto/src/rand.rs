pub fn random_bytes<const N: usize>() -> Vec<u8> {
    let mut buffer = vec![0u8; N];
    openssl::rand::rand_bytes(&mut buffer).expect("OpenSSL RNG failure");
    buffer
}
