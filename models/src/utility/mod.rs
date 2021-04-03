use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};
use std::io::Read;
use std::path::PathBuf;

pub fn hash_from_signature(pub_key: &[u8], signature: &[u8]) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(pub_key).unwrap();
    let mut output = Vec::from([0u8; 512]);
    rsa.public_decrypt(&signature, &mut output, Padding::PKCS1)
        .unwrap();

    output.drain(0..19);
    output.truncate(32);

    output
}

pub fn open_private_key(path: PathBuf) -> Rsa<Private> {
    let mut file = std::fs::File::open(path).unwrap();
    let mut private_key_str = String::new();

    file.read_to_string(&mut private_key_str).unwrap();

    Rsa::private_key_from_pem(private_key_str.as_bytes()).unwrap()
}
