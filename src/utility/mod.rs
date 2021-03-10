use openssl::rsa::{Padding, Rsa};

pub fn hash_from_signature(pub_key: &[u8], signature: &[u8]) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(pub_key).unwrap();
    let mut output = vec![0u8; 256];
    rsa.public_decrypt(&signature, &mut output, Padding::PKCS1)
        .unwrap();

    output.drain(0..19);
    output.truncate(32);

    output
}
