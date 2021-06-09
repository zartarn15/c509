use c509::*;

fn ec_sign_fn(_data: &Vec<u8>, _sign_key: &Vec<u8>) -> Option<Vec<u8>> {
    // TODO: impl real signing

    let signature = vec![
        0x44, 0x5D, 0x79, 0x8C, 0x90, 0xE7, 0xF5, 0x00, 0xDC, 0x74, 0x7A, 0x65, 0x4C, 0xEC, 0x6C,
        0xFA, 0x6F, 0x03, 0x72, 0x76, 0xE1, 0x4E, 0x52, 0xED, 0x07, 0xFC, 0x16, 0x29, 0x4C, 0x84,
        0x66, 0x0D, 0x5A, 0x33, 0x98, 0x5D, 0xFB, 0xD4, 0xBF, 0xDD, 0x6D, 0x4A, 0xCF, 0x38, 0x04,
        0xC3, 0xD4, 0x6E, 0xBF, 0x3B, 0x7F, 0xA6, 0x26, 0x40, 0x67, 0x4F, 0xC0, 0x35, 0x4F, 0xA0,
        0x56, 0xDB, 0xAE, 0xA6,
    ];

    Some(signature)
}

#[test]
fn c509_root_test() {
    let pub_ec: Vec<u8> = vec![
        0x02, 0xB1, 0x21, 0x6A, 0xB9, 0x6E, 0x5B, 0x3B, 0x33, 0x40, 0xF5, 0xBD, 0xF0, 0x2E, 0x69,
        0x3F, 0x16, 0x21, 0x3A, 0x04, 0x52, 0x5E, 0xD4, 0x44, 0x50, 0xB1, 0x01, 0x9C, 0x2D, 0xFD,
        0x38, 0x38, 0xAB,
    ];

    let c = C509Builder::new()
        .cert_type(CertType::CborSigned)
        .serial_number(vec![0x01, 0xf5, 0x0d])
        .issuer(NameOid::CommonName, "RFC test CA")
        .not_before(1_577_836_800)
        .not_after(1_612_224_000)
        .subject(NameOid::CommonName, "01-23-45-FF-FE-67-89-AB")
        .pub_key_algo(PubAlgoId::EcPublicKeyWithSecp256r1)
        .pub_key_ec(pub_ec)
        .sign_algo(SignAlgoId::EcdsaWithSha256)
        .build();

    let cbor = c.enc().unwrap_or_else(|| panic!("Encoding failed"));

    let sign_key = Vec::new(); // TODO: load real key
    let cert = cbor
        .sign(ec_sign_fn, &sign_key)
        .unwrap_or_else(|| panic!("Signing failed"));

    println!("\n>>> {:02x?}", cert);
}
