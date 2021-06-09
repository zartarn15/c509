use c509::*;

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
        .not_after(1_622_224_000)
        .subject(NameOid::CommonName, "RFC test CA")
        .pub_key_algo(PubAlgoId::Rsa)
        .pub_key_rsa(pub_rsa_n, 65537)
        .sign_algo(SignAlgoId::RsaSsaPkcs1v15WithSha256)
        .build();

    let cbor = c.enc().unwrap_or_else(|| panic!("Encoding failed"));

    println!(">>> {:02x?}", cbor);
}
