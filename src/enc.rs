use crate::cbor::*;
use crate::{Name, NameOid, C509};

fn enc_serial_number(sn: Vec<u8>) -> Option<Vec<u8>> {
    // TODO: Any leading 0x00 is therefore omitted
    sn.to_cbor()
}

fn enc_name(n: Vec<Name>) -> Option<Vec<u8>> {
    if n.len() == 1 {
        let name = n.get(0)?;
        if name.oid == NameOid::CommonName {
            return name.name.to_cbor();
        }
    }

    None
}

fn serialize(cbor: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut ser = Vec::new();
    println!("");
    for item in cbor.iter() {
        println!("> {:02x?}", item);
        ser.extend(item);
    }

    ser
}

fn encode(c: C509) -> Option<Vec<u8>> {
    let mut cbor = Vec::new();

    /* cborCertificateType */
    match c.cert_type {
        Some(t) => cbor.push(vec![t as u8]),
        None => {
            println!("Failed: cert_type is not set");
            return None;
        }
    }

    /* certificateSerialNumber */
    if c.serial_number.len() == 0 {
        println!("Failed: cert_type is not set");
        return None;
    }
    cbor.push(enc_serial_number(c.serial_number)?);

    /* issuerName */
    if c.issuer.len() == 0 {
        println!("Failed: no issuer found");
        return None;
    }
    cbor.push(enc_name(c.issuer)?);

    Some(serialize(&cbor))
}

pub trait C509Enc {
    fn enc(self) -> Option<Vec<u8>>;
}

impl C509Enc for C509 {
    fn enc(self) -> Option<Vec<u8>> {
        encode(self)
    }
}
