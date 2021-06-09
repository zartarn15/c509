use crate::cbor::*;
use crate::{Name, NameOid, PubKey, C509};

fn enc_serial_number(sn: Vec<u8>) -> Option<Vec<u8>> {
    if sn.len() == 0 {
        return None;
    }

    /* Any leading 0x00 is therefore omitted */
    // TODO

    sn.to_cbor()
}

fn enc_name(n: Vec<Name>) -> Option<Vec<u8>> {
    if n.len() == 0 {
        return None;
    }

    /* Convert CN format HH-HH-HH-HH-HH-HH-HH-HH */
    // TODO

    /* Single CommonName case */
    if n.len() == 1 {
        let name = n.get(0)?;
        if name.oid == NameOid::CommonName {
            return name.name.to_cbor();
        }
    }

    /* Multiple names */
    // TODO

    None
}

fn enc_pub_key(pk: Option<PubKey>) -> Option<Vec<u8>> {
    match pk? {
        PubKey::Rsa(r) => r.n.to_cbor(), //TODO: If the exponent is not 65537
        PubKey::Ec(e) => e.key.to_cbor(),
    }
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

    if let Some(v) = (c.cert_type? as i32).to_cbor() {
        cbor.push(v);
    } else {
        println!("Failed: Type");
        return None;
    }

    if let Some(v) = enc_serial_number(c.serial_number) {
        cbor.push(v);
    } else {
        println!("Failed: SerialNumber");
        return None;
    }

    if let Some(v) = enc_name(c.issuer) {
        cbor.push(v);
    } else {
        println!("Failed: IssuerName");
        return None;
    }

    if let Some(v) = c.not_before.to_cbor() {
        cbor.push(v);
    } else {
        println!("Failed: NotBefore");
        return None;
    }

    if let Some(v) = c.not_after.to_cbor() {
        cbor.push(v);
    } else {
        println!("Failed: NotAfter");
        return None;
    }

    if let Some(v) = enc_name(c.subject) {
        cbor.push(v);
    } else {
        println!("Failed: SubjectName");
        return None;
    }

    if let Some(v) = (c.pub_key_algo? as i32).to_cbor() {
        cbor.push(v);
    } else {
        println!("Failed: PubKeyAlgo");
        return None;
    }

    if let Some(v) = enc_pub_key(c.pub_key) {
        cbor.push(v);
    } else {
        println!("Failed: PubKey");
        return None;
    }

    // TODO: Extensions
    cbor.push(vec![1]);

    if let Some(v) = (c.sign_algo? as i32).to_cbor() {
        cbor.push(v);
    } else {
        println!("Failed: SignAlgo");
        return None;
    }

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
