use crate::cbor::*;

pub trait C509Sign {
    fn sign<F>(&self, sign_cb: F, sign_key: &Vec<u8>) -> Option<Vec<u8>>
    where
        F: Fn(&Vec<u8>, &Vec<u8>) -> Option<Vec<u8>>;
}

impl C509Sign for Vec<u8> {
    fn sign<F>(&self, sign_cb: F, sign_key: &Vec<u8>) -> Option<Vec<u8>>
    where
        F: Fn(&Vec<u8>, &Vec<u8>) -> Option<Vec<u8>>,
    {
        let sign = sign_cb(self, sign_key)?;
        let cbor = sign.to_cbor()?;
        println!("> {:02x?}", cbor);

        let mut cert = self.clone();
        cert.extend(cbor);

        Some(cert)
    }
}
