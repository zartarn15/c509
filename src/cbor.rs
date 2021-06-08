use serde::ser::Serializer;
use serde_cbor::Serializer as Ser;

pub trait Cbor {
    fn to_cbor(&self) -> Option<Vec<u8>>;
}

impl Cbor for Vec<u8> {
    fn to_cbor(&self) -> Option<Vec<u8>> {
        let mut ret = Vec::new();
        Ser::new(&mut ret).serialize_bytes(self).ok()?;

        Some(ret)
    }
}

impl Cbor for String {
    fn to_cbor(&self) -> Option<Vec<u8>> {
        let mut ret = Vec::new();
        Ser::new(&mut ret).serialize_str(self).ok()?;

        Some(ret)
    }
}
