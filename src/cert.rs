#[derive(Debug, PartialEq)]
pub enum CertType {
    NatSigned = 0,  /* Natively signed C509 certificate following X.509 v3 */
    CborSigned = 1, /* CBOR re-encoded X.509 v3 DER */
}

#[derive(Debug, PartialEq)]
pub enum NameOid {
    CommonName = 1,
    Surname = 2,
    SerialNumber = 3,
    Country = 4,
    Locality = 5,
    StateOrProvince = 6,
    StreetAddress = 7,
    Organization = 8,
    OrganizationalUnit = 9,
    Title = 10,
    PostalCode = 11,
    GivenName = 12,
    Initials = 13,
    GenerationQualifier = 14,
    DNQualifier = 15,
    Pseudonym = 16,
    OrganizationIdentifier = 17,
}

#[derive(Debug, PartialEq)]
pub struct Name {
    pub oid: NameOid,
    pub name: String,
}

#[derive(Debug, PartialEq)]
pub enum PubAlgoId {
    Rsa = 0,
    EcPublicKeyWithSecp256r1 = 1,
    EcPublicKeyWithSecp384r1 = 2,
    EcPublicKeyWithSecp521r1 = 3,
    X25519 = 8,
    X448 = 9,
    Ed25519 = 10,
    Ed448 = 11,
    HssLms = 16,
    Xmss = 17,
    XmssMt = 18,
}

#[derive(Debug, PartialEq)]
pub enum SignAlgoId {
    RsaSsaPkcs1v15WithSha1 = -256,
    EcdsaWithSha1 = -255,
    EcdsaWithSha256 = 0,
    EcdsaWithSha384 = 1,
    EcdsaWithSha512 = 2,
    EcdsaWithShake128 = 3,
    EcdsaWithShake256 = 4,
    Ed25519 = 12,
    Ed448 = 13,
    RsaSsaPkcs1v15WithSha256 = 23,
    RsaSsaPkcs1v15WithSha384 = 24,
    RsaSsaPkcs1v15WithSha512 = 25,
    RsaSsaPssWithSha256 = 26,
    RsaSsaPssWithSha384 = 27,
    RsaSsaPssWithSha512 = 28,
    RsaSsaPssWithShake128 = 29,
    RsaSsaPssWithShake256 = 30,
    HssLms = 42,
    Xmss = 43,
    XmssMt = 44,
}

#[derive(Debug, PartialEq)]
pub struct RsaPub {
    pub n: Vec<u8>,
    pub e: u32,
}

#[derive(Debug, PartialEq)]
pub struct EcPub {
    pub key: Vec<u8>,
    pub curve: Vec<u64>,
}

#[derive(Debug, PartialEq)]
pub enum PubKey {
    Rsa(RsaPub),
    Ec(EcPub),
}

#[derive(Debug, PartialEq)]
pub enum ExtOid {
    SubjectKeyIdentifier = 0,
    KeyUsage = 1,
    SubjectAlternativeName = 2,
    BasicConstraints = 3,
    CrlDistributionPoints = 4,
    CertificatePolicies = 5,
    AuthorityKeyIdentifier = 6,
    ExtendedKeyUsage = 7,
    AuthorityInformationAccess = 8,
    SignedCertificateTimestampList = 9,
    SubjectDirectoryAttributes = 24,
    IssuerAlternativeName = 25,
    NameConstraints = 26,
    PolicyMappings = 27,
    PolicyConstraints = 28,
    FreshestCrl = 29,
    InhibitAnyPolicy = 30,
    SubjectInformationAccess = 31,
}

#[derive(Debug, PartialEq)]
pub struct Extension {
    pub oid: ExtOid,
    pub critical: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct C509 {
    pub cert_type: Option<CertType>,
    pub serial_number: Vec<u8>,
    pub issuer: Vec<Name>,
    pub not_before: u64,
    pub not_after: u64,
    pub subject: Vec<Name>,
    pub pub_key_algo: Option<PubAlgoId>,
    pub pub_key: Option<PubKey>,
    pub extensions: Vec<Extension>,
    pub sign_algo: Option<SignAlgoId>,
    pub sign: Vec<u8>,
}

impl C509 {
    pub fn builder() -> C509Builder {
        C509Builder::default()
    }
}

#[derive(Default)]
pub struct C509Builder {
    cert_type: Option<CertType>,
    serial_number: Vec<u8>,
    issuer: Vec<Name>,
    not_before: u64,
    not_after: u64,
    subject: Vec<Name>,
    pub_key_algo: Option<PubAlgoId>,
    pub_key: Option<PubKey>,
    extensions: Vec<Extension>,
    sign_algo: Option<SignAlgoId>,
    sign: Vec<u8>,
}

impl C509Builder {
    pub fn new() -> C509Builder {
        C509Builder {
            cert_type: None,
            serial_number: Vec::new(),
            issuer: Vec::new(),
            not_before: 0,
            not_after: 0,
            subject: Vec::new(),
            pub_key_algo: None,
            pub_key: None,
            extensions: Vec::new(),
            sign_algo: None,
            sign: Vec::new(),
        }
    }

    pub fn cert_type(mut self, cert_type: CertType) -> C509Builder {
        self.cert_type = Some(cert_type);
        self
    }

    pub fn serial_number(mut self, serial_number: Vec<u8>) -> C509Builder {
        self.serial_number = serial_number;
        self
    }

    pub fn issuer(mut self, oid: NameOid, name: &str) -> C509Builder {
        let issuer = Name {
            oid: oid,
            name: name.to_string(),
        };
        self.issuer.push(issuer);
        self
    }

    pub fn not_before(mut self, not_before: u64) -> C509Builder {
        self.not_before = not_before;
        self
    }

    pub fn not_after(mut self, not_after: u64) -> C509Builder {
        self.not_after = not_after;
        self
    }

    pub fn subject(mut self, oid: NameOid, name: &str) -> C509Builder {
        let subject = Name {
            oid: oid,
            name: name.to_string(),
        };
        self.subject.push(subject);
        self
    }

    pub fn pub_key_algo(mut self, algo: PubAlgoId) -> C509Builder {
        self.pub_key_algo = Some(algo);
        self
    }

    pub fn pub_key_rsa(mut self, n: Vec<u8>, e: u32) -> C509Builder {
        let pub_key = PubKey::Rsa(RsaPub { n: n, e: e });
        self.pub_key = Some(pub_key);
        self
    }

    pub fn pub_key_ec(mut self, key: Vec<u8>, curve: Vec<u64>) -> C509Builder {
        let pub_key = PubKey::Ec(EcPub {
            key: key,
            curve: curve,
        });
        self.pub_key = Some(pub_key);
        self
    }

    pub fn sign_algo(mut self, algo: SignAlgoId) -> C509Builder {
        self.sign_algo = Some(algo);
        self
    }

    pub fn build(self) -> C509 {
        C509 {
            cert_type: self.cert_type,
            serial_number: self.serial_number,
            issuer: self.issuer,
            not_before: self.not_before,
            not_after: self.not_after,
            subject: self.subject,
            pub_key_algo: self.pub_key_algo,
            pub_key: self.pub_key,
            extensions: self.extensions,
            sign_algo: self.sign_algo,
            sign: self.sign,
        }
    }
}
