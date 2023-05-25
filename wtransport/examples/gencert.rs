use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use rcgen::CertificateParams;
use rcgen::DistinguishedName;
use rcgen::DnType;
use rcgen::KeyPair;
use rcgen::PKCS_ECDSA_P256_SHA256;
use ring::digest::digest;
use ring::digest::SHA256;
use std::fs;
use std::io::Write;
use time::Duration;
use time::OffsetDateTime;

fn main() {
    const COMMON_NAME: &str = "localhost";

    let mut dname = DistinguishedName::new();
    dname.push(DnType::CommonName, COMMON_NAME);

    let keypair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap();

    let digest = digest(&SHA256, &keypair.public_key_der());

    let mut cert_params = CertificateParams::new(vec![COMMON_NAME.to_string()]);
    cert_params.distinguished_name = dname;
    cert_params.alg = &PKCS_ECDSA_P256_SHA256;
    cert_params.key_pair = Some(keypair);
    cert_params.not_before = OffsetDateTime::now_utc()
        .checked_sub(Duration::days(2))
        .unwrap();
    cert_params.not_after = OffsetDateTime::now_utc()
        .checked_add(Duration::days(2))
        .unwrap();

    let certificate = rcgen::Certificate::from_params(cert_params).unwrap();

    fs::File::create("cert.pem")
        .unwrap()
        .write_all(certificate.serialize_pem().unwrap().as_bytes())
        .unwrap();

    fs::File::create("key.pem")
        .unwrap()
        .write_all(certificate.serialize_private_key_pem().as_bytes())
        .unwrap();

    println!("Certificate generated");
    println!("Fingerprint: {}", Base64Engine.encode(digest));
}
