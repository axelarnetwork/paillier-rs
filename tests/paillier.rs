use k256::elliptic_curve::sec1::ToEncodedPoint;
use libpaillier::*;
use unknown_order::BigNumber;

/// Taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
/// prefix'd with '9' for multibase to work
const TEST_PRIMES: [&str; 4] = [
    "9153739637779647327330155094463476939112913405723627932550795546376536722298275674187199768137486929460478138431076223176750734095693166283451594721829574797878338183845296809008576378039501400850628591798770214582527154641716248943964626446190042367043984306973709604255015629102866732543697075866901827761489",
    "966295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859",
    "937313426856874901938110133384605074194791927500210707276948918975046371522830901596065044944558427864187196889881993164303255749681644627614963632713725183364319410825898054225147061624559894980555489070322738683900143562848200257354774040241218537613789091499134051387344396560066242901217378861764936185029",
    "989884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164815053566739"
];

/// prefix with 9 any input
fn b10(s: &str) -> BigNumber {
    let (_, bytes) = multibase::decode(s).unwrap();
    BigNumber::from_slice(bytes.as_slice())
}

#[test]
fn encrypt() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m = b"this is a test message";
    let res = pk.encrypt(m, None);
    assert!(res.is_some());

    let (c, _) = res.unwrap();
    let res = sk.decrypt(&c);
    assert!(res.is_some());
    let m1 = res.unwrap();
    assert_eq!(m1, m);

    // bad messages
    let nn1: BigNumber = pk.nn() + 1;
    let nn = pk.nn().to_bytes();
    let nn1_bytes = nn1.to_bytes();
    let bad_messages: [&[u8]; 3] = [b"", nn.as_slice(), nn1_bytes.as_slice()];

    for b in &bad_messages {
        let res = pk.encrypt(&b, None);
        assert!(res.is_none());
    }
}

#[test]
fn add() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m1 = BigNumber::from(7);
    let m2 = BigNumber::from(6);

    let res1 = pk.encrypt(&m1.to_bytes(), None);
    let res2 = pk.encrypt(&m2.to_bytes(), None);
    assert!(res1.is_some());
    assert!(res2.is_some());

    let (c1, _) = res1.unwrap();
    let (c2, _) = res2.unwrap();
    let res = pk.add(&c1, &c2);
    assert!(res.is_some());
    let c3 = res.unwrap();
    let res = sk.decrypt(&c3);
    assert!(res.is_some());
    let bytes = res.unwrap();
    let m3 = BigNumber::from_slice(bytes);
    assert_eq!(m3, BigNumber::from(13));
}

#[test]
fn mul() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[0]), &b10(TEST_PRIMES[1]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m1 = BigNumber::from(7);
    let m2 = BigNumber::from(6);

    let res1 = pk.encrypt(&m1.to_bytes(), None);
    assert!(res1.is_some());

    let (c1, _) = res1.unwrap();
    let res = pk.mul(&c1, &m2);
    assert!(res.is_some());
    let c2 = res.unwrap();
    let res = sk.decrypt(&c2);
    assert!(res.is_some());
    let bytes = res.unwrap();
    let m3 = BigNumber::from_slice(bytes.as_slice());
    assert_eq!(m3, BigNumber::from(42));
}

#[test]
fn serialization() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let res = bincode::serialize(&pk);
    assert!(res.is_ok());
    let res = res.unwrap();

    let expected_bytes = vec![
        0, 1, 0, 0, 0, 0, 0, 0, 26, 145, 107, 48, 56, 94, 77, 52, 43, 188, 182, 227, 197, 109, 112,
        195, 124, 181, 92, 110, 245, 8, 66, 0, 96, 129, 231, 227, 157, 240, 103, 12, 240, 222, 0,
        112, 118, 17, 131, 155, 184, 67, 85, 180, 61, 220, 135, 20, 118, 251, 242, 81, 101, 30, 57,
        29, 40, 17, 234, 219, 20, 139, 127, 74, 175, 121, 187, 119, 10, 82, 98, 41, 11, 169, 216,
        190, 65, 182, 155, 3, 202, 80, 86, 183, 2, 235, 2, 210, 158, 200, 150, 235, 18, 116, 102,
        17, 129, 181, 110, 75, 39, 151, 154, 138, 71, 35, 140, 146, 95, 145, 101, 55, 102, 251, 40,
        109, 131, 61, 177, 253, 185, 56, 22, 216, 38, 214, 10, 101, 59, 208, 210, 175, 161, 150,
        201, 82, 101, 99, 81, 8, 189, 50, 239, 99, 197, 35, 16, 185, 59, 182, 130, 73, 141, 23,
        209, 110, 37, 127, 25, 80, 63, 233, 215, 24, 65, 138, 215, 161, 131, 76, 100, 241, 37, 148,
        72, 24, 103, 74, 175, 44, 44, 11, 187, 18, 209, 61, 69, 188, 199, 13, 141, 182, 151, 135,
        159, 186, 130, 15, 190, 221, 233, 134, 128, 122, 208, 241, 86, 34, 209, 217, 255, 126, 222,
        126, 41, 183, 84, 124, 61, 185, 162, 179, 202, 109, 62, 8, 106, 29, 37, 139, 11, 63, 139,
        110, 80, 8, 227, 216, 168, 94, 116, 66, 153, 36, 15, 210, 6, 72, 17, 174, 181, 225, 219,
        43, 41, 159,
    ];

    assert_eq!(res, expected_bytes);

    let res = bincode::deserialize::<EncryptionKey>(&res[..]);
    assert!(res.is_ok());

    let pk1 = res.unwrap();
    assert_eq!(pk1.n(), pk.n());

    let res = bincode::serialize(&sk);
    assert!(res.is_ok());
    let sk_str = res.unwrap();

    let res = bincode::deserialize::<DecryptionKey>(&sk_str);
    assert!(res.is_ok());
    let sk1 = res.unwrap();
    assert_eq!(sk, sk1);
    assert_eq!(sk.u(), sk1.u());
    assert_eq!(sk.totient(), sk1.totient());
    assert_eq!(sk.lambda(), sk1.lambda());
    assert_eq!(sk.n(), sk1.n());
}

#[test]
fn bytes() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 256);
    let pk1 = EncryptionKey::from_bytes(bytes.as_slice()).unwrap();
    assert_eq!(pk1.n(), pk.n());

    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 1550);
    let res = DecryptionKey::from_bytes(bytes.as_slice());
    assert!(res.is_ok());
    let sk1 = res.unwrap();
    assert_eq!(sk.u(), sk1.u());
    assert_eq!(sk.totient(), sk1.totient());
    assert_eq!(sk.lambda(), sk1.lambda());
    assert_eq!(sk.n(), sk1.n());
}

#[test]
fn proof() {
    let res = DecryptionKey::with_safe_primes_unchecked(&b10(TEST_PRIMES[2]), &b10(TEST_PRIMES[3]));
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let ssk = k256::SecretKey::random(rand::thread_rng());
    let spk = ssk.public_key();
    let mut nonce = Vec::new();
    nonce.extend_from_slice(
        k256::AffinePoint::generator()
            .to_encoded_point(true)
            .as_bytes(),
    );
    nonce.extend_from_slice(
        &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").unwrap(),
    );
    nonce.extend_from_slice(spk.as_affine().to_encoded_point(true).as_bytes());
    nonce.push(1u8);

    let res = ProofSquareFree::generate::<sha2::Sha256>(&sk, nonce.as_slice());
    assert!(res.is_some());
    let proof = res.unwrap();

    assert!(proof.verify::<sha2::Sha256>(&pk, nonce.as_slice()));

    let mut bytes = proof.to_bytes();
    let res = ProofSquareFree::from_bytes(bytes.as_slice());
    assert!(res.is_ok());
    let proof1 = res.unwrap();
    assert_eq!(proof1.to_bytes(), proof.to_bytes());

    bytes[0] = bytes[1];
    let res = ProofSquareFree::from_bytes(bytes.as_slice());
    assert!(res.is_err());
}

#[test]
fn all() {
    let res = DecryptionKey::random();
    assert!(res.is_some());
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m = b"this is a test message";
    let res = pk.encrypt(m, None);
    assert!(res.is_some());

    let (c, _) = res.unwrap();
    let res = sk.decrypt(&c);
    assert!(res.is_some());
    let m1 = res.unwrap();
    assert_eq!(m1, m);

    // bad messages
    let nn1: BigNumber = pk.nn() + 1;
    let nn = pk.nn().to_bytes();
    let nn1_bytes = nn1.to_bytes();
    let bad_messages: [&[u8]; 3] = [b"", nn.as_slice(), nn1_bytes.as_slice()];

    for b in &bad_messages {
        let res = pk.encrypt(&b, None);
        assert!(res.is_none());
    }
}
