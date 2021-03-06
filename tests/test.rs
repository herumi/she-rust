use she_rust::*;

macro_rules! serialize_test {
    ($t:ty, $x:expr) => {
        let buf = $x.serialize();
        let mut y: $t = unsafe { <$t>::uninit() };
        assert!(y.deserialize(&buf));
        assert_eq!($x, y);

        let z = <$t>::from_serialized(&buf);
        assert_eq!($x, z.unwrap());
    };
}

#[test]
fn test() {
    assert!(init(CurveType::BLS12_381));

    let mut sec = unsafe { SecretKey::uninit() };
    sec.set_by_csprng();
    let pubkey = sec.get_publickey();
    let m11: i64 = 4;
    let m12: i64 = 9;
    let m21: i64 = 3;
    let m22: i64 = -2;
    let y: i64 = 5;
    let c11 = pubkey.enc_g1(m11);
    let c12 = pubkey.enc_g1(m12);
    let c1a = add_g1(&c11, &c12);
    let c1s = sub_g1(&c11, &c12);
    let c1y = mul_g1(&c11, y);
    let c1n = neg_g1(&c11);
    assert_eq!(sec.dec_g1(&c11).unwrap(), m11);
    assert_eq!(sec.dec_g1(&c12).unwrap(), m12);
    assert_eq!(sec.dec_g1(&c1a).unwrap(), m11 + m12);
    assert_eq!(sec.dec_g1(&c1s).unwrap(), m11 - m12);
    assert_eq!(sec.dec_g1(&c1y).unwrap(), m11 * y);
    assert_eq!(sec.dec_g1(&c1n).unwrap(), -m11);
    assert!(sec.is_zero_g1(&pubkey.enc_g1(0)));
    assert!(!sec.is_zero_g1(&pubkey.enc_g1(123)));

    let c21 = pubkey.enc_g2(m21);
    let c22 = pubkey.enc_g2(m22);
    let c2a = add_g2(&c21, &c22);
    let c2s = sub_g2(&c21, &c22);
    let c2y = mul_g2(&c21, y);
    let c2n = neg_g2(&c21);
    assert_eq!(sec.dec_g2(&c21).unwrap(), m21);
    assert_eq!(sec.dec_g2(&c22).unwrap(), m22);
    assert_eq!(sec.dec_g2(&c2a).unwrap(), m21 + m22);
    assert_eq!(sec.dec_g2(&c2s).unwrap(), m21 - m22);
    assert_eq!(sec.dec_g2(&c2y).unwrap(), m21 * y);
    assert_eq!(sec.dec_g2(&c2n).unwrap(), -m21);
    assert!(sec.is_zero_g2(&pubkey.enc_g2(0)));
    assert!(!sec.is_zero_g2(&pubkey.enc_g2(123)));

    let ct1 = pubkey.enc_gt(m21);
    let ct2 = pubkey.enc_gt(m22);
    let cta = add_gt(&ct1, &ct2);
    let cts = sub_gt(&ct1, &ct2);
    let cty = mul_gt(&ct1, y);
    let ctn = neg_gt(&ct1);
    assert_eq!(sec.dec_gt(&ct1).unwrap(), m21);
    assert_eq!(sec.dec_gt(&ct2).unwrap(), m22);
    assert_eq!(sec.dec_gt(&cta).unwrap(), m21 + m22);
    assert_eq!(sec.dec_gt(&cts).unwrap(), m21 - m22);
    assert_eq!(sec.dec_gt(&cty).unwrap(), m21 * y);
    assert_eq!(sec.dec_gt(&ctn).unwrap(), -m21);
    assert!(sec.is_zero_gt(&pubkey.enc_gt(0)));
    assert!(!sec.is_zero_gt(&pubkey.enc_gt(123)));

    let ctm = mul(&c11, &c21);
    assert_eq!(sec.dec_gt(&ctm).unwrap(), m11 * m21);

    serialize_test![SecretKey, sec];
    serialize_test![PublicKey, pubkey];
    serialize_test![CipherTextG1, c11];
    serialize_test![CipherTextG2, c21];
    serialize_test![CipherTextGT, ct1];

    let mut ppub = PrecomputedPublicKey::new();
    ppub.init(&pubkey);
    let cp1 = ppub.enc_g1(m11);
    let cp2 = ppub.enc_g2(m11);
    let cpt = ppub.enc_gt(m11);
    assert_eq!(sec.dec_g1(&cp1).unwrap(), m11);
    assert_eq!(sec.dec_g2(&cp2).unwrap(), m11);
    assert_eq!(sec.dec_gt(&cpt).unwrap(), m11);

    // for large value
    let lv = 12345;
    let c = ppub.enc_g1(lv);
    set_try_num(1);
    match sec.dec_g1(&c) {
        Ok(_) => assert!(false),
        Err(err) => assert_eq!(SheError::CantDecrypt, err),
    }
    set_range_for_dlp(20000);
    match sec.dec_g1(&c) {
        Ok(v) => assert_eq!(lv, v),
        Err(_) => assert!(false),
    }
}
