use she_rust::*;
use std::mem;

#[test]
fn test() {
    assert_eq!(mem::size_of::<Fr>(), 32);
    assert_eq!(mem::size_of::<Fp>(), 48);
    assert_eq!(mem::size_of::<Fp2>(), 48 * 2);
    assert_eq!(mem::size_of::<G1>(), 48 * 3);
    assert_eq!(mem::size_of::<G2>(), 48 * 2 * 3);
    assert_eq!(mem::size_of::<GT>(), 48 * 12);
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

    let ctm = mul(&c11, &c21);
    assert_eq!(sec.dec_gt(&ctm).unwrap(), m11 * m21);
}
