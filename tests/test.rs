use she_rust::*;
use std::mem;

#[test]
#[allow(non_snake_case)]
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
    let c1y = mul_g1(&c11, y);
    assert_eq!(sec.dec_g1(&c11).unwrap(), m11);
    assert_eq!(sec.dec_g1(&c12).unwrap(), m12);
    assert_eq!(sec.dec_g1(&c1a).unwrap(), m11 + m12);
    assert_eq!(sec.dec_g1(&c1y).unwrap(), m11 * y);

    let c21 = pubkey.enc_g2(m21);
    let c22 = pubkey.enc_g2(m22);
    let c2a = add_g2(&c21, &c22);
    let c2y = mul_g2(&c21, y);
    assert_eq!(sec.dec_g2(&c21).unwrap(), m21);
    assert_eq!(sec.dec_g2(&c22).unwrap(), m22);
    assert_eq!(sec.dec_g2(&c2a).unwrap(), m21 + m22);
    assert_eq!(sec.dec_g2(&c2y).unwrap(), m21 * y);
}
