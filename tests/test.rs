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
    let m11: i64 = 123;
    let m21: i64 = 234;
    let c11 = pubkey.enc_g1(m11);
    let c21 = pubkey.enc_g1(m21);
    let c31 = add(&c11, &c21);
    assert_eq!(sec.dec(&c11).unwrap(), m11);
    assert_eq!(sec.dec(&c21).unwrap(), m21);
    assert_eq!(sec.dec(&c31).unwrap(), m11 + m21);
}
