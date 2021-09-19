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
}
