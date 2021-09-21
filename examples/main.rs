// env RUSTFLAGS="-L <mcl>/lib" cargo run
use she_rust::*;

fn two_level_he() {
    println!("two_level_he");
    if !init(CurveType::BN254) {
        println!("init err");
        return;
    }
    let mut sec = unsafe { SecretKey::uninit() };
    sec.set_by_csprng();
    let pubkey = sec.get_publickey();

    let mut ppub = PrecomputedPublicKey::new();
    ppub.init(&pubkey);

    let m1 = 3;
    let m2 = 5;
    let m3 = 7;
    let m4 = -4;
    let m5 = 6;
    let m6 = 7;

    let c1 = ppub.enc_g1(m1);
    let c2 = ppub.enc_g1(m2);
    let c3 = ppub.enc_g2(m3);
    let c4 = ppub.enc_g2(m4);
    let c5 = ppub.enc_g1(m5);
    let c6 = ppub.enc_g2(m6);
    let c = add_gt(&mul(&add_g1(&c1, &c2), &add_g2(&c3, &c4)), &mul(&c5, &c6));
    println!(
        "dec(c)={}, ({} + {}) * ({} + {}) + {} * {} = {}\n",
        sec.dec_gt(&c).unwrap(),
        m1,
        m2,
        m3,
        m4,
        m5,
        m6,
        (m1 + m2) * (m3 + m4) + (m5 * m6)
    );
}

fn lifted_elgamal() {
    if !init_g1_only(CurveType::SECP256K1) {
        println!("init err");
        return;
    }
    println!("lifted_elgamal");
    let mut sec = unsafe { SecretKey::uninit() };
    sec.set_by_csprng();
    let pubkey = sec.get_publickey();

    let mut ppub = PrecomputedPublicKey::new();
    ppub.init(&pubkey);

    let m1 = 3;
    let m2 = 5;
    let m3 = 7;
    let m4 = -4;

    let c1 = ppub.enc_g1(m1);
    let c2 = ppub.enc_g1(m2);
    let c = add_g1(&mul_g1(&c1, m3), &mul_g1(&c2, m4));
    println!(
        "dec(c)={}, ({} * {}) + ({} * {}) = {}\n",
        sec.dec_g1(&c).unwrap(),
        m1,
        m3,
        m2,
        m4,
        (m1 * m3) + (m2 * m4)
    );
}

fn main() {
    two_level_he();
    lifted_elgamal();
}
