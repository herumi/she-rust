// env RUSTFLAGS="-L <mcl>/lib" cargo run
use she_rust::*;

fn main() {
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
    let ct = add_gt(&mul(&add_g1(&c1, &c2), &add_g2(&c3, &c4)), &mul(&c5, &c6));
    println!(
        "dec(ct)={}, ({} + {}) * ({} + {}) + {} * {} = {}\n",
        sec.dec_gt(&ct).unwrap(),
        m1,
        m2,
        m3,
        m4,
        m5,
        m6,
        (m1 + m2) * (m3 + m4) + (m5 * m6)
    );
}
