// env RUSTFLAGS="-L <mcl>/lib" cargo run
use she_rust::*;

fn large_enc() {
    if !init_g1_only(CurveType::SECP256K1) {
        println!("init err");
        return;
    }
    println!("large_enc");
    let mut sec = unsafe { SecretKey::uninit() };
    sec.set_by_csprng();
    let pubkey = sec.get_publickey();

    let mut ppub = PrecomputedPublicKey::new();
    ppub.init(&pubkey);

    println!("making table...");
    set_range_for_g1_dlp(1 << 20);
    println!("complete");
    set_try_num(1 << 11);
    let c = ppub.enc_g1(i32::MAX as i64);
    match sec.dec_g1(&c) {
        Ok(m) => println!("m={}\n", m),
        Err(err) => println!("err={:?}\n", err),
    }
}

fn main() {
    large_enc();
}
