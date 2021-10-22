// env RUSTFLAGS="-L <mcl>/lib" cargo run
use she_rust::*;
use std::path::Path;

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

    const L: i32 = 17;
    println!("making table...");
    set_range_for_g1_dlp(1 << L);
    let name = Path::new("./g1_dlp.bin");
    if !save_table_for_g1_dlp(name) {
        println!("save err");
        return;
    }
    set_range_for_g1_dlp(100);
    println!("table size={}", get_table_size_for_g1_dlp());
    if !load_table_for_g1_dlp(name) {
        println!("load err");
        return;
    }
    println!("table size={}", get_table_size_for_g1_dlp());
    println!("complete");
    set_try_num(1 << (31 - L));
    let c = ppub.enc_g1(i32::MAX as i64);
    match sec.dec_g1(&c) {
        Ok(m) => println!("m={}\n", m),
        Err(err) => println!("err={:?}\n", err),
    }
}

fn main() {
    large_enc();
}
