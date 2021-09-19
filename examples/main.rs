// env RUSTFLAGS="-L <mcl>/lib" cargo run
use she_rust::*;

#[allow(non_snake_case)]
fn main() {
    let b = init(CurveType::BN254);
    if !b {
        println!("init err");
    }
}
