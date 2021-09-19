# she for Rust

This is a wrapper library of [mcl/she](https://github.com/herumi/mcl/blob/master/include/mcl/she.h),
- which can add two ciphertexts many times, and
- can multiply two ciphertexts once.

For two vectors x = (x1, ..., xn) and y = (y1, ..., yn),
EncG1(x1) * EncG2(y1) + ... + EncG1(xn) * EncG2(yn) = EncGT(x1 * y1 + ... + xn * yn).

see [she-api](https://github.com/herumi/mcl/blob/master/misc/she/she-api.md)

# Test

```
git clone https://github.com/herumi/mcl
cd mcl
make lib/libmcl.a lib/libmclshe384_256.a
git clone https://github.com/herumi/she-rust
cd she-rust
env RUSTFLAGS="-L../mcl/lib" cargo test
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)

# Sponsors welcome
[GitHub Sponsor](https://github.com/sponsors/herumi)
