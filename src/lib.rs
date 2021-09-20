use std::os::raw::c_int;

#[link(name = "mcl", kind = "static")]
#[link(name = "mclshe384_256", kind = "static")]
#[link(name = "gmp")]
#[link(name = "stdc++")]
#[link(name = "crypto")]
#[allow(non_snake_case)]
extern "C" {
    // global functions
    fn sheInit(curve: c_int, compiledTimeVar: c_int) -> c_int;
    fn sheSecretKeySetByCSPRNG(sec: *mut SecretKey) -> c_int;
    fn sheGetPublicKey(pubkey: *mut PublicKey, sec: *const SecretKey);
    fn sheEncG1(c: *mut CipherTextG1, pubkey: *const PublicKey, m: i64) -> c_int;
    fn sheEncG2(c: *mut CipherTextG2, pubkey: *const PublicKey, m: i64) -> c_int;
    fn sheEncGT(c: *mut CipherTextGT, pubkey: *const PublicKey, m: i64) -> c_int;
    fn sheDecG1(m: *mut i64, sec: *const SecretKey, c: *const CipherTextG1) -> c_int;
    fn sheDecG2(m: *mut i64, sec: *const SecretKey, c: *const CipherTextG2) -> c_int;
    fn sheDecGT(m: *mut i64, sec: *const SecretKey, c: *const CipherTextGT) -> c_int;
    fn sheAddG1(c: *mut CipherTextG1, x: *const CipherTextG1, y: *const CipherTextG1) -> c_int;
    fn sheAddG2(c: *mut CipherTextG2, x: *const CipherTextG2, y: *const CipherTextG2) -> c_int;
    fn sheAddGT(c: *mut CipherTextGT, x: *const CipherTextGT, y: *const CipherTextGT) -> c_int;
    fn sheSubG1(c: *mut CipherTextG1, x: *const CipherTextG1, y: *const CipherTextG1) -> c_int;
    fn sheSubG2(c: *mut CipherTextG2, x: *const CipherTextG2, y: *const CipherTextG2) -> c_int;
    fn sheSubGT(c: *mut CipherTextGT, x: *const CipherTextGT, y: *const CipherTextGT) -> c_int;
    fn sheMulG1(c: *mut CipherTextG1, x: *const CipherTextG1, y: i64) -> c_int;
    fn sheMulG2(c: *mut CipherTextG2, x: *const CipherTextG2, y: i64) -> c_int;
    fn sheMulGT(c: *mut CipherTextGT, x: *const CipherTextGT, y: i64) -> c_int;
    fn sheMul(c: *mut CipherTextGT, x: *const CipherTextG1, y: *const CipherTextG2) -> c_int;
}

#[allow(non_camel_case_types)]
pub enum CurveType {
    BN254 = 0,
    BN381 = 1,
    SNARK = 4,
    BLS12_381 = 5,
    SECP192K1 = 100,
    SECP224K1 = 101,
    SECP256K1 = 102,
    NIST_P192 = 105,
    NIST_P224 = 106,
    NIST_P256 = 107,
}
#[derive(Debug, PartialEq, Clone)]
/// `SheError` type for error
pub enum SheError {
    /// can't decrypt
    CantDecrypt,
    /// internal error
    InternalError,
}

const MCLBN_FP_UNIT_SIZE: usize = 6;
const MCLBN_FR_UNIT_SIZE: usize = 4;
const FR_SIZE: usize = MCLBN_FR_UNIT_SIZE;
const G1_SIZE: usize = MCLBN_FP_UNIT_SIZE * 3;
const G2_SIZE: usize = MCLBN_FP_UNIT_SIZE * 6;
const GT_SIZE: usize = MCLBN_FP_UNIT_SIZE * 12;

const SEC_SIZE: usize = FR_SIZE * 2;
const PUB_SIZE: usize = G1_SIZE + G2_SIZE;
const G1_CIPHER_SIZE: usize = G1_SIZE * 2;
const G2_CIPHER_SIZE: usize = G2_SIZE * 2;
const GT_CIPHER_SIZE: usize = GT_SIZE * 4;
const MCLBN_COMPILED_TIME_VAR: c_int = (MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE) as c_int;

macro_rules! common_impl {
    ($t:ty) => {
        impl $t {
            pub fn zero() -> $t {
                Default::default()
            }
            pub unsafe fn uninit() -> $t {
                std::mem::MaybeUninit::uninit().assume_init()
            }
            pub fn clear(&mut self) {
                *self = <$t>::zero()
            }
        }
    };
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct Fp {
    d: [u64; MCLBN_FP_UNIT_SIZE],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct Fr {
    d: [u64; MCLBN_FR_UNIT_SIZE],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct Fp2 {
    d: [Fp; 2],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct G1 {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct G2 {
    pub x: Fp2,
    pub y: Fp2,
    pub z: Fp2,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct GT {
    d: [Fp; 12],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct SecretKey {
    pub x: Fr,
    pub y: Fr,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
pub struct PublicKey {
    pub xP: G1,
    pub yQ: G2,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct CipherTextG1 {
    pub S: G1,
    pub T: G1,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct CipherTextG2 {
    pub S: G2,
    pub T: G2,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct CipherTextGT {
    pub g: [GT; 4],
}

common_impl![SecretKey];
common_impl![PublicKey];
common_impl![CipherTextG1];
common_impl![CipherTextG2];
common_impl![CipherTextGT];

macro_rules! dec_impl {
    ($func_name:ident, $class:ident, $dec_fn:ident) => {
        impl SecretKey {
            pub fn $func_name(&self, c: *const $class) -> Result<i64, SheError> {
                let mut v: i64 = 0;
                if unsafe { $dec_fn(&mut v, self, c) } == 0 {
                    return Ok(v);
                } else {
                    Err(SheError::CantDecrypt)
                }
            }
        }
    };
}

dec_impl![dec_g1, CipherTextG1, sheDecG1];
dec_impl![dec_g2, CipherTextG2, sheDecG2];
dec_impl![dec_gt, CipherTextGT, sheDecGT];

impl SecretKey {
    pub fn set_by_csprng(&mut self) {
        if !unsafe { sheSecretKeySetByCSPRNG(self) == 0 } {
            panic!("sheSecretKeySetByCSPRNG")
        }
    }
    pub fn get_publickey(&self) -> PublicKey {
        let mut v = unsafe { PublicKey::uninit() };
        unsafe {
            sheGetPublicKey(&mut v, self);
        }
        v
    }
}

impl PublicKey {
    pub fn enc_g1(&self, m: i64) -> CipherTextG1 {
        let mut v = unsafe { CipherTextG1::uninit() };
        unsafe {
            sheEncG1(&mut v, self, m);
        }
        v
    }
    pub fn enc_g2(&self, m: i64) -> CipherTextG2 {
        let mut v = unsafe { CipherTextG2::uninit() };
        unsafe {
            sheEncG2(&mut v, self, m);
        }
        v
    }
    pub fn enc_gt(&self, m: i64) -> CipherTextGT {
        let mut v = unsafe { CipherTextGT::uninit() };
        unsafe {
            sheEncGT(&mut v, self, m);
        }
        v
    }
}
/*
serialize_impl![
    Fp,
    mclBn_getFpByteSize(),
    mclBnFp_serialize,
    mclBnFp_deserialize
];
*/

pub fn init(curve: CurveType) -> bool {
    unsafe { sheInit(curve as c_int, MCLBN_COMPILED_TIME_VAR) == 0 }
}

pub fn add_g1(c1: &CipherTextG1, c2: &CipherTextG1) -> CipherTextG1 {
    let mut v = unsafe { CipherTextG1::uninit() };
    unsafe {
        sheAddG1(&mut v, c1, c2);
    }
    v
}
