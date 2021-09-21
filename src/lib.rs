use std::ffi::c_void;
use std::mem;
use std::os::raw::c_int;

#[link(name = "mcl", kind = "static")]
#[link(name = "mclshe384_256", kind = "static")]
#[link(name = "stdc++")]
#[allow(non_snake_case)]
extern "C" {
    // global functions
    fn sheInit(curve: c_int, compiledTimeVar: c_int) -> c_int;
    fn sheInitG1only(curve: c_int, compiledTimeVar: c_int) -> c_int;
    fn sheSetTryNum(tryNum: usize);
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
    fn sheNegG1(c: *mut CipherTextG1, x: *const CipherTextG1) -> c_int;
    fn sheNegG2(c: *mut CipherTextG2, x: *const CipherTextG2) -> c_int;
    fn sheNegGT(c: *mut CipherTextGT, x: *const CipherTextGT) -> c_int;
    fn sheSetRangeForDLP(hashSize: usize) -> c_int;
    fn sheSetRangeForG1DLP(hashSize: usize) -> c_int;
    fn sheSetRangeForG2DLP(hashSize: usize) -> c_int;
    fn sheSetRangeForGTDLP(hashSize: usize) -> c_int;
    fn sheIsZeroG1(sec: *const SecretKey, c: *const CipherTextG1) -> c_int;
    fn sheIsZeroG2(sec: *const SecretKey, c: *const CipherTextG2) -> c_int;
    fn sheIsZeroGT(sec: *const SecretKey, c: *const CipherTextGT) -> c_int;
    fn sheSecretKeySerialize(buf: *mut u8, maxBufSize: usize, x: *const SecretKey) -> usize;
    fn shePublicKeySerialize(buf: *mut u8, maxBufSize: usize, x: *const PublicKey) -> usize;
    fn sheCipherTextG1Serialize(buf: *mut u8, maxBufSize: usize, x: *const CipherTextG1) -> usize;
    fn sheCipherTextG2Serialize(buf: *mut u8, maxBufSize: usize, x: *const CipherTextG2) -> usize;
    fn sheCipherTextGTSerialize(buf: *mut u8, maxBufSize: usize, x: *const CipherTextGT) -> usize;
    fn sheSecretKeyDeserialize(x: *mut SecretKey, buf: *const u8, bufSize: usize) -> usize;
    fn shePublicKeyDeserialize(x: *mut PublicKey, buf: *const u8, bufSize: usize) -> usize;
    fn sheCipherTextG1Deserialize(x: *mut CipherTextG1, buf: *const u8, bufSize: usize) -> usize;
    fn sheCipherTextG2Deserialize(x: *mut CipherTextG2, buf: *const u8, bufSize: usize) -> usize;
    fn sheCipherTextGTDeserialize(x: *mut CipherTextGT, buf: *const u8, bufSize: usize) -> usize;
    fn sheSecretKeyIsEqual(x: *const SecretKey, y: *const SecretKey) -> c_int;
    fn shePublicKeyIsEqual(x: *const PublicKey, y: *const PublicKey) -> c_int;
    fn sheCipherTextG1IsEqual(x: *const CipherTextG1, y: *const CipherTextG1) -> c_int;
    fn sheCipherTextG2IsEqual(x: *const CipherTextG2, y: *const CipherTextG2) -> c_int;
    fn sheCipherTextGTIsEqual(x: *const CipherTextGT, y: *const CipherTextGT) -> c_int;
    fn shePrecomputedPublicKeyCreate() -> *mut c_void;
    fn shePrecomputedPublicKeyDestroy(ppub: *mut c_void);
    fn shePrecomputedPublicKeyInit(ppub: *mut c_void, pubkey: *const PublicKey) -> c_int;
    fn shePrecomputedPublicKeyEncG1(c: *mut CipherTextG1, ppub: *const c_void, m: i64) -> c_int;
    fn shePrecomputedPublicKeyEncG2(c: *mut CipherTextG2, ppub: *const c_void, m: i64) -> c_int;
    fn shePrecomputedPublicKeyEncGT(c: *mut CipherTextGT, ppub: *const c_void, m: i64) -> c_int;
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
    /// invalid data
    InvalidData,
    /// internal error
    InternalError,
}

const MCLBN_FP_UNIT_SIZE: usize = 6;
const MCLBN_FR_UNIT_SIZE: usize = 4;
/*
const FR_SIZE: usize = MCLBN_FR_UNIT_SIZE;
const G1_SIZE: usize = MCLBN_FP_UNIT_SIZE * 3;
const G2_SIZE: usize = MCLBN_FP_UNIT_SIZE * 6;
const GT_SIZE: usize = MCLBN_FP_UNIT_SIZE * 12;

const SEC_SIZE: usize = FR_SIZE * 2;
const PUB_SIZE: usize = G1_SIZE + G2_SIZE;
const G1_CIPHER_SIZE: usize = G1_SIZE * 2;
const G2_CIPHER_SIZE: usize = G2_SIZE * 2;
const GT_CIPHER_SIZE: usize = GT_SIZE * 4;
*/
const MCLBN_COMPILED_TIME_VAR: c_int = (MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE) as c_int;

macro_rules! common_impl {
    ($t:ty, $is_equal_fn:ident) => {
        impl PartialEq for $t {
            /// return true if `self` is equal to `rhs`
            fn eq(&self, rhs: &Self) -> bool {
                unsafe { $is_equal_fn(self, rhs) == 1 }
            }
        }
        impl Eq for $t {}
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

macro_rules! serialize_impl {
    ($t:ty, $serialize_fn:ident, $deserialize_fn:ident) => {
        impl $t {
            /// return true if `buf` is deserialized successfully
            /// * `buf` - serialized data by `serialize`
            pub fn deserialize(&mut self, buf: &[u8]) -> bool {
                let n = unsafe { $deserialize_fn(self, buf.as_ptr(), buf.len()) };
                return n > 0 && n == buf.len();
            }
            /// return deserialized `buf`
            pub fn from_serialized(buf: &[u8]) -> Result<$t, SheError> {
                let mut v = unsafe { <$t>::uninit() };
                if v.deserialize(buf) {
                    return Ok(v);
                }
                Err(SheError::InvalidData)
            }
            /// return serialized byte array
            pub fn serialize(&self) -> Vec<u8> {
                let size = mem::size_of::<$t>() + 1;
                let mut buf: Vec<u8> = Vec::with_capacity(size);
                let n: usize;
                unsafe {
                    n = $serialize_fn(buf.as_mut_ptr(), size, self);
                }
                if n == 0 {
                    panic!("she serialization error");
                }
                unsafe {
                    buf.set_len(n);
                }
                buf
            }
            /// alias of serialize
            pub fn as_bytes(&self) -> Vec<u8> {
                self.serialize()
            }
        }
    };
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
struct Fp {
    d: [u64; MCLBN_FP_UNIT_SIZE],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
struct Fr {
    d: [u64; MCLBN_FR_UNIT_SIZE],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
struct Fp2 {
    d: [Fp; 2],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
struct G1 {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
struct G2 {
    pub x: Fp2,
    pub y: Fp2,
    pub z: Fp2,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
struct GT {
    d: [Fp; 12],
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct SecretKey {
    x: Fr,
    y: Fr,
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
pub struct PublicKey {
    xP: G1,
    yQ: G2,
}

impl PublicKey {
    pub fn encrypt<C: CipherText>(&self, m: i64) -> C {
        let mut v = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        unsafe {
            C::enc(&mut v, self, m);
        }
        v
    }
}

pub trait CipherText: Sized {
    unsafe fn enc(c: *mut Self, pubkey: *const PublicKey, m: i64) -> c_int;
    unsafe fn penc(c: *mut Self, ppub: *const c_void, m: i64) -> c_int;
    unsafe fn dec(m: *mut i64, sec: *const SecretKey, c: *const Self) -> c_int;
    unsafe fn add(c: *mut Self, x: *const Self, y: *const Self) -> c_int;
    unsafe fn sub(c: *mut Self, x: *const Self, y: *const Self) -> c_int;
    unsafe fn mul(c: *mut Self, x: *const Self, y: i64) -> c_int;
    unsafe fn neg(c: *mut Self, x: *const Self) -> c_int;
    unsafe fn is_zero(sec: *const SecretKey, c: *const Self) -> c_int;
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct CipherTextG1 {
    S: G1,
    T: G1,
}

impl CipherText for CipherTextG1 {
    unsafe fn enc(c: *mut Self, pubkey: *const PublicKey, m: i64) -> c_int {
        sheEncG1(c, pubkey, m)
    }
    unsafe fn penc(c: *mut Self, ppub: *const c_void, m: i64) -> c_int {
        shePrecomputedPublicKeyEncG1(c, ppub, m)
    }
    unsafe fn dec(m: *mut i64, sec: *const SecretKey, c: *const Self) -> c_int {
        sheDecG1(m, sec, c)
    }
    unsafe fn add(c: *mut Self, x: *const Self, y: *const Self) -> c_int {
        sheAddG1(c, x, y)
    }
    unsafe fn sub(c: *mut Self, x: *const Self, y: *const Self) -> c_int {
        sheSubG1(c, x, y)
    }
    unsafe fn mul(c: *mut Self, x: *const Self, y: i64) -> c_int {
        sheMulG1(c, x, y)
    }
    unsafe fn neg(c: *mut Self, x: *const Self) -> c_int {
        sheNegG1(c, x)
    }
    unsafe fn is_zero(sec: *const SecretKey, c: *const Self) -> c_int {
        sheIsZeroG1(sec, c)
    }
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct CipherTextG2 {
    S: G2,
    T: G2,
}

impl CipherText for CipherTextG2 {
    unsafe fn enc(c: *mut Self, pubkey: *const PublicKey, m: i64) -> c_int {
        sheEncG2(c, pubkey, m)
    }
    unsafe fn penc(c: *mut Self, ppub: *const c_void, m: i64) -> c_int {
        shePrecomputedPublicKeyEncG2(c, ppub, m)
    }
    unsafe fn dec(m: *mut i64, sec: *const SecretKey, c: *const Self) -> c_int {
        sheDecG2(m, sec, c)
    }
    unsafe fn add(c: *mut Self, x: *const Self, y: *const Self) -> c_int {
        sheAddG2(c, x, y)
    }
    unsafe fn sub(c: *mut Self, x: *const Self, y: *const Self) -> c_int {
        sheSubG2(c, x, y)
    }
    unsafe fn mul(c: *mut Self, x: *const Self, y: i64) -> c_int {
        sheMulG2(c, x, y)
    }
    unsafe fn neg(c: *mut Self, x: *const Self) -> c_int {
        sheNegG2(c, x)
    }
    unsafe fn is_zero(sec: *const SecretKey, c: *const Self) -> c_int {
        sheIsZeroG2(sec, c)
    }
}

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct CipherTextGT {
    g: [GT; 4],
}

impl CipherText for CipherTextGT {
    unsafe fn enc(c: *mut Self, pubkey: *const PublicKey, m: i64) -> c_int {
        sheEncGT(c, pubkey, m)
    }
    unsafe fn penc(c: *mut Self, ppub: *const c_void, m: i64) -> c_int {
        shePrecomputedPublicKeyEncGT(c, ppub, m)
    }
    unsafe fn dec(m: *mut i64, sec: *const SecretKey, c: *const Self) -> c_int {
        sheDecGT(m, sec, c)
    }
    unsafe fn add(c: *mut Self, x: *const Self, y: *const Self) -> c_int {
        sheAddGT(c, x, y)
    }
    unsafe fn sub(c: *mut Self, x: *const Self, y: *const Self) -> c_int {
        sheSubGT(c, x, y)
    }
    unsafe fn mul(c: *mut Self, x: *const Self, y: i64) -> c_int {
        sheMulGT(c, x, y)
    }
    unsafe fn neg(c: *mut Self, x: *const Self) -> c_int {
        sheNegGT(c, x)
    }
    unsafe fn is_zero(sec: *const SecretKey, c: *const Self) -> c_int {
        sheIsZeroGT(sec, c)
    }
}

#[derive(Debug)] // Don't Clone
#[repr(C)]
pub struct PrecomputedPublicKey {
    p: *mut c_void,
}

impl PrecomputedPublicKey {
    pub fn new() -> PrecomputedPublicKey {
        PrecomputedPublicKey {
            p: unsafe { shePrecomputedPublicKeyCreate() },
        }
    }
    pub fn init(&mut self, pubkey: *const PublicKey) {
        unsafe {
            shePrecomputedPublicKeyInit(self.p, pubkey);
        }
    }
    pub fn encrypt<C: CipherText>(&self, m: i64) -> C {
        let mut v = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        unsafe {
            C::penc(&mut v, self.p, m);
        }
        v
    }
}

impl Drop for PrecomputedPublicKey {
    fn drop(&mut self) {
        unsafe { shePrecomputedPublicKeyDestroy(self.p) }
    }
}

common_impl![SecretKey, sheSecretKeyIsEqual];
common_impl![PublicKey, shePublicKeyIsEqual];
common_impl![CipherTextG1, sheCipherTextG1IsEqual];
common_impl![CipherTextG2, sheCipherTextG2IsEqual];
common_impl![CipherTextGT, sheCipherTextGTIsEqual];

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
    pub fn decrpyt<C: CipherText>(&self, c: *const C) -> Result<i64, SheError> {
        let mut v: i64 = 0;
        if unsafe { C::dec(&mut v, self, c) } == 0 {
            return Ok(v);
        } else {
            Err(SheError::CantDecrypt)
        }
    }
    pub fn is_zero<C: CipherText>(&self, c: *const C) -> bool {
        unsafe { C::is_zero(self, c) == 1 }
    }
}

impl PublicKey {}

pub fn mul<C: CipherText>(c: C, x: i64) -> C {
    let mut v = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    unsafe {
        C::mul(&mut v, c, x);
    }
    v
}

pub fn mul_g1_g2(c1: &CipherTextG1, c2: &CipherTextG2) -> CipherTextGT {
    let mut v = unsafe { CipherTextGT::uninit() };
    unsafe {
        sheMul(&mut v, c1, c2);
    }
    v
}

/*
serialize_impl![
    Fp,
    mclBn_getFpByteSize(),
    mclBnFp_serialize,
    mclBnFp_deserialize
];
*/

// for 2 level homomorphic encryption (curve = BN254 or BLS12_381)
pub fn init(curve: CurveType) -> bool {
    unsafe { sheInit(curve as c_int, MCLBN_COMPILED_TIME_VAR) == 0 }
}

// for only lifted-ElGamal encryption (curve = SECP256K1)
pub fn init_g1_only(curve: CurveType) -> bool {
    unsafe { sheInitG1only(curve as c_int, MCLBN_COMPILED_TIME_VAR) == 0 }
}

/*
    dec() can decrypt Enc(x) such that |x| <= hash_size * try_num
    The table size of DLP is hash_size * 4 bytes
    decryption time is alpha + beta * int(x/hash_size)
    where alpha and beta are constant
*/
pub fn set_try_num(try_num: usize) {
    unsafe { sheSetTryNum(try_num) }
}

// make hash_size entry table for all DLP
pub fn set_range_for_dlp(hash_size: usize) -> bool {
    unsafe { sheSetRangeForDLP(hash_size) == 0 }
}

// make hash_size entry table for G1 DLP
pub fn set_range_for_g1_dlp(hash_size: usize) -> bool {
    unsafe { sheSetRangeForG1DLP(hash_size) == 0 }
}

// make hash_size entry table for G2 DLP
pub fn set_range_for_g2_dlp(hash_size: usize) -> bool {
    unsafe { sheSetRangeForG2DLP(hash_size) == 0 }
}

// make hash_size entry table for GT DLP
pub fn set_range_for_gt_dlp(hash_size: usize) -> bool {
    unsafe { sheSetRangeForGTDLP(hash_size) == 0 }
}

pub fn add<C: CipherText>(c1: C, c2: C) -> C {
    let mut v = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    unsafe {
        C::add(&mut v, c1, c2);
    }
    v
}

pub fn sub<C: CipherText>(c1: C, c2: C) -> C {
    let mut v = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    unsafe {
        C::sub(&mut v, c1, c2);
    }
    v
}

pub fn neg<C: CipherText>(c: C) -> C {
    let mut v = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    unsafe {
        C::neg(&mut v, c);
    }
    v
}

serialize_impl![SecretKey, sheSecretKeySerialize, sheSecretKeyDeserialize];
serialize_impl![PublicKey, shePublicKeySerialize, shePublicKeyDeserialize];
serialize_impl![
    CipherTextG1,
    sheCipherTextG1Serialize,
    sheCipherTextG1Deserialize
];
serialize_impl![
    CipherTextG2,
    sheCipherTextG2Serialize,
    sheCipherTextG2Deserialize
];
serialize_impl![
    CipherTextGT,
    sheCipherTextGTSerialize,
    sheCipherTextGTDeserialize
];
