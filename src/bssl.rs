//! BoringSSL SLH-DSA-SHA2-128s (FIPS 205 pure, empty context): a hardware-SHA-256
//! implementation measured on the same corpus as liboqs's parameter set.

use std::ffi::{CStr, c_char, c_int};

/// Suffix that selects BoringSSL for a liboqs parameter-set name.
pub(crate) const SUFFIX: &str = "@boringssl";
/// Only parameter set where BoringSSL adds a faster implementation; its SHAKE
/// variant uses portable Keccak and is slower than liboqs.
pub(crate) const PARAMETER_SET: &str = "SLH_DSA_PURE_SHA2_128S";
pub(crate) const PUBLIC_KEY_LEN: usize = 32;
pub(crate) const SECRET_KEY_LEN: usize = 64;
pub(crate) const SIGNATURE_LEN: usize = 7856;

unsafe extern "C" {
    fn SLHDSA_SHA2_128S_generate_key(public_key: *mut u8, private_key: *mut u8);
    fn SLHDSA_SHA2_128S_sign(
        signature: *mut u8,
        private_key: *const u8,
        msg: *const u8,
        msg_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> c_int;
    fn SLHDSA_SHA2_128S_verify(
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
        msg: *const u8,
        msg_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> c_int;
    fn pq_bssl_sha256_backend() -> *const c_char;
}

pub(crate) fn sha256_backend() -> String {
    // SAFETY: returns a pointer to a static NUL-terminated string literal.
    unsafe { CStr::from_ptr(pq_bssl_sha256_backend()) }.to_string_lossy().into_owned()
}

pub(crate) fn keypair(public_key: &mut [u8], private_key: &mut [u8]) {
    assert_eq!((public_key.len(), private_key.len()), (PUBLIC_KEY_LEN, SECRET_KEY_LEN));
    // SAFETY: both buffers have exactly the fixed lengths the API writes.
    unsafe { SLHDSA_SHA2_128S_generate_key(public_key.as_mut_ptr(), private_key.as_mut_ptr()) };
}

pub(crate) fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> bool {
    assert_eq!((private_key.len(), signature.len()), (SECRET_KEY_LEN, SIGNATURE_LEN));
    // SAFETY: fixed-size key and output buffers; the message has an explicit length;
    // a null context with length 0 is the documented empty context.
    unsafe {
        SLHDSA_SHA2_128S_sign(
            signature.as_mut_ptr(),
            private_key.as_ptr(),
            message.as_ptr(),
            message.len(),
            std::ptr::null(),
            0,
        ) == 1
    }
}

pub(crate) fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    assert_eq!(public_key.len(), PUBLIC_KEY_LEN);
    // SAFETY: the public key has the fixed length; message and signature carry
    // explicit lengths; a null context with length 0 is the empty context.
    unsafe {
        SLHDSA_SHA2_128S_verify(
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len(),
            std::ptr::null(),
            0,
        ) == 1
    }
}
