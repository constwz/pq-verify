use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    ptr::NonNull,
};

use crate::{Result, bssl};

pub(crate) struct Verifier {
    provider: Provider,
    pub(crate) name: String,
    /// Parameter set whose corpus this verifier reads; shared across providers.
    pub(crate) corpus_name: String,
    pub(crate) public_key_len: usize,
    secret_key_len: usize,
    pub(crate) signature_max: usize,
    pub(crate) category: u32,
    pub(crate) version: String,
    pub(crate) backend: String,
    pub(crate) hash_backend: String,
}

#[derive(Clone, Copy)]
enum Provider {
    Oqs(NonNull<c_void>),
    BoringSsl,
}

pub(crate) struct SecretKey(Vec<u8>);

unsafe extern "C" {
    fn OQS_init();
    fn OQS_version() -> *const c_char;
    fn OQS_SIG_new(name: *const c_char) -> *mut c_void;
    fn OQS_SIG_free(sig: *mut c_void);
    fn OQS_SIG_keypair(sig: *const c_void, pk: *mut u8, sk: *mut u8) -> c_int;
    fn OQS_SIG_sign(
        sig: *const c_void,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        sk: *const u8,
    ) -> c_int;
    fn OQS_SIG_verify(
        sig: *const c_void,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        pk: *const u8,
    ) -> c_int;
    fn OQS_MEM_cleanse(ptr: *mut c_void, len: usize);
    fn OQS_randombytes(ptr: *mut u8, len: usize);
    fn pq_public_key_len(sig: *const c_void) -> usize;
    fn pq_secret_key_len(sig: *const c_void) -> usize;
    fn pq_signature_len(sig: *const c_void) -> usize;
    fn pq_category(sig: *const c_void) -> c_uint;
    fn pq_algorithm_version(sig: *const c_void) -> *const c_char;
    fn pq_backend(sig: *const c_void) -> *const c_char;
    fn pq_dist_build() -> c_int;
    fn pq_sha3_backend() -> *const c_char;
}

/// Whether liboqs was built with runtime CPU dispatch (`OQS_DIST_BUILD`).
pub(crate) fn dist_build() -> bool {
    // SAFETY: reads a compile-time constant; no arguments or state.
    unsafe { pq_dist_build() != 0 }
}

/// Backends that a dispatching build selects only when CPU feature detection
/// fails or the CPU lacks the required extensions. slhdsa-c is excluded: this
/// liboqs pin has no other SLH-DSA backend.
pub(crate) fn is_fallback(backend: &str, hash_backend: &str) -> bool {
    matches!(backend, "mldsa-native/C" | "PQClean/clean") || hash_backend == "boringssl-sha256/nohw"
}

pub(crate) fn init() -> String {
    // SAFETY: called once on the main thread before constructing any verifier.
    unsafe {
        OQS_init();
        CStr::from_ptr(OQS_version()).to_string_lossy().into_owned()
    }
}

pub(crate) fn random_message(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    // SAFETY: the buffer is writable for exactly len bytes. Uses liboqs' OS RNG.
    unsafe { OQS_randombytes(bytes.as_mut_ptr(), bytes.len()) };
    bytes
}

impl Verifier {
    pub(crate) fn new(name: &str) -> Result<Self> {
        if let Some(parameter_set) = name.strip_suffix(bssl::SUFFIX) {
            if parameter_set != bssl::PARAMETER_SET {
                return Err(format!("algorithm unavailable: {name}").into());
            }
            return Ok(Self {
                provider: Provider::BoringSsl,
                name: name.to_owned(),
                corpus_name: parameter_set.to_owned(),
                public_key_len: bssl::PUBLIC_KEY_LEN,
                secret_key_len: bssl::SECRET_KEY_LEN,
                signature_max: bssl::SIGNATURE_LEN,
                category: 1,
                version: concat!("boringssl ", env!("PQ_BSSL_REVISION")).to_owned(),
                backend: "boringssl/slhdsa".to_owned(),
                hash_backend: bssl::sha256_backend(),
            });
        }
        let c_name = CString::new(name)?;
        // SAFETY: name is NUL-terminated; null signals an unavailable algorithm.
        let handle = NonNull::new(unsafe { OQS_SIG_new(c_name.as_ptr()) })
            .ok_or_else(|| format!("algorithm unavailable: {name}"))?;
        // SAFETY: all accessors receive the live OQS_SIG allocated above.
        unsafe {
            Ok(Self {
                provider: Provider::Oqs(handle),
                name: name.to_owned(),
                corpus_name: name.to_owned(),
                public_key_len: pq_public_key_len(handle.as_ptr()),
                secret_key_len: pq_secret_key_len(handle.as_ptr()),
                signature_max: pq_signature_len(handle.as_ptr()),
                category: pq_category(handle.as_ptr()),
                version: CStr::from_ptr(pq_algorithm_version(handle.as_ptr()))
                    .to_string_lossy()
                    .into_owned(),
                backend: CStr::from_ptr(pq_backend(handle.as_ptr())).to_string_lossy().into_owned(),
                hash_backend: if name.starts_with("SLH_DSA") {
                    "slhdsa-c/internal".to_owned()
                } else {
                    CStr::from_ptr(pq_sha3_backend()).to_string_lossy().into_owned()
                },
            })
        }
    }

    pub(crate) fn keypair(&self) -> Result<(Vec<u8>, SecretKey)> {
        let mut pk = vec![0; self.public_key_len];
        let mut sk = SecretKey(vec![0; self.secret_key_len]);
        match self.provider {
            Provider::Oqs(handle) => {
                // SAFETY: both output buffers have the lengths advertised by this OQS_SIG.
                let status =
                    unsafe { OQS_SIG_keypair(handle.as_ptr(), pk.as_mut_ptr(), sk.0.as_mut_ptr()) };
                if status != 0 {
                    return Err(format!("{} key generation failed: {status}", self.name).into());
                }
            }
            Provider::BoringSsl => bssl::keypair(&mut pk, &mut sk.0),
        }
        Ok((pk, sk))
    }

    pub(crate) fn sign(&self, sk: &SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        if sk.0.len() != self.secret_key_len {
            return Err("wrong secret key length".into());
        }
        let mut signature = vec![0; self.signature_max];
        let len = match self.provider {
            Provider::Oqs(handle) => {
                let mut len = signature.len();
                // SAFETY: inputs are readable for their lengths, output has maximum signature capacity.
                let status = unsafe {
                    OQS_SIG_sign(
                        handle.as_ptr(),
                        signature.as_mut_ptr(),
                        &mut len,
                        message.as_ptr(),
                        message.len(),
                        sk.0.as_ptr(),
                    )
                };
                if status != 0 {
                    return Err(format!("{} signing failed: {status}", self.name).into());
                }
                len
            }
            Provider::BoringSsl => {
                if !bssl::sign(&sk.0, message, &mut signature) {
                    return Err(format!("{} signing failed", self.name).into());
                }
                signature.len()
            }
        };
        if len == 0 || len > signature.len() {
            return Err(format!("{} signing failed: length={len}", self.name).into());
        }
        signature.truncate(len);
        Ok(signature)
    }

    pub(crate) fn verify(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Neither API takes a public-key length; never pass a short key.
        assert_eq!(pk.len(), self.public_key_len);
        match self.provider {
            Provider::Oqs(handle) => {
                // SAFETY: pk has exactly the required size; message/signature have explicit lengths.
                unsafe {
                    OQS_SIG_verify(
                        handle.as_ptr(),
                        message.as_ptr(),
                        message.len(),
                        signature.as_ptr(),
                        signature.len(),
                        pk.as_ptr(),
                    ) == 0
                }
            }
            Provider::BoringSsl => bssl::verify(pk, message, signature),
        }
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        if let Provider::Oqs(handle) = self.provider {
            // SAFETY: this object uniquely owns the handle and releases it exactly once.
            unsafe { OQS_SIG_free(handle.as_ptr()) };
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // SAFETY: the allocation is still live and writable for its entire length.
        unsafe { OQS_MEM_cleanse(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_generic_backends_count_as_fallback() {
        for (backend, hash) in [
            ("mldsa-native/C", "xkcp/plain64"),
            ("PQClean/clean", "xkcp/avx2"),
            ("boringssl/slhdsa", "boringssl-sha256/nohw"),
        ] {
            assert!(is_fallback(backend, hash), "{backend} {hash}");
        }
        for (backend, hash) in [
            ("mldsa-native/x86_64", "xkcp/avx2"),
            ("mldsa-native/aarch64", "xkcp/plain64"),
            ("PQClean/avx2", "xkcp/avx2"),
            ("PQClean/aarch64", "xkcp/plain64"),
            ("slhdsa-c/portable", "slhdsa-c/internal"),
            ("boringssl/slhdsa", "boringssl-sha256/hw"),
            ("boringssl/slhdsa", "boringssl-sha256/avx"),
            ("boringssl/slhdsa", "boringssl-sha256/c"),
        ] {
            assert!(!is_fallback(backend, hash), "{backend} {hash}");
        }
    }
}
