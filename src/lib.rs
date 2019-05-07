extern crate schnorrkel;
//#![feature(rustc_private)]
extern crate libc;

mod wrapper;
use wrapper::*;
use std::slice;
use std::os::raw::c_uchar;
use bytes::Bytes;

const SEED_LEN:u32 = 32;
const PUB_KEY_LEN:u32 = 32;
const PRI_KEY_LEN:u32 = 64;
const STATUS_OK:u32 = 0;
const STATUS_NOK:u32 = 1;
/// Perform a derivation on a secret
///
/// * secret: UIntArray with 64 bytes
/// * cc: UIntArray with 32 bytes
///
/// returned vector the derived keypair as a array of 96 bytes

pub fn derive_keypair_hard(pair: &[u8], cc: &[u8]) -> Vec<u8> {
	__derive_keypair_hard(pair, cc).to_vec()
}

/// Perform a derivation on a secret
///
/// * secret: UIntArray with 64 bytes
/// * cc: UIntArray with 32 bytes
///
/// returned vector the derived keypair as a array of 96 bytes

pub fn derive_keypair_soft(pair: &[u8], cc: &[u8]) -> Vec<u8> {
	__derive_keypair_soft(pair, cc).to_vec()
}

/// Perform a derivation on a publicKey
///
/// * pubkey: UIntArray with 32 bytes
/// * cc: UIntArray with 32 bytes
///
/// returned vector is the derived publicKey as a array of 32 bytes

pub fn derive_public_soft(public: &[u8], cc: &[u8]) -> Vec<u8> {
	__derive_public_soft(public, cc).to_vec()
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * public: UIntArray with 32 element
/// * private: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
///
/// * returned vector is the signature consisting of 64 bytes.

pub fn sign(public: &[u8], private: &[u8], message: &[u8]) -> Vec<u8> {
	__sign(public, private, message).to_vec()
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 32 element

pub fn verify(signature: &[u8], message: &[u8], pubkey: &[u8]) -> bool {
	__verify(signature, message, pubkey)
}

/// Generate a secret key (aka. private key) from a seed phrase.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the private key consisting of 64 bytes.
#[repr(C)]
pub struct c_secret{
	status:u32,
    data:[u8;64],
    len: u32
}
#[no_mangle]
pub unsafe extern "C" fn schnr_secret_from_seed(seed:*const c_uchar) -> (Box<c_secret>) {
	assert!(!seed.is_null(), "Null pointer in sum()");
	let rseed: &[c_uchar] = slice::from_raw_parts(seed, 32);
	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;
	let data_bytes = Bytes::from(__secret_from_seed(rseed).to_vec());
	let mut data:[u8;64] = [0;64];
	let status:u32 = STATUS_OK;
	let mut i =0;
	while i<64 {
		data[i] = data_bytes[i];
		i = i+1;
	}
	let secret = c_secret { data: data,len:len, status:status};
	Box::new(secret)
}
/// Generate a key pair. .
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (64 bytes)
/// followed by the public key (32) bytes.
#[repr(C)]
pub struct c_keypair{
	status:u32,
    data:[u8;96],
    len: u32
}

#[no_mangle]
pub unsafe extern "C" fn schnr_keypair_from_seed(seed:*const c_uchar) -> (Box<c_keypair>) {
	assert!(!seed.is_null(), "Null pointer in sum()");
	let rseed: &[c_uchar] = slice::from_raw_parts(seed, 32);
	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;
	let data_bytes = Bytes::from(__keypair_from_seed(rseed).to_vec());
	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;
	let mut i =0;
	while i<96 {
		data[i] = data_bytes[i];
		i = i+1;
	}
	let pair = c_keypair { data, len, status};
	Box::new(pair) 
}

