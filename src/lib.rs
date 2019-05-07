extern crate schnorrkel;
//#![feature(rustc_private)]
extern crate libc;

mod wrapper;
use wrapper::*;
use std::slice;
use std::os::raw::c_uchar;
use bytes::Bytes;

const PUB_KEY_LEN:u32 = 32;
const PRI_KEY_LEN:u32 = 64;
const STATUS_OK:u32 = 0;


#[repr(C)]
pub struct sr_data{
	status:u32,
    data:[u8;96],
    len: u32
}

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
 
#[no_mangle]
pub unsafe extern "C" fn schnr_sign(puk:*const c_uchar,pri:*const c_uchar,msg:*const c_uchar,msg_len:usize) -> (Box<sr_data>) {

	assert!(!pri.is_null(), "Null pointer in sum()");
	assert!(!puk.is_null(), "Null pointer in sum()");
	assert!(!msg.is_null(), "Null pointer in sum()");

	let rpri: &[c_uchar] = slice::from_raw_parts(pri, 64);
	let rpuk: &[c_uchar] = slice::from_raw_parts(puk, 32);
	let rmsg: &[c_uchar] = slice::from_raw_parts(msg, msg_len);
	
	let data_bytes = Bytes::from(__sign(rpuk,rpri,rmsg).to_vec());

	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;
	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;

	let mut i =0;
	while i<64 {
		data[i] = data_bytes[i];
		i = i+1;
	}
	let sr_data = sr_data { data: data,len:len, status:status};
	Box::new(sr_data)
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 32 element

#[no_mangle]
pub unsafe extern "C" fn schnr_verify(sign:*const c_uchar,puk:*const c_uchar,msg:*const c_uchar,msg_len:usize) -> u32 {

	assert!(!sign.is_null(), "Null pointer in sum()");
	assert!(!puk.is_null(), "Null pointer in sum()");
	assert!(!msg.is_null(), "Null pointer in sum()");

	let rsign: &[c_uchar] = slice::from_raw_parts(sign, 64);
	let rpuk: &[c_uchar] = slice::from_raw_parts(puk, 32);
	let rmsg: &[c_uchar] = slice::from_raw_parts(msg, msg_len);

	match __verify(rsign, rmsg, rpuk){
		true => 1,
		false => 0,
	}
}

/// Generate a secret key (aka. private key) from a seed phrase.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the private key consisting of 64 bytes.

#[no_mangle]
pub unsafe extern "C" fn schnr_secret_from_seed(seed:*const c_uchar) -> (Box<sr_data>) {

	assert!(!seed.is_null(), "Null pointer in sum()");

	let rseed: &[c_uchar] = slice::from_raw_parts(seed, 32);
	
	let data_bytes = Bytes::from(__secret_from_seed(rseed).to_vec());

	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;
	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;

	let mut i =0;
	while i<64 {
		data[i] = data_bytes[i];
		i = i+1;
	}

	let sr_data = sr_data { data: data,len:len, status:status};
	Box::new(sr_data)
}
/// Generate a key pair. .
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (64 bytes)
/// followed by the public key (32) bytes.

#[no_mangle]
pub unsafe extern "C" fn schnr_keypair_from_seed(seed:*const c_uchar) -> (Box<sr_data>) {

	assert!(!seed.is_null(), "Null pointer in sum()");

	let rseed: &[c_uchar] = slice::from_raw_parts(seed, 32);
	let data_bytes = Bytes::from(__keypair_from_seed(rseed).to_vec());
	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;
	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;

	let mut i =0;
	while i<96 {
		data[i] = data_bytes[i];
		i = i+1;
	}

	let sr_data = sr_data { data, len, status};
	Box::new(sr_data) 
}

