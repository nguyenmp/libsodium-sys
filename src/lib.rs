extern crate libc;

pub mod helpers {
	use libc::c_char;
	use libc::c_uchar;
	use libc::size_t;
	use std::ffi::CString;

	#[link(name = "sodium")]
	extern {
		fn sodium_bin2hex(hex: *const c_char, hex_maxlen: size_t,
			bin: *const c_uchar, bin_len: size_t) -> *mut c_char;
	}

	pub fn bin_to_hex(bin: &[u8]) -> String {
		super::init();

		// Buffer must be at least bin_len * 2 + 1
		let hex_max_len = bin.len() * 2 + 1;
		let hex = CString::new(vec!('0' as u8, hex_max_len as u8)).unwrap();

		// The function always returns hex, but we already have hex
		unsafe {
			let hex_raw = sodium_bin2hex(hex.into_raw(), hex_max_len,
				bin.as_ptr(), bin.len());
			CString::from_raw(hex_raw).into_string().unwrap()
		}
	}
}

pub mod hash {
	use libc::size_t;
	use libc::c_ulonglong;
	use libc::c_uchar;
	use libc::c_char;
	use libc::c_int;
	use std::ptr::null;

	#[link(name = "sodium")]
	extern {
		fn crypto_generichash_bytes_max() -> size_t;
		fn crypto_generichash(output: *mut c_uchar, output_length: size_t,
			input: *const c_uchar, input_length: c_ulonglong,
			key: *const c_uchar, key_length: size_t) -> c_int;
		fn crypto_pwhash(out: *const c_uchar,
                  outlen: c_ulonglong,
                  passwd: *const c_char,
                  passwdlen: c_ulonglong,
                  salt: *const c_uchar,
                  opslimit: c_ulonglong,
                  memlimit: size_t,
                  alg: c_int) -> c_int;
		fn crypto_pwhash_alg_default() -> c_int;
		fn crypto_pwhash_opslimit_sensitive() -> size_t;
		fn crypto_pwhash_memlimit_sensitive() -> size_t;
		fn crypto_pwhash_saltbytes() -> size_t;
		fn crypto_secretbox_keybytes() -> size_t;
	}

	// Fast but "secure" hashing.  If hashing passwords, use password(...)
	pub fn generic(input: &[u8], key: Option<&[u8]>) -> Vec<u8> {
		super::init();
		let output_length = unsafe {
			crypto_generichash_bytes_max()
		};
		let (key_ptr, key_len) = match key {
			Some(k) => (k.as_ptr(), k.len()),
			None => (null(), 0),
		};
		let mut output = vec!(0; output_length);
		let _ = unsafe {
			crypto_generichash(output.as_mut_ptr(), output.len(),
				input.as_ptr(), input.len() as c_ulonglong,
				key_ptr, key_len)
		};
		output
	}

	pub struct PasswordHashingParams {
		keylen : c_ulonglong,
		opslimit : c_ulonglong,
		memlimit : size_t,
		alg : c_int,
		salt : Vec<u8>,
	}

	// Good for hashing passwords because it's expensive
	pub fn password(passwd: &str) -> (PasswordHashingParams, Vec<u8>) {
		super::init();

		let params = unsafe {
			let salt_size = crypto_pwhash_saltbytes();
			PasswordHashingParams {
				keylen: crypto_secretbox_keybytes() as u64,
				opslimit: crypto_pwhash_opslimit_sensitive() as u64,
				memlimit: crypto_pwhash_memlimit_sensitive(),
				alg: crypto_pwhash_alg_default(),
				salt: super::random::buffer(salt_size)
			}
		};
		let key = _crypto_pwhash(passwd, &params);
		(params, key)
	}

	pub fn re_password(passwd: &str, params: &PasswordHashingParams) -> Vec<u8> {
		_crypto_pwhash(passwd, params)
	}

	fn _crypto_pwhash(passwd: &str, params : &PasswordHashingParams) -> Vec<u8> {
		let mut out = vec![0; params.keylen as usize];
		let result = unsafe {
			crypto_pwhash(
				out.as_mut_ptr(), out.len() as c_ulonglong,
				passwd.as_ptr() as *const c_char, passwd.len() as c_ulonglong,
				params.salt.as_ptr(),  // No len for salt because it's fixed sized
				params.opslimit, params.memlimit, params.alg
			)
		};

		if let 0 = result {
			out
		} else if let -1 = result {
			panic!("the computation didn't complete, usually because the\
				operating system refused to allocate the amount of requested\
				memory.");
		} else {
			panic!("Unexpected result from crypto_pwhash(...): {}", result);
		}
	}
}

pub mod random {
	use libc::uint32_t;
	use libc::size_t;
	use libc::c_void;

	#[link(name = "sodium")]
	extern {
		fn randombytes_random() -> uint32_t;
		fn randombytes_uniform(_: uint32_t) -> uint32_t;
		fn randombytes_buf(buf: *const c_void, size: size_t);
	}

	// Returns a random number
	pub fn int() -> u32 {
		super::init();
		unsafe {
			randombytes_random()
		}
	}

	// Returns a random number between 0 and limit (inclusive)
	pub fn range(limit: u32) -> u32 {
		super::init();
		unsafe {
			randombytes_uniform(limit)
		}
	}

	// Fills the given buffer with random bytes
	pub fn buffer(size: usize) -> Vec<u8> {
		super::init();
		let mut buffer : Vec<u8> = vec!(0, size as u8);
		unsafe {
			randombytes_buf(buffer.as_mut_ptr() as *const c_void, buffer.len())
		}
		buffer
	}
}

pub mod crypto {
	use libc::c_uchar;
	use libc::c_ulonglong;
	use libc::size_t;
	use libc::c_int;

	type Nonce = Vec<u8>;
	type Cipher = Vec<u8>;

	#[link(name = "sodium")]
	extern {
		fn crypto_secretbox_easy(
			c: *mut c_uchar,
			m: *const c_uchar, mlen: c_ulonglong,
			n: *const c_uchar,
			k: *const c_uchar,
		) -> c_int;
		fn crypto_secretbox_noncebytes() -> size_t;
		fn crypto_secretbox_macbytes() -> size_t;
		fn crypto_secretbox_open_easy(
			m: *const c_uchar,
			c: *const c_uchar, clen: c_ulonglong,
			n: *const c_uchar,
            k: *const c_uchar,
        ) -> c_int;
	}

	pub fn encrypt(message: &[u8], key: &[u8]) -> (Nonce, Cipher) {
		unsafe {
			let cypher_len = crypto_secretbox_macbytes() + message.len();
			let mut cypher : Cipher= vec![0; cypher_len];
			let nonce_len = crypto_secretbox_noncebytes();
			let nonce : Nonce = super::random::buffer(nonce_len);
			crypto_secretbox_easy(
				cypher.as_mut_ptr(),
				message.as_ptr(), message.len() as u64,
				nonce.as_ptr(),
				key.as_ptr(),
			);
			(nonce, cypher)
		}
	}

	pub fn decrypt(nonce: Nonce, cipher: Cipher, key: &[u8]) -> Result<Vec<u8>, &'static str> {
		unsafe {
			let message_len = cipher.len() - crypto_secretbox_macbytes();
			let mut message = vec![0; message_len];
			let result = crypto_secretbox_open_easy(
				message.as_mut_ptr(),
				cipher.as_ptr(), cipher.len() as u64,
				nonce.as_ptr(),
	            key.as_ptr(),
	        );
			match result {
				0 => Ok(message),
				-1 => Err("Verification failed"),
				_ => unreachable!(),
			}
		}
	}
}

use libc::c_int;

#[link(name = "sodium")]
extern {
	fn sodium_init() -> c_int;
}

fn init() {
	let result : c_int = unsafe {
		sodium_init()
	};

	assert!(result >= 0);
}
