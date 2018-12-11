extern crate libc;

pub mod helpers {
	use libc::c_char;
	use libc::c_uchar;
	use libc::size_t;

	#[link(name = "sodium")]
	extern {
		fn sodium_bin2hex(hex: *const c_char, hex_maxlen: size_t,
			bin: *const c_uchar, bin_len: size_t) -> *mut c_char;
	}

	pub fn bin_to_hex(bin: &[u8]) -> String {
		super::init();

		// Buffer must be at least bin_len * 2 + 1
		let hex_max_len = bin.len() * 2 + 1;
		let mut hex = vec!['0' as u8; hex_max_len];

		// The function always returns hex, but we already have hex
		unsafe {
			let _ = sodium_bin2hex(hex.as_mut_ptr() as *mut c_char, hex.len(),
				bin.as_ptr(), bin.len());

		}
		let mut index = 0;
		for i in 0..hex.len() {
			let byte = hex.get(i).unwrap();
			if *byte == 0 {
				index = i;
				break
			}
		}
		hex.truncate(index);
		String::from_utf8(hex).unwrap()
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
		let mut output = vec![0; output_length];
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
		let mut buffer : Vec<u8> = vec![0; size];
		unsafe {
			randombytes_buf(buffer.as_mut_ptr() as *const c_void, buffer.len())
		}
		buffer
	}
}

pub mod sign {
	use libc::c_uchar;
	use libc::c_int;
	use libc::size_t;
	use libc::c_ulonglong;

	#[link(name = "sodium")]
	extern {
		fn crypto_sign_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
		fn crypto_sign_secretkeybytes() -> size_t;
		fn crypto_sign_publickeybytes() -> size_t;
		fn crypto_sign_detached(
			sig: *mut c_uchar, siglen: *mut c_ulonglong,
			m: *const c_uchar, mlen: c_ulonglong,
			sk: *const c_uchar
		) -> c_int;
		fn crypto_sign_bytes() -> size_t;
		fn crypto_sign_verify_detached(
			sig: *const c_uchar,
			m: *const c_uchar, mlen: c_ulonglong,
			pk: *const c_uchar) -> c_int;
	}

	pub struct PublicKey(Vec<u8>);
	pub struct PrivateKey(Vec<u8>);
	pub struct Signature(Vec<u8>);
	pub struct Message(pub Vec<u8>);

	pub fn generate_key_pair() -> (PublicKey, PrivateKey) {
		unsafe {
			let mut public_key_bytes = vec![0; crypto_sign_publickeybytes()];
			let mut private_key_bytes = vec![0; crypto_sign_secretkeybytes()];
			crypto_sign_keypair(public_key_bytes.as_mut_ptr(), private_key_bytes.as_mut_ptr());
			(PublicKey(public_key_bytes), PrivateKey(private_key_bytes))
		}
	}

	pub fn sign(message: &Message, private_key: &PrivateKey) -> Signature {
		// Extract the bytes out of their containers
		let PrivateKey(private_key_bytes) = private_key;
		let Message(message_bytes) = message;

		unsafe {
			// signature_length should probably be mutable, but rust warns of unnecessary mut
			let signature_length = crypto_sign_bytes();
			let mut signature_bytes = vec![0; signature_length];
			assert_eq!(private_key_bytes.len(), crypto_sign_secretkeybytes());

			// This func wasn't documented to return anything, and source code shows it always returns zero
			let _ = crypto_sign_detached(
				signature_bytes.as_mut_ptr(), &mut (signature_length as c_ulonglong),
				message_bytes.as_ptr(), message_bytes.len() as c_ulonglong,
				private_key_bytes.as_ptr(),
			);
			signature_bytes.truncate(signature_length);
			assert_eq!(private_key_bytes.len(), signature_length);
			Signature(signature_bytes)
		}
	}

	pub fn check(message: &Message, signature: &Signature, public_key: &PublicKey) -> Result<(), &'static str> {
		let Message(message_bytes) = message;
		let Signature(signature_bytes) = signature;
		let PublicKey(public_key_bytes) = public_key;
		let result = unsafe {
			crypto_sign_verify_detached(
				signature_bytes.as_ptr(),
				message_bytes.as_ptr(), message_bytes.len() as c_ulonglong,
				public_key_bytes.as_ptr(),
			)
		};
		match result {
			0 => Ok(()),
			-1 => Err("the signature fails verification"),
			_ => panic!("crypto_sign_verify_detached is only defined to return 0 and -1, not {}", result)
		}
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

pub fn generate_password(num_chars: usize, alphabet: Vec<char>) -> String {
	let mut chars : Vec<char> = vec![];
	for _ in 0..num_chars {
		let index : usize = random::range(alphabet.len() as u32 - 1) as usize;
		chars.push(*alphabet.get(index).unwrap());
	}
	let result : String = chars.into_iter().collect();
	result
}