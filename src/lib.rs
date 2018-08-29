extern crate libc;

#[cfg(test)]
mod tests {
    #[test]
    fn foo_and_bar_are_equal() {
        assert_eq!(super::bar(), super::foo());
    }
}

fn bar() -> &'static str {
    "asdff"
}

pub fn foo() -> &'static str {
    bar()
}

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
	use libc::c_int;
	use std::ptr::null;

	#[link(name = "sodium")]
	extern {
		fn crypto_generichash_bytes_max() -> size_t;
		fn crypto_generichash(output: *mut c_uchar, output_length: size_t,
			input: *const c_uchar, input_length: c_ulonglong,
			key: *const c_uchar, key_length: size_t) -> c_int;
	}

	pub fn generic(input: &[u8], key: Option<&[u8]>) -> Vec<u8> {
		super::init();
		let output_length = unsafe {
			crypto_generichash_bytes_max()
		};
		let key_ptr = match key {
			Some(k) => k.as_ptr(),
			None => null(),
		};
		let key_len = match key {
			Some(k) => k.len(),
			None => 0,
		};
		let mut output = vec!(0; output_length);
		let result = unsafe {
			crypto_generichash(output.as_mut_ptr(), output.len(),
				input.as_ptr(), input.len() as c_ulonglong,
				key_ptr, key_len)
		};
		output
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

	pub fn int() -> u32 {
		super::init();
		unsafe {
			randombytes_random()
		}
	}

	pub fn range(limit: u32) -> u32 {
		super::init();
		unsafe {
			randombytes_uniform(limit)
		}
	}

	pub fn buffer(buf: &mut[u8]) {
		super::init();
		unsafe {
			randombytes_buf(buf.as_mut_ptr() as *const c_void, buf.len())
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

#[test]
fn assert_sodium_init_once() {
	init();
}


#[test]
fn assert_sodium_init_twice() {
	init();
	init();
}
