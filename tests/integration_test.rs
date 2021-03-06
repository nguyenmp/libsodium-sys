extern crate sodium;

// Many of these tests are applications of the quick start FAQs
// https://download.libsodium.org/doc/quickstart/

#[test]
fn random_int() {
	let _ : u32 = sodium::random::int();
}

#[test]
fn random_range() {
	let _ : u32 = sodium::random::range(32);
}

#[test]
fn random_buffer() {
	let buffer = sodium::random::buffer(4);
	let _ = sodium::helpers::bin_to_hex(&buffer[..]);
}

#[test]
fn compute_a_hash_and_verify() {
	let bin = [];
	let key = None;
	let hash_bin = sodium::hash::generic(&bin, key);
	let hash_hex = sodium::helpers::bin_to_hex(&hash_bin[..]);
	let known_correct_answer = "786A02F742015903C6C6FD852552D272912F4740E1584\
	7618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F70\
	1AFE9BE2CE";
	assert_eq!(known_correct_answer.to_lowercase(), hash_hex);
}

#[test]
fn compute_another_hash_and_verify() {
	let input = String::from("The quick brown fox jumps over the lazy dog");
	let bin : &[u8] = input.as_bytes();
	let key = None;
	let hash_bin = sodium::hash::generic(bin, key);
	let hash_hex = sodium::helpers::bin_to_hex(&hash_bin[..]);
	let known_correct_answer = "A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC1\
	48D95090BC7333B3673F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B1391\
	4CDCD6A918";
	assert_eq!(known_correct_answer.to_lowercase(), hash_hex);
}

#[test]
fn derive_key_from_passcode() {
	let password = "my password";
	let (_, key_1) = sodium::hash::password(password);
	let (_, key_2) = sodium::hash::password(password);
	assert_ne!(key_1, key_2);
}

#[test]
fn rederive_key_from_passcode() {
	let password = "my password";
	let (rehash_data, first_key) = sodium::hash::password(password);
	let second_key = sodium::hash::re_password(password, &rehash_data);
	assert_eq!(first_key, second_key);
}

#[test]
fn encrypt_message_with_passcode() {
	let message = "my message";
	let password = "my password";
	let (_, key) = sodium::hash::password(password);
	let (nonce, cipher) = sodium::crypto::encrypt(message.as_bytes(), &key[..]);
	let result = sodium::crypto::decrypt(nonce, cipher, &key[..]);
	let new_message = match result {
		Ok(message) => message,
		Err(message) => panic!(message),
	};
	assert_eq!(message, std::str::from_utf8(&new_message[..]).unwrap());
}

#[test]
fn sign_and_verify() {
	let message_1 = sodium::sign::Message("my message 1".as_bytes().to_vec());
	let message_2 = sodium::sign::Message("my message 2".as_bytes().to_vec());
	let (public_key_1, private_key_1) = sodium::sign::generate_key_pair();
	let (public_key_2, private_key_2) = sodium::sign::generate_key_pair();
	let signature_1 = sodium::sign::sign(&message_1, &private_key_1);
	let signature_2 = sodium::sign::sign(&message_2, &private_key_2);
	assert!(sodium::sign::check(&message_1, &signature_1, &public_key_1).is_ok());
	assert!(sodium::sign::check(&message_2, &signature_2, &public_key_2).is_ok());

	assert!(sodium::sign::check(&message_1, &signature_1, &public_key_2).is_err());
	assert!(sodium::sign::check(&message_1, &signature_2, &public_key_1).is_err());
	assert!(sodium::sign::check(&message_2, &signature_1, &public_key_1).is_err());

	assert!(sodium::sign::check(&message_1, &signature_2, &public_key_2).is_err());
	assert!(sodium::sign::check(&message_2, &signature_1, &public_key_2).is_err());
	assert!(sodium::sign::check(&message_2, &signature_2, &public_key_1).is_err());
}