extern crate sodium;

fn main() {
	let mut alphabet : Vec<char> = vec![];
	for code in 32 as u8 .. 126 + 1 {
		alphabet.push(code as char)
	}
    println!("{}", sodium::generate_password(32, alphabet));
}
