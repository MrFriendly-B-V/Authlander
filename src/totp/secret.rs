use rand::Rng;
use anyhow::Result;
use sha1::Sha1;
use hmac::{Hmac, NewMac, Mac};

/// Base32 without padding
const BASE32_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

/// The amount of digits in the HOTP code
const DIGITS: u32 = 6;

pub fn generate_secret() -> String {
    let random: Vec<u8> = rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(20).collect();
    base32::encode(BASE32_ALPHABET, &random)
}

type HmacSha1 = Hmac<Sha1>;

/// Generate a HOTP code from a provided secret and counter value
pub fn generate_hotp(secret: String, counter: &[u8; 8]) -> Result<i32> {
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(counter);
    let hmac_result = mac.finalize().into_bytes();

    let offset = (hmac_result[19] & 0xf) as usize;
    let truncated_hash = (hmac_result[offset] as i32 & 0x7f) << 24
        | (hmac_result[offset + 1] as i32 & 0xff) << 16
        | (hmac_result[offset + 2] as i32 & 0xff) << 8
        | (hmac_result[offset + 3] as i32 & 0xff);

    let hotp = truncated_hash % (10_i32.pow(DIGITS));
    Ok(hotp)
}
