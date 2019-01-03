/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

use crypto::digest::Digest;
use crypto::sha2::{Sha256, Sha512};
use enclave_sgx::WaitCertificate;
use hex as hex_codec;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sign::Verifier,
};
use sawtooth_sdk::consensus::engine::*;
use std::fs::File;
use std::io::Read;
use std::io::Write;

const WC_DELIM_CHAR: u8 = b'#' as u8; //0x23

pub fn to_hex_string(bytes: &[u8]) -> String {
    hex_codec::encode(bytes)
}

pub fn from_hex_string(str: String) -> Vec<u8> {
    hex_codec::decode(str).expect("Error while decoding hex string.")
}

pub fn blockid_to_hex_string(blockid: BlockId) -> String {
    let blockid_vec = Vec::from(blockid);
    to_hex_string(&blockid_vec)
}

pub fn format_block(block: &Block) -> String {
    format!(
        "{}{}{}{}{}{}{}{}{}",
        String::from("Block [ block_num : "),
        block.block_num,
        String::from(", block_id : "),
        to_hex_string(&block.block_id),
        String::from(", prev_block_id : "),
        to_hex_string(&block.previous_id),
        String::from(", peer_id : "),
        to_hex_string(&block.signer_id),
        String::from(" ] "),
    )
}

pub fn get_cert_and_sig_from(block: &Block) -> (String, String) {
    let payload = &block.payload;
    debug!("Extracted payload from block: {}", to_hex_string(&payload));
    let delim_index = payload.iter().position(|&i| i == WC_DELIM_CHAR).unwrap();
    let payload_parts = payload.split_at(delim_index + 1);
    let mut wait_certificate = String::from_utf8(payload_parts.0.to_vec()).unwrap();
    wait_certificate.pop(); // remove trailing delim
    let wait_certificate_sig = String::from_utf8(payload_parts.1.to_vec()).unwrap();
    (wait_certificate, wait_certificate_sig)
}

pub fn get_wait_time_from(block: &Block) -> u64 {
    // Handling genesis block where there is no certificate
    if block.block_num == 0 {
        return 0_u64;
    }
    WaitCertificate::from(block).wait_time
}

/// Reads the given file as string
///
/// Note: This method will panic if file is not found or error occurs when reading file as string.
pub fn read_file_as_string(filename: &str) -> String {
    let mut file_handler = match File::open(filename) {
        Ok(file_open_successful) => file_open_successful,
        Err(error) => panic!("Error opening file! {} : {}", error, filename),
    };
    let mut read_contents = String::new();
    file_handler
        .read_to_string(&mut read_contents)
        .expect("Read operation failed");
    read_contents
}

/// Reads the given file as string, ignore the new line character at end
///
/// Note: This method will panic if file is not found or error occurs when reading file as string.
pub fn read_file_as_string_ignore_line_end(filename: &str) -> String {
    let mut read_contents = read_file_as_string(filename);
    read_contents.pop();
    read_contents
}

/// Reads binary file and returns vector of u8
///
/// Note: This method will panic if file is not found or error occurs when reading file as binary.
pub fn read_binary_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).expect("File not found");
    let mut buffer = vec![];
    file.read_to_end(&mut buffer).expect("Read failed!");
    info!("{:?}", buffer);
    buffer
}

/// Write binary data to a file
pub fn write_binary_file(data: &[u8], filename: &str) {
    let mut file = File::create(filename).expect("File not found");
    file.write_all(data).expect("Write binary file failed");
}

/// Returns SHA256 of input &str in String
pub fn sha256_from_str(input_value: &str) -> String {
    let mut sha256_calculator = Sha256::new();
    sha256_calculator.input_str(input_value);
    sha256_calculator.result_str()
}

/// Returns SHA512 of input &str in String
pub fn sha512_from_str(input_value: &str) -> String {
    let mut sha512_calculator = Sha512::new();
    sha512_calculator.input_str(input_value);
    sha512_calculator.result_str()
}

/// Function to verify signature of a message, accepts message, signature and public key as input
/// Checks if message digest is signed using private key associated with the public key supplied
/// as input.
///
/// Note: SHA256 algorithm is used to find message digest.
pub fn verify_message_signature(pub_key: &PKey<Public>, message: &[u8], signature: &[u8]) -> bool {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key).unwrap();
    verifier.update(message).expect("Error adding message");
    verifier
        .verify(signature)
        .expect("Error verifying message signature")
}

#[cfg(test)]
mod tests {
    use super::*;

    static EXPECTED_FILE_CONTENT: &'static str = "This is expected content from
The dummy file.
";

    #[test]
    fn test_read_file_as_string() {
        let what_is_read_from_file = read_file_as_string("src/tests/resources/dummy_file.txt");
        assert_eq!(EXPECTED_FILE_CONTENT, what_is_read_from_file)
    }

    #[test]
    fn test_sha512_from_str() {
        let sha512_of_validator_tp = "06774ab4d0c0dea67a6fb29dd0fee42d89cf66e0c41f63e7058e77839f18877460f260ad7dc99d12428bb188eaa1ddf87a9d9cf59570de95e9f76773bc190e78";
        let sha512_calculated = sha512_from_str("validator_registry");
        assert_eq!(sha512_of_validator_tp, sha512_calculated)
    }

    #[test]
    fn test_sha256_from_str() {
        let sha256_of_validator_tp =
            "6a437209808cff53912c184ab0d3742d47c601c32367e8c34dbe34e9b923e147";
        let sha256_calculated = sha256_from_str("validator_registry");
        assert_eq!(sha256_of_validator_tp, sha256_calculated)
    }

    #[test]
    fn test_to_hex_string() {
        let dummy_string = "This is dummy string";
        let vec_of_dummy_string = dummy_string.to_string().as_bytes().to_vec();
        let dummy_string_in_hex = "546869732069732064756d6d7920737472696e67";
        let what_is_returned_from_fun = to_hex_string(&vec_of_dummy_string);
        assert_eq!(dummy_string_in_hex, what_is_returned_from_fun);
    }

    #[test]
    fn test_block_id_to_hex_string() {
        let dummy_string = "This is dummy string";
        let vec_of_dummy_string: BlockId = dummy_string.to_string().as_bytes().to_vec();
        let dummy_string_in_hex = "546869732069732064756d6d7920737472696e67";
        let what_is_returned_from_fun = to_hex_string(&vec_of_dummy_string);
        assert_eq!(dummy_string_in_hex, what_is_returned_from_fun);
    }
}
