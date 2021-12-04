use aes::{
    cipher::{
        generic_array::{
            typenum::{
                bit::B0,
                bit::B1,
                uint::{UInt, UTerm},
            },
            GenericArray,
        },
        BlockDecryptMut,
    },
    Aes256, BlockEncrypt,
};
use hex::{decode as hex_decode, encode as hex_encode};
use rand::rngs::OsRng;
use rsa::{pkcs1::ToRsaPublicKey, PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

pub trait RsaPublicHelpers {
    fn print_key(&self) -> String;
}

impl RsaPublicHelpers for RsaPublicKey {
    fn print_key(&self) -> String {
        let s = self
            .to_pkcs1_pem()
            .expect("Unable to serialize RsaPublicKey");

        return s;
    }
}

type U16 = UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>;

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub to: String,
    pub from: String,
    pub text: String,
    pub signing_key: Option<String>,
}

impl Message {
    pub fn new(to: &RsaPublicKey, from: &RsaPublicKey, text: &str) -> Self {
        Message {
            to: hex::encode(to.print_key()),
            from: hex::encode(from.print_key()),
            text: String::from(text),
            signing_key: None,
        }
    }

    pub fn encrypt(&mut self, public_key: &RsaPublicKey) -> Result<(), rsa::errors::Error> {
        let mut rng = OsRng;
        let padding = PaddingScheme::PKCS1v15Encrypt;

        let mut raw_key: [u8; 32] = [0u8; 32];

        for index in 0..raw_key.len() {
            raw_key[index] = rand::random();
        }

        let text_bytes = self.text.as_bytes();
        let total_blocks_length: f32 = (text_bytes.len() as f32) / 16f32;

        let key: &GenericArray<u8, _> =
            aes::cipher::generic_array::GenericArray::from_slice(&raw_key);
        let cipher: Aes256 = aes::NewBlockCipher::new(&key);

        let mut blocks: Vec<GenericArray<u8, U16>> = Vec::new();

        for index in 0..total_blocks_length.ceil() as usize {
            let mut arr = [0u8; 16];
            for byte_index in 0..16 as usize {
                if (index * 16) + byte_index > text_bytes.len() - 1 {
                    continue;
                }
                arr[byte_index] = text_bytes[((index) * 16) + byte_index];
            }

            let block = aes::Block::clone_from_slice(&arr);

            blocks.push(block);
        }

        cipher.encrypt_blocks(&mut blocks[..]);

        let mut new_text = String::new();

        for b in blocks {
            new_text += &hex_encode(b);
        }
        self.text = new_text;

        let encrypted_signing_key;
        encrypted_signing_key = hex_encode(
            public_key
                .encrypt(&mut rng, padding, key.as_slice())
                .unwrap(),
        );

        self.signing_key = Some(encrypted_signing_key);

        return Ok(());
    }

    pub fn decrypt(&mut self, private_key: &RsaPrivateKey) {
        let padding = PaddingScheme::PKCS1v15Encrypt;
        let encrypted_key = match &self.signing_key {
            None => {
                panic!("No key to decrypt")
            }
            Some(k) => hex_decode(k).expect("Unable to convert from hex"),
        };

        let key = private_key
            .decrypt(padding, &encrypted_key)
            .expect("Unable to decrypt key");

        let mut cipher: Aes256 =
            aes::NewBlockCipher::new(aes::cipher::generic_array::GenericArray::from_slice(&key));

        let encoded_message = hex_decode(&self.text).expect("Unable to convert text from hex");
        let total_blocks_length: f32 = (encoded_message.len() as f32) / 16f32;

        let mut blocks: Vec<GenericArray<u8, U16>> = Vec::new();

        for index in 0..total_blocks_length.ceil() as usize {
            let mut arr = [0u8; 16];
            for byte_index in 0..16 as usize {
                if (index * 16) + byte_index > encoded_message.len() - 1 {
                    continue;
                }
                arr[byte_index] = encoded_message[((index) * 16) + byte_index];
            }

            let mut block = aes::Block::clone_from_slice(&arr);
            cipher.decrypt_block_mut(&mut block);

            blocks.push(block);
        }
        let mut built_string = String::new();
        for (index, b) in blocks.iter().enumerate() {
            if index == blocks.len() - 1 {
                let mut built_vec: Vec<u8> = Vec::new();
                for ch in b {
                    if ch != &0u8 {
                        built_vec.push(ch.to_owned());
                    }
                }
                built_string += &String::from_utf8(built_vec).expect("Unable to convert from utf8");
            } else {
                built_string +=
                    &String::from_utf8(b.as_slice().to_vec()).expect("Unable to convert from utf8");
            }
        }

        self.signing_key = None;
        self.text = built_string;
    }
}

impl ToString for Message {
    fn to_string(&self) -> String {
        format!(
            "to:\n{}\nfrom:\n{}\ntext:\n{}\n\nsigning_key:\n{:?}",
            self.to,
            self.from,
            self.text,
            match &self.signing_key {
                Some(key) => key,
                None => "",
            }
        )
    }
}
