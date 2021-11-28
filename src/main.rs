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
use rsa::{
    pkcs1::{FromRsaPrivateKey, FromRsaPublicKey, ToRsaPrivateKey, ToRsaPublicKey},
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

type U16 = UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>;

trait RsaPublicHelpers {
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

struct Message {
    to: RsaPublicKey,
    from: RsaPublicKey,
    text: String,
    signing_key: Option<String>,
}

impl Message {
    fn new(to: &RsaPublicKey, from: &RsaPublicKey, text: &str) -> Message {
        Message {
            to: to.to_owned(),
            from: to.to_owned(),
            text: String::from(text),
            signing_key: None,
        }
    }

    fn encrypt(&mut self, public_key: &RsaPublicKey) -> Result<(), rsa::errors::Error> {
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

    fn decrypt(&mut self, private_key: &RsaPrivateKey) {
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
            self.to.print_key(),
            self.from.print_key(),
            self.text,
            match &self.signing_key {
                Some(key) => key,
                None => "",
            }
        )
    }
}

struct Block {
    node_id: u32,
    previous_hash: Option<String>,
    hash: String,
    data: Message,
    author_public_key: RsaPublicKey,
    seed: u32,
}

impl Block {
    fn new(
        data: Message,
        author: &RsaPublicKey,
        previous_block_hash: Option<String>,
        node_id: u32,
    ) -> Block {
        let seed: u32 = 0;
        Block {
            hash: Block::generate_block_hash(author, &data, &previous_block_hash, &seed, &node_id),
            previous_hash: previous_block_hash,
            data,
            author_public_key: author.to_owned(),
            seed,
            node_id,
        }
    }

    fn generate_block_hash(
        author: &RsaPublicKey,
        data: &Message,
        previous_hash: &Option<String>,
        seed: &u32,
        node_id: &u32,
    ) -> String {
        let mut hasher = Sha256::new();
        let mut string_to_hash: String = format!("{}", author.print_key());
        string_to_hash += &data.to_string();
        match previous_hash {
            Some(str) => {
                string_to_hash += str;
            }
            None => {}
        }
        string_to_hash += &seed.to_string();
        string_to_hash += &node_id.to_string();

        hasher.update(string_to_hash);

        let mut result: String = String::from("");
        let finalized: &[u8] = &hasher.finalize()[..];

        for num in finalized {
            result += &format!("{:02X?}", num);
        }
        return result;
    }

    fn finalize(&mut self) {
        let mut is_final: bool = false;
        loop {
            if &self.hash[..4] == "4249" {
                is_final = true;
            }
            if is_final {
                break;
            }

            self.seed += 1;

            self.hash = Block::generate_block_hash(
                &self.author_public_key,
                &self.data,
                &self.previous_hash,
                &self.seed,
                &self.node_id,
            );
        }
    }
}

fn get_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let current_dir = std::fs::read_dir(".");
    let public_key: RsaPublicKey;
    let private_key: RsaPrivateKey;

    let mut has_private_key = false;
    let mut has_public_key = false;

    match current_dir {
        Ok(dir) => {
            for d in dir {
                let file = d.expect("Unable to read directory");
                if file.file_name() == "biddykey.pub" {
                    has_public_key = true;
                }
                if file.file_name() == "biddykey" {
                    has_private_key = true;
                }
            }
        }
        Err(whut) => {}
    }

    if !has_public_key && has_private_key {
        private_key = get_private_key().expect("Unable to get private key");
        public_key = generate_public_key(&private_key).expect("Unable to generate public key");
    } else if !has_private_key {
        private_key = generate_private_key().expect("Unable to generate private key");
        public_key = generate_public_key(&private_key).expect("Unable to generate public key");
    } else {
        private_key = get_private_key().expect("Unable to get private key");
        public_key = get_public_key().expect("Unable to get public key");
    };

    return (private_key, public_key);
}

fn generate_public_key(private_key: &RsaPrivateKey) -> Result<RsaPublicKey, std::io::Error> {
    let public_key = RsaPublicKey::from(private_key);

    let path = std::path::Path::new("./biddykey.pub");

    public_key
        .write_pkcs1_pem_file(path)
        .expect("Unable to write public key to file");

    return Ok(public_key);
}

fn generate_private_key() -> Result<RsaPrivateKey, std::io::Error> {
    let mut rng = OsRng;

    let private_key = RsaPrivateKey::new(&mut rng, 4096).expect("Unable to generate Private Key");

    let path = std::path::Path::new("./biddykey");

    private_key
        .write_pkcs1_pem_file(path)
        .expect("Unable to write private key to file");

    return Ok(private_key);
}

fn get_public_key() -> Result<RsaPublicKey, std::io::Error> {
    let path = std::path::Path::new("./biddykey.pub");

    let public_key =
        RsaPublicKey::read_pkcs1_pem_file(path).expect("Unable to read public key from file");

    return Ok(public_key);
}

fn get_private_key() -> Result<RsaPrivateKey, std::io::Error> {
    let path = std::path::Path::new("./biddykey");

    let private_key =
        RsaPrivateKey::read_pkcs1_pem_file(path).expect("Unable to read private key from file");

    return Ok(private_key);
}

fn main() {}

#[cfg(test)]
mod tests {
    use crate::{get_keys, Message};

    #[test]
    fn message_decryption_works() {
        let (private_key, public_key) = get_keys();

        let test_text = "Testing123";

        let mut message: Message = Message::new(&public_key, &public_key, &test_text);

        assert_eq!(&test_text, &message.text);

        message
            .encrypt(&public_key)
            .expect("Unable to encrypt message");

        assert_ne!(&message.text, &test_text);

        message.decrypt(&private_key);

        assert_eq!(&test_text, &message.text);
    }
}
