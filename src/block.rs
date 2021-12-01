use crate::message::{Message, RsaPublicHelpers};
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

const BLOCK_NONCE: &str = "4249";

pub struct Block {
    pub node_id: u32,
    pub previous_hash: Option<String>,
    pub hash: String,
    pub data: Message,
    pub author_public_key: RsaPublicKey,
    seed: u32,
}

impl Block {
    pub fn new(
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
        let finalized = &hasher.finalize()[..];

        for num in finalized {
            result += &format!("{:02X?}", num);
        }
        return result;
    }

    pub fn finalize(&mut self) {
        let mut is_final: bool = false;
        loop {
            if &self.hash[..4] == BLOCK_NONCE {
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

    pub fn validate_block(&self) -> bool {
        if &self.hash[..4] != BLOCK_NONCE {
            return false;
        };
        match &self.previous_hash {
            Some(ref hash) => {
                if &hash[..4] != BLOCK_NONCE {
                    return false;
                };
            }
            None => {
                if self.node_id != 0 {
                    return false;
                }
            }
        }
        return true;
    }
}
