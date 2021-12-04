use std::{
    collections::HashMap,
    fmt::Debug,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::{utils::get_keys, Block, Message, Network};

const CHAIN_STORAGE_LOCATION: &str = "./chain";

pub enum ChainError {
    InvalidBlock,
    InvalidChain,
    SaveError,
}

impl Debug for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlock => write!(f, "InvalidBlock"),
            Self::InvalidChain => write!(f, "InvalidChain"),
            Self::SaveError => write!(f, "SaveError"),
        }
    }
}

pub struct Chain<'a> {
    peer_list: Arc<Mutex<HashMap<SocketAddr, Box<Network>>>>,
    chain_directory: &'a Path,
    chain: HashMap<String, Block>,
    latest_block_hash: Option<String>,
    latest_block_id: u32,
}

impl<'a> Chain<'a> {
    pub fn new(peer_list: Arc<Mutex<HashMap<SocketAddr, Box<Network>>>>) -> Option<Self> {
        let mut p = Path::new(CHAIN_STORAGE_LOCATION);

        if !p.exists() {
            match std::fs::create_dir(CHAIN_STORAGE_LOCATION) {
                Ok(_) => {
                    p = Path::new(CHAIN_STORAGE_LOCATION);
                }
                Err(_) => return None,
            }
        }

        Some(Chain {
            peer_list,
            chain_directory: p,
            chain: HashMap::new(),
            latest_block_hash: None,
            latest_block_id: 0,
        })
    }

    fn verify_chain(&self, block: &Block) -> bool {
        let mut current_block_option = Some(block);
        let mut is_valid_chain = true;
        let mut counted_blocks: u32 = 0;

        while current_block_option.is_some() && is_valid_chain {
            let current_block = current_block_option.unwrap();
            if !current_block.validate_block() {
                return false;
            }

            match &current_block.previous_hash {
                None => {
                    if current_block.node_id != 0 {
                        return false;
                    }
                    return is_valid_chain;
                }
                Some(hash) => {
                    let previous_block = self.chain.get(hash);

                    match previous_block {
                        None => {
                            if current_block.node_id != 0
                                && counted_blocks != self.chain.len() as u32
                            {
                                is_valid_chain = false;
                            }
                            current_block_option = None
                        }
                        Some(p_block) => current_block_option = Some(p_block),
                    }
                }
            };
            counted_blocks += 1;
        }

        return is_valid_chain;
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), ChainError> {
        if !self.verify_chain(&block) {
            return Err(ChainError::InvalidChain);
        }

        let block_hash = String::from(&block.hash);
        let block_id = block.node_id.to_owned();

        if self.chain.len() >= 50 {
            self.save_chain().unwrap();
        }

        self.chain.insert(block_hash.to_owned(), block);

        println!(
            "New block added with id {:?} and hash {:?} -- new chain size: {:?} bytes",
            block_id,
            block_hash,
            std::mem::size_of::<HashMap<String, Block>>() * self.chain.len()
        );

        self.latest_block_hash = Some(block_hash);
        self.latest_block_id = block_id;

        return Ok(());
    }

    pub fn init(&mut self) {
        let (_, public) = get_keys();
        let mut block: Option<Block>;

        loop {
            let mut message = Message::new(&public, &public, "testing");
            message.encrypt(&public).unwrap();
            match &self.latest_block_hash {
                Some(hash) => match self.chain.get(hash) {
                    Some(b) => {
                        block = Some(Block::new(
                            message,
                            &public,
                            Some(b.hash.to_owned()),
                            self.latest_block_id + 1,
                        ));
                    }
                    None => block = None,
                },
                None => {
                    block = Some(Block::new(message, &public, None, self.latest_block_id));
                }
            }

            if block.is_some() {
                let mut to_finalize = block.unwrap();
                to_finalize.finalize();
                self.add_block(to_finalize).unwrap();
            }
        }
    }

    fn get_min_max_block_id(&self) -> Option<(u32, u32)> {
        let mut last_id: Option<u32> = None;
        let first_id: Option<u32>;
        let mut current_block: Option<&Block>;

        match &self.latest_block_hash {
            Some(hash) => match self.chain.get(hash) {
                Some(block) => {
                    first_id = Some(block.node_id.to_owned());
                    current_block = Some(block);
                }
                None => return None,
            },
            None => return None,
        };

        while current_block.is_some() {
            let block: &Block = current_block.unwrap();
            match &block.previous_hash {
                Some(hash) => match self.chain.get(hash) {
                    Some(block) => {
                        current_block = Some(block);
                    }
                    None => {
                        current_block = None;
                        last_id = Some(block.node_id.to_owned())
                    }
                },
                None => {
                    last_id = Some(block.node_id.to_owned());
                    current_block = None
                }
            }
        }

        if first_id.is_none() || last_id.is_none() {
            return None;
        }

        return Some((last_id.unwrap(), first_id.unwrap()));
    }

    fn save_chain(&mut self) -> Result<(), ChainError> {
        match std::fs::canonicalize(self.chain_directory) {
            Ok(buff) => {
                let min_block_id: u32;
                let max_block_id: u32;

                match self.get_min_max_block_id() {
                    Some((min, max)) => {
                        min_block_id = min;
                        max_block_id = max;
                    }
                    None => return Err(ChainError::InvalidChain),
                }

                let chain_name = buff.join(Path::new(&format!(
                    "chain-{}-{}.chain.part",
                    min_block_id, max_block_id
                )));

                println!("Saving blockchain to {:?}", chain_name.as_os_str());

                let byte_vec: Vec<u8> = bincode::serialize(&self.chain).unwrap();
                // for block in self.chain.values() {
                //     byte_vec.append(&mut block.print_block());
                //     for byte in BLOCK_PADDING {
                //         byte_vec.push(byte);
                //     }
                // }

                match std::fs::write(chain_name, &byte_vec[..]) {
                    Ok(_) => {
                        self.chain = HashMap::new();
                        return Ok(());
                    }
                    Err(_) => return Err(ChainError::SaveError),
                }
            }
            Err(_) => return Err(ChainError::SaveError),
        }
    }
}
