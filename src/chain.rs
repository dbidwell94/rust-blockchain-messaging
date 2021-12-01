use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

use crate::{utils, Block, Message, Network};

const CHAIN_STORAGE_LOCATION: &str = "./chain";
const MAX_CHAIN_CHUNK: usize = 1024 * 10;
const BLOCK_PADDING: [u8; 4] = [0x0, 0x0, 0x0, 0x0];

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
        })
    }

    fn verify_chain(&self, block: &Block) -> bool {
        let mut current_block_option = Some(block);
        let mut is_valid_chain = true;

        while current_block_option.is_some() && is_valid_chain {
            let current_block = current_block_option.unwrap();
            if !current_block.validate_block() {
                return false;
            }

            match current_block.previous_hash {
                None => {
                    if current_block.node_id != 0 {
                        return false;
                    }
                    return is_valid_chain;
                }
                Some(ref hash) => {
                    let previous_block = self.chain.get(hash.as_str());

                    match previous_block {
                        None => {
                            if current_block.node_id != 0 {
                                is_valid_chain = false;
                            }
                            current_block_option = None
                        }
                        Some(p_block) => current_block_option = Some(p_block),
                    }
                }
            };
        }

        return is_valid_chain;
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), ChainError> {
        if !self.verify_chain(&block) {
            return Err(ChainError::InvalidChain);
        }

        let block_hash = String::from(&block.hash);

        self.chain.insert(block_hash.to_owned(), block);
        self.latest_block_hash = Some(block_hash);
        return Ok(());
    }

    pub fn init(&mut self) {
        let (_, public) = utils::get_keys();
        
        loop {
            sleep(Duration::from_millis(1500));

            let message = Message::new(&public, &public, "testing123");

            let mut block = Block::new(
                message,
                &public,
                self.latest_block_hash.to_owned(),
                self.chain.len() as u32,
            );

            block.finalize();
            let block_hash = block.hash.to_owned();
            match self.add_block(block) {
                Ok(_) => {
                    println!("Block successfully added with hash: {:?}", block_hash);
                }
                Err(err) => {
                    println!("{:?}", err)
                }
            }
        }
    }

    async fn save_chain(&self) -> Result<(), ChainError> {
        match std::fs::canonicalize(self.chain_directory) {
            Ok(buff) => {
                println!("Saving blockchain to {:?}", buff.as_os_str());

                let save_buffer: [u8; MAX_CHAIN_CHUNK] = [0u8; MAX_CHAIN_CHUNK];
                let buffer_write_amount: usize = 0;

                return Ok(());
            }
            Err(_) => return Err(ChainError::SaveError),
        }
    }
}
