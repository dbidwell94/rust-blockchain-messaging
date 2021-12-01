mod block;
mod chain;
mod message;
mod network;
pub mod utils;
pub use crate::chain::Chain;
pub use crate::{block::Block, message::Message, network::Network};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    print!("\x1B[2J\x1B[1;1H");
    let listener = TcpListener::bind("0.0.0.0:8675").await.unwrap();
    let network_list: Arc<Mutex<HashMap<SocketAddr, Box<Network>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let peer_list = network_list.clone();

    tokio::spawn(async move {
        match Chain::new(peer_list) {
            Some(mut chain) => chain.init(),
            None => {
                println!("Unable to initialize the blockchain");
            }
        };
    });

    loop {
        let (socket, address) = listener.accept().await.unwrap();

        let connection = Network::new(Some(socket), address.clone());
        let mut connection_clone = connection.clone();

        let copied_network_list = network_list.clone();
        (*copied_network_list.lock().unwrap()).insert(address.clone(), Box::new(connection));

        println!("{:?} has just connected", address);

        tokio::spawn(async move {
            connection_clone.run().await;

            println!("Connection to {:?} has terminated.", address);
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{utils, Message};

    #[test]
    fn message_decryption_works() {
        let (private_key, public_key) = utils::get_keys();

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
