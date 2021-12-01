use futures::future;
use std::collections::VecDeque;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpStream, spawn};

struct MessageQueue {
    receive_byte_queue: Arc<Mutex<Option<VecDeque<Vec<u8>>>>>,
    send_byte_queue: Arc<Mutex<Option<VecDeque<Vec<u8>>>>>,
}

impl Clone for MessageQueue {
    fn clone(&self) -> Self {
        Self {
            receive_byte_queue: self.receive_byte_queue.clone(),
            send_byte_queue: self.send_byte_queue.clone(),
        }
    }
}

pub struct Network {
    message_queue: MessageQueue,
    stream: Arc<Mutex<Option<TcpStream>>>,
    pub remote_address: SocketAddr,
}

impl<'a> Hash for Network {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.remote_address.hash(state);
    }
}

impl PartialEq for Network {
    fn eq(&self, other: &Self) -> bool {
        self.remote_address == other.remote_address
    }
}

impl Eq for Network {
    fn assert_receiver_is_total_eq(&self) {}
}

impl Clone for Network {
    fn clone(&self) -> Self {
        Self {
            message_queue: self.message_queue.clone(),
            stream: self.stream.clone(),
            remote_address: self.remote_address.clone(),
        }
    }
}

impl<'a> Network {
    pub fn new(stream: Option<TcpStream>, address: SocketAddr) -> Self {
        Self {
            message_queue: MessageQueue {
                receive_byte_queue: Arc::new(Mutex::new(Some(VecDeque::new()))),
                send_byte_queue: Arc::new(Mutex::new(Some(VecDeque::new()))),
            },
            stream: Arc::new(Mutex::new(stream)),
            remote_address: address,
        }
    }

    pub async fn run(&mut self) {
        let should_shutdown = Arc::new(Mutex::new(false));
        let should_shutdown_clone = should_shutdown.clone();

        let stream = self
            .stream
            .lock()
            .unwrap()
            .take()
            .expect("There is no TcpStream to work on!");

        let (mut r, mut w) = io::split(stream);

        // Receive Logic
        let receive_queue = (self.message_queue).clone().receive_byte_queue;
        let read_handle = spawn(async move {
            Network::do_read(&mut r, receive_queue, should_shutdown.clone()).await;
        });

        let send_queue = (self.message_queue).clone().send_byte_queue;
        // Write Logic
        let write_handle = spawn(async move {
            Network::do_write(&mut w, send_queue, should_shutdown_clone.clone()).await;
        });

        let (read_result, write_result) = future::join(read_handle, write_handle).await;

        read_result.expect("Unable to join read handle into current thread");
        write_result.expect("Unable to join write handle into current thread");

        println!("Shutting down connection to {:?}", self.remote_address);
    }

    async fn do_read(
        reader: &mut io::ReadHalf<TcpStream>,
        read_queue: Arc<Mutex<Option<VecDeque<Vec<u8>>>>>,
        should_shutdown: Arc<Mutex<bool>>,
    ) {
        let mut buffer = [0u8; 1024];
        let mut bytes_read: usize;
        loop {
            bytes_read = match reader.read(&mut buffer).await {
                Ok(amount) => amount,
                Err(_) => 0,
            };

            if bytes_read == 0 {
                *should_shutdown.lock().unwrap() = true;
                break;
            }

            read_queue
                .as_ref()
                .lock()
                .as_mut()
                .unwrap()
                .as_mut()
                .expect("Unable to get a VecDeque from the Mutex in the reader")
                .push_front(buffer[0..bytes_read].to_vec());
        }
    }

    async fn do_write(
        writer: &mut io::WriteHalf<TcpStream>,
        write_queue: Arc<Mutex<Option<VecDeque<Vec<u8>>>>>,
        should_shutdown: Arc<Mutex<bool>>,
    ) {
        loop {
            {
                let shutdown = *should_shutdown.lock().unwrap();
                if shutdown {
                    break;
                }
            }
            let result;
            {
                result = write_queue
                    .as_ref()
                    .lock()
                    .expect("Unable to aquire lock for write deque")
                    .as_mut()
                    .expect("Write deque is unavailable")
                    .pop_back();
            }
            match result {
                None => sleep(Duration::from_millis(500)),
                Some(data) => match writer.write_all(&data[..]).await {
                    Ok(_) => {}
                    Err(_) => {
                        println!("An error occured writing to an output stream");
                        *should_shutdown.lock().unwrap() = true;
                    }
                },
            }
        }
    }

    pub fn get_next_data(&mut self) -> Option<Vec<u8>> {
        let receive_queue_arc = &self.message_queue.receive_byte_queue;

        receive_queue_arc
            .lock()
            .expect("Unable to aquire lock for receive queue")
            .as_mut()
            .expect("Receive queue is not available")
            .pop_back()
    }

    pub fn send_data(&mut self, data: Vec<u8>) {
        let send_queue_arc = &self.message_queue.send_byte_queue;

        send_queue_arc
            .lock()
            .expect("Unable to aquire lock for queue")
            .as_mut()
            .expect("VecDeque is not available")
            .push_front(data);
    }
}
