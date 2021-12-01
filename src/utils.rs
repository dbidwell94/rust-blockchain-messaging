use rand::rngs::OsRng;
use rsa::{
    pkcs1::{FromRsaPrivateKey, FromRsaPublicKey, ToRsaPrivateKey, ToRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};

pub fn get_keys() -> (RsaPrivateKey, RsaPublicKey) {
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
        Err(_) => {}
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
