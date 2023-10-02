use bip39::{Mnemonic, MnemonicType, Language, Seed};
use ed25519_dalek::{SecretKey, SigningKey};
use rand::{RngCore, SeedableRng};
use rsa::{RsaPrivateKey, rand_core::CryptoRngCore};
use schnorrkel::{keys, Keypair, Signature};
use substrate_bip39::mini_secret_from_entropy;

fn main() {
    let mnemonic: Mnemonic = Mnemonic::new(MnemonicType::Words12, Language::Italian);
    let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();

    println!("Entropy length {}", mnemonic.entropy().len());
    let key_pair: Keypair = mini_secret_from_entropy(mnemonic.entropy(), "")
        .expect("Invalid")
        .expand_to_keypair(keys::ExpansionMode::Uniform);

    let signature: Signature = key_pair.sign_simple(&[], message);



    
    /*let priv_key = create_private_key(&seed.as_bytes());

    let data = b"value";
    println!("{}", std::str::from_utf8(data).unwrap());

    let enc_data = encrypt(&priv_key, &data);  

    let res = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
    println!("{}", std::str::from_utf8(&res[..]).unwrap());*/
}

fn generate_private_key(seed: &Seed) -> SecretKey {
    let private_key = SecretKey::from_bytes(&seed.as_bytes()).expect("Invalid seed");
    private_key
}



/*fn create_private_key(seed_bytes: &[u8]) -> RsaPrivateKey {
    let mut rng = ThreadRng(rng: seed_bytes);
    return RsaPrivateKey::new(&mut rng, KEY_BITS).expect("failed to generate a key")
}

fn encrypt(priv_key: &RsaPrivateKey, data: &[u8; 5]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let pub_key = RsaPublicKey::from(priv_key);
    pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt")
}*/