use bip39::Language;

const LANGUAGE: Language = Language::Italian;

pub mod mnemonic {
    use bip39::{Mnemonic, MnemonicType};

    /**
     * Generate a new random menmonic
     */
    pub fn generate() -> Vec<String> {
        let mnemonic: Mnemonic = Mnemonic::new(MnemonicType::Words12, super::LANGUAGE);
        mnemonic.phrase().split(" ").map(|w| w.to_string()).collect()
    }

}

pub mod keystore {
    use bip39::Mnemonic;
    use substrate_bip39::mini_secret_from_entropy;
    use schnorrkel::{Keypair, keys, Signature};
    use anyhow::Error;

    /**
     * Get a keystore from a mnemonic phrase
     */
    pub fn private_key_from_phrase(words: &Vec<String>) -> Result<PrivateKey, Error> {
        Mnemonic::from_phrase(words.join(" ").as_str(), super::LANGUAGE)
            .and_then(|m| PrivateKey::new(m))
            .map_err(|_| Error::msg("Invalid mnemonic"))
    }

    pub struct PrivateKey {
        key_pair: Keypair
    }

    impl PrivateKey {

        /**
         * Create a new keystore from a mnemonic
         */
        pub fn new(mnemonic: Mnemonic) -> Result<Self, Error> {
            mini_secret_from_entropy(mnemonic.entropy(), "")
                .map(|secret_key| secret_key.expand_to_keypair(keys::ExpansionMode::Uniform))
                .map(|key_pair| PrivateKey { key_pair })
                .map_err(|_| Error::msg("Invalid entrophy or password"))
        }
        
        /**
         * Sign a message and return the signature
         */
        pub fn sign(&self, message: &String) -> Signature {
            self.key_pair.sign_simple(&[], &message.as_bytes())
        }

        /**
         * Get the public key
         */
        pub fn public_key(&self) -> PublicKey {
            PublicKey::new(self.key_pair.public.to_bytes()).unwrap()
        }

    }

    pub struct PublicKey {
        key: schnorrkel::PublicKey
    }

    impl PublicKey {
        pub fn new(bytes: [u8; 32]) -> Result<Self, Error> {
            schnorrkel::PublicKey::from_bytes(&bytes)
                .map(|key| PublicKey { key })
                .map_err(|_| Error::msg("Invalid public key"))
        }

        pub fn verify(&self, message: &String, signature: &Signature) -> Result<(), Error> {
            self.key.verify_simple(&[], &message.as_bytes(), &signature)
                .map_err(|_| Error::msg("Invalid signature"))
        }

        #[inline]
        pub fn to_bytes(&self) -> [u8; 32] {
            self.key.to_bytes()
        }
    }

}

#[cfg(test)]
mod vault_tests {
    use crate::vault;

    #[test]
    fn test_keystore_new() {
        // Given
        let words: Vec<String>  = "scrutinio casaccio cedibile oste tumulto irrorare notturno uffa doganale classico esercito vibrante".split(" ").map(|s| s.to_string()).collect();

        // When
        let result = vault::keystore::private_key_from_phrase(&words);

        // Then
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate() {
        // When
        let result = vault::mnemonic::generate();

        // Then
        assert_eq!(result.len(), 12);
    }

    #[test]
    fn test_sign_message() {
        // Given
        let words: Vec<String>  = "scrutinio casaccio cedibile oste tumulto irrorare notturno uffa doganale classico esercito vibrante".split(" ").map(|s| s.to_string()).collect();
        let private_key = vault::keystore::private_key_from_phrase(&words).unwrap();
        let message = "Hello, world!".to_string();

        // When
        let signature = private_key.sign(&message);

        // Then
        assert!(private_key.public_key().verify(&message, &signature).is_ok());
    }
    
}