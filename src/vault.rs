pub mod mnemonic {
    use anyhow::Error;
    use bip39::{Mnemonic, MnemonicType, Language};
    use schnorrkel::{Keypair, keys, Signature, PublicKey};
    use substrate_bip39::mini_secret_from_entropy;

    const LANGUAGE: Language = Language::Italian;

    /**
     * Generate a new random menmonic
     */
    pub fn generate() -> Vec<String> {
        let mnemonic: Mnemonic = Mnemonic::new(MnemonicType::Words12, LANGUAGE);
        mnemonic.phrase().split(" ").map(|w| w.to_string()).collect()
    }

    /**
     * Get a keystore from a mnemonic phrase
     */
    pub fn keystore_from_phrase(words: &Vec<String>) -> Result<Keystore, Error> {
        Mnemonic::from_phrase(words.join(" ").as_str(), LANGUAGE)
            .and_then(|m| Keystore::new(m))
            .map_err(|_| Error::msg("Invalid mnemonic"))
    }

    pub struct Keystore {
        key_pair: Keypair
    }

    impl Keystore {
        /**
         * Create a new keystore from a mnemonic
         */
        pub fn new(mnemonic: Mnemonic) -> Result<Self, Error> {
            mini_secret_from_entropy(mnemonic.entropy(), "")
                .map(|secret_key| secret_key.expand_to_keypair(keys::ExpansionMode::Uniform))
                .map(|key_pair| Keystore { key_pair })
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
            self.key_pair.public
        }

    }
}

#[cfg(test)]
mod tests {
    use crate::vault;

    #[test]
    fn test_keystore_new() {
        // Given
        let words: Vec<String>  = "scrutinio casaccio cedibile oste tumulto irrorare notturno uffa doganale classico esercito vibrante".split(" ").map(|s| s.to_string()).collect();

        // When
        let result = vault::mnemonic::keystore_from_phrase(&words);

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
        let keystore = vault::mnemonic::keystore_from_phrase(&words).unwrap();
        let message = "Hello, world!".to_string();

        // When
        let signature = keystore.sign(&message);

        // Then
        assert!(keystore.public_key().verify_simple(&[], &message.as_bytes(), &signature).is_ok());
    }
    
}