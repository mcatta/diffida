pub mod base64 {
    use anyhow::Error;
    use base64::{engine::general_purpose, Engine};

    pub fn encode(input: &[u8]) -> String {
        general_purpose::STANDARD_NO_PAD.encode(input)
    }

    pub fn decode(input: &str) -> Result<Vec<u8>, Error> {
        general_purpose::STANDARD_NO_PAD.decode(input)
            .map_err(|_| Error::msg("Error on decoding"))
    }
}

mod hasher_tess {
    use crate::hasher;

    #[test]
    fn test_base64_encode() {
        // Given
        let input = "Hello World!";

        // When
        let result = hasher::base64::encode(input.as_bytes());

        // Then
        assert_eq!(result, "SGVsbG8gV29ybGQh");
    }

    #[test]
    fn test_base64_decode() {
        // Given
        let input = "SGVsbG8gV29ybGQh";

        // When
        let result = hasher::base64::decode(input).unwrap();

        // Then
        assert_eq!(result, "Hello World!".as_bytes());
    }
}