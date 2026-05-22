use crate::error::{LocalPassError, Result};
use rand::distributions::{Distribution, Uniform};
use rand::rngs::OsRng;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

pub struct GeneratorOptions {
    pub length: usize,
    pub symbols: bool,
    pub no_upper: bool,
    pub no_digits: bool,
}

pub fn generate_password(options: &GeneratorOptions) -> Result<String> {
    if options.length == 0 {
        return Err(LocalPassError::InvalidGeneratorOptions);
    }

    let mut alphabet = Vec::new();
    alphabet.extend_from_slice(LOWER);
    if !options.no_upper {
        alphabet.extend_from_slice(UPPER);
    }
    if !options.no_digits {
        alphabet.extend_from_slice(DIGITS);
    }
    if options.symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }

    let mut output = String::with_capacity(options.length);
    let distribution = Uniform::from(0..alphabet.len());
    let mut rng = OsRng;
    for _ in 0..options.length {
        let index = distribution.sample(&mut rng);
        output.push(alphabet[index] as char);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_length() {
        let password = generate_password(&GeneratorOptions {
            length: 24,
            symbols: true,
            no_upper: false,
            no_digits: false,
        })
        .unwrap();

        assert_eq!(password.len(), 24);
    }

    #[test]
    fn rejects_zero_length_passwords() {
        let result = generate_password(&GeneratorOptions {
            length: 0,
            symbols: false,
            no_upper: true,
            no_digits: true,
        });

        assert!(matches!(
            result,
            Err(LocalPassError::InvalidGeneratorOptions)
        ));
    }

    #[test]
    fn respects_disabled_character_sets() {
        let password = generate_password(&GeneratorOptions {
            length: 64,
            symbols: false,
            no_upper: true,
            no_digits: true,
        })
        .unwrap();

        assert!(
            password
                .chars()
                .all(|character| character.is_ascii_lowercase())
        );
    }
}
