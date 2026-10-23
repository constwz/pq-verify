use std::{
    borrow::Cow,
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    path::Path,
};

use crate::{
    Result,
    oqs::{self, Verifier},
};

pub(crate) struct Corpus {
    pub(crate) keys: Vec<Vec<u8>>,
    wrong_key: Vec<u8>,
    pub(crate) samples: Vec<Sample>,
    pub(crate) messages_per_key: usize,
}

pub(crate) struct Sample {
    pub(crate) message: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    Valid,
    WrongMessage,
    WrongKey,
    // Separate positions: Falcon rejects a bad header byte in ~100 ns but a bad
    // body byte only after full verification; pooling them yields bimodal rows.
    CorruptHead,
    CorruptMid,
    CorruptTail,
    Truncated,
    Extended,
}

pub(crate) struct Input<'a> {
    pub(crate) pk: &'a [u8],
    pub(crate) message: Cow<'a, [u8]>,
    pub(crate) signature: Cow<'a, [u8]>,
}

impl Case {
    pub(crate) const ALL: [Self; 8] = [
        Self::Valid,
        Self::WrongMessage,
        Self::WrongKey,
        Self::CorruptHead,
        Self::CorruptMid,
        Self::CorruptTail,
        Self::Truncated,
        Self::Extended,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::WrongMessage => "wrong-message",
            Self::WrongKey => "wrong-key",
            Self::CorruptHead => "corrupt-head",
            Self::CorruptMid => "corrupt-mid",
            Self::CorruptTail => "corrupt-tail",
            Self::Truncated => "truncated",
            Self::Extended => "extended",
        }
    }
}

impl Corpus {
    pub(crate) fn load_or_generate(
        path: &Path,
        verifier: &Verifier,
        keys: usize,
        messages: usize,
        message_bytes: usize,
    ) -> Result<Self> {
        let corpus = if path.exists() {
            let max_bytes = 1024
                + (keys + 1) * verifier.public_key_len
                + keys * messages * (message_bytes + verifier.signature_max + 16);
            if fs::metadata(path)?.len() > max_bytes as u64 {
                return Err("oversized corpus".into());
            }
            let bytes = fs::read(path)?;
            Self::decode(&bytes, verifier, keys, messages, message_bytes)?
        } else {
            let corpus = Self::generate(verifier, keys, messages, message_bytes)?;
            let bytes = corpus.encode(&verifier.name, message_bytes)?;
            // A failed write remains visibly invalid on the next run, never silently regenerated.
            let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            corpus
        };
        corpus.validate(verifier)?;
        Ok(corpus)
    }

    fn generate(verifier: &Verifier, keys: usize, messages: usize, bytes: usize) -> Result<Self> {
        let (wrong_key, _) = verifier.keypair()?;
        let mut corpus = Self {
            keys: Vec::with_capacity(keys),
            wrong_key,
            samples: Vec::with_capacity(keys * messages),
            messages_per_key: messages,
        };
        for _ in 0..keys {
            let (pk, sk) = verifier.keypair()?;
            for _ in 0..messages {
                let message = oqs::random_message(bytes);
                let signature = verifier.sign(&sk, &message)?;
                corpus.samples.push(Sample { message, signature });
            }
            corpus.keys.push(pk);
        }
        Ok(corpus)
    }

    pub(crate) fn inputs(&self, case: Case) -> Vec<Input<'_>> {
        self.samples
            .iter()
            .enumerate()
            .map(|(i, sample)| {
                let key = i / self.messages_per_key;
                let mut input = Input {
                    pk: &self.keys[key],
                    message: Cow::Borrowed(&sample.message),
                    signature: Cow::Borrowed(&sample.signature),
                };
                let last = sample.signature.len() - 1;
                match case {
                    Case::Valid => {}
                    Case::WrongMessage => {
                        input.message.to_mut()[0] ^= 1;
                    }
                    // Another account's key keeps the public-key working set equal to
                    // `valid`; the extra key is only needed when there is one account.
                    Case::WrongKey => {
                        input.pk = if self.keys.len() > 1 {
                            &self.keys[(key + 1) % self.keys.len()]
                        } else {
                            &self.wrong_key
                        };
                    }
                    Case::CorruptHead => input.signature.to_mut()[0] ^= 1,
                    Case::CorruptMid => input.signature.to_mut()[last / 2] ^= 1,
                    Case::CorruptTail => input.signature.to_mut()[last] ^= 1,
                    Case::Truncated => {
                        input.signature = Cow::Borrowed(&sample.signature[..last]);
                    }
                    // Falcon accepts zero bytes that pad a signature to its fixed padded
                    // size, so a zero would complete one that is a byte short of it.
                    Case::Extended => {
                        input.signature.to_mut().push(0xff);
                    }
                }
                input
            })
            .collect()
    }

    fn validate(&self, verifier: &Verifier) -> Result<()> {
        for case in Case::ALL {
            for (i, input) in self.inputs(case).iter().enumerate() {
                if verifier.verify(input.pk, &input.message, &input.signature)
                    != (case == Case::Valid)
                {
                    return Err(format!(
                        "{} sample {i}: unexpected result for {}",
                        verifier.name,
                        case.name()
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    fn encode(&self, algorithm: &str, message_bytes: usize) -> Result<Vec<u8>> {
        let mut out = b"PQVB0001".to_vec();
        put_bytes(&mut out, algorithm.as_bytes())?;
        for n in [self.keys.len(), self.messages_per_key, message_bytes] {
            put_u64(&mut out, n as u64)?;
        }
        for key in self.keys.iter().chain(std::iter::once(&self.wrong_key)) {
            put_bytes(&mut out, key)?;
        }
        for sample in &self.samples {
            put_bytes(&mut out, &sample.message)?;
            put_bytes(&mut out, &sample.signature)?;
        }
        Ok(out)
    }

    fn decode(
        bytes: &[u8],
        verifier: &Verifier,
        keys: usize,
        messages: usize,
        message_bytes: usize,
    ) -> Result<Self> {
        let mut reader = Cursor::new(bytes);
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        if &magic != b"PQVB0001" {
            return Err("invalid corpus format".into());
        }
        if read_bytes(&mut reader, 128)? != verifier.name.as_bytes() {
            return Err("corpus algorithm mismatch".into());
        }
        for expected in [keys, messages, message_bytes] {
            if read_u64(&mut reader)? != expected as u64 {
                return Err("corpus dimensions mismatch".into());
            }
        }
        let mut public_keys = Vec::with_capacity(keys);
        for _ in 0..keys {
            public_keys.push(read_exact_bytes(&mut reader, verifier.public_key_len)?);
        }
        let wrong_key = read_exact_bytes(&mut reader, verifier.public_key_len)?;
        let mut samples = Vec::with_capacity(keys * messages);
        for _ in 0..keys * messages {
            let message = read_exact_bytes(&mut reader, message_bytes)?;
            let signature = read_bytes(&mut reader, verifier.signature_max)?;
            if signature.is_empty() {
                return Err("empty corpus signature".into());
            }
            samples.push(Sample { message, signature });
        }
        if reader.position() != bytes.len() as u64 {
            return Err("trailing corpus data".into());
        }
        Ok(Self { keys: public_keys, wrong_key, samples, messages_per_key: messages })
    }
}

fn put_u64(out: &mut impl Write, value: u64) -> Result<()> {
    out.write_all(&value.to_le_bytes())?;
    Ok(())
}
fn put_bytes(out: &mut impl Write, bytes: &[u8]) -> Result<()> {
    put_u64(out, bytes.len() as u64)?;
    out.write_all(bytes)?;
    Ok(())
}
fn read_u64(reader: &mut impl Read) -> Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
fn read_bytes(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let len = read_u64(reader)?;
    if len > maximum as u64 {
        return Err("invalid corpus field length".into());
    }
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn read_exact_bytes(reader: &mut impl Read, expected: usize) -> Result<Vec<u8>> {
    let bytes = read_bytes(reader, expected)?;
    if bytes.len() != expected {
        return Err("invalid corpus field length".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_algorithms_reject_negative_cases_and_corpus_damage() -> Result<()> {
        oqs::init();
        for name in crate::all_algorithms() {
            let verifier = Verifier::new(&name)?;
            let corpus = Corpus::generate(&verifier, 2, 2, 32)?;
            corpus.validate(&verifier)?;
            let wrong: Vec<_> = corpus.inputs(Case::WrongKey).iter().map(|i| i.pk).collect();
            let (k0, k1) = (corpus.keys[0].as_slice(), corpus.keys[1].as_slice());
            assert_eq!(wrong, [k1, k1, k0, k0]);
            let single = Corpus::generate(&verifier, 1, 1, 32)?;
            single.validate(&verifier)?;
            assert_eq!(single.inputs(Case::WrongKey)[0].pk, single.wrong_key.as_slice());
            let bytes = corpus.encode(&name, 32)?;
            let restored = Corpus::decode(&bytes, &verifier, 2, 2, 32)?;
            restored.validate(&verifier)?;
            assert_eq!(bytes, restored.encode(&name, 32)?);
            assert!(Corpus::decode(&bytes, &verifier, 1, 1, 32).is_err());
            assert!(Corpus::decode(&bytes[..bytes.len() - 1], &verifier, 2, 2, 32).is_err());
            let mut damaged = bytes.clone();
            *damaged.last_mut().unwrap() ^= 1;
            assert!(Corpus::decode(&damaged, &verifier, 2, 2, 32)?.validate(&verifier).is_err());
            let mut oversized = bytes;
            oversized[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(Corpus::decode(&oversized, &verifier, 2, 2, 32).is_err());
        }
        Ok(())
    }

    #[test]
    fn extended_signature_stays_invalid_one_byte_below_falcon_padded_size() -> Result<()> {
        const FALCON_512_PADDED_BYTES: usize = 666;
        oqs::init();
        let verifier = Verifier::new("Falcon-512")?;
        let (pk, sk) = verifier.keypair()?;
        let message = oqs::random_message(32);
        let mut signature = verifier.sign(&sk, &message)?;
        signature.resize(FALCON_512_PADDED_BYTES - 1, 0);
        let mut padded = signature.clone();
        padded.push(0);
        assert!(verifier.verify(&pk, &message, &padded));

        let corpus = Corpus {
            keys: vec![pk],
            wrong_key: Vec::new(),
            samples: vec![Sample { message, signature }],
            messages_per_key: 1,
        };
        let input = &corpus.inputs(Case::Extended)[0];
        assert!(!verifier.verify(input.pk, &input.message, &input.signature));
        Ok(())
    }
}
