use openssl::{
    ec, pkey,
    pkey::{Private, Public},
    sha::sha256,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
};

// Constants

const WALLET_PATH: &str = "/tmp/private_key.pem";

const MINIMUM_DIFFICULTY_LEVEL: u8 = 16;

const COIN: u64 = 1_0000_0000;
const BLOCK_REWARD: u64 = 10 * COIN;

// Types

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayerPublicKey(Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInput {
    transaction_hash: Hash,
    output_index: u16,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOutput {
    amount: u64,
    recipient_hash: Hash,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    payer: PayerPublicKey,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    signature: Signature,
}

#[derive(Debug)]
pub struct Wallet {
    public_serialized: PayerPublicKey,
    private_key: ec::EcKey<Private>,
    public_key: ec::EcKey<Public>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    nonce: u64,
    transactions: Vec<Transaction>,
    parent_hash: Hash,
    block_hash: Hash,
}

// Impls

impl Hash {
    pub fn zeroes() -> Self { Hash([0u8; 32]) }

    pub fn sha256(b: &[u8]) -> Self { Hash(sha256(b)) }

    pub fn has_difficulty(self: &Self, mut difficulty: u8) -> bool {
        for &byte in self.0.iter() {
            if difficulty == 0 {
                return true;
            } else if difficulty < 8 {
                return byte.leading_zeros() >= difficulty.into();
            } else {
                if byte != 0 {
                    return false;
                }
                difficulty -= 8;
            }
        }
        // NOTE that the u8 type is carefully chosen because it can't represent
        // any number greater than or equal to 256, or 32*8. Worst case
        // scenario, when difficulty is 255, in the last iteration of the loop
        // difficulty would be < 8 and therefore return.
        unreachable!()
    }
}

impl PayerPublicKey {
    fn check_len(self: &Self) -> bool { self.0.len() == 88 }
}

impl Transaction {
    fn to_signature_data(self: &Self) -> Vec<u8> {
        let content = (&self.payer, &self.inputs, &self.outputs);
        bincode::serialize(&content).unwrap()
    }

    fn transaction_hash(self: &Self) -> Hash { Hash::sha256(self.signature.0.as_slice()) }

    pub fn verify_signature(self: &Self) -> bool {
        fn verify(t: &Transaction) -> Result<bool, openssl::error::ErrorStack> {
            let pubkey = pkey::PKey::public_key_from_der(t.payer.0.as_slice())?;
            let eckey = pubkey.ec_key()?;
            let sig = openssl::ecdsa::EcdsaSig::from_der(&t.signature.0)?;
            sig.verify(&sha256(t.to_signature_data().as_slice()), &eckey)
        }
        self.payer.check_len() && verify(self).unwrap_or(false)
    }
}

impl PartialEq for Wallet {
    fn eq(&self, other: &Self) -> bool { self.public_serialized == other.public_serialized }
}

impl Wallet {
    fn from_privkey(privkey: ec::EcKey<Private>) -> Result<Self, openssl::error::ErrorStack> {
        privkey.check_key()?;
        let ecg = privkey.group();
        let correct_type = ecg.curve_name().map_or(false, |nid| nid == openssl::nid::Nid::SECP256K1);
        assert!(correct_type);
        let pubkey = ec::EcKey::from_public_key(ecg, privkey.public_key())?;
        Ok(Wallet {
            private_key: privkey,
            public_key: pubkey.clone(),
            public_serialized: PayerPublicKey(pkey::PKey::from_ec_key(pubkey)?.public_key_to_der()?),
        })
    }

    pub fn new() -> Self {
        let ecg = ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1).unwrap();
        let privkey = ec::EcKey::generate(ecg.as_ref()).unwrap();
        Wallet::from_privkey(privkey).unwrap()
    }

    fn create_raw_transaction(
        self: &Self, inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>,
    ) -> Transaction {
        assert!(inputs.len() < 256);
        assert!(outputs.len() < 256);
        let mut txn =
            Transaction { payer: self.public_serialized.clone(), inputs, outputs, signature: Signature(vec![]) };
        let sig =
            openssl::ecdsa::EcdsaSig::sign(&sha256(txn.to_signature_data().as_slice()), &self.private_key).unwrap();
        let sig_der = sig.to_der().unwrap();
        txn.signature = Signature(sig_der);
        assert!(txn.verify_signature(), "newly created signature should be verified");
        txn
    }

    fn save_to_disk(self: &Self) -> std::io::Result<()> {
        let pem = self.private_key.private_key_to_pem().unwrap();
        let mut f = File::create(WALLET_PATH)?;
        f.write_all(pem.as_slice())
    }

    fn load_from_disk() -> Option<Self> {
        fn read() -> std::io::Result<Vec<u8>> {
            let mut f = File::open(WALLET_PATH)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            Ok(buf)
        }
        fn des(buf: Vec<u8>) -> Result<Wallet, openssl::error::ErrorStack> {
            let eckey = ec::EcKey::private_key_from_pem(buf.as_slice())?;
            Wallet::from_privkey(eckey)
        }
        read().ok().and_then(|buf| des(buf).ok())
    }
}

impl Block {
    fn to_hash_challenge(self: &Self) -> Vec<u8> {
        let content = (&self.nonce, &self.transactions, &self.parent_hash);
        bincode::serialize(&content).unwrap()
    }

    pub fn solve_hash_challenge(self: &mut Self, difficulty: u8, max_tries: Option<u64>) -> bool {
        let mut b = self.to_hash_challenge();
        for _ in 0..max_tries.unwrap_or(1 << 63) {
            let this_hash = Hash::sha256(&b);
            if this_hash.has_difficulty(difficulty) {
                self.block_hash = this_hash;
                return true;
            }
            self.nonce += 1;
            self.nonce %= 1 << 63;
            bincode::serialize_into(&mut b[0..8], &self.nonce).unwrap();
            debug_assert_eq!(b, self.to_hash_challenge());
        }
        false
    }

    pub fn verify_difficulty(self: &Self, difficulty: u8) -> bool { self.block_hash.has_difficulty(difficulty) }

    pub fn verify_hash_challenge(self: &Self, difficulty: u8) -> bool {
        self.verify_difficulty(difficulty) && self.block_hash == Hash::sha256(&self.to_hash_challenge())
    }

    fn new_mine_block(w: &Wallet) -> Self {
        Block {
            parent_hash: Hash::zeroes(),
            block_hash: Hash::zeroes(),
            nonce: 0,
            transactions: vec![w.create_raw_transaction(vec![], vec![TransactionOutput {
                recipient_hash: Hash::sha256(&w.public_serialized.0),
                amount: BLOCK_REWARD,
            }])],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_wallet() {
        let w = Wallet::new();
        assert!(w.public_serialized.check_len());
    }

    #[test]
    fn can_create_raw_transaction() {
        let w = Wallet::new();
        w.create_raw_transaction(vec![], vec![]);
    }

    #[test]
    fn round_trips_to_disk() {
        let w = Wallet::new();
        assert!(w.save_to_disk().is_ok());
        let w2 = Wallet::load_from_disk().unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn serialized_block_has_nonce_first() {
        let b = Block {
            nonce: 0x4142434445464748,
            transactions: vec![],
            parent_hash: Hash::zeroes(),
            block_hash: Hash::zeroes(),
        };
        assert_eq!(&b.to_hash_challenge()[0..8], bincode::serialize(&b.nonce).unwrap().as_slice());
    }

    #[test]
    fn can_solve_hash_challenge() {
        let mut b = Block { nonce: 0, transactions: vec![], parent_hash: Hash::zeroes(), block_hash: Hash::zeroes() };
        assert!(b.solve_hash_challenge(16, None));
        eprintln!("Block with solved hash challenge: {:?}", b);
        assert_ne!(b.block_hash, Hash::zeroes());
        assert!(b.verify_hash_challenge(16));
    }
}
