use expanduser::expanduser;
use openssl::{
    ec, pkey,
    pkey::{Private, Public},
    sha::sha256,
};
use rusqlite as sql;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
};

// Constants

const WALLET_PATH: &str = "~/.config/rs_simple_blockchain/wallet.pem";

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

#[derive(Debug)]
pub struct BlockchainStorage {
    path: Option<std::path::PathBuf>,
    conn: sql::Connection,
    default_wallet: Wallet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockchainStats {
    pub block_count: u64,
    pub pending_txn_count: u64,
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

impl sql::ToSql for Hash {
    fn to_sql(self: &Self) -> sql::Result<sql::types::ToSqlOutput> { (&self.0[..]).to_sql() }
}

impl PayerPublicKey {
    fn check_len(self: &Self) -> bool { self.0.len() == 88 }
}

impl sql::ToSql for PayerPublicKey {
    fn to_sql(self: &Self) -> sql::Result<sql::types::ToSqlOutput> { (&self.0[..]).to_sql() }
}

impl sql::ToSql for Signature {
    fn to_sql(self: &Self) -> sql::Result<sql::types::ToSqlOutput> { (&self.0[..]).to_sql() }
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
        let path = expanduser(WALLET_PATH)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut f = File::create(path)?;
        f.write_all(pem.as_slice())
    }

    fn load_from_disk() -> Option<Self> {
        fn read() -> std::io::Result<Vec<u8>> {
            let mut f = File::open(expanduser(WALLET_PATH)?)?;
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

impl BlockchainStorage {
    fn open_conn(path: Option<&std::path::Path>) -> sql::Connection {
        let conn = match path {
            None => sql::Connection::open_in_memory().unwrap(),
            Some(ref p) => sql::Connection::open(p).unwrap(),
        };
        assert!(conn.is_autocommit());
        conn.execute_batch(
            "
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS blocks (
                    block_hash BLOB NOT NULL PRIMARY KEY ON CONFLICT IGNORE,
                    parent_hash BLOB REFERENCES blocks (block_hash),
                    block_height INTEGER NOT NULL DEFAULT 0,
                    nonce INTEGER NOT NULL,
                    discovered_at REAL NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0),
                    CHECK ( block_height >= 0 ),
                    CHECK ( nonce >= 0 ),
                    CHECK ( length(block_hash) = 32 OR block_hash = x'deadface' )
                );
                CREATE INDEX IF NOT EXISTS block_parent ON blocks (parent_hash);
                CREATE INDEX IF NOT EXISTS block_height ON blocks (block_height);
                CREATE INDEX IF NOT EXISTS block_discovered_at ON blocks (discovered_at);
                CREATE TRIGGER IF NOT EXISTS set_block_height
                AFTER INSERT ON blocks
                FOR EACH ROW BEGIN
                    UPDATE blocks
                    SET block_height = (SELECT ifnull((SELECT 1 + block_height FROM blocks WHERE block_hash = NEW.parent_hash), 0))
                    WHERE block_hash = NEW.block_hash;
                END;

                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_hash BLOB NOT NULL PRIMARY KEY ON CONFLICT IGNORE,
                    payer BLOB NOT NULL,
                    payer_hash BLOB NOT NULL,
                    discovered_at REAL NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0),
                    signature BLOB NOT NULL,
                    CHECK ( length(transaction_hash) = 32 ),
                    CHECK ( length(payer) = 88 ),
                    CHECK ( length(payer_hash) = 32 )
                );
                CREATE INDEX IF NOT EXISTS transaction_payer ON transactions (payer_hash);

                CREATE TABLE IF NOT EXISTS transaction_in_block (
                    transaction_hash BLOB NOT NULL REFERENCES transactions,
                    block_hash BLOB NOT NULL REFERENCES blocks ON DELETE CASCADE,
                    transaction_index INTEGER NOT NULL,
                    UNIQUE (transaction_hash, block_hash),
                    UNIQUE (block_hash, transaction_index),
                    CHECK ( transaction_index BETWEEN 0 AND 1999 )
                );

                CREATE TABLE IF NOT EXISTS transaction_outputs (
                    out_transaction_hash BLOB NOT NULL REFERENCES transactions (transaction_hash),
                    out_transaction_index INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    recipient_hash BLOB NOT NULL,
                    PRIMARY KEY (out_transaction_hash, out_transaction_index) ON CONFLICT IGNORE,
                    UNIQUE (out_transaction_hash, recipient_hash),
                    CHECK ( amount > 0 ),
                    CHECK ( out_transaction_index BETWEEN 0 AND 255 ),
                    CHECK ( length(recipient_hash) = 32 )
                );
                CREATE INDEX IF NOT EXISTS output_recipient ON transaction_outputs (recipient_hash);

                CREATE TABLE IF NOT EXISTS transaction_inputs (
                    in_transaction_hash BLOB NOT NULL REFERENCES transactions (transaction_hash),
                    in_transaction_index INTEGER NOT NULL,
                    out_transaction_hash BLOB NOT NULL,
                    out_transaction_index INTEGER NOT NULL,
                    PRIMARY KEY (in_transaction_hash, in_transaction_index) ON CONFLICT IGNORE,
                    FOREIGN KEY(out_transaction_hash, out_transaction_index) REFERENCES transaction_outputs DEFERRABLE INITIALLY DEFERRED,
                    CHECK ( in_transaction_index BETWEEN 0 AND 255 )
                );
                CREATE INDEX IF NOT EXISTS input_referred ON transaction_inputs (out_transaction_hash, out_transaction_index);

                CREATE TABLE IF NOT EXISTS trustworthy_wallets (
                    payer_hash BLOB NOT NULL PRIMARY KEY ON CONFLICT IGNORE,
                    CHECK ( length(payer_hash) = 32 )
                );

                CREATE VIEW IF NOT EXISTS unauthorized_spending AS
                SELECT transactions.*, transaction_outputs.recipient_hash AS owner_hash, transaction_outputs.amount
                FROM transactions
                JOIN transaction_inputs ON transactions.transaction_hash = transaction_inputs.in_transaction_hash
                JOIN transaction_outputs USING (out_transaction_hash, out_transaction_index)
                WHERE payer_hash != owner_hash;

                CREATE VIEW IF NOT EXISTS transaction_credit_debit AS
                WITH
                transaction_debits AS (
                    SELECT out_transaction_hash AS transaction_hash, sum(amount) AS debited_amount
                    FROM transaction_outputs
                    GROUP BY transaction_hash
                ),
                transaction_credits AS (
                    SELECT in_transaction_hash AS transaction_hash, sum(transaction_outputs.amount) AS credited_amount
                    FROM transaction_inputs JOIN transaction_outputs USING (out_transaction_hash, out_transaction_index)
                    GROUP BY transaction_hash
                )
                SELECT * FROM transaction_credits
                JOIN transaction_debits USING (transaction_hash)
                JOIN transactions USING (transaction_hash);

                CREATE VIEW IF NOT EXISTS ancestors AS
                WITH RECURSIVE
                ancestors AS (
                    SELECT block_hash, block_hash AS ancestor, 0 AS path_length FROM blocks
                    UNION ALL
                    SELECT ancestors.block_hash, blocks.parent_hash AS ancestor, 1 + path_length AS path_length
                    FROM ancestors JOIN blocks ON ancestor = blocks.block_hash
                    WHERE blocks.parent_hash IS NOT NULL
                )
                SELECT * FROM ancestors;

                CREATE VIEW IF NOT EXISTS longest_chain AS
                WITH RECURSIVE
                initial AS (SELECT * FROM blocks ORDER BY block_height DESC, discovered_at ASC LIMIT 1),
                chain AS (
                    SELECT block_hash, parent_hash, block_height, 1 AS confirmations FROM initial
                    UNION ALL
                    SELECT blocks.block_hash, blocks.parent_hash, blocks.block_height, 1 + confirmations
                        FROM blocks JOIN chain ON blocks.block_hash = chain.parent_hash
                )
                SELECT * FROM chain;

                CREATE VIEW IF NOT EXISTS all_tentative_txns AS
                WITH lc_transaction_in_block AS (
                    SELECT transaction_in_block.* FROM transaction_in_block JOIN longest_chain USING (block_hash)
                ),
                txns_not_on_longest AS (
                    SELECT transaction_hash, payer, signature, discovered_at
                    FROM transactions LEFT JOIN lc_transaction_in_block USING (transaction_hash)
                    WHERE block_hash IS NULL
                )
                SELECT * from txns_not_on_longest WHERE transaction_hash IN (SELECT in_transaction_hash FROM transaction_inputs);

                CREATE VIEW IF NOT EXISTS utxo AS
                WITH tx_confirmations AS (
                    SELECT transaction_in_block.transaction_hash, longest_chain.confirmations
                    FROM transaction_in_block JOIN longest_chain USING (block_hash)
                ),
                all_utxo AS (
                    SELECT transaction_outputs.*
                    FROM transaction_outputs LEFT JOIN transaction_inputs USING (out_transaction_hash, out_transaction_index)
                    WHERE in_transaction_index IS NULL
                ),
                all_utxo_confirmations AS (
                    SELECT all_utxo.*, ifnull(tx_confirmations.confirmations, 0) AS confirmations
                    FROM all_utxo LEFT JOIN tx_confirmations ON all_utxo.out_transaction_hash = tx_confirmations.transaction_hash
                ),
                trustworthy_even_if_unconfirmed AS (
                    SELECT transaction_hash
                    FROM transactions
                    JOIN trustworthy_wallets USING (payer_hash)
                    JOIN transaction_inputs ON transactions.transaction_hash = transaction_inputs.in_transaction_hash
                )
                SELECT *
                FROM all_utxo_confirmations
                WHERE confirmations > 0 OR out_transaction_hash IN (SELECT transaction_hash FROM trustworthy_even_if_unconfirmed);

                CREATE VIEW IF NOT EXISTS block_consistency AS
                SELECT block_hash AS perspective_block, (
                   WITH
                   my_ancestors AS (
                       SELECT ancestor AS block_hash FROM ancestors WHERE block_hash = ob.block_hash
                   ),
                   my_transaction_in_block AS (
                       SELECT transaction_in_block.* FROM transaction_in_block JOIN my_ancestors USING (block_hash)
                   ),
                   my_transaction_inputs AS (
                       SELECT transaction_inputs.*
                       FROM transaction_inputs JOIN my_transaction_in_block
                       ON transaction_inputs.in_transaction_hash = my_transaction_in_block.transaction_hash
                   ),
                   my_transaction_outputs AS (
                       SELECT transaction_outputs.*
                       FROM transaction_outputs JOIN my_transaction_in_block
                       ON transaction_outputs.out_transaction_hash = my_transaction_in_block.transaction_hash
                   ),
                   error_input_referring_to_nonexistent_outputs AS (
                       SELECT count(*) AS violations_count
                       FROM my_transaction_inputs LEFT JOIN my_transaction_outputs USING (out_transaction_hash, out_transaction_index)
                       WHERE my_transaction_outputs.amount IS NULL
                   ),
                   error_double_spent AS (
                       SELECT count(*) AS violations_count FROM (
                           SELECT count(*) AS spent_times
                           FROM my_transaction_outputs JOIN my_transaction_inputs USING (out_transaction_hash, out_transaction_index)
                           GROUP BY out_transaction_hash, out_transaction_index
                           HAVING spent_times > 1
                       )
                   )
                   SELECT (SELECT violations_count FROM error_input_referring_to_nonexistent_outputs) +
                          (SELECT violations_count FROM error_double_spent)
                ) AS total_violations_count
                FROM blocks AS ob;").unwrap();
        conn
    }
    pub fn new(path: Option<&std::path::Path>, default_wallet: Option<Wallet>) -> Self {
        BlockchainStorage {
            default_wallet: default_wallet.or_else(Wallet::load_from_disk).unwrap_or_else(|| {
                let w = Wallet::new();
                w.save_to_disk().unwrap();
                w
            }),
            path: path.map(|p| p.to_path_buf()),
            conn: BlockchainStorage::open_conn(path),
        }
    }

    pub fn recreate_db(self: &mut Self) {
        fn unlink_ignore_enoent(p: &std::path::Path) -> std::io::Result<()> {
            std::fs::remove_file(p).or_else(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(e),
            })
        }
        fn add(p: &std::path::Path, suffix: &str) -> std::path::PathBuf {
            let mut f = p.file_name().unwrap().to_os_string();
            f.push(suffix);
            p.with_file_name(f)
        }

        // First, drop the database. (There's no "invalid" state for the
        // Connection object so we supply a new, blank connection.)
        std::mem::replace(&mut self.conn, sql::Connection::open_in_memory().unwrap());

        // Then, unlink all files, if needed and present.
        if let Some(ref p) = self.path {
            unlink_ignore_enoent(p).unwrap();
            unlink_ignore_enoent(&add(p, "-shm")).unwrap();
            unlink_ignore_enoent(&add(p, "-wal")).unwrap();
        }

        // Finally, recreate the database on disk.
        std::mem::replace(&mut self.conn, BlockchainStorage::open_conn(self.path.as_ref().map(|p| p.as_path())));
    }

    pub fn produce_stats(self: &mut Self) -> sql::Result<BlockchainStats> {
        let t = self.conn.transaction()?;
        Ok(BlockchainStats {
            block_count: {
                let mut stmt = t.prepare_cached("SELECT 1 + ifnull((SELECT max(block_height) FROM blocks), -1)")?;
                stmt.query_row(sql::NO_PARAMS, |r| r.get::<_, i64>(0))? as u64
            },
            pending_txn_count: {
                let mut stmt = t.prepare_cached("SELECT count(*) FROM all_tentative_txns")?;
                stmt.query_row(sql::NO_PARAMS, |r| r.get::<_, i64>(0))? as u64
            },
        })
    }

    pub fn make_wallet_trustworthy(self: &mut Self, h: &Hash) -> sql::Result<()> {
        let mut stmt = self.conn.prepare_cached("INSERT INTO trustworthy_wallets VALUES (?)")?;
        stmt.execute(&[&h.0[..]])?;
        Ok(())
    }

    pub fn make_wallet(self: &mut Self) -> sql::Result<Wallet> {
        let w = Wallet::new();
        self.make_wallet_trustworthy(&Hash::sha256(&w.public_serialized.0))?;
        Ok(w)
    }

    fn insert_raw_transaction(t: &sql::Transaction, txn: &Transaction) -> sql::Result<()> {
        let txn_hash = txn.transaction_hash();
        let row_count = {
            let mut stmt = t.prepare_cached(
                "INSERT INTO transactions (transaction_hash, payer, payer_hash, signature) VALUES (?,?,?,?)",
            )?;
            let params: [&dyn sql::ToSql; 4] = [&txn_hash, &txn.payer, &Hash::sha256(&txn.payer.0), &txn.signature];
            stmt.execute(&params)?
        };
        if row_count > 0 {
            {
                let mut stmt = t.prepare_cached("INSERT INTO transaction_outputs VALUES (?,?,?,?)")?;
                for (index, out) in txn.outputs.iter().enumerate() {
                    let params: [&dyn sql::ToSql; 4] =
                        [&txn_hash, &(index as i64), &(out.amount as i64), &out.recipient_hash];
                    stmt.execute(&params)?;
                }
            }
            {
                let mut stmt = t.prepare_cached("INSERT INTO transaction_inputs VALUES (?,?,?,?)")?;
                for (index, inp) in txn.inputs.iter().enumerate() {
                    let params: [&dyn sql::ToSql; 4] =
                        [&txn_hash, &(index as i64), &inp.transaction_hash, &(inp.output_index)];
                    stmt.execute(&params)?;
                }
            }
        }
        Ok(())
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

    #[test]
    fn can_create_bs() {
        BlockchainStorage::new(None, None);
        let path = std::path::Path::new("/tmp/storage.db");
        BlockchainStorage::new(Some(&path), None);
        assert!(path.exists());
    }

    #[test]
    fn can_recreate_db() {
        let path = std::path::Path::new("/tmp/storage.db");
        let mut bs = BlockchainStorage::new(Some(&path), None);
        // TODO add some stuff to the db and later check it's not there
        bs.recreate_db();
    }

    #[test]
    fn can_produce_empty_stats() {
        let mut bs = BlockchainStorage::new(None, None);
        assert_eq!(bs.produce_stats().unwrap(), BlockchainStats { pending_txn_count: 0, block_count: 0 });
    }

    #[test]
    fn can_create_trustworthy_wallet() {
        let mut bs = BlockchainStorage::new(None, None);
        bs.make_wallet().unwrap();
        assert_eq!(
            bs.conn
                .query_row("SELECT count(*) FROM trustworthy_wallets", sql::NO_PARAMS, |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
