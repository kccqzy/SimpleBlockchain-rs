use expanduser::expanduser;
use openssl::{
    ec, pkey,
    pkey::{Private, Public},
    sha::sha256,
};
use rusqlite as sql;
use rusqlite::OptionalExtension;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
};

// Constants

const WALLET_PATH: &str = "~/.config/rs_simple_blockchain/wallet.pem";

const MINIMUM_DIFFICULTY_LEVEL: u8 = 16;

// Types

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(u64);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    amount: Amount,
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
    parent_hash: Hash, // TODO refactor into Option
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

#[derive(Debug, PartialEq)]
pub enum BlockchainError {
    DatabaseError(sql::Error),
    InvalidReceivedBlock(&'static str),
    InvalidReceivedTentativeTxn(&'static str),
    InsufficientBalance { requested_amount: Amount, available_amount: Amount },
    MonetaryAmountTooLarge(),
}

// Impls

impl Amount {
    const COIN: Amount = Amount(1_0000_0000);
    const BLOCK_REWARD: Amount = Amount(10 * Amount::COIN.0);
    const MAX_MONEY: Amount = Amount(100_000_000_000 * Amount::COIN.0);
}

impl std::convert::TryFrom<u64> for Amount {
    type Error = BlockchainError;
    fn try_from(u: u64) -> Result<Amount, BlockchainError> {
        if u > Amount::MAX_MONEY.0 {
            Err(BlockchainError::MonetaryAmountTooLarge())
        } else {
            Ok(Amount(u))
        }
    }
}

impl std::ops::Mul<u64> for Amount {
    type Output = Self;
    fn mul(self, rhs: u64) -> Self {
        debug_assert!(self.0.checked_mul(rhs).map_or(false, |a| a <= Amount::MAX_MONEY.0));
        Amount(self.0 * rhs)
    }
}

impl sql::ToSql for Amount {
    fn to_sql(self: &Self) -> sql::Result<sql::types::ToSqlOutput> {
        // NOTE that the maximum amount of money can be expressed as i64.
        debug_assert!(self.0 <= (i64::max_value() as u64));
        Ok((self.0 as i64).into())
    }
}

impl sql::types::FromSql for Amount {
    fn column_result(value: sql::types::ValueRef) -> sql::types::FromSqlResult<Self> {
        let r: sql::types::FromSqlResult<i64> = sql::types::FromSql::column_result(value);
        r.map(|v| Amount(v as u64))
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let integral_part = self.0 / Amount::COIN.0;
        let fractional_part = self.0 % Amount::COIN.0;
        let integral_part_w_sep = Vec::from(format!("{}", integral_part))
            .rchunks(3)
            .rfold(None, |r, c| match r {
                None => Some(c.to_owned()),
                Some(mut rc) => Some({
                    rc.push(b',');
                    rc.extend_from_slice(c);
                    rc
                }),
            })
            .unwrap();
        write!(f, "{}.{:08}", unsafe { String::from_utf8_unchecked(integral_part_w_sep) }, fractional_part)
    }
}

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

    pub fn display_base58(self: &Self) -> String { bs58::encode(&self.0).into_string() }

    pub fn display_hex(self: &Self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        for &b in self.0.iter() {
            write!(&mut s, "{:x}", b).unwrap();
        }
        s
    }
}

impl sql::ToSql for Hash {
    fn to_sql(self: &Self) -> sql::Result<sql::types::ToSqlOutput> { (&self.0[..]).to_sql() }
}

impl sql::types::FromSql for Hash {
    fn column_result(value: sql::types::ValueRef) -> sql::types::FromSqlResult<Self> {
        let val: Vec<u8> = sql::types::FromSql::column_result(value)?;
        if val.len() == 32 {
            let mut arr = [0; 32];
            arr.copy_from_slice(&val[..32]);
            Ok(Hash(arr))
        } else {
            Err(sql::types::FromSqlError::InvalidType)
        }
    }
}

impl PayerPublicKey {
    fn check_len(self: &Self) -> bool { self.0.len() == 88 }
}

impl sql::ToSql for PayerPublicKey {
    fn to_sql(self: &Self) -> sql::Result<sql::types::ToSqlOutput> { (&self.0[..]).to_sql() }
}

impl sql::types::FromSql for PayerPublicKey {
    fn column_result(value: sql::types::ValueRef) -> sql::types::FromSqlResult<Self> {
        sql::types::FromSql::column_result(value).map(PayerPublicKey)
    }
}

impl sql::ToSql for Signature {
    fn to_sql(self: &Self) -> sql::Result<sql::types::ToSqlOutput> { (&self.0[..]).to_sql() }
}

impl sql::types::FromSql for Signature {
    fn column_result(value: sql::types::ValueRef) -> sql::types::FromSqlResult<Self> {
        sql::types::FromSql::column_result(value).map(Signature)
    }
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
                amount: Amount::BLOCK_REWARD,
            }])],
        }
    }
}

impl std::convert::From<sql::Error> for BlockchainError {
    fn from(error: sql::Error) -> Self { BlockchainError::DatabaseError(error) }
}

impl BlockchainStorage {
    fn open_conn(path: Option<&std::path::Path>) -> sql::Connection {
        let conn = match path {
            None => sql::Connection::open_in_memory().unwrap(),
            Some(ref p) => sql::Connection::open(p).unwrap(),
        };
        assert!(conn.is_autocommit());
        conn.set_prepared_statement_cache_capacity(64);
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
        // Conceptually this shouldn't need to take a mutable reference to self.
        // But it's just easier to write this way while guaranteeing both stats
        // are consistent. TODO Maybe refactor.
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

    pub fn make_wallet_trustworthy(self: &Self, h: &Hash) -> sql::Result<()> {
        let mut stmt = self.conn.prepare_cached("INSERT INTO trustworthy_wallets VALUES (?)")?;
        stmt.execute(&[&h.0[..]])?;
        Ok(())
    }

    pub fn make_wallet(self: &mut Self) -> sql::Result<Wallet> {
        let w = Wallet::new();
        self.make_wallet_trustworthy(&Hash::sha256(&w.public_serialized.0))?;
        Ok(w)
    }

    fn insert_transaction_raw(t: &sql::Transaction, txn: &Transaction) -> sql::Result<()> {
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
                    let params: [&dyn sql::ToSql; 4] = [&txn_hash, &(index as i64), &out.amount, &out.recipient_hash];
                    stmt.execute(&params)?;
                }
            }
            {
                let mut stmt = t.prepare_cached("INSERT INTO transaction_inputs VALUES (?,?,?,?)")?;
                for (index, inp) in txn.inputs.iter().enumerate() {
                    let params: [&dyn sql::ToSql; 4] =
                        [&txn_hash, &(index as i64), &inp.transaction_hash, &inp.output_index];
                    stmt.execute(&params)?;
                }
            }
        }
        Ok(())
    }

    pub fn receive_block(self: &mut Self, block: &Block) -> Result<(), BlockchainError> {
        fn err(msg: &'static str) -> Result<(), BlockchainError> { Err(BlockchainError::InvalidReceivedBlock(msg)) }

        fn report_integrity(e: sql::Error) -> BlockchainError {
            if let sql::Error::SqliteFailure(
                libsqlite3_sys::Error { code: libsqlite3_sys::ErrorCode::ConstraintViolation, .. },
                _,
            ) = e
            {
                BlockchainError::InvalidReceivedBlock("Block contains transactions that do not abide by all rules")
            } else {
                BlockchainError::DatabaseError(e)
            }
        }

        if block.transactions.len() > 2000 {
            err("A block may have at most 2000 transactions")?;
        }

        if block.nonce >= 1 << 63 {
            err("Block nonce must be within 63 bits")?;
        }

        if block.transactions.len() == 0
            || block.transactions[0].inputs.len() != 0
            || block.transactions[0].outputs.len() != 1
            || block.transactions[0].outputs[0].amount != Amount::BLOCK_REWARD
        {
            err("The first transaction must be a reward transaction: have no inputs, and only one output of exactly the reward amount")?;
        }

        if !block.transactions.iter().all(|t| 1 <= t.outputs.len() && t.outputs.len() <= 256) {
            err("Every transaction must have at least one output and at most 256")?;
        }

        if !block.transactions.iter().skip(1).all(|t| 1 <= t.inputs.len() && t.inputs.len() <= 256) {
            err("Every transaction except for the first must have at least one input and at most 256")?;
        }

        if !block.transactions.iter().all(|t| t.outputs.iter().all(|o| o.amount <= Amount::MAX_MONEY)) {
            err("Every output of every transaction must have a value of no more than 100 billion")?;
        }

        if !block.transactions.iter().all(|t| {
            t.outputs.len()
                == t.outputs.iter().map(|o| &o.recipient_hash).collect::<std::collections::HashSet<_>>().len()
        }) {
            err("Every transaction must have distinct output recipients")?;
        }

        if !block.verify_hash_challenge(MINIMUM_DIFFICULTY_LEVEL) {
            err("Block has incorrect or insufficiently hard hash")?;
        }

        if !block.transactions.iter().all(Transaction::verify_signature) {
            err("Every transaction must be correctly signed")?;
        }

        let t = self.conn.transaction()?;

        {
            let mut stmt = t.prepare_cached("INSERT INTO blocks (block_hash, parent_hash, nonce) VALUES (?,?,?)")?;
            let params: [&dyn sql::ToSql; 3] = [
                &block.block_hash,
                if block.parent_hash != Hash::zeroes() { &block.parent_hash } else { &sql::types::Null },
                &(block.nonce as i64),
            ];
            stmt.execute(&params).map_err(report_integrity)?;
        }
        for txn in block.transactions.iter() {
            BlockchainStorage::insert_transaction_raw(&t, &txn).map_err(report_integrity)?;
        }
        {
            let mut stmt = t.prepare_cached("INSERT INTO transaction_in_block VALUES (?,?,?)")?;
            for (index, txn) in block.transactions.iter().enumerate() {
                let params: [&dyn sql::ToSql; 3] = [&txn.transaction_hash(), &block.block_hash, &(index as i64)];
                stmt.execute(&params).map_err(report_integrity)?;
            }
        }
        {
            let mut stmt = t.prepare_cached("SELECT count(*) FROM unauthorized_spending JOIN transaction_in_block USING (transaction_hash) WHERE block_hash = ?")?;
            if stmt.query_row(&[&block.block_hash], |r| r.get::<_, i64>(0))? > 0 {
                err("Transaction(s) in block contain unauthorized spending")?;
            }
        }
        {
            let mut stmt = t.prepare_cached("SELECT count(*) FROM transaction_credit_debit JOIN transaction_in_block USING (transaction_hash) WHERE block_hash = ? AND debited_amount > credited_amount")?;
            if stmt.query_row(&[&block.block_hash], |r| r.get::<_, i64>(0))? > 0 {
                err("Transaction(s) in block have an input that spends more than the amount in the referenced output")?;
            }
        }
        {
            let mut stmt =
                t.prepare_cached("SELECT total_violations_count FROM block_consistency WHERE perspective_block = ?")?;
            if stmt.query_row(&[&block.block_hash], |r| r.get::<_, i64>(0))? > 0 {
                err("Transaction(s) in block are not consistent with ancestor blocks; one or more transactions either refer to a nonexistent parent or double spend a previously spent parent")?;
            }
        }

        t.commit().map_err(report_integrity)?;
        Ok(())
    }

    fn receive_tentative_transaction_internal(
        t: &sql::Transaction, ts: &[&Transaction],
    ) -> Result<(), BlockchainError> {
        fn err(msg: &'static str) -> Result<(), BlockchainError> {
            Err(BlockchainError::InvalidReceivedTentativeTxn(msg))
        }

        if !ts
            .iter()
            .all(|t| 1 <= t.outputs.len() && t.outputs.len() <= 256 && 1 <= t.inputs.len() && t.inputs.len() <= 256)
        {
            err("Tentative transaction(s) must each have at least one input and one output, and at most 256")?;
        }

        if !ts.iter().all(|t| t.outputs.iter().all(|o| o.amount <= Amount::MAX_MONEY)) {
            err("Every output of every tentative transaction must have a value of no more than 100 billion")?;
        }

        if !ts.iter().all(|t| {
            t.outputs.len()
                == t.outputs.iter().map(|o| &o.recipient_hash).collect::<std::collections::HashSet<_>>().len()
        }) {
            err("Tentative transaction(s) must each have distinct output recipients")?;
        }

        if !ts.iter().all(|t| t.verify_signature()) {
            err("Tentative transaction(s) must be correctly signed")?;
        }

        for tx in ts {
            BlockchainStorage::insert_transaction_raw(t, tx)?;
            let th = tx.transaction_hash();
            {
                let mut stmt =
                    t.prepare_cached("SELECT count(*) FROM unauthorized_spending WHERE transaction_hash = ?")?;
                if stmt.query_row(&[&th], |r| r.get::<_, i64>(0))? > 0 {
                    err("Tentative transaction(s) contain unauthorized spending")?;
                }
            }
            {
                let mut stmt = t.prepare_cached("SELECT count(*) FROM transaction_credit_debit WHERE transaction_hash = ? AND debited_amount > credited_amount")?;
                if stmt.query_row(&[&th], |r| r.get::<_, i64>(0))? > 0 {
                    err("Tentative transaction(s) have an input that spends more than the amount in the referenced output")?;
                }
            }
        }
        Ok(())
    }

    pub fn receive_tentative_transaction(self: &mut Self, ts: &[&Transaction]) -> Result<(), BlockchainError> {
        fn report_integrity(e: sql::Error) -> BlockchainError {
            if let sql::Error::SqliteFailure(
                libsqlite3_sys::Error { code: libsqlite3_sys::ErrorCode::ConstraintViolation, .. },
                _,
            ) = e
            {
                BlockchainError::InvalidReceivedBlock("Tentative transaction(s) do not abide by all rules")
            } else {
                BlockchainError::DatabaseError(e)
            }
        }

        let t = self.conn.transaction()?;
        BlockchainStorage::receive_tentative_transaction_internal(&t, ts)?;
        t.commit().map_err(report_integrity)?;
        Ok(())
    }

    fn find_available_spend(
        t: &sql::Transaction, wallet_public_key_hash: &Hash,
    ) -> sql::Result<impl Iterator<Item = (TransactionInput, Amount)>> {
        let mut stmt = t.prepare_cached(
            "SELECT out_transaction_hash, out_transaction_index, amount FROM utxo WHERE recipient_hash = ?",
        )?;
        let rows = stmt.query_map(&[wallet_public_key_hash], |row| {
            Ok((TransactionInput { transaction_hash: row.get(0)?, output_index: row.get(1)? }, row.get(2)?))
        })?;
        Ok(rows.collect::<sql::Result<Vec<_>>>()?.into_iter())
        // NOTE that we have to collect it into a Vec or some other
        // container and finish consuming the entire mapped rows; this is
        // because if any future element is an Err, we return Err without
        // giving any item.
    }

    pub fn find_wallet_balance(
        self: &Self, wallet_public_key_hash: &Hash, required_confirmations: Option<u32>,
    ) -> sql::Result<u64> {
        // NOTE that we return a plain u64 because although an individual
        // monetary amount is not allowed to exceed MAX_MONEY, the sum may.
        Ok((match required_confirmations {
            None => {
                let mut stmt = self.conn.prepare_cached("SELECT sum(amount) FROM utxo WHERE recipient_hash = ?")?;
                stmt.query_row(&[&wallet_public_key_hash], |r| r.get::<_, Option<i64>>(0))?
            }
            Some(conf) => {
                let mut stmt = self
                    .conn
                    .prepare_cached("SELECT sum(amount) FROM utxo WHERE recipient_hash = ? AND confirmations >= ?")?;
                let params: [&dyn sql::ToSql; 2] = [&wallet_public_key_hash, &conf];
                stmt.query_row(&params, |r| r.get::<_, Option<i64>>(0))?
            }
        })
        .unwrap_or(0) as u64)
    }

    pub fn create_simple_transaction(
        self: &mut Self, wallet: Option<&Wallet>, requested_amount: Amount, recipient_hash: &Hash,
    ) -> Result<Transaction, BlockchainError> {
        let wallet = wallet.unwrap_or(&self.default_wallet);
        let wallet_hash = Hash::sha256(&wallet.public_serialized.0);

        self.make_wallet_trustworthy(&wallet_hash)?; // We have the private key of this wallet so it is trustworthy.

        let t = self.conn.transaction()?;
        let result = BlockchainStorage::find_available_spend(&t, &wallet_hash)?.try_fold(
            (Vec::new(), Amount(0)),
            |(inputs, Amount(sum)), (ti, Amount(amt))| {
                let mut new_inputs = inputs;
                new_inputs.push(ti);
                let rv = (new_inputs, Amount(sum + amt));
                if rv.1 >= requested_amount {
                    Err(rv)
                } else {
                    Ok(rv)
                }
            },
        );
        match result {
            Ok((_, available_amount)) =>
                Err(BlockchainError::InsufficientBalance { available_amount, requested_amount }),
            Err((inputs, total_amount)) => {
                let outputs = if wallet_hash != *recipient_hash {
                    let mut o =
                        vec![TransactionOutput { amount: requested_amount, recipient_hash: recipient_hash.clone() }];
                    if total_amount > requested_amount {
                        o.push(TransactionOutput {
                            amount: Amount(total_amount.0 - requested_amount.0),
                            recipient_hash: wallet_hash,
                        });
                    }
                    o
                } else {
                    vec![TransactionOutput { amount: total_amount, recipient_hash: recipient_hash.clone() }]
                };
                let txn = wallet.create_raw_transaction(inputs, outputs);
                BlockchainStorage::receive_tentative_transaction_internal(&t, &[&txn])?;
                t.commit()?;
                Ok(txn)
            }
        }
    }

    pub fn get_longest_chain(self: &Self) -> sql::Result<impl Iterator<Item = (Hash, u64)>> {
        let mut stmt = self.conn.prepare_cached("SELECT block_hash, block_height FROM longest_chain")?;
        let rows = stmt.query_map(sql::NO_PARAMS, |row| Ok((row.get(0)?, row.get::<_, i64>(1)? as u64)))?;
        Ok(rows.collect::<sql::Result<Vec<_>>>()?.into_iter())
    }

    fn fill_transaction_in_out(t: &sql::Transaction, tx: Transaction) -> sql::Result<Transaction> {
        let th = tx.transaction_hash();
        let inputs = {
            let mut stmt = t.prepare_cached("SELECT out_transaction_hash, out_transaction_index FROM transaction_inputs WHERE in_transaction_hash = ? ORDER BY in_transaction_index")?;
            let rows = stmt.query_map(&[&th], |row| {
                Ok(TransactionInput { transaction_hash: row.get(0)?, output_index: row.get(1)? })
            })?;
            rows.collect::<sql::Result<Vec<_>>>()?
        };
        let outputs = {
            let mut stmt = t.prepare_cached("SELECT amount, recipient_hash FROM transaction_outputs WHERE out_transaction_hash = ? ORDER BY out_transaction_index")?;
            let rows = stmt
                .query_map(&[&th], |row| Ok(TransactionOutput { amount: row.get(0)?, recipient_hash: row.get(1)? }))?;
            rows.collect::<sql::Result<Vec<_>>>()?
        };
        Ok(Transaction { inputs, outputs, ..tx })
    }

    pub fn get_block_by_hash(self: &mut Self, block_hash: &Hash) -> sql::Result<Option<Block>> {
        let t = self.conn.transaction()?;
        {
            let mut stmt =
                t.prepare_cached("SELECT nonce, parent_hash, block_hash FROM blocks WHERE block_hash = ?")?;
            stmt.query_row(&[&block_hash], |row| {
                Ok(Block {
                    nonce: row.get::<_, i64>(0)? as u64,
                    transactions: vec![],
                    parent_hash: row.get(1)?,
                    block_hash: row.get(2)?,
                })
            })
            .optional()
        }?
        .map_or(Ok(None), |b| {
            Ok(Some(Block {
                transactions: {
                    let mut stmt = t.prepare_cached("SELECT payer, signature FROM transactions JOIN transaction_in_block USING (transaction_hash) WHERE block_hash = ? ORDER BY transaction_index")?;
                    let rows = stmt.query_map(&[block_hash], |row| {
                        BlockchainStorage::fill_transaction_in_out(&t, Transaction {
                            payer: row.get(0)?,
                            signature: row.get(1)?,
                            inputs: vec![],
                            outputs: vec![],
                        })
                    })?;
                    rows.collect::<sql::Result<Vec<_>>>()?
                },
                ..b
            }))
        })
    }

    pub fn get_all_tentative_transactions(self: &mut Self) -> sql::Result<Vec<Transaction>> {
        let t = self.conn.transaction()?;
        let mut stmt = t.prepare_cached("SELECT payer, signature FROM all_tentative_txns")?;
        let rows = stmt.query_map(sql::NO_PARAMS, |row| {
            BlockchainStorage::fill_transaction_in_out(&t, Transaction {
                payer: row.get(0)?,
                signature: row.get(1)?,
                inputs: vec![],
                outputs: vec![],
            })
        })?;
        rows.collect::<sql::Result<Vec<_>>>()
    }

    pub fn get_mineable_tentative_transactions(
        self: &mut Self, limit: Option<u16>,
    ) -> sql::Result<(Vec<Transaction>, Option<Hash>)> {
        // We need to temporarily modify the database inside the transaction to
        // check for validity. We will not actually make any modifications to
        // the DB.
        let mut t = self.conn.transaction()?;
        let mut rv = Vec::new();
        let limit = limit.unwrap_or(100);

        // Find a parent hash.
        let parent_hash = {
            let mut stmt = t.prepare_cached(
                "SELECT block_hash FROM blocks ORDER BY block_height DESC, discovered_at ASC LIMIT 1",
            )?;
            stmt.query_row(sql::NO_PARAMS, |r| r.get(0)).optional()?
        };
        {
            let mut stmt =
                t.prepare_cached("INSERT INTO blocks (block_hash, parent_hash, nonce) VALUES (x'deadface', ?, 0)")?;
            stmt.execute(&[&parent_hash])?;
        }

        while rv.len() < limit as usize {
            let all_tentative_txns: Vec<(Hash, PayerPublicKey, Signature)> = {
                let mut stmt = t.prepare_cached("SELECT transaction_hash, payer, signature FROM all_tentative_txns ORDER BY discovered_at ASC LIMIT ?")?;
                let rows =
                    stmt.query_map(&[&(limit - (rv.len() as u16))], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
                rows.collect::<sql::Result<Vec<_>>>()?
            };
            if all_tentative_txns.is_empty() {
                break; // Found all tentative txns.
            }
            let mut progress = false;
            for (h, p, s) in all_tentative_txns.into_iter() {
                let mut sp = t.savepoint()?;
                {
                    let mut stmt = sp.prepare_cached("INSERT INTO transaction_in_block (transaction_hash, block_hash, transaction_index) VALUES (?, x'deadface', ?)")?;
                    let params: [&dyn sql::ToSql; 2] = [&h, &(rv.len() as u16)];
                    stmt.execute(&params)?;
                }
                let violations_count: i64 = {
                    let mut stmt = sp.prepare_cached(
                        "SELECT total_violations_count FROM block_consistency WHERE perspective_block = x'deadface'",
                    )?;
                    stmt.query_row(sql::NO_PARAMS, |r| r.get(0))?
                };
                if violations_count > 0 {
                    sp.rollback()?
                } else {
                    sp.commit()?;
                    progress = true;
                    rv.push(BlockchainStorage::fill_transaction_in_out(&t, Transaction {
                        payer: p,
                        signature: s,
                        inputs: vec![],
                        outputs: vec![],
                    })?);
                }
            }
            if !progress {
                // None of the remaining tentative transactions can be added to
                // the block (i.e. compatible with the block).
                break;
            }
        }
        Ok((rv, parent_hash))
    }

    pub fn get_ui_transaction_by_hash(self: &mut Self, h: &Hash) -> sql::Result<Option<Vec<(String, String)>>> {
        let t = self.conn.transaction()?; // TODO this ideally would not use a transaction, but a single statement.
        {
            let mut stmt = t.prepare_cached("SELECT payer, signature FROM transactions WHERE transaction_hash = ?")?;
            stmt.query_row(&[h], |row| {
                BlockchainStorage::fill_transaction_in_out(&t, Transaction {
                    payer: row.get(0)?,
                    signature: row.get(1)?,
                    inputs: vec![],
                    outputs: vec![],
                })
            }).optional()?
        }.map_or(Ok(None), |tx| {
            let mut rv = Vec::new();
                rv.push(("Transaction Hash".to_owned(), h.display_hex()));
            rv.push(("Originating Wallet".to_owned(), Hash::sha256(&tx.payer.0).display_base58()));
            for (i, tx_output) in tx.outputs.into_iter().enumerate() {
                rv.push((format!("Output {} Amount", i), tx_output.amount.to_string()));
                rv.push((format!("Output {} Recipient", i), tx_output.recipient_hash.display_base58()));
            }
            if tx.inputs.is_empty() {
                rv.push(("Input".to_owned(), "None (this is a miner reward)".to_owned()));
            }
            for (i, tx_input) in tx.inputs.into_iter().enumerate() {
                rv.push((format!("Input {}", i), format!("{}.{}", tx_input.transaction_hash.display_hex(), tx_input.output_index)));
            }
            {
                let mut stmt = t.prepare_cached("SELECT credited_amount, debited_amount FROM transaction_credit_debit WHERE transaction_hash = ?")?;
                if let Some((cr, db)) = stmt.query_row(&[h], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))).optional()? {
                    rv.push(("Credit Amount".to_owned(), cr.to_string()));
                    rv.push(("Debit Amount".to_owned(), db.to_string()));
                }
            }
            let conf = {
                let mut stmt = t.prepare_cached("SELECT ifnull((SELECT longest_chain.confirmations FROM transaction_in_block JOIN longest_chain USING (block_hash) WHERE transaction_hash = ?), 0)")?;
                stmt.query_row(&[h], |r| r.get::<_, i64>(0))?
            };
            rv.push(("Confirmations".to_owned(), conf.to_string()));
            Ok(Some(rv))
        })
    }

    pub fn prepare_mineable_block(self: &mut Self, miner_wallet: Option<&Wallet>) -> sql::Result<Block> {
        let miner_wallet = miner_wallet.unwrap_or(&self.default_wallet);
        let mut block = Block::new_mine_block(miner_wallet);
        let (mut new_tx, parent_hash) = self.get_mineable_tentative_transactions(None)?;
        let parent_hash = parent_hash.unwrap_or_else(Hash::zeroes);
        block.transactions.append(&mut new_tx);
        block.parent_hash = parent_hash;
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_amount() {
        assert_eq!(format!("{}", Amount(0)), "0.00000000".to_owned());
        assert_eq!(format!("{}", Amount(1)), "0.00000001".to_owned());
        assert_eq!(format!("{}", Amount(100)), "0.00000100".to_owned());
        assert_eq!(format!("{}", Amount::COIN), "1.00000000".to_owned());
        assert_eq!(format!("{}", Amount::COIN * 10), "10.00000000".to_owned());
        assert_eq!(format!("{}", Amount::COIN * 1000), "1,000.00000000".to_owned());
        assert_eq!(format!("{}", Amount::COIN * 1234567), "1,234,567.00000000".to_owned());
        assert_eq!(format!("{}", Amount::MAX_MONEY), "100,000,000,000.00000000".to_owned());
    }

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

    #[test]
    fn initial_default_wallet_zero_balance() {
        let mut bs = BlockchainStorage::new(None, None);
        let h = Hash::sha256(&bs.default_wallet.public_serialized.0);
        assert_eq!(bs.find_wallet_balance(&h, None).unwrap(), 0);
        assert_eq!(BlockchainStorage::find_available_spend(&bs.conn.transaction().unwrap(), &h).unwrap().count(), 0);
    }

    #[test]
    fn initial_no_tentative_txns() {
        let mut bs = BlockchainStorage::new(None, None);
        assert!(bs.get_all_tentative_transactions().unwrap().is_empty());
        assert!(bs.get_mineable_tentative_transactions(None).unwrap().0.is_empty());
    }
}
