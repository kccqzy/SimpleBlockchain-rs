use crate::core::*;
use serde::{Deserialize, Serialize};

pub mod tracker {
    use serde::{Deserialize, Serialize};
    use std::net::Ipv6Addr;

    pub const HANDSHAKE_MESSAGE: &'static [u8] = b"Simple Blockchain Tracker v1.0\r\n";
    pub const DEFAULT_REPOLL_INTERVAL: u16 = 600;
    pub const DEFAULT_TRACKER: (Ipv6Addr, u16) = (Ipv6Addr::LOCALHOST, 6781);

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
    pub struct AnnounceMessage {
        pub listen_port: u16,
        pub peer_id: [u8; 32],
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
    pub struct Peer {
        pub listen_ip: Ipv6Addr,
        pub listen_port: u16,
        pub peer_id: [u8; 32],
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
    pub struct Response {
        pub next_announce_delay: u16,
        pub peer_list: Vec<Peer>,
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockchainMessage {
    GetLongestChain,
    ReplyLongestChain(Vec<(Hash, u64)>),
    GetBlockByHash(Hash),
    ReplyBlockByHash(Block),
    GetTentativeTransactions,
    ReplyTentativeTransactions(Vec<Transaction>),
    AnnounceNewMinedBlock(Block),
    AnnounceNewTentativeTransaction(Transaction),
}
