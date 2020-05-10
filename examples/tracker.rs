use anyhow::anyhow;
use bytes::BufMut;
use simple_blockchain::net::{tracker::*};
use std::{
    collections::HashMap,
    io,
    net::{Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

type Ipv6AddrPort = (Ipv6Addr, u16);
type PeerMap = Arc<Mutex<HashMap<Ipv6AddrPort, Peer>>>;

const MAX_RECV_LEN: u32 = 409;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(600);

pub async fn write_with_length<M, S>(stream: &mut S, msg: &M) -> io::Result<()>
where
    M: serde::Serialize,
    S: AsyncWriteExt + Unpin,
{
    let serialized_size = bincode::serialized_size(&msg).unwrap();
    let mut buf = Vec::with_capacity(4 + serialized_size as usize);
    buf.put_u32(serialized_size as u32);
    bincode::serialize_into(&mut buf, &msg).unwrap();
    debug_assert_eq!(buf.len() as u64, 4 + bincode::serialized_size(&msg).unwrap());
    stream.write_all(&buf).await
}

pub async fn read_with_length<M, S>(stream: &mut S) -> anyhow::Result<M>
where
    for<'de> M: serde::Deserialize<'de>,
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let len = loop {
        match timeout(KEEPALIVE_INTERVAL, stream.read_u32()).await {
            Ok(r) => {
                let r = r?;
                if r == 0 {
                    continue;
                } else if r > MAX_RECV_LEN {
                    return Err(anyhow!("peer requested message size too large: {} bytes", r));
                } else {
                    break r;
                }
            }
            Err(_) => stream.write_u32(0).await?, // Send keepalive.
        }
    };
    let mut buf = Vec::new();
    buf.resize(len as usize, 0);
    stream.read_exact(buf.as_mut_slice()).await?;
    bincode::deserialize(buf.as_slice())
        .map_err(|e| anyhow::Error::new(*e).context(format!("while processing peer message {:?}", buf)))
}

async fn handle_peer(mut socket: TcpStream, peer_ip_port: Ipv6AddrPort, peers: &PeerMap) -> anyhow::Result<()> {
    // Perform handshake.
    let mut buf = [0; HANDSHAKE_MESSAGE.len()];
    timeout(Duration::from_secs(10), socket.read_exact(&mut buf)).await??;
    if buf != HANDSHAKE_MESSAGE {
        return Err(anyhow!("client {}:{} did not send correct handshake, closing", peer_ip_port.0, peer_ip_port.1));
    }
    socket.write_all(&buf).await?;

    // Now read TrackerAnnounceMessage and reply with TrackerResponse.
    loop {
        let announce_msg: AnnounceMessage = read_with_length(&mut socket).await?;
        let peers_to_send = {
            let mut peers = peers.lock().unwrap();
            peers.remove(&peer_ip_port);
            let rv = peers.values().cloned().collect();
            peers.insert(peer_ip_port, Peer {
                listen_ip: peer_ip_port.0,
                listen_port: announce_msg.listen_port,
                peer_id: announce_msg.peer_id,
            });
            rv
        };
        write_with_length(&mut socket, &Response {
            next_announce_delay: DEFAULT_REPOLL_INTERVAL,
            peer_list: peers_to_send,
        })
        .await?;
    }
}

#[tokio::main(basic_scheduler)]
async fn main() -> io::Result<()> {
    let mut listener = TcpListener::bind(&DEFAULT_TRACKER).await?;
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    loop {
        if let Ok((socket, peer_addr)) = listener.accept().await {
            socket.set_keepalive(Some(Duration::from_secs(600)))?;
            socket.set_linger(Some(Duration::from_secs(0)))?;
            let peer_ip_port = match peer_addr {
                SocketAddr::V6(inet6) => (inet6.ip().clone(), inet6.port()),
                SocketAddr::V4(inet) => (inet.ip().to_ipv6_mapped(), inet.port()), // No IPv4 socket support. Use IPv4-mapped IPv6 addresses instead.
            };

            // NOTE cloning is needed because the async block would otherwise
            // attempt to move the original peers.
            let peers = peers.clone();
            tokio::spawn(async move {
                match handle_peer(socket, peer_ip_port, &peers).await {
                    Ok(_) => unreachable!("handle_peer() does not normally return"),
                    Err(_) => {
                        // Remove the peer from the list.
                        let mut peers = peers.lock().unwrap();
                        peers.remove(&peer_ip_port);
                    }
                }
            });
        }
    }
}
