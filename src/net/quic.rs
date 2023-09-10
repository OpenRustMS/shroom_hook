use std::{
    io::{self, ErrorKind, IoSliceMut},
    mem::MaybeUninit,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Instant,
};

use bytes::{Buf, BufMut, BytesMut};
use quinn_proto::{ClientConfig, EndpointConfig, StreamId};
use quinn_udp::{RecvMeta, UdpSockRef, UdpSocketState, UdpState};

pub type Result<T> = anyhow::Result<T>;

const MAX_DATAGRAM_SIZE: usize = 1350;

// Quic connection wrapper to use an existing socket
// as the Game uses WSAAsyncSelectEx and the WndProc to handle callbacks

// TODO figure out if send_to really works all the time

pub struct QConnection {
    socket: UdpSocket,
    sock_state: quinn_udp::UdpSocketState,
    udp_state: quinn_udp::UdpState,
    ep: quinn_proto::Endpoint,
    conn: quinn_proto::Connection,
    last_transmit: Option<quinn_udp::Transmit>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    rd_buf: BytesMut,
}

const SERVER_NAME: &str = "shroom";

impl QConnection {
    pub fn connect(local: SocketAddr, remote: SocketAddr, client: ClientConfig) -> Result<Self> {
        let cfg = Arc::new(EndpointConfig::default());
        let mut ep = quinn_proto::Endpoint::new(cfg, None, true);
        let socket = UdpSocket::bind(local)?;

        let conn = ep.connect(client, remote, SERVER_NAME)?;

        let res = Self {
            socket,
            udp_state: UdpState::new(),
            sock_state: UdpSocketState::new(),
            ep,
            conn: conn.1,
            last_transmit: None,
            local_addr: local,
            remote_addr: remote,
            rd_buf: BytesMut::new(),
        };

        Ok(res)
    }

    pub fn send(&mut self, stream: u64, data: &[u8]) -> Result<()> {
        let mut tx = self.conn.send_stream(StreamId(stream));
        let ln = (data.len() as u16).to_le_bytes();
        tx.write(ln.as_slice())?;
        tx.write(data)?;

        Ok(())
    }

    pub fn recv(&mut self, stream: u64, pkt_buf: &mut BytesMut) -> Result<Option<usize>> {
        let mut rx = self.conn.recv_stream(StreamId(stream));
        let mut chunks = rx.read(true)?;

        loop {
            if pkt_buf.len() >= 2 {
                let n = u16::from_le_bytes(pkt_buf[..2].try_into().unwrap()) as usize;
                if pkt_buf.len() > n + 2 {
                    pkt_buf.advance(2);
                    return Ok(Some(n));
                }
            }

            if let Some(chunk) = chunks.next(512)? {
                pkt_buf.put_slice(&chunk.bytes);
            } else {
                let _ = chunks.finalize();
                return Ok(None);
            }
        }
    }

    pub fn init_socket(&mut self) -> Result<()> {
        UdpSocketState::configure(UdpSockRef::from(&self.socket))?;
        Ok(())
    }

    fn try_send(&mut self, trans: quinn_udp::Transmit) -> Result<bool> {
        Ok(
            match self
                .sock_state
                .send((&self.socket).into(), &self.udp_state, &[trans.clone()])
            {
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    // Try again later
                    self.last_transmit = Some(trans);
                    false
                }
                Err(err) => return Err(err.into()),
                _ => true,
            },
        )
    }

    pub fn handle_write(&mut self) -> Result<()> {
        // Attempt to send pending frame
        if let Some(trans) = self.last_transmit.take() {
            // Send didn't work quit here
            if !self.try_send(trans)? {
                return Ok(());
            }
        }

        while let Some(trans) = self.ep.poll_transmit() {
            let trans = quinn_udp::Transmit {
                destination: trans.destination,
                ecn: quinn_udp::EcnCodepoint::from_bits(trans.ecn.unwrap() as u8),
                contents: trans.contents,
                segment_size: trans.segment_size,
                src_ip: trans.src_ip,
            };

            if !self.try_send(trans)? {
                break;
            }
        }

        Ok(())
    }

    pub fn sock_read(&mut self, buf: &mut BytesMut, meta: &mut [RecvMeta]) -> io::Result<usize> {
        buf.reserve(1024);
        let data = buf.spare_capacity_mut();

        let mut data = unsafe {
            [IoSliceMut::new(std::slice::from_raw_parts_mut(
                data.as_mut_ptr() as *mut u8,
                data.len(),
            ))]
        };

        let read = self
            .sock_state
            .recv((&self.socket).into(), &mut data, meta)?;

        unsafe { buf.set_len(buf.len() + read) };
        Ok(read)
    }

    pub fn handle_read(&mut self) -> Result<()> {
        let mut buf = BytesMut::new();
        let mut meta = [RecvMeta::default()];
        loop {
            match self.sock_read(&mut buf, &mut meta) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    return Err(err.into());
                }
            }

            let meta = meta[0];
            let (_, _) = self
                .ep
                .handle(Instant::now(), meta.addr, meta.dst_ip, None, buf.clone())
                .unwrap();
        }
    }
}
