//pub mod quic;
/* 
pub struct ShroomSocket {
    conn: quic::QConnection,
    last_hdr: Option<usize>
}


impl ShroomSocket {
    pub fn handle_read(&mut self, _socket_fd: u32) -> anyhow::Result<()> {
        self.conn.handle_read()?;
        Ok(())
    }

    pub fn handle_write(&mut self, _socket_fd: u32) -> anyhow::Result<()> {
        self.conn.handle_write()?;
        Ok(())
    }

    pub fn send_packet(&mut self, pkt: &[u8]) -> anyhow::Result<()> {
        self.conn.send(1, pkt)?;
        Ok(())
    }
}*/