use std::io;

use serde::{Deserialize, Serialize};

pub const CLIENT_MAGIC: u64 = 0x0BAD_BABE_DEAD_BEEF;
pub const SERVER_MAGIC: u64 = 0xDEAD_BEEF_0123_4567;

pub const PROTOCOL_VER_MAJOR: u32 = 1;
pub const PROTOCOL_VER_MINOR: u32 = 0;

/// Message types sent by client
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMsg {
    Handshake {
        magic: u64,
        ver_major: u32,
        ver_minor: u32,
    },
    Disconnect,
    SetUsername {
        username: Option<String>,
    },
    PublicMessage {
        message: String,
    },
}

/// Message types sent by server
#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMsg {
    Handshake {
        magic: u64,
        ver_major: u32,
        ver_minor: u32,
    },
    Error(String),
    UserDisconnected {
        conn_idx: usize,
        username: Option<String>,
    },
    UsernameChange {
        conn_idx: usize,
        new_username: Option<String>,
        old_username: Option<String>,
    },
    PublicMessage {
        message: String,
        conn_idx: usize,
        username: Option<String>,
    },
}

pub fn read_msg<T: serde::de::DeserializeOwned>(mut r: impl io::Read) -> io::Result<T> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let len = usize::from(u16::from_le_bytes(len_buf));
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    bincode::deserialize(&buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub fn write_msg<T: Serialize>(mut w: impl io::Write, msg: &T) -> io::Result<()> {
    let buf = bincode::serialize(msg).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let len_buf = match u16::try_from(buf.len()) {
        Ok(len) => len.to_le_bytes(),
        Err(_) => {
            let msg = format!("Serialized message is too big! {}/{}", buf.len(), u16::MAX);
            let err = io::Error::new(io::ErrorKind::Other, msg);
            return Err(err);
        }
    };
    w.write_all(&len_buf)?;
    w.write_all(&buf)?;
    Ok(())
}
