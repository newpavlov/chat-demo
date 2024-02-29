use crate::{
    cli::ServerArgs,
    protocol::{
        read_msg, write_msg, ClientMsg, ServerMsg, CLIENT_MAGIC, PROTOCOL_VER_MAJOR,
        PROTOCOL_VER_MINOR, SERVER_MAGIC,
    },
};
use snafu::{ResultExt, Snafu};
use std::{
    collections::HashMap,
    io,
    net::{self, SocketAddr, TcpStream},
    ops::DerefMut,
    sync::{Arc, Mutex, RwLock},
    thread,
};

type WriteConns = Arc<RwLock<HashMap<usize, Mutex<TcpStream>>>>;

/// Incoming client connection
struct ClientConn {
    conn_idx: usize,
    read_conn: TcpStream,
    write_conns: WriteConns,
    username: Option<String>,
}

impl ClientConn {
    /// Handle incoming TCP connection
    fn handle(conn_idx: usize, conn: TcpStream, write_conns: WriteConns) {
        let res = std::panic::catch_unwind(move || {
            match ClientConn::try_handle(conn_idx, conn, write_conns) {
                Ok(()) => log::info!("(conn #{conn_idx}) Closed."),
                Err(err) => log::warn!("(conn #{conn_idx}) Closed with error: {err}"),
            }
        });
        if res.is_err() {
            log::warn!("(conn #{conn_idx}) Closed with panic");
        }
    }

    fn try_handle(
        conn_idx: usize,
        read_conn: TcpStream,
        write_conns: WriteConns,
    ) -> Result<(), ClientConnError> {
        let conn = Self {
            conn_idx,
            read_conn,
            write_conns,
            username: None,
        };
        conn.handshake()?;
        conn.main_loop()
    }

    fn main_loop(mut self) -> Result<(), ClientConnError> {
        use ClientMsg::*;
        loop {
            match self.read_msg()? {
                Disconnect => return self.disconnect(),
                SetUsername { username } => self.set_username(username)?,
                PublicMessage { message } => self.public_message(message)?,
                msg @ Handshake { .. } => {
                    let err = ClientConnError::UnexpectedMsg { msg };
                    self.write_msg(ServerMsg::Error(format!("{err}")))?;
                    return Err(err);
                }
            }
        }
    }

    fn read_msg(&self) -> Result<ClientMsg, ClientConnError> {
        let msg = read_msg(&self.read_conn).context(ClientMsgReadSnafu)?;
        log::debug!("(conn #{}) Got client message: {msg:?}", self.conn_idx);
        Ok(msg)
    }

    fn write_msg(&self, msg: ServerMsg) -> Result<(), ClientConnError> {
        log::debug!("(conn #{}) Responding with message: {msg:?}", self.conn_idx);
        let write_conns = self.write_conns.read().unwrap();
        let conn_mutex = write_conns.get(&self.conn_idx).unwrap();
        let mut conn = conn_mutex.lock().unwrap();
        write_msg(conn.deref_mut(), &msg).context(ServerMsgWriteSnafu)
    }

    fn write_err(&self, err: String) -> Result<(), ClientConnError> {
        self.write_msg(ServerMsg::Error(err))
    }

    fn handshake(&self) -> Result<(), ClientConnError> {
        let conn_idx = self.conn_idx;
        let (magic, ver_major, ver_minor) = match self.read_msg()? {
            ClientMsg::Handshake {
                magic,
                ver_major,
                ver_minor,
            } => (magic, ver_major, ver_minor),
            msg => return Err(ClientConnError::UnexpectedMsg { msg }),
        };
        if magic != CLIENT_MAGIC {
            let err = ClientConnError::BadMagic { magic };
            self.write_err(format!("{err}"))?;
            return Err(err);
        }
        if ver_major != PROTOCOL_VER_MAJOR || ver_minor > PROTOCOL_VER_MINOR {
            let err = ClientConnError::IncompatibleProtocolVersions {
                client_major: ver_major,
                client_minor: ver_minor,
                server_major: PROTOCOL_VER_MAJOR,
                server_minor: PROTOCOL_VER_MINOR,
            };
            self.write_err(format!("{err}"))?;
            return Err(err);
        }

        self.write_msg(ServerMsg::Handshake {
            magic: SERVER_MAGIC,
            ver_major: PROTOCOL_VER_MAJOR,
            ver_minor: PROTOCOL_VER_MINOR,
        })?;
        log::info!(
            "(conn #{conn_idx}) Successful handhake. \
             Client protocol version: {ver_major}.{ver_minor}"
        );
        Ok(())
    }

    fn disconnect(&self) -> Result<(), ClientConnError> {
        let write_conns = self.write_conns.read().unwrap();
        for (&conn_idx, conn_mutex) in write_conns.iter() {
            if conn_idx == self.conn_idx {
                continue;
            }
            let mut conn = conn_mutex.lock().unwrap();
            write_msg_other(
                conn_idx,
                conn.deref_mut(),
                ServerMsg::UserDisconnected {
                    conn_idx: self.conn_idx,
                    username: self.username.clone(),
                },
            )?;
        }
        Ok(())
    }

    fn set_username(&mut self, username: Option<String>) -> Result<(), ClientConnError> {
        let old_username = self.username.take();
        self.username = username;
        let write_conns = self.write_conns.read().unwrap();
        for (&conn_idx, conn_mutex) in write_conns.iter() {
            let mut conn = conn_mutex.lock().unwrap();
            write_msg_other(
                conn_idx,
                conn.deref_mut(),
                ServerMsg::UsernameChange {
                    conn_idx: self.conn_idx,
                    old_username: old_username.clone(),
                    new_username: self.username.clone(),
                },
            )?;
        }
        Ok(())
    }

    fn public_message(&self, message: String) -> Result<(), ClientConnError> {
        let write_conns = self.write_conns.read().unwrap();
        for (&conn_idx, conn_mutex) in write_conns.iter() {
            let mut conn = conn_mutex.lock().unwrap();
            write_msg_other(
                conn_idx,
                conn.deref_mut(),
                ServerMsg::PublicMessage {
                    message: message.clone(),
                    conn_idx: self.conn_idx,
                    username: self.username.clone(),
                },
            )?;
        }
        Ok(())
    }
}

impl Drop for ClientConn {
    fn drop(&mut self) {
        self.write_conns
            .write()
            .unwrap()
            .remove(&self.conn_idx)
            .unwrap();
    }
}

fn write_msg_other(
    conn_idx: usize,
    conn: &mut TcpStream,
    msg: ServerMsg,
) -> Result<(), ClientConnError> {
    log::debug!("(conn #{conn_idx}) Sending message: {msg:?}");
    write_msg(conn, &msg).context(ServerMsgWriteSnafu)
}

/// Start demo chat sever
pub fn run(args: ServerArgs) -> Result<(), ServerError> {
    let addr = SocketAddr::from((args.ip, args.port));
    let socket = net::TcpListener::bind(addr).context(SocketBindSnafu { addr })?;
    let write_conns = WriteConns::default();

    log::info!("Listening for incoming connections on {addr}");
    for (conn_idx, conn) in socket.incoming().enumerate() {
        let read_conn = conn.context(AcceptSnafu { conn_idx })?;
        log::info!("Accepted connection #{conn_idx}");

        let write_conn = read_conn.try_clone().context(CloneConnSnafu { conn_idx })?;
        let mut write_conns_locked = write_conns.write().unwrap();
        write_conns_locked.insert(conn_idx, Mutex::new(write_conn));
        drop(write_conns_locked);

        let wc_copy = write_conns.clone();
        thread::spawn(move || ClientConn::handle(conn_idx, read_conn, wc_copy));
    }
    Ok(())
}

/// Error of launching chat demo server
#[derive(Debug, Snafu)]
pub enum ServerError {
    /// Failed to bind TCP socket
    #[snafu(display("Failed to bind TCP socket on address {addr}: {source}"))]
    SocketBind { source: io::Error, addr: SocketAddr },
    /// Failed to bind TCP socket
    #[snafu(display("Failed to accept incoming TCP connection #{conn_idx}: {source}"))]
    Accept { source: io::Error, conn_idx: usize },
    /// Failed to split TCP socket
    #[snafu(display("Failed to split TCP socket #{conn_idx}: {source}"))]
    CloneConn { source: io::Error, conn_idx: usize },
}

/// Error of launching chat demo server
#[derive(Debug, Snafu)]
pub enum ClientConnError {
    /// Failed to write server message
    #[snafu(display("Failed to write server message: {source}"))]
    ServerMsgWrite { source: io::Error },
    /// Failed to read client message
    #[snafu(display("Failed to read client message: {source}"))]
    ClientMsgRead { source: io::Error },
    /// Unexpected client message
    #[snafu(display("Got unexpected client message: {msg:?}"))]
    UnexpectedMsg { msg: ClientMsg },
    /// Recieved bad magic value from server
    #[snafu(display(
        "Recieved bad magic value from client 0x{magic:016X}, expected: 0x{CLIENT_MAGIC:016X}"
    ))]
    BadMagic { magic: u64 },
    /// Incompatible protocol versions
    #[snafu(display(
        "Incompatible protocol versions. \
        Client: {client_major}.{client_minor} \
        Server: {server_major}.{server_minor}"
    ))]
    IncompatibleProtocolVersions {
        client_major: u32,
        client_minor: u32,
        server_major: u32,
        server_minor: u32,
    },
}
