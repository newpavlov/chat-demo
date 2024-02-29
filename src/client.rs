use std::{io, net::TcpStream};

use crate::{
    cli::ClientArgs,
    protocol::{
        read_msg, write_msg, ClientMsg, ServerMsg, CLIENT_MAGIC, PROTOCOL_VER_MAJOR,
        PROTOCOL_VER_MINOR, SERVER_MAGIC,
    },
};
use snafu::{ResultExt, Snafu};

/// Client connection to chat server
pub struct Client {
    conn: TcpStream,
}

impl Client {
    /// Start demo chat client
    pub fn run(
        ClientArgs {
            addr,
            port,
            username,
        }: ClientArgs,
    ) -> Result<(), ClientError> {
        let a = (addr.as_str(), port);
        let conn = TcpStream::connect(a).context(ConnectSnafu { addr, port })?;
        let read_conn = conn.try_clone().context(CloneConnSnafu)?;

        let client = Self { conn };

        client.handshake()?;

        if let Some(username) = username {
            client.set_username(&username)?;
        }

        let read_client = Client { conn: read_conn };
        std::thread::spawn(move || match read_client.handle_server_msgs() {
            Ok(()) => (),
            Err(err) => {
                log::error!("Failed to handle server messages: {err}");
                std::process::exit(1);
            }
        });

        for line in io::stdin().lines() {
            let line = line.context(ReadLineSnafu)?;
            if line.is_empty() {
                continue;
            }
            if line.starts_with('/') {
                let cmd = line.split(' ').nth(0).unwrap();
                let n = cmd.len() + 1;
                match cmd {
                    "/username" => client.set_username(&line[n..])?,
                    "/exit" => {
                        client.disconnect()?;
                        break;
                    }
                    _ => log::error!("Unknown command"),
                }
            } else {
                client.public_message(line)?;
            }
        }
        Ok(())
    }

    fn handle_server_msgs(&self) -> Result<(), ClientError> {
        use ServerMsg::*;
        loop {
            match self.read_msg()? {
                PublicMessage {
                    message,
                    conn_idx,
                    username,
                } => {
                    println!("{} (ID: {conn_idx}): {message}", map_username(&username));
                }
                UsernameChange {
                    conn_idx,
                    old_username,
                    new_username,
                } => {
                    println!(
                        "[server]: Username change from {} to {} (ID: {conn_idx})",
                        map_username(&old_username),
                        map_username(&new_username)
                    )
                }
                UserDisconnected { conn_idx, username } => println!(
                    "[server]: User disconnected: {} (ID: {conn_idx})",
                    map_username(&username)
                ),
                Error(err) => log::warn!("Server error: {err}"),
                msg @ Handshake { .. } => log::warn!("Unexpected server message: {msg:?}"),
            }
        }
    }

    fn read_msg(&self) -> Result<ServerMsg, ClientError> {
        let msg = read_msg(&self.conn).context(ServerMsgReadSnafu)?;
        log::debug!("Got server message: {msg:?}");
        Ok(msg)
    }

    fn write_msg(&self, msg: ClientMsg) -> Result<(), ClientError> {
        log::debug!("Sending message: {msg:?}");
        write_msg(&self.conn, &msg).context(ClientMsgWriteSnafu)
    }

    fn handshake(&self) -> Result<(), ClientError> {
        self.write_msg(ClientMsg::Handshake {
            magic: CLIENT_MAGIC,
            ver_major: PROTOCOL_VER_MAJOR,
            ver_minor: PROTOCOL_VER_MINOR,
        })?;

        let (magic, ver_major, ver_minor) = match self.read_msg()? {
            ServerMsg::Handshake {
                magic,
                ver_major,
                ver_minor,
            } => (magic, ver_major, ver_minor),
            ServerMsg::Error(err) => return Err(ClientError::ServerError { err }),
            msg => return Err(ClientError::UnexpectedMsg { msg }),
        };
        if magic != SERVER_MAGIC {
            return Err(ClientError::BadMagic { magic });
        }
        log::info!("Successful handshake. Server protocol version: {ver_major}.{ver_minor}");
        Ok(())
    }

    fn set_username(&self, username: &str) -> Result<(), ClientError> {
        let username = if username.is_empty() {
            None
        } else {
            Some(username.to_string())
        };
        self.write_msg(ClientMsg::SetUsername { username })
    }

    fn public_message(&self, message: String) -> Result<(), ClientError> {
        self.write_msg(ClientMsg::PublicMessage { message })
    }

    fn disconnect(&self) -> Result<(), ClientError> {
        self.write_msg(ClientMsg::Disconnect)
    }
}

fn map_username(username: &Option<String>) -> &str {
    username.as_ref().map(|s| s.as_str()).unwrap_or("Anonymous")
}

/// Error of launching chat demo server
#[derive(Debug, Snafu)]
pub enum ClientError {
    /// Failed to connect to chat server
    #[snafu(display(
        "Failed to connect to chat server on address {addr} (port: {port}): {source}"
    ))]
    Connect {
        source: io::Error,
        addr: String,
        port: u16,
    },
    /// Failed to split TCP socket
    #[snafu(display("Failed to split TCP socket: {source}"))]
    CloneConn { source: io::Error },
    /// Failed to write client message
    #[snafu(display("Failed to write client message: {source}"))]
    ClientMsgWrite { source: io::Error },
    /// Failed to write client message
    #[snafu(display("Failed to read server message: {source}"))]
    ServerMsgRead { source: io::Error },
    /// Server error
    #[snafu(display("Server error: {err}"))]
    ServerError { err: String },
    /// Unexpected server message
    #[snafu(display("Got unexpected server message: {msg:?}"))]
    UnexpectedMsg { msg: ServerMsg },
    /// Recieved bad magic value from server
    #[snafu(display(
        "Recieved bad magic value from server 0x{magic:016X}, expected: 0x{SERVER_MAGIC:016X}"
    ))]
    BadMagic { magic: u64 },
    /// Failed to read user input
    #[snafu(display("Failed to read user input: {source}"))]
    ReadLine { source: io::Error },
}
