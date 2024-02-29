use std::net::IpAddr;

use clap::Parser;

const DEFAULT_PORT: &str = "30000";

/// Simple demo chat
#[derive(Parser, Debug)]
pub enum Cli {
    /// Launch chat server
    Server(ServerArgs),
    /// Launch chat client
    Client(ClientArgs),
}

/// Server CLI arguments
#[derive(Parser, Debug)]
pub struct ServerArgs {
    /// Port for incoming TCP connections
    #[arg(short, long, default_value = DEFAULT_PORT)]
    pub port: u16,
    /// IP for incoming TCP connections
    #[arg(long, default_value = "0.0.0.0")]
    pub ip: IpAddr,
}

/// Client CLI arguments
#[derive(Parser, Debug)]
pub struct ClientArgs {
    /// IP address or host name of char server
    pub addr: String,
    /// Port used by chat server
    #[arg(short, long, default_value = DEFAULT_PORT)]
    pub port: u16,
    #[arg(short, long)]
    pub username: Option<String>,
}
