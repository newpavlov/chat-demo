# Chat Demo

TCP-based chat demo client and server written in Rust.

## Usage

Starting server:
```sh
cargo run --release -- server
```

Starting client:

```sh
cargo run --release -- client 127.0.0.1
```

Compiled binary and its subcommands contain built-in help accesible using
`-h` or `--help` flags.

You can change logging level using `RUST_LOG` enviromental variable
See [`env_logger`] docs for more information.

Client commands:
- `hello world`: send public message "hello world".
- `/username foo`: change username to `foo`.
- `/exit`: disconnect from chat server.

[`env_logger`]: https://docs.rs/env_logger
