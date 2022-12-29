# EQ Labs Interview Take-Home
See [original](https://github.com/eqlabs/recruitment-exercises/blob/cebb3a622ac7d59746e1febc0e809ab701a4c51a/node-handshake.md).

This crate implements a fast non-blocking message-oriented transport layer for the bitcoin protocol.
You can try it out with the following:
```sh
cargo run -- do-handshake "144.91.82.22:8333"
```

Or perform handshakes with a bunch of nodes using [shake-hands-with-bitcoin-seeds](./shake-hands-with-bitcoin-seeds).

