//! Tests for the connection helper of the network adapter.

use super::*;

#[test]
fn connects_to_the_first_reachable_address() -> std::io::Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let stream = connect_any("127.0.0.1", port, TIMEOUT)?;
    assert_eq!(stream.peer_addr()?.port(), port);

    // Nothing listens on a port that was just freed.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    assert!(connect_any("127.0.0.1", closed, TIMEOUT).is_err());
    // A name that cannot be resolved.
    assert!(connect_any("host.invalid", 993, TIMEOUT).is_err());
    Ok(())
}
