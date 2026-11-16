//! Tests for `utf7`.

use super::*;

#[test]
fn roundtrips_known_names() -> Result<(), Error> {
    let cases = [
        ("INBOX", "INBOX"),
        ("Research & Development", "Research &- Development"),
        ("Ångström & Co", "&AMU-ngstr&APY-m &- Co"),
        ("日本語", "&ZeVnLIqe-"),
        ("Ä", "&AMQ-"),
        ("😀", "&2D3eAA-"),
    ];
    for (plain, wire) in cases {
        assert_eq!(encode(plain), wire, "encode {plain}");
        assert_eq!(decode(wire)?, plain, "decode {wire}");
    }
    Ok(())
}

#[test]
fn rejects_malformed_input() {
    assert!(decode("&AMQ").is_err());
    assert!(decode("&A*Q-").is_err());
    assert!(decode("&AM-").is_err());
    assert!(decode("&2D0-").is_err());
}
