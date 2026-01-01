# Bracha Reliable Broadcast (Rust)

A Rust implementation of **Bracha’s Byzantine Fault-Tolerant Reliable Broadcast** protocol.

This library allows a node to reliably broadcast a message to a set of participants such that all honest nodes either deliver the same message or deliver nothing, even in the presence of Byzantine faults.

## Protocol

The protocol proceeds in three phases:

1. **INIT** — The initiator broadcasts the signed message
2. **ECHO** — Nodes echo the message hash after verification
3. **READY** — Nodes broadcast readiness once quorum thresholds are met

The protocol tolerates up to `t = ⌊(n-1)/3⌋` Byzantine faults.

## References

This implementation is based on **Bracha’s Reliable Broadcast**:

- Gabriel Bracha, *An Asynchronous [(n−1)/3]-Resilient Consensus Protocol*, INRIA  
  https://inria.hal.science/hal-03347874v1/document
  
## Properties

- **Validity** — Honest broadcasts are eventually delivered
- **Agreement** — No two honest nodes deliver different values
- **Integrity** — All messages are signed and verified

## Implementation notes

- Uses **Ed25519 + SHA-512** signatures
- Deterministic serialization required for MsgLink.data (`Vec`, `BTreeMap`)
- Async Rust with Tokio
- Transport-agnostic (currently HTTP)
