# Chatix Protocol

Wire protocol and cryptographic core for **Chatix**, a messaging system built
around post-quantum key exchange and end-to-end encryption. This crate
defines the binary framing, connection state machine, and all three
cryptographic layers that a Chatix client and server are built on top of. It
doesn't include a server or client binary, just the shared protocol
library.

## Why

Classical key exchange (X25519, RSA) and classical signatures (Ed25519,
ECDSA) don't hold up against a sufficiently large quantum computer. Chatix
pairs a classical algorithm with a post-quantum one everywhere a secret is
derived or an identity is proven, so breaking either one alone isn't enough
to compromise a session, a message, or an identity claim.

## Architecture

Three cryptographic layers:

| Layer | Purpose | Algorithms | Where |
|---|---|---|---|
| **Auth** | Mutual identity proof bound to the specific handshake: the client proves its long-term device identity to the server, and the server proves its pinned long-term identity to the client | ML-DSA-65 (FIPS 204) signatures: client signs a handshake-transcript hash plus the server's nonce; server signs its `ServerHello` material | `crypto/auth.rs` |
| **Transport session** | Encrypts the connection between a client and its server | X25519 + ML-KEM-768 (FIPS 203) → HKDF-SHA256 → AES-256-GCM | `crypto/session.rs`, `codec.rs` |
| **End-to-end (E2E)** | Encrypts message content so the server never sees plaintext | X25519 + ML-KEM-768 (per-message hybrid KEM) → HKDF-SHA256 → AES-256-GCM, signed with ML-DSA-65 | `crypto/e2e.rs` |

The server terminates the transport session but never sees
`SendMessagePayload` / `DeliverMessagePayload` content in the clear. That's
encrypted and signed directly between sender and recipient's identity
keypairs.

### Packet framing

Every packet is a fixed 24-byte header followed by a payload:

```
[ magic (4B) "CHTX" | version (1B) | packet_type (1B) | flags (1B) | header_len (1B)
| payload_len (4B, BE) | sequence (8B, BE) | reserved (4B, BE) ]
[ payload (payload_len bytes) ]
```

`payload_len` is capped globally at 1 MiB (`MAX_PAYLOAD_LEN`) and again per
packet type (`PacketType::max_payload_size`, enforced in
`PacketCodec::read_packet`). A `Ping`, for instance, tops out at 8 bytes
regardless of the global cap. Encrypted frames get an extra `GCM_TAG_LEN`
(16 bytes) of headroom over the plaintext limit.

`sequence` strictly increases per direction and doubles as the AES-GCM
nonce input once a session is established, so replays and nonce reuse are
caught at the codec level. `flags` currently defines one bit, `ENCRYPTED`,
marking a payload as sealed with the transport session key. `packet_type`
and `flags` are bound into the AES-GCM tag as associated data, so an
intercepted packet's type can't be relabeled in transit: swapping a
`DeliveryReceipt` for an `AckQueuedMessage`, say, even though both are
8-byte plaintexts, would fail to decrypt. Once
`PacketCodec::establish_session` has run, `read_packet` also refuses any
incoming packet that arrives without `ENCRYPTED` set, so a keyless attacker
can't inject a plaintext packet into an otherwise-encrypted session.

### Connection state machine

`ConnectionState` (in `connection_state.rs`) is role-aware; a `Role` of
`Client` or `Server` picks which sequence applies, since the two sides wait
on different messages during the handshake:

```
Server: AwaitingClientHello → AwaitingClientFinish → AwaitingAuth → Established → Closing
```
```
Client: AwaitingServerHello → AwaitingServerAccept → AwaitingAuthChallenge → AwaitingAuthResult → Established → Closing
```

`ConnectionState::validate_incoming(role, packet_type)` checks both the
phase (no `SendMessage` before `Established`) and the direction
(`PacketType::direction()`: a client can never legitimately receive
`SendMessage`, since that type only travels client → server). Any
`Error`/`Close` packet moves straight to `Closing` from any state; on the
client side, an `AuthReject` while `AwaitingAuthResult` does the same,
since the server has no equivalent choice on its own side of the
handshake.

### Identity authentication (mutual)

**Client → server.** Once the transport session is established
(`AwaitingAuth` state), the server sends `AuthChallengePayload { nonce }`
and the client replies with `AuthResponsePayload { public_key, signature,
attestation_token }`. The signature covers more than the nonce: it's over
`SHA-256(client_hello_bytes || server_hello_bytes) || nonce`
(`crypto::auth::sign_auth_response` / `verify_auth_response`), with both
sides computing the transcript hash independently from the bytes they
actually sent or received. That transcript binding is what stops a relay
attack: an attacker terminating two separate sessions, one with the real
client and one with the real server, can't forward a valid `AuthResponse`
between them, because the two sessions have different transcripts and the
signature only verifies against the one the client actually signed.

**Server → client.** `ServerHelloPayload` carries a `signature`: the server
signs `SHA-256(client_hello_bytes) || x25519_public_key ||
ml_kem_ciphertext` with its long-term ML-DSA-65 identity key
(`crypto::auth::sign_server_hello` / `verify_server_hello`), and the client
checks it against its own pinned copy of the server's verifying key,
distributed out-of-band (shipped in the client build, for instance), not
read off the wire, so trust doesn't depend on a certificate authority.
Including `client_hello_bytes` means a captured signature from one
handshake can't be replayed as proof for another. Getting that pinned key
onto a client in the first place, and rotating it later, is left to the
deploying application. This crate only provides the sign/verify
primitives.

### Key derivation context binding

Both symmetric-key derivations in this crate feed HKDF's `info` parameter
with more than a fixed label. The Layer 1 transport session keys
(`crypto::session::derive_keys`) and the Layer 2 per-message content key
(`crypto::e2e::derive_e2e_key`) each prepend a context built from the exact
public keys and KEM ciphertext behind the shared secrets
(`handshake_context` / `e2e_context`) before the purpose label
(`chatix-c2s-v1`, `chatix-e2e-content-v1`, etc.). So the derived key depends
on *which* ephemeral X25519 keys and ML-KEM ciphertext produced it, not
just the raw shared secrets. Two handshakes or two messages can't land on
the same derived key through the label alone, and derivation stays
domain-separated even if one of the raw ECDH/KEM secrets ever repeated
across exchanges (already extremely unlikely on its own).

### Identity key distribution

None of the above puts an `E2ePublicKey` (the Layer 2 identity
`crypto::e2e` uses) on the wire: `ClientHelloPayload`/`ServerHelloPayload`
only carry ephemeral Layer 1 transport keys, and `AuthResponsePayload`
carries the separate device-level ML-DSA-65 auth identity (Layer 0).
`PublishE2eKeyPayload` (client → server, `Established` state) is how a
client uploads its own `E2ePublicKey` bundle, with all three fields
fixed-size, so no length prefixes are needed, the same convention as the
key portion of `ClientHelloPayload`. The server acknowledges with
`PublishE2eKeyResultPayload { success, message }`. Any other client can
then send `FetchE2eKeyPayload { target_username }` and get back an
`E2eKeyResponsePayload`, whose `Found`/`NotFound` status byte decides
whether the key bundle follows on the wire at all: a `NotFound` response
carries no key material rather than a zeroed placeholder.

The server only stores and forwards these bundles; it has no way to use
them itself, since every `crypto::e2e` operation needs private key material
the server never sees. That said, this doesn't close the
trust-on-first-contact gap covered under Safety numbers below. A malicious
or compromised server can still serve a substituted `E2eKeyResponsePayload`
the first time two users look each other up, since nothing here forces
out-of-band verification before a client trusts a fetched key. That's what
`crypto::safety_number` is for; this layer just gets a key onto the wire in
the first place.

### Safety numbers (E2E key verification)

`crypto::safety_number` lets two users confirm, out-of-band, that they hold
each other's genuine `E2ePublicKey`. `safety_number(local_id, local_key,
remote_id, remote_key)` produces a 60-digit code (numeric-fingerprint format, adapted to SHA-256) that comes out identical on
both sides, since the fingerprints are ordered by identifier before
combining. It's a local computation only (nothing goes over the wire), and
presenting the code for comparison (in person, by QR, etc.) is left to the
client application.

`verify_key_unchanged(identifier, pinned, fetched)` covers what happens
after that first comparison: it checks a freshly `FetchE2eKey`-ed
`E2ePublicKey` against one already pinned for the same identifier, and
returns `ProtocolError::IdentityKeyChanged` if they differ. The two
mechanisms sit at different points: `safety_number` is how two users
establish a key is genuine the first time, which still takes a person
acting on it; `verify_key_unchanged` is how a client notices, without any
user action, that a key it already trusted has since changed. It can't
substitute for the first-contact check: a key substituted before the
client ever pinned it just gets pinned as if it were genuine.

### Packet types

Handshake (1–19), auth (5–8), control: friends/presence/typing/E2E key
publishing (20–39), messaging (40–79), close/error (240–255). Full list and
per-type payload size limits in `packet_type.rs`.

## Known limitations

- **No distribution or rotation for the pinned server identity key.**

  `sign_server_hello`/`verify_server_hello` provide the primitives, but
  getting the initial verifying key onto a client, and rotating it if the
  server's long-term key is ever replaced, is left to the deploying
  application.
- **First-contact safety-number verification is manual.**

  Nothing here requires two users to compare their safety number before exchanging messages for the first time: it's available, not enforced. A client that never surfaces it gets no benefit from it existing `verify_key_unchanged` does catch a key changing after it's pinned, but
  it can't establish trust on that first contact.
- **No automated key-transparency log.**

  Safety numbers rely on users proactively comparing them out-of-band, and `verify_key_unchanged` only protects a key already pinned by the client running it. Neither is a publicly verifiable, cross-client record of an identity's key history.

## Building & testing

```
cargo test
```

Tests cover header round-tripping, payload encode/decode round-trips,
role-aware connection-state transitions (including direction violations,
like a server receiving a server-only packet type), and all three crypto
layers: transcript-binding rejection for both client and server auth
(`crypto/auth.rs`), session-key derivation and cross-direction key
separation for the transport layer (`crypto/session.rs`), tampered-payload
and wrong-key rejection for E2E crypto (`crypto/e2e.rs`), safety-number
symmetry, tamper detection, and pinned-key-change detection
(`crypto/safety_number.rs`), and codec-level tests for the encryption and
header-AAD guarantees above.

## Status

Early-stage, actively developed. Protocol version `1`.