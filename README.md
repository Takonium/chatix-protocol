# Chatix Protocol

Wire protocol and cryptographic core for **Chatix**, a messaging system designed
around post-quantum key exchange and end-to-end encryption. This crate defines
the binary framing, connection state machine, and all three cryptographic
layers that a Chatix client and server implementation are built on top of.
It does not include a server or client binary — it's the shared protocol
library.

## Why

Classical key exchange (X25519, RSA) and classical signatures (Ed25519, ECDSA)
are not secure against a sufficiently large quantum computer. Chatix uses
**hybrid** constructions everywhere a secret is derived or an identity is
proven: a classical algorithm combined with a post-quantum one, so that
breaking either alone is not enough to compromise a session, a message, or
an identity claim.

## Architecture

The protocol has three cryptographic layers:

| Layer | Purpose | Algorithms | Where |
|---|---|---|---|
| **Auth** | Mutual identity proof, each direction bound to this specific handshake: the client proves its long-term device identity to the server, and the server proves its pinned long-term identity to the client | ML-DSA-65 (FIPS 204) signatures — client signs a handshake-transcript hash + server nonce; server signs its `ServerHello` material | `crypto/auth.rs` |
| **Transport session** | Encrypts the connection between a client and *its* server | X25519 + ML-KEM-768 (FIPS 203) → HKDF-SHA256 → AES-256-GCM | `crypto/session.rs`, `codec.rs` |
| **End-to-end (E2E)** | Encrypts message content so the server never sees plaintext | X25519 + ML-KEM-768 (per-message hybrid KEM) + ML-DSA-65 signatures → AES-256-GCM | `crypto/e2e.rs` |

The server terminates the transport session but is never able to decrypt
`SendMessagePayload` / `DeliverMessagePayload` content — that's encrypted
and signed directly between the two identity keypairs of sender and
recipient.

### Packet framing

Every packet is a fixed 24-byte header followed by a payload:

```
[ magic (4B) "CHTX" | version (1B) | packet_type (1B) | flags (1B) | header_len (1B)
| payload_len (4B, BE) | sequence (8B, BE) | reserved (4B, BE) ]
[ payload (payload_len bytes) ]
```

- `payload_len` is capped globally at 1 MiB (`MAX_PAYLOAD_LEN`) **and**
  per packet type (`PacketType::max_payload_size`, enforced in
  `PacketCodec::read_packet`) — e.g. a `Ping` can't carry more than 8 bytes,
  regardless of the global cap. Encrypted frames get an extra `GCM_TAG_LEN`
  (16 bytes) of allowance over the plaintext limit.
- `sequence` must strictly increase per direction; it also doubles as the
  AES-GCM nonce input once the session is established, so replays and
  nonce reuse are rejected at the codec level.
- `flags` currently defines a single bit, `ENCRYPTED`, telling the receiver
  the payload is sealed with the transport session key. `packet_type` and
  `flags` are also bound into the AES-GCM tag as associated data (AAD), so
  an on-path attacker can't relabel an intercepted packet's type — e.g.
  swap a `DeliveryReceipt` for an `AckQueuedMessage`, both an 8-byte
  plaintext — and have it still decrypt successfully.
- Once `PacketCodec::establish_session` has been called, `read_packet`
  rejects any incoming packet that arrives *without* `ENCRYPTED` set.
  Without this, a network attacker holding no key could still inject a
  plaintext, fully attacker-controlled packet into an otherwise-encrypted
  session and have it accepted as genuine.

### Connection state machine

`ConnectionState` (in `connection_state.rs`) is role-aware — a `Role` of
`Client` or `Server` selects which sequence applies, since the two sides
wait on different messages during the handshake:

```
Server: AwaitingClientHello → AwaitingClientFinish → AwaitingAuth → Established → Closing
Client: AwaitingServerHello → AwaitingServerAccept → AwaitingAuthChallenge → AwaitingAuthResult → Established → Closing
```

`ConnectionState::validate_incoming(role, packet_type)` rejects a packet
for either of two independent reasons: the wrong phase (e.g. no
`SendMessage` before `Established`), or the wrong direction (e.g. a client
can never legitimately receive `SendMessage`, since that type only ever
travels client → server — checked via `PacketType::direction()`). Any
`Error`/`Close` packet transitions straight to `Closing` from any state;
the client has one more way in: receiving `AuthReject` (as opposed to
`AuthAccept`) while `AwaitingAuthResult` also moves it straight to
`Closing`, since the server never gets an equivalent choice to make on its
own side of the handshake.

### Identity authentication (mutual)

**Client → server.** After the transport session is established
(`AwaitingAuth` state), the server sends `AuthChallengePayload { nonce }`
and the client responds with `AuthResponsePayload { public_key, signature,
attestation_token }`.

The signature is **not** just over the nonce — it's over
`SHA-256(client_hello_bytes || server_hello_bytes) || nonce`
(`crypto::auth::sign_auth_response` / `verify_auth_response`). Both sides
compute the transcript hash independently from the exact bytes they sent or
received during the handshake. This closes a relay attack that a
nonce-only signature would be open to: an on-path attacker terminating two
separate transport sessions (one with the real client, one with the real
server) cannot relay a valid `AuthResponse` between them, because the two
sessions have different transcripts and the client's signature only
verifies against the transcript it actually signed.

**Server → client.** `ServerHelloPayload` carries a `signature` field: the
server signs `SHA-256(client_hello_bytes) || x25519_public_key ||
ml_kem_ciphertext` with its long-term ML-DSA-65 identity key
(`crypto::auth::sign_server_hello` / `verify_server_hello`). The client
verifies it against its own **pinned** copy of the server's verifying key —
distributed out-of-band (e.g. shipped in the client build), not read off
the wire, so trust doesn't depend on a certificate authority. Binding in
`client_hello_bytes` means a captured signature from one handshake can't be
replayed as proof for a different one. Key distribution and rotation for
the pinned key are outside this crate's scope — it only provides the
sign/verify primitives.

### Safety numbers (E2E key verification)

`crypto::safety_number` gives two users a way to confirm, out-of-band, that
they hold each other's genuine `E2ePublicKey` — closing the gap where a
compromised server could otherwise substitute a recipient's key on first
contact. `safety_number(local_id, local_key, remote_id, remote_key)`
produces a 60-digit code (Signal's numeric-fingerprint format, adapted to
use SHA-256) that comes out identical regardless of which side computes it,
since both parties' fingerprints are ordered by identifier before
combining. This is a local computation only — nothing is sent over the
wire, and presenting the resulting code for comparison (in person, by QR,
etc.) is left to the client application.

### Packet types

Handshake (1–19), auth (5–8), control — friends/presence/typing (20–39),
messaging (40–79), close/error (240–255). Full list and per-type payload
size limits in `packet_type.rs`.

## Known limitations / not yet implemented

Being upfront about the current state rather than overselling it:

- **No key-distribution or rotation mechanism for the pinned server
  identity key.** `sign_server_hello`/`verify_server_hello` (see Identity
  authentication above) provide the primitives, but getting the initial
  verifying key onto a client, and rotating it if the server's long-term
  key is ever replaced, is left to the deploying application.
- **Safety-number verification is manual, not enforced.** Nothing in this
  crate requires two users to actually compare their safety number before
  exchanging messages — it's an available check, not a mandatory gate. A
  client application that never surfaces it to users gets no benefit from
  it existing.
- **No automated key-transparency log.** Safety numbers rely on users
  proactively comparing them out-of-band; an automated, publicly
  verifiable log of identity-key changes (à la Signal/WhatsApp's more
  recent key-transparency work) would catch a substitution without
  requiring that, but is substantially more infrastructure and wasn't
  built here.

## Building & testing

```
cargo test
```

Unit tests cover header round-tripping, payload encode/decode round-trips,
role-aware connection-state transitions (including direction-violation
cases, e.g. a server receiving a server-only packet type), and all crypto
layers — transcript-binding rejection tests for both client and server auth
(`crypto/auth.rs`), session-key derivation and cross-direction
key-separation tests for the transport layer (`crypto/session.rs`),
tampered-payload / wrong-key rejection tests for E2E crypto
(`crypto/e2e.rs`), safety-number symmetry and tamper-detection
(`crypto/safety_number.rs`), and codec-level tests for the
mandatory-encryption and header-AAD protections described above.

## Status

Early-stage / actively developed. Protocol version `1`. Breaking wire-format
changes are expected before a `0.2` release — the auth layer's field sizes
already changed once (Ed25519 → ML-DSA-65), and `ServerHelloPayload` has
since gained a `signature` field, both within this version.
