# SharkSSH design overview

This document explains how SharkSSH is built internally and why its protocol,
memory, transport, and lifecycle boundaries look the way they do. It is for
maintainers, reviewers, and integrators who need to evaluate those design
choices. To configure an application, use the
[core API guide](../core.md) instead.

At a high level, one connection object owns the SSH protocol state for one TCP
connection and one session channel. Application callbacks provide
authentication and the selected shell, command, or subsystem. Optional
plugins add a bounded shell or Secure File Transfer Protocol (SFTP) service
without changing the core.

## Supported protocol profile

The first vertical slice uses the
[SharkSSL API](https://realtimelogic.com/ba/doc/en/C/shark/index.html) and
implements:

- SSH protocol version 2;
- `curve25519-sha256` key exchange;
- `rsa-sha2-256` server host authentication;
- `aes128-ctr` encryption;
- `hmac-sha2-256` integrity;
- no compression;
- extension negotiation using `ext-info-c` and `ext-info-s`;
- the standard and OpenSSH-compatible Strict KEX markers;
- RSA/SHA-256 public-key and optional password user authentication;
- separate shell, exec, and subsystem authorization;
- rejection of unsupported global requests when a reply is requested;
- client- and server-initiated in-session rekey;
- monotonic handshake, authentication, idle, and session deadlines;
- structured security audit events independent of diagnostic logging;
- one `session` channel per connection;
- pseudo-terminal (PTY), window-change, shell, exec, and custom-subsystem
  callbacks;
- channel windows, data, extended data, EOF, close, and exit status.

The encodings and message flows follow
[RFC 4251](https://www.rfc-editor.org/rfc/rfc4251),
[RFC 4252](https://www.rfc-editor.org/rfc/rfc4252),
[RFC 4253](https://www.rfc-editor.org/rfc/rfc4253),
[RFC 4344](https://www.rfc-editor.org/rfc/rfc4344),
[RFC 6668](https://www.rfc-editor.org/rfc/rfc6668),
[RFC 8332](https://www.rfc-editor.org/rfc/rfc8332), and
[RFC 8731](https://www.rfc-editor.org/rfc/rfc8731). Extension negotiation
follows [RFC 8308](https://www.rfc-editor.org/rfc/rfc8308.html), and Strict KEX
follows the
[IETF Strict KEX specification](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-strict-kex-02).

The server KEX name-list contains the one implemented key exchange followed by
`ext-info-s`, `kex-strict-s`, and `kex-strict-s-v00@openssh.com`. The fixed
algorithm in each remaining category must occur in the client's valid
name-list. Because the server implements only one choice per category, this is
also the only possible client-preference match. If
`first_kex_packet_follows` contains a wrong key-exchange or host-key guess, the
next packet is discarded before the expected ECDH-init packet is parsed.

Strict KEX requires the client KEXINIT to be the first received packet, admits
only the expected initial key-exchange message sequence, and resets each packet
sequence number immediately after the corresponding NEWKEYS. The server emits
both Strict KEX marker families for current and pre-standard OpenSSH peers.
Sequence-number wrap is rejected instead of allowing an unprotected wrap.
Once Strict KEX is negotiated initially, it remains active for the connection.
Each initial or later NEWKEYS resets the corresponding directional sequence
number as required by Strict KEX.

The channel state machine tolerates channel requests and zero-length channel
data already in flight when the server sends `SSH_MSG_CHANNEL_CLOSE`. Their
common framing is validated, but they are then ignored without calling the
application or sending a reply. This accommodates clients that queue terminal
updates, an empty stdin write, or shutdown requests immediately after an exec
request. Non-empty data after close remains a protocol error.

If `ext-info-c` is present, the first encrypted server packet after NEWKEYS is
an RFC 8308 EXT_INFO. When the public-key authentication callback is installed,
it contains `server-sig-algs=rsa-sha2-256`; otherwise it contains zero entries.
A client EXT_INFO is accepted only at its permitted post-NEWKEYS location,
parsed with bounded strings, and otherwise ignored.

Global requests are parsed in the connection state. SharkSSH has no global
services yet, so a valid request receives REQUEST_FAILURE when `want-reply` is
true and is ignored otherwise. An optional lifetime counter rejects excess
requests. Its default is disabled so client keepalives remain usable without
pretending to implement forwarding or another global service.

## How the parts fit together

```text
authentication / shell / exec / subsystem callbacks
filesystem and platform callback tables
                         |
                  synchronous SSH core
                         |
       SharkSSL hash, MAC, cipher, RNG, RSA, X25519
                         |
              +----------+----------+
              |                     |
       standalone selib       BAS/BWS SoDisp
```

The protocol engine is synchronous. One task owns a connection and all
callbacks for that connection run in the same task. The core does not retain
callback spans or hold an application lock while invoking a callback.

The connection object contains fixed packet, negotiation, host-key, version,
cipher, MAC, sequence, channel, and session storage. The parser bounds input
against those compile-time capacities. The protocol path does not allocate
variable packet buffers.

Packet parsing validates padding, block alignment, MAC, name-list syntax,
message-specific fields, and state-specific message order. Malformed control
messages produce a protocol disconnect; a MAC failure after key exchange uses
the MAC-error disconnect reason. Password bytes are erased immediately after
authentication callbacks, and connection destruction erases packet buffers,
counters, MAC keys, session identifiers, host-key exchange copies, and user
identity and public-key fingerprint data retained by the core.

## Authentication and authorization

Authentication methods are derived from the installed callback table, so a
build can enable public key, password, both, or neither without conditional
protocol code. The `none` request used by clients to discover methods does not
consume an attempt. Rejected passwords, signed public-key requests, rejected
key probes, and unsupported methods consume the fixed per-connection attempt
budget. An accepted unsigned key probe returns USERAUTH_PK_OK without marking
the connection authenticated or consuming an attempt.

A second request counter includes `none`, unsigned probes, failed methods, and
the successful method, preventing discovery/probe traffic from bypassing the
failed-attempt counter. Before an expensive verifier runs, the abuse-control
callback may reject the request or request a platform delay. Parsing and
password erasure still occur on a policy rejection. Protocol errors remain
protocol errors and are never downgraded by the policy result.

The password field is a span into the decrypted packet workspace. Every path
after parsing it overwrites the span before the authentication state machine
emits success/failure or sends its response. This includes accepted and
rejected verifier results, policy rejection, malformed trailing fields, and
unsupported password-change requests. The verifier result is reduced to the
same SSH authentication-failure response used for an unknown user or secret;
account lookup and password-hash timing remain the application's responsibility.

Public-key authentication accepts only the `rsa-sha2-256` signature algorithm.
The SSH public-key blob retains its RFC 4253 `ssh-rsa` encoding with canonical
positive exponent and modulus mpints. The core hashes the complete blob for
the application-visible fingerprint, asks the callback for a matching
application-owned SharkSSL RSA key, compares its exponent and modulus with the
offered blob, constructs the RFC 4252 signed-data hash using the session ID and
request fields, and verifies the signature with
`sharkssl_RSA_PKCS1V1_5_verify_hash` and SHA-256. This prevents a callback from
accidentally returning a different verification key for an approved
fingerprint.

On success the connection stores the counted user, authentication method, and
public-key fingerprint when applicable. The service authorization callback is
then invoked for each candidate shell, exec, or subsystem request. Only a zero
result permits the corresponding plugin start callback. PTY and window-change
requests remain terminal setup and notification operations rather than
service authorization decisions.

## Channel and service lifecycle

Each connection contains one fixed `SharkSshChannel`. After the session
channel is admitted, the first accepted `shell`, `exec`, or `subsystem`
request fixes its service type. Any later service-start request on that channel
is answered with channel failure without calling the application start
callback. Before the first service starts, the authorization callback receives
the authenticated identity and exact command or subsystem name. PTY setup is
accepted only before a service starts; window-change
notifications remain valid while the service is active.

The start callback initializes application state. The core sends the request
success reply and then invokes `writable`, which prevents initial service data
from preceding the reply. The same callback is invoked after each valid peer
window adjustment. A service uses `writeSome` or `writeErrorSome`, advances by
the reported byte count, and retains only the unsent suffix. Exhausting the
peer window returns `SharkSshTimeout`; this is a normal pause in `writable`,
not a connection error.

SharkSSH does not allocate an output queue. The service owns bounded output
state, and the core owns only packet workspace and channel counters. Incoming
data callbacks must consume or copy their transient span synchronously. This
keeps backpressure and memory policy visible to the shell, command, or
subsystem implementation rather than hiding an unbounded queue in the core.

Peer EOF and local EOF are tracked separately. The application may continue
writing after peer EOF, sends exit status once when appropriate, and then
half-closes. `SharkSshChannel_close` sends local EOF followed by channel close,
but the receive loop remains alive until the peer's close arrives. Cleanup is
therefore notified exactly once either after the close handshake or from
connection destruction after cancellation, transport failure, or protocol
failure.

## Rekey, lifecycle controls, and audit

The initial exchange hash becomes the SSH session identifier and remains
unchanged by later exchanges. Rekey builds fresh KEXINIT, X25519, exchange-
hash, cipher, IV, and MAC state, sends and receives NEWKEYS using the old
directional state, and switches each direction only at its NEWKEYS boundary.
EXT_INFO is not repeated. Authentication, channel counters, windows, and
plugin state are retained.

During server-initiated rekey, connection-layer packets that were already in
flight are processed with the old keys while the core waits for the peer's
KEXINIT. After KEXINIT, only the expected key-exchange sequence is accepted.
This avoids adding a second packet buffer while allowing rekey during active
channel traffic. Byte and packet thresholds are checked at packet boundaries.
An elapsed-time threshold shortens the next header receive; if a partial
packet is already arriving, rekey waits for that bounded packet to complete.

Server keepalives use the same maintenance wakeup without treating it as an
I/O failure. The core sends one bounded global request, accepts the matching
success or failure response, and terminates after the configured unanswered
request count. Maintenance packets do not themselves refresh the idle timer.

All deadline calculations use subtraction on an optional application-provided
U32 monotonic millisecond counter. The effective read wait is the earliest of
the transport I/O timeout and the policy deadline for the current state. A
successful read or write refreshes idle activity; the absolute session start
does not move.

Cancellation is polled before transport I/O. An optional receive-side poll
interval bounds cancellation latency while no data arrives. Immediate mode
lets normal teardown close the socket; graceful mode suppresses further
cancellation checks while sending one best-effort SSH disconnect. Neither
mode adds an asynchronous write-completion or write-timeout abstraction.

Connection audit events are constructed on the connection task's stack and
delivered synchronously. Listener lifecycle and pre-worker rejection events
are similarly constructed in the bind/stop or dispatcher path and carry no
connection pointer. An application audit sink can therefore receive events
concurrently and must provide its own synchronization.

The fixed connection object is the correlation identity for authentication,
channel, service, rekey, timeout, disconnect, and session-end events. The core
does not allocate or retain an exec command: service start/denial receives the
transient packet span, while service stop reports the optional exit status.
The sink can correlate those records through the connection pointer and apply
its own command-redaction policy. Passwords, private or session keys, channel
payloads, and file data are never exposed.

Channel teardown calls the service cleanup callback once, then reports service
stop and channel close before session end. This ordering is shared by peer
close, local completion, cancellation, protocol failure, timeout, and socket
failure. Server and connection lifecycle records are also emitted by both
transport integrations, while operation-level shell and SFTP audit remains in
the optional plugins. Diagnostic logging and structured audit delivery use
separate callbacks and neither depends on the other being installed.

## Abuse-control lifecycle

Admission policy runs in the connection task after the session-start audit but
before version exchange. A rejection therefore closes without sending binary
SSH data to a peer that may not have identified itself. Accepted admission is
remembered in the fixed connection object. Its release callback runs once,
after the session-end audit, on every authentication, protocol, timeout,
cancellation, peer-close, and normal service completion path.

The core keeps no source-address table and performs no allocation for abuse
control. The callback context owns synchronized global/per-source counters and
may associate state through `abuseData`. This keeps IP address representation,
clocking, locking, and storage policy in the selected real-time operating
system (RTOS) or BAS/BWS port.
Authentication backoff uses a platform sleep callback and then rechecks
cancellation and the authentication deadline.

Existing packet, name-list, state, channel, SFTP, and fixed-buffer bounds cover
per-message resource use. Handshake, authentication, idle, and session
deadlines cover slow receive-side peers. The synchronous core has no new write
deadline; send blocking remains a transport-port property, while core and
plugin pending output remain bounded.

## Standalone transport

Standalone builds select
[`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html)
when `SHARKSSL_BA` is not enabled. The
transport adapter uses `se_bind`, `se_accept`, `se_send`, `se_recv`,
`se_close`, and `se_sockValid`. Server and connection objects are supplied by
the application, which also selects the accept-loop and connection-task model.

## BAS/BWS transport

Barracuda builds select the
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
transport when the linked
[`SharkSSL.h`](https://realtimelogic.com/ba/doc/en/C/shark/SharkSSL_8h_source.html)
defines
[`SHARKSSL_BA`](https://realtimelogic.com/ba/doc/en/C/shark/SharkSSL_8h_source.html).

`SharkSshServer_bind` registers a dedicated plain-TCP
[`HttpServCon`](https://realtimelogic.com/ba/doc/en/C/reference/html/structHttpServCon.html)
listener on the SSH port. It is not an HTTP or TLS listener. When a client is
admitted,
the accepted connection is moved to a connection-owned
[`SoDispCon`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDispCon.html).
A connection-owned
[`Thread`](https://realtimelogic.com/ba/doc/en/C/reference/html/structThread.html)
then runs the blocking SSH receive/response loop.
The connection object embeds `Thread` first so the worker entry can recover
the enclosing object; the server embeds its listener first for the equivalent
accept-callback ownership pattern.

The dispatcher listener remains responsive because protocol processing occurs
in the connection worker. Each worker destroys its moved socket, releases its
connection allocation, and updates the server counters when the session ends.
Each embedded `Thread` is constructed and started exactly once. On most BAS
ports, thread-object destruction does not terminate the current callback and
can happen before the final bookkeeping. The BAS FreeRTOS destructor deletes
the current task immediately, so that port performs the bookkeeping first and
then explicitly deletes the worker task.

The dispatcher and its
[`ThreadMutex`](https://realtimelogic.com/ba/doc/en/C/reference/html/structThreadMutex.html)
remain application-owned. Counter accessors use that mutex when needed. Server
stop removes the listener but deliberately does not destroy active workers;
the application keeps the server, dispatcher, and
callback state alive until the active count reaches zero.

## Memory model

Standalone code does not allocate `SharkSshCon` storage. BAS/BWS mode allocates
one combined connection/thread object per admitted client. Its default is
[`baMalloc`/`baFree`](https://realtimelogic.com/ba/doc/en/C/reference/html/group__DynamicMemory.html);
`SharkSshConnectionAllocator` provides a fixed-pool
boundary. Allocation is requested from the dispatcher accept path and release
occurs after worker teardown, so a custom pool must support both contexts.

Admission is bounded by `SHARKSSH_DEFAULT_MAX_CONNECTIONS` unless changed
before bind. Capacity and allocation failures close the new connection while
leaving the listener available.

The checked SharkSSL implementation of raw Curve25519 uses `baMalloc` for
temporary elliptic-curve workspace and releases it before returning. A target
that forbids every handshake-time allocation will require an appropriate
SharkSSL API or configuration using caller-supplied workspace.

## SharkSSL reuse boundary

| SSH operation | SharkSSL API |
| --- | --- |
| SHA-256 and exchange hash | [`SharkSslSha256Ctx_*`](https://realtimelogic.com/ba/doc/en/C/shark/group__RayCryptoSHA256.html) |
| Packet MAC | [`SharkSslHMACCtx_*`](https://realtimelogic.com/ba/doc/en/C/shark/group__RayCryptoHMAC.html) |
| Packet encryption | [`SharkSslAesCtx_encrypt`](https://realtimelogic.com/ba/doc/en/C/shark/group__RayCryptoAES.html) |
| Cookies and packet padding | [`sharkssl_rng`](https://realtimelogic.com/ba/doc/en/C/shark/SharkSslCrypto_8h_source.html) |
| Constant-time MAC comparison | [`sharkssl_kmemcmp`](https://realtimelogic.com/ba/doc/en/C/shark/SharkSslCrypto_8h_source.html) |
| RSA/SHA-256 host signature | [`sharkssl_RSA_PKCS1V1_5_sign_hash`](https://realtimelogic.com/ba/doc/en/C/shark/group__RSA.html) |
| RSA/SHA-256 user signature verification | [`sharkssl_RSA_PKCS1V1_5_verify_hash`](https://realtimelogic.com/ba/doc/en/C/shark/group__RSA.html) |
| RSA public-key extraction | [`SharkSslKey_vectSize_keyInfo`](https://realtimelogic.com/ba/doc/en/C/shark/group__SharkSslCertApi.html) |
| X25519 key-pair generation | `sharkssl_X25519_createKeyPair` |
| X25519 shared-secret calculation | `sharkssl_X25519_sharedSecret` |

All SharkSSL operations used by SharkSSH are accessed through public headers.
The X25519 functions reject an invalid all-zero shared secret, and the adapter
maps any key-generation or key-agreement failure to `SharkSshErrCrypto`.

The software RSA host-key adapter uses a SharkSSL private key. The public
callback boundary also permits a Trusted Platform Module (TPM) or secure
element to expose the public
key and sign the already-computed SHA-256 digest without exporting private-key
material.

The
[SharkSSL configuration](https://realtimelogic.com/ba/doc/en/C/shark/group__SharkSslCfg.html)
must enable SHA-256, AES-128, RSA, the RSA API, PKCS#1 v1.5
signatures, ECDHE, Curve25519, and the key-info API. Its random number generator
must be securely seeded before the first handshake. Multithreaded products
must provide the mutex support required by their SharkSSL configuration.

## Filesystem boundary

[`SharkSshFileSystem`](../filesystem.md) is deliberately independent of
POSIX, C `FILE`, file
descriptors, and RTOS-specific types. Opaque file and directory handles keep
filesystem-facing plugins separate from the storage driver.

This differs from the inspected
[`LibSSH-ESP32`](https://github.com/ewpa/LibSSH-ESP32) tree. Its ESP32 file
examples
mount SPIFFS and call POSIX/C-library functions such as `open`, `fopen`,
`fread`, and `fwrite`; it does not provide a libssh filesystem hook table.
SharkSSH makes this integration boundary explicit so an RTOS filesystem does
not have to emulate POSIX.

The core passes the configured filesystem table to a subsystem. The optional
SFTP plugin consumes that table without adding filesystem or SFTP state to a
core-only build. Its packet, path, transfer, and handle bounds remain plugin
compile-time settings.

## Source layout

```text
inc/SharkSSH.h          public API and fixed-size connection state
src/SharkSSH.c          SSH codec, state machines, and TCP integrations
src/SharkSshCrypto.c    SharkSSL host-key and X25519 adapter
src/SharkSshPriv.h      private constants and codec declarations
src/plugins/BasIo/      BAS IoIntf filesystem adapter
src/plugins/Shell/      bounded shell and fixed-command registry
src/plugins/Sftp/       bounded SFTP version 3 subsystem
doc/core.md             application integration and API reference
doc/filesystem.md       generic filesystem API and integration guide
doc/design/             implementation and test design
doc/plugins/            plugin integration guides
```

## Deliberate current limits

- no multiple channels;
- no SCP compatibility command;
- no port, agent, or X11 forwarding;
- no arbitrary environment variables;
- no asynchronous/event-driven SSH engine;
- no core-owned output queue or asynchronous write-completion API;
- no host-key rotation or multiple host-key algorithms;
- no test-only entropy or transport hooks in production code.

These constraints keep the protocol and security surface small enough for
focused interoperability and negative testing. The fixed cryptographic
profile and one-channel model also let optional plugins remain independent of
the core.
