# SharkSSH core API

This guide explains how to integrate the SharkSSH core into a product. It
covers both supported TCP environments and the server, connection, channel,
authentication, service, platform, and host-key APIs. It is written for C
developers who already have a network port and want to supply their own
product policy through callbacks.

If this is your first SharkSSH build, begin with the repository
[README](../README.md#choose-an-integration). It explains the dependency
layout and helps you choose between standalone SharkSSL/selib and BAS/BWS
SoDisp. The prepared [examples](../examples/README.md) are the shortest path to
a running server; this guide is for applications that integrate the core API
directly.

## Find the section you need

| Goal | Start here |
| --- | --- |
| Choose standalone SharkSSL or Barracuda | [Select the integration mode](#select-the-integration-mode) |
| Bring up a server for the first time | [Initialization sequence](#initialization-sequence) |
| Install and protect a host key | [Creating and using the RSA host key](#creating-and-using-the-rsa-host-key) |
| Configure user login and command access | [Configure user authentication and authorization](#configure-user-authentication-and-authorization) |
| Add timeouts, rekeying, cancellation, or audit | [Configure rekeying, lifecycle controls, and audit](#configure-rekeying-lifecycle-controls-and-audit) |
| Integrate the bounded shell or Secure File Transfer Protocol (SFTP) | [Plugin index](plugins/README.md) |
| Look up fields and functions | [Public type reference](#public-type-reference) |

The generic [filesystem interface](filesystem.md) is documented separately.

## Select the integration mode

[`SharkSSH.h`](../inc/SharkSSH.h) includes
[`SharkSSL.h`](https://realtimelogic.com/ba/doc/en/C/shark/SharkSSL_8h_source.html)
first. The [SharkSSL](https://realtimelogic.com/ba/doc/en/C/shark/index.html)
configuration then selects one of these APIs:

| SharkSSL configuration | TCP integration | Application supplies |
| --- | --- | --- |
| [`SHARKSSL_BA`](https://realtimelogic.com/ba/doc/en/C/shark/SharkSSL_8h_source.html) is nonzero | Barracuda App Server (BAS) or Barracuda Web Server (BWS), using the [SoDisp](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html) socket dispatcher | An already-constructed [HttpServer](https://realtimelogic.com/ba/doc/en/C/reference/html/structHttpServer.html) whose dispatcher is already configured and operated by the application |
| [`SHARKSSL_BA`](https://realtimelogic.com/ba/doc/en/C/shark/SharkSSL_8h_source.html) is zero or undefined | Standalone SharkSSL and [selib](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html) | The target `selib` port, application-owned connection tasks, and [`SeCtx`](https://realtimelogic.com/ba/doc/en/C/shark/group__BareMetal.html) only for **Bare Metal Systems** |

Do not define `SHARKSSL_BA` independently of SharkSSL. Use the value selected
by the `SharkSSL.h` in the product being linked.

**Bare Metal Systems** run without an RTOS and are typically event-driven.
`SeCtx` lets sequential `selib` code cooperate with that event-driven main
loop. RTOS and host socket ports do not use this context and normally pass
`NULL`.

Both modes use the same configuration, host-key, authentication, service,
platform, filesystem, and channel APIs. Only server construction, accepting,
and connection ownership differ.

In practical terms, a standalone executable links SharkSSL and `selib`
directly. A Barracuda executable links one BAS/BWS amalgamation, which already
contains SharkSSL, and does not link `selib`. Source-tree placement for the
supplied builds is documented in the repository
[README](../README.md#arrange-the-source-trees).

## Supported SSH profile

The current compact profile negotiates `curve25519-sha256`, `rsa-sha2-256`,
`aes128-ctr`, `hmac-sha2-256`, and no compression. A client must offer every
member of this profile; unsupported alternatives are not silently selected.
The profile is identical in standalone and BAS/BWS builds.

SharkSSH advertises the server side of
[SSH extension negotiation](https://www.rfc-editor.org/rfc/rfc8308.html) and
both the current and [OpenSSH](https://www.openssh.com/)-compatible server
markers from the
[Strict KEX specification](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-strict-kex-02).
Strict KEX is applied automatically when the client offers a corresponding
marker. No application callback or configuration field is required.

Either endpoint may rekey an established connection without closing its
authenticated session channel. `rekeyBytes` controls automatic server-
initiated rekeying; the original SSH session identifier and authenticated
service remain in effect while the directional cipher and MAC keys change.

When the client offers `ext-info-c`, SharkSSH sends a valid extension message.
When `SharkSshAuthenticator.publicKey` is configured, the message advertises
`server-sig-algs=rsa-sha2-256`. With no public-key callback, no user-signature
algorithm is advertised. If a client sends its extension message at the
permitted point, SharkSSH accepts it and ignores unknown extension values.

Unknown SSH global requests are rejected with `SSH_MSG_REQUEST_FAILURE` when
the peer asks for a reply. Requests that do not ask for a reply are ignored.
This makes common client keepalive requests safe to use without requiring an
application hook. `maxGlobalRequests` can optionally terminate a connection
that exceeds a product-selected lifetime request count; it is disabled by
default so periodic client keepalives do not shorten a normal session.

## Initialization sequence

1. Initialize the target and SharkSSL, including a securely seeded random
   number generator.
2. Allocate persistent storage for `SharkSshConfig`, the host-key adapter or
   host-key callback context, and `SharkSshServer`.
3. Call `SharkSshConfig_constructor` before assigning any configuration
   fields.
4. Install a host key and at least one authenticator: RSA public key,
   password, or both.
5. Install an `authorize` callback and the service callbacks the product
   supports. A product normally
   provides one or more of `exec`, `shell`, and `subsystem`, plus the common
   `data`, `eof`, and `writable` lifecycle callbacks it needs.
6. Optionally install platform callbacks and a
   [generic filesystem table](filesystem.md).
7. Construct the server for the selected TCP integration, then bind it to the
   desired port.
8. On shutdown, stop the server, finish all active connections, and then
   destroy the server and the application-owned objects.

The configuration and every callback context referenced by it must remain
valid until the server and all its connections are finished.

## Callback and lifetime rules

- Callback return value `0` means accept or success. A nonzero return rejects
  or fails the requested operation unless a callback description states a
  more specific convention.
- A `SharkSshSpan` is a counted byte string. Its data is not NUL terminated
  and is valid only for the duration of the callback. Copy it when it must be
  retained.
- Service callbacks may call the channel output, EOF, exit-status, and close
  functions synchronously. Use `writeSome` or `writeErrorSome` when output may
  exceed the peer's current channel window.
- Do not call channel APIs concurrently from another task. Queue asynchronous
  output to the task that owns the connection.
- `SharkSshChannel.userData` is reserved for application-owned per-session
  state. Release that state from `SharkSshServices.close` and set the pointer
  back to `NULL`.
- Shared callback contexts may be used by multiple connections at once and
  must be made thread-safe by the application.
- Treat fields not specifically documented for application use as private
  state. Applications provide storage for public objects but should operate
  on them through the API functions.

## Common configuration example

This example accepts one fixed account and one allowlisted command. Production
code should use the product's credential store, constant-time secret handling,
rate limits, and audit policy.

```c
#include <SharkSSH.h>
#include <string.h>

static int
spanEquals(SharkSshSpan span, const char* text)
{
   U32 size = (U32)strlen(text);
   return span.len == size && !memcmp(span.ptr, text, size);
}

static int
verifyPassword(void* context, SharkSshSpan user, SharkSshSpan password)
{
   (void)context;
   return spanEquals(user, "operator") && spanEquals(password, "replace-me")
      ? SharkSshOk : SharkSshErrAuth;
}

static int
authorizeService(void* context, SharkSshChannel* channel,
                 const SharkSshAuthorization* request)
{
   (void)context;
   (void)channel;
   return request->serviceType == SharkSshServiceExec &&
          spanEquals(request->request, "status") ?
      SharkSshOk : SharkSshErrAuth;
}

typedef struct
{
   const U8* output;
   U32 outputSize;
   U32 outputOffset;
   U8 inUse;
} CommandState;

static int
openSession(void* context, SharkSshChannel* channel, SharkSshSpan user)
{
   CommandState* state = (CommandState*)context;
   (void)user;
   if(state->inUse)
      return SharkSshErrService;
   memset(state, 0, sizeof(*state));
   state->inUse = 1;
   channel->userData = state;
   return SharkSshOk;
}

static void
closeSession(void* context, SharkSshChannel* channel)
{
   CommandState* state = (CommandState*)context;
   channel->userData = NULL;
   memset(state, 0, sizeof(*state));
}

static int
executeCommand(void* context, SharkSshChannel* channel,
               SharkSshSpan command)
{
   static const char response[] = "device is ready\r\n";
   CommandState* state = (CommandState*)channel->userData;
   (void)context;
   if(!state || !spanEquals(command, "status"))
      return SharkSshErrService;
   state->output = (const U8*)response;
   state->outputSize = (U32)(sizeof(response) - 1);
   return SharkSshOk;
}

static int
writeCommandOutput(void* context, SharkSshChannel* channel)
{
   CommandState* state = (CommandState*)channel->userData;
   U32 written = 0;
   int status;
   (void)context;
   status = SharkSshChannel_writeSome(
      channel, state->output + state->outputOffset,
      state->outputSize - state->outputOffset, &written);
   state->outputOffset += written;
   if(status)
      return status;
   status = SharkSshChannel_sendExitStatus(channel, 0);
   return status ? status : SharkSshChannel_close(channel);
}

static void
configureSsh(SharkSshConfig* config, SharkSshRsaHostKey* adapter,
             SharkSslRSAKey privateKey, CommandState* commandState)
{
   SharkSshConfig_constructor(config);
   SharkSshRsaHostKey_constructor(adapter, privateKey);
   SharkSshRsaHostKey_set(&config->hostKey, adapter);
   config->authenticator.password = verifyPassword;
   config->services.context = commandState;
   config->services.authorize = authorizeService;
   config->services.open = openSession;
   config->services.close = closeSession;
   config->services.exec = executeCommand;
   config->services.writable = writeCommandOutput;
}
```

The software RSA key and its backing storage must remain valid for every
connection. This compact example intentionally permits only one active
channel because it supplies one `CommandState`; a real product normally uses
a fixed session pool. A secure element can be used instead by installing
custom `SharkSshHostKey` callbacks.

## Creating and using the RSA host key

An SSH host key identifies the server to its clients. OpenSSH normally caches
the public-key fingerprint after the first connection and warns if the key
later changes. A deployed device should therefore keep the same host key
across reboots and firmware updates. Provision a unique key per device when
possible; do not ship a test key or one shared private key in every device.

The current SharkSSH profile uses an RSA host key and `rsa-sha2-256`
signatures. SSH does not require an X.509 certificate or certificate chain for
this operation; supply the RSA private key itself, not a SharkSSL TLS
certificate object.

Two objects appear in the examples:

- `privateKey` is a `SharkSslRSAKey`. It points to an RSA **private** key in
  SharkSSL's optimized binary key format. The application owns the key and its
  backing storage.
- `rsaHostKey` is a small `SharkSshRsaHostKey` adapter. It does not contain,
  copy, generate, or free the private key. It installs the `publicKey` and
  `signHash` callbacks required by `SharkSshConfig.hostKey`.

The adapter is installed as follows:

```c
SharkSshConfig config;
SharkSshRsaHostKey rsaHostKey;
SharkSslRSAKey privateKey;

/* First obtain privateKey using one of the methods below. */
SharkSshConfig_constructor(&config);
SharkSshRsaHostKey_constructor(&rsaHostKey, privateKey);
SharkSshRsaHostKey_set(&config.hostKey, &rsaHostKey);
```

`SharkSshRsaHostKey_constructor` stores the key pointer in the adapter.
`SharkSshRsaHostKey_set` points `config.hostKey.context` at that adapter and
installs its two callback functions. A public-only RSA key is insufficient:
the SSH handshake requires the private key to sign the exchange hash.

### Recommended embedded method: provision the key offline

Create the device's RSA private key in a controlled provisioning environment,
then use the SharkSSL
[`SharkSslParseKey`](https://realtimelogic.com/ba/doc/en/C/shark/md_md_Certificate_Management.html)
tool to convert the PEM key to SharkSSL's binary key format:

```text
SharkSSLParseKey device-ssh-host-key.pem > DeviceSshHostKey.h
```

The generated header contains a constant byte array. After assigning the
generated array a product-specific name, install it like this:

```c
#include "DeviceSshHostKey.h"

SharkSshConfig config;
SharkSshRsaHostKey rsaHostKey;
SharkSslRSAKey privateKey =
   (SharkSslRSAKey)sharkSslPrivRSAKeyDeviceSsh;

SharkSshConfig_constructor(&config);
SharkSshRsaHostKey_constructor(&rsaHostKey, privateKey);
SharkSshRsaHostKey_set(&config.hostKey, &rsaHostKey);
```

The array may reside in read-only flash because SharkSSH only reads it. Do not
call `SharkSslRSAKey_free` for a compiled-in or statically provisioned array.
Protect the generated header and any binary containing an exportable private
key as sensitive material.

`SharkSslParseKey` can instead create a binary file for a manufacturing or
secure-storage workflow:

```text
SharkSSLParseKey device-ssh-host-key.pem -b device-ssh-host-key.bin
```

Load or map the complete binary blob and cast its first byte to
`SharkSslRSAKey`. Keep that storage unchanged and address-stable until every
SSH connection has finished.

### Convert a PEM private key at runtime

When the product already stores PEM and the SharkSSL build enables its PEM
API, convert it with
[`sharkssl_PEM_to_RSAKey`](https://realtimelogic.com/ba/doc/en/C/shark/group__RSA.html):

```c
SharkSslRSAKey privateKey;

privateKey = sharkssl_PEM_to_RSAKey(deviceHostKeyPem, passphrase);
if(!privateKey)
   return SharkSshErrCrypto;

SharkSshRsaHostKey_constructor(&rsaHostKey, privateKey);
SharkSshRsaHostKey_set(&config.hostKey, &rsaHostKey);
```

This conversion allocates the SharkSSL-format key. After stopping the server
and waiting for all connections to finish, release it with
`SharkSslRSAKey_free(privateKey)`. Do not free the original PEM buffer while
another product component still uses it, and erase plaintext PEM and
passphrase buffers when they are no longer needed.

### Generate a key on the device

If `SHARKSSL_ENABLE_RSAKEY_CREATE` is enabled, SharkSSL can allocate and
generate a key with
[`SharkSslRSAKey_create`](https://realtimelogic.com/ba/doc/en/C/shark/group__SharkSslCertApi.html):

```c
int keySize;
SharkSslRSAKey privateKey = NULL;

keySize = SharkSslRSAKey_create(&privateKey, 2048);
if(keySize <= 0 || !privateKey)
   return SharkSshErrCrypto;

SharkSshRsaHostKey_constructor(&rsaHostKey, privateKey);
SharkSshRsaHostKey_set(&config.hostKey, &rsaHostKey);
```

The API supports 1024-, 2048-, and 4096-bit generation; use at least 2048 bits
for a new SSH host key. The returned `keySize` is the number of bytes in the
allocated binary key. Persist exactly those bytes in protected nonvolatile
storage if the generated key is to become the device identity. Generating a
new key at every boot causes host-key-change warnings and defeats persistent
server identity.

Release a key returned by `SharkSslRSAKey_create` with
`SharkSslRSAKey_free(privateKey)` after its final use. A production device must
also ensure that SharkSSL's random number generator is securely seeded before
generating the key.

### Lifetime and shutdown order

These objects and their backing storage must outlive the listener and every
active connection:

```text
privateKey storage
    -> SharkSshRsaHostKey rsaHostKey
        -> SharkSshConfig config
            -> SharkSshServer and all SharkSshCon objects
```

Use this shutdown order:

1. Stop accepting new clients with `SharkSshServer_stop`.
2. Let all active connections finish.
3. Call `SharkSshServer_destructor`.
4. Release a dynamically converted or generated key with
   `SharkSslRSAKey_free`.

`SharkSshRsaHostKey` has no destructor because it owns no resources. If the
private key must never be exportable, do not use the software adapter. Provide
custom `SharkSshHostKey.publicKey` and `SharkSshHostKey.signHash` callbacks
that delegate signing to a Trusted Platform Module (TPM) or secure element.

### Report the host-key fingerprint

After installing the host-key callbacks, obtain the raw SHA-256 fingerprint
of the encoded SSH public key with `SharkSshHostKey_fingerprint`:

```c
U8 fingerprint[32];
int status;

status = SharkSshHostKey_fingerprint(&config.hostKey, fingerprint);
if(status != SharkSshOk)
   return status;

/* Present fingerprint through the product's commissioning interface. */
reportSshHostFingerprint(fingerprint, sizeof(fingerprint));
```

The result is exactly 32 binary bytes. A product may present it as hexadecimal
or as unpadded Base64 prefixed with `SHA256:` to match common SSH-client
display. The function never returns the private key. Call it after the host
key is installed and while its callback context remains valid. Commissioning
software should compare this value through a trusted channel and should treat
an unexpected change as a device-identity warning.

## Configure user authentication and authorization

Public-key and password authentication are independently selectable. Set only
`SharkSshAuthenticator.publicKey` for a key-only product, only `password` for
a password-only product, or both to let the SSH client choose. A successful
authentication establishes an identity; it does not by itself grant a shell,
command, or subsystem. Use `SharkSshServices.authorize` for that decision.

### RSA/SHA-256 public-key authentication

This is passwordless SSH login. Install `config.authenticator.publicKey` and
leave `config.authenticator.password` unset to advertise and accept only
public-key authentication. This is independent of the server host key: the
host key identifies the device to the client, while a user key identifies an
authorized client to the device.

The public-key callback identifies the offered key in an application-owned
account store and returns a matching application-owned `SharkSslRSAKey`:

```c
static int
verifyUserKey(void* context, SharkSshSpan user,
              SharkSshSpan algorithm, SharkSshSpan keyBlob,
              const U8 fingerprint[32],
              SharkSslRSAKey* verificationKey)
{
   AccountStore* accounts = (AccountStore*)context;
   const AccountKey* key;

   key = AccountStore_findRsaSha256(
      accounts, user, fingerprint, 32, algorithm, keyBlob);
   if(!key)
      return SharkSshErrAuth;
   *verificationKey = key->publicKey;
   return SharkSshOk;
}

config.authenticator.context = &accountStore;
config.authenticator.publicKey = verifyUserKey;
```

`algorithm` is `rsa-sha2-256`. `keyBlob` is the client's complete encoded SSH
RSA public-key blob, and `fingerprint` is its raw 32-byte SHA-256 fingerprint.
The returned SharkSSL key may be public-only or private, but it must describe
the same exponent and modulus as `keyBlob`. It remains owned by the account
store. SharkSSH validates the key match and the client's RSA/SHA-256 signature
before accepting the user.

The callback may select among multiple keys per user, consult revocation or
expiry policy, or map a compact binary key store. The core does not require
the OpenSSH `authorized_keys` text format. Do not retain any callback span.

#### Create a user key with `ssh-keygen`

OpenSSH [`ssh-keygen`](https://man.openbsd.org/ssh-keygen.1) can create the
client RSA key pair. This example creates
a 3072-bit key and prompts for an optional passphrase:

```text
ssh-keygen -t rsa -b 3072 -f sharkssh_user
```

The client keeps `sharkssh_user` private. Provision only
`sharkssh_user.pub` to the device's account-management workflow. A
passphrase protects the private key at rest but may require an SSH agent or a
prompt; it does not change SharkSSH's public-key protocol.

SharkSSH deliberately does not parse an `authorized_keys` file. The
application may decode its base64 key blob directly into an account store, or
export the OpenSSH public key as PKCS#8 PEM for conversion with the product's
SharkSSL key-loading or provisioning tool:

```text
ssh-keygen -e -m PKCS8 -f sharkssh_user.pub > sharkssh_user.pem
```

Store the resulting RSA public key as an application-owned
`SharkSslRSAKey`, associate it with the permitted username and policy, and
return it from `SharkSshAuthenticator.publicKey` only when the offered user,
algorithm, blob, and fingerprint match. Never provision the user's private
key to the server.

Use the private key from OpenSSH as follows:

```text
ssh -o IdentitiesOnly=yes -o PasswordAuthentication=no \
    -i sharkssh_user operator@device-address
```

The current server accepts RSA user keys with `rsa-sha2-256` signatures. An
Ed25519, ECDSA, DSA, SSH certificate, or X.509 key is not accepted by this
profile. The key-only authentication path is exercised against both the
standalone `selib` and BAS/BWS `SoDisp` transports.

### Optional password authentication

`password(context, user, password)` receives counted credentials and returns
zero to authenticate or a nonzero value to reject. SharkSSH gives the peer the
same failure response for an unknown user and a wrong secret and erases the
transient password bytes immediately after the callback. It rejects password-
change requests; changing credentials belongs to a separate application
service.

Use the product's password-verifier service rather than retaining plaintext
passwords. The verifier should perform equivalent bounded work for an unknown
account and a wrong password so application timing does not undo the protocol's
uniform response. Set `config.authenticator.password` to `NULL` to omit the
method completely; a public-key-only product needs no password database or
password-specific conditional build of the core.

`maxAuthAttempts` bounds failed method attempts within one SSH
connection, while `maxAuthRequests` also counts method discovery and unsigned
public-key probes. Cross-connection and per-source policy uses the abuse-
control callbacks described next.

A product can prohibit password login for privileged or key-only accounts
before invoking its credential verifier:

```c
static int
controlAuthentication(void* context, SharkSshCon* connection,
                      const SharkSshAuthenticationAttempt* attempt,
                      U32* delay)
{
   AccountPolicy* policy = (AccountPolicy*)context;
   (void)connection;
   (void)delay;
   if(attempt->authMethod == SharkSshAuthPassword &&
      AccountPolicy_requiresPublicKey(policy, attempt->user))
      return SharkSshErrAuth;
   return SharkSshOk;
}

config.abuse.context = &accountPolicy;
config.abuse.authentication = controlAuthentication;
```

The core still parses and erases the supplied password on a policy rejection,
but it does not call `SharkSshAuthenticator.password`. Return the same policy
result for every prohibited account and avoid diagnostic text that reveals
whether an account exists.

## Configure admission and authentication abuse controls

`SharkSshAbuseControl` is an optional policy boundary for limits that require
application-wide or source-specific state. Install the table in
`config.abuse`:

| Callback | When called and how to use it |
| --- | --- |
| `admit(context, connection)` | Runs after the session-start audit and before SSH identification. Return zero to admit the connection or nonzero to close it silently. A rejected callback must not leave reserved state behind. |
| `authentication(context, connection, attempt, delay)` | Runs for each syntactically framed user-authentication request before a password verifier, public-key lookup, or signature verification. Return zero to allow normal verification or nonzero to deny it. Set `*delay` to a millisecond backoff applied before the response. |
| `authenticationResult(context, connection, attempt, status)` | Receives exactly one outcome for every request passed to `authentication`, including protocol, delay, and transport failures. An accepted public-key probe has status zero but leaves `connection->authenticated` false; a completed login sets it true. |
| `release(context, connection)` | Runs exactly once for every connection accepted by `admit`, after the session-end audit. Release admission counters and any `connection->abuseData` state here. It is not called when `admit` rejects. |

`SharkSshAuthenticationAttempt.user` is transient. `authMethod` is
`SharkSshAuthPassword`, `SharkSshAuthPublicKey`, or `SharkSshAuthNone` for an
unknown or discovery method. `requestCount` includes the initial `none`
request and unsigned public-key probes. `failedAttempts` is the number of
failed verifier attempts already charged to `maxAuthAttempts`.
`publicKeyProbe` reports the unsigned form before any key lookup.

When `authentication` sets a nonzero delay, `platform.delay` must be
installed. It should put only the current connection task to sleep and must
not busy-wait. After it returns, cancellation and the authentication deadline
are checked before a response is sent. A missing delay callback produces
`SharkSshErrArgument`; zero delay needs no platform callback.

The callbacks may use `connection->abuseData` for application-owned
per-connection policy state. The core never interprets the pointer and clears
it after `release`. Shared abuse-control context can be reached concurrently
by BAS/BWS workers or application-created standalone tasks, so counters and
source tables must be synchronized by the application.

A typical setup is:

```c
config.abuse.context = &loginGuard;
config.abuse.admit = admitConnection;
config.abuse.authentication = checkAuthenticationRate;
config.abuse.authenticationResult = recordAuthenticationResult;
config.abuse.release = releaseConnection;
config.platform.delay = sleepMilliseconds;
config.maxAuthRequests = 8;
```

`admitConnection` normally reserves a global and per-source unauthenticated
slot and records the reservation in `connection->abuseData`.
`recordAuthenticationResult` converts or releases that reservation when
`connection->authenticated` becomes true, and `releaseConnection` handles all
remaining cleanup. Source identity is deliberately not standardized by the
real-time operating system (RTOS) neutral core. A standalone accept loop can
attach port-owned peer state
before `SharkSshCon_run`; a BAS/BWS policy can obtain it through the product's
socket-port integration. No address database or IP type is built into
SharkSSH.

## Configure rekeying, lifecycle controls, and audit

`SharkSshConfig_constructor` enables automatic rekey after 1 GiB in either
direction. `rekeyBytes`, `rekeyPackets`, and `rekeyTime` independently trigger
a server-initiated rekey after the selected directional byte count,
directional SSH packet count, or elapsed milliseconds. Zero disables that
trigger. Client-initiated rekey remains accepted in all cases. A rekey does
not repeat user authentication, restart the plugin, or change
`SharkSshChannel.userData`.

The four policy deadlines are disabled by default:

```c
static U32
monotonicMilliseconds(void* context)
{
   DeviceClock* clock = (DeviceClock*)context;
   return DeviceClock_milliseconds(clock);
}

config.platform.context = &deviceClock;
config.platform.now = monotonicMilliseconds;
config.handshakeTimeout = 10000;
config.authenticationTimeout = 30000;
config.idleTimeout = 300000;
config.sessionTimeout = 86400000;
config.rekeyTime = 3600000;
config.keepAliveInterval = 30000;
config.keepAliveMaxMissed = 3;
```

`now` must return monotonic milliseconds; wall-clock adjustments must not
change it. Unsigned wrap is supported. Keep each configured interval below
`0x80000000` milliseconds. Without `platform.now`, the four policy deadlines,
elapsed-time rekey, and server keepalives are ignored. `ioTimeout` continues
to control an individual socket receive wait, and byte- and packet-count
rekeying remain available.

- `handshakeTimeout` covers identification and the initial key exchange.
- `authenticationTimeout` starts when encrypted user authentication begins.
- `idleTimeout` is renewed by successful network reads and writes after
  authentication. Sending a server keepalive does not renew it.
- `sessionTimeout` is an absolute lifetime measured from connection start and
  is not renewed by activity.

`keepAliveInterval` sends `keepalive@openssh.com` after that many milliseconds
without a complete incoming SSH packet. The request asks for a reply. A
success or failure reply proves liveness; after `keepAliveMaxMissed`
unanswered requests, the connection ends with `SharkSshTimeout` and a
`SharkSshTimeoutKeepAlive` audit reason. Zero disables server keepalives. A
zero `keepAliveMaxMissed` selects `SHARKSSH_DEFAULT_KEEPALIVE_MISSES`.
Incoming client keepalive requests continue to receive
`SSH_MSG_REQUEST_FAILURE`, which is a valid reply for an unsupported global
request.

### Application-initiated termination

`platform.shouldCancel` may return `SharkSshCancelImmediate` to stop and close
the transport, or `SharkSshCancelGraceful` to make a best-effort
`SSH_MSG_DISCONNECT` with the by-application reason before closing.
`SharkSshCancelNone` continues the connection. Returning the legacy nonzero
value `1` retains immediate-termination behavior.

Set `cancelPollInterval` to bound how long an otherwise idle receive can wait
before polling `shouldCancel` again. It is a receive-side control and does not
add a write-timeout API or preempt a transport send already in progress. Zero
adds no cancellation-only wakeup, so a target needing prompt administrative
termination should select a finite value appropriate for its scheduler and
socket-port timer resolution.

Security audit records are independent of diagnostic strings:

```c
static void
recordAudit(void* context, const SharkSshAuditEvent* event)
{
   AuditStore* store = (AuditStore*)context;
   AuditStore_append(store, event->type, event->status, event->reason,
                     event->user, event->request, event->authMethod,
                     event->serviceType, event->value,
                     event->hasValue, event->bytesReceived,
                     event->bytesSent);
}

config.platform.audit = recordAudit;
```

The callback is synchronous. Its spans are transient, so copy only the
bounded fields the product retains. A service decision event can expose the
requested exec command or subsystem name in `request`; the application decides
whether to retain, redact, hash, or discard it. Events never contain passwords,
private keys, session keys, decrypted channel data, or file contents. The
public-key fingerprint is present for applicable public-key authentication
records. Applications can disable diagnostic logging while retaining the
structured audit callback.

### Resource-limit map

The core's storage limits are fixed at compile time and reject oversized
input. `SHARKSSH_MAX_PACKET_LEN`, `SHARKSSH_MAX_KEXINIT_LEN`,
`SHARKSSH_MAX_HOST_KEY_LEN`, `SHARKSSH_CHANNEL_WINDOW`, and
`SHARKSSH_CHANNEL_PACKET_LEN` control transport and channel storage.
Usernames are limited to 64 bytes, name-list elements to 64 bytes, and the
current core permits one session channel and one accepted service per
connection. A command or subsystem name must fit in the bounded SSH packet.

`maxAuthAttempts` controls failed authentication attempts per connection.
`maxAuthRequests` additionally bounds discovery requests and public-key
probes, preventing those requests from bypassing the failed-attempt budget.
`maxGlobalRequests` optionally bounds valid connection-layer global requests;
zero disables this lifetime limit. BAS/BWS
applications use `SharkSshServer_setMaxConnections` for simultaneous workers;
standalone applications impose the equivalent limit in their own accept/task
loop. A fixed `SharkSshConnectionAllocator` can enforce the BAS/BWS connection
memory budget. `SharkSshAbuseControl.admit` supplies the common callback
boundary for global or per-source unauthenticated-connection caps.

Slow identification, authentication, and authenticated peers are bounded by
the configured handshake, authentication, idle, and session deadlines. Packet
workspace, channel windows, and plugin queues remain bounded. SharkSSH does
not add a write-timeout API; a transport send already in progress follows the
selected socket port's behavior.

Paths and open handles belong to filesystem-facing plugins, not the core.
Configure their path, command, transfer, and handle limits separately. See the
[generic filesystem interface](filesystem.md) and the selected
[plugin guide](plugins/README.md).

### Authorize each requested service

`authorize(context, channel, request)` runs after authentication and before a
shell, exec, or subsystem start callback. Return zero to allow that request or
nonzero to reject it. A rejection sends channel failure and the corresponding
plugin callback is not called.

`request` supplies:

- `user`: the authenticated user;
- `authMethod`: `SharkSshAuthPassword` or `SharkSshAuthPublicKey`;
- `publicKeyFingerprint`: the raw 32-byte key fingerprint for public-key
  authentication, or an empty span for password authentication;
- `serviceType`: `SharkSshServiceShell`, `SharkSshServiceExec`, or
  `SharkSshServiceSubsystem`; and
- `request`: an empty span for shell, the command for exec, or the subsystem
  name.

All spans are read-only and valid only during the callback. The application
can use this one policy point for per-user commands, key-specific restrictions,
read-only SFTP selection, forced commands, or disabled interactive access.
When `authorize` is `NULL`, an installed service callback is eligible to
accept the request; security-sensitive products should install an explicit
policy callback.

## Standalone SharkSSL with [selib](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html)

Compile `src/SharkSSH.c` and `src/SharkSshCrypto.c` with the target SharkSSL
library, `SharkSSL/src/selib.c`, and the target's `selibplat.h` port. The
SharkSSL version must provide `sharkssl_X25519_createKeyPair` and
`sharkssl_X25519_sharedSecret` in its public `SharkSSL.h`. Enable
`SHARKSSL_ENABLE_X25519_API` in the SharkSSL configuration. The
include path normally contains:

```text
SharkSSH/inc
SharkSSH/src
SharkSSL/inc
SharkSSL/inc/arch/<target>
SharkSSL/src
SharkSSL/src/arch/<target>
```

The typical small embedded server accepts and serves clients in a loop. This
example handles one client at a time and then returns to `accept`. The finite
accept timeout lets the task periodically observe the global `run` flag.

```c
static volatile U8 run = TRUE;

void
stopSshServer(void)
{
   run = FALSE;
}

int
serveClients(SeCtx* socketContext, SharkSslRSAKey privateKey)
{
   SharkSshConfig config;
   SharkSshRsaHostKey rsaHostKey;
   SharkSshServer server;
   SharkSshCon connection;
   int status;

   configureSsh(&config, &rsaHostKey, privateKey);
   SharkSshServer_constructor(&server, &config, socketContext);
   status = SharkSshServer_bind(&server, 22);

   while(status == SharkSshOk && run)
   {
      status = SharkSshServer_accept(&server, &connection, socketContext,
                                     1000);
      if(status == SharkSshTimeout)
      {
         status = SharkSshOk;
         continue;
      }
      if(status != SharkSshOk)
         break;

      (void)SharkSshCon_run(&connection);
      SharkSshCon_destructor(&connection);
   }

   SharkSshServer_destructor(&server);
   return status;
}
```

Setting `run` to `FALSE` stops the accept loop after the current client exits,
or after the next one-second accept timeout when the server is idle. Replace
the volatile flag with the target's atomic, event, or task-notification
primitive when its concurrency rules require one. A per-session protocol or
authentication failure is intentionally confined to that client and does not
stop the listening server.

To serve clients concurrently, keep the listening server in an accept task
and give each accepted, application-owned `SharkSshCon` to one dedicated
connection task. Do not reuse the connection storage until that task has
called `SharkSshCon_destructor`.

## [BAS/BWS](https://realtimelogic.com/ba/doc/en/C/reference/html/index.html) with an existing [SoDisp](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)

Compile `src/SharkSSH.c` and `src/SharkSshCrypto.c` with exactly one BAS/BWS
amalgamation: `BWS.c` for a native application without Lua, or `BAS.c` when
BAS/Lua services are required. Add the target's normal thread and dispatcher
porting files. The BAS/BWS amalgamation must include the public SharkSSL
X25519 functions described in the standalone section. Do not compile
`selib.c` in this mode.

The application must create and operate its
[`HttpServer`](https://realtimelogic.com/ba/doc/en/C/reference/html/structHttpServer.html)
and SoDisp before
starting SharkSSH. SharkSSH only needs the existing `HttpServer`; it does not
require a separate dispatcher.

```c
typedef struct
{
   SharkSshConfig config;
   SharkSshRsaHostKey rsaHostKey;
   SharkSshServer server;
} AppSsh;

int
AppSsh_start(AppSsh* ssh, HttpServer* httpServer,
             SharkSslRSAKey privateKey)
{
   int status;
   configureSsh(&ssh->config, &ssh->rsaHostKey, privateKey);
   SharkSshServer_constructor(&ssh->server, &ssh->config, httpServer);

   status = SharkSshServer_setMaxConnections(&ssh->server, 4);
   if(status != SharkSshOk)
      return status;

   return SharkSshServer_bind(&ssh->server, 22);
}

void
AppSsh_stop(AppSsh* ssh)
{
   /* Call according to the owning application's dispatcher-locking rules. */
   SharkSshServer_stop(&ssh->server);
}

int
AppSsh_canDestroy(AppSsh* ssh)
{
   return SharkSshServer_activeConnections(&ssh->server) == 0;
}

void
AppSsh_destructor(AppSsh* ssh)
{
   /* AppSsh_canDestroy must be true and the dispatcher must still exist. */
   SharkSshServer_destructor(&ssh->server);
}
```

After `AppSsh_start` succeeds, the application continues operating its normal
dispatcher loop. `AppSsh_stop` prevents new SSH connections. Keep `AppSsh`,
the `HttpServer`, its dispatcher, the host key, and all callback contexts alive
until `AppSsh_canDestroy` returns true. Only then call `AppSsh_destructor`.

`SharkSshServer_setConnectionAllocator` may be called before `bind` when a
fixed RTOS pool should supply per-connection storage:

```c
SharkSshConnectionAllocator allocator;
allocator.context = &sshConnectionPool;
allocator.allocate = poolAllocate;
allocator.release = poolRelease;

status = SharkSshServer_setConnectionAllocator(&ssh->server, &allocator);
```

Both allocator functions can run in different application execution contexts,
so the pool must provide the required synchronization. Passing `NULL` restores
the default BAS/BWS allocator. The allocator object is copied, but its
`context` must remain valid until all connections finish.

## Public type reference

The preceding sections are the task-oriented integration guide. Use the
remainder of this document when you need the exact meaning of a public type,
field, callback, or function.

### Status values

Most functions return a `SharkSshStatus` value:

| Value | Meaning |
| --- | --- |
| `SharkSshOk` | Operation succeeded |
| `SharkSshTimeout` | A socket or policy deadline expired, the keepalive miss limit was reached, or a channel write could not proceed because the peer's window was zero |
| `SharkSshClosed` | The peer sent an SSH disconnect or the application requested immediate or graceful cancellation |
| `SharkSshErrArgument` | A required argument or callback input was invalid |
| `SharkSshErrSocket` | TCP send, receive, listen, or accept failed |
| `SharkSshErrProtocol` | The peer sent an invalid or unexpected SSH message |
| `SharkSshErrBounds` | Data exceeded a configured or supplied capacity |
| `SharkSshErrCrypto` | A cryptographic operation failed |
| `SharkSshErrAuth` | Authentication failed |
| `SharkSshErrService` | A requested application service failed or is unavailable |
| `SharkSshErrState` | The object is not in a state that permits the operation |

`SHARKSSH_TIMEOUT_INFINITE` requests an indefinite socket wait where a timeout
argument is accepted.

### `SharkSshSpan`

```c
typedef struct { const U8* ptr; U32 len; } SharkSshSpan;
```

This is a read-only, counted byte sequence. User names, passwords, commands,
terminal names, subsystem names, input data, and paths use spans. They may
contain any byte unless the receiving application API imposes additional
rules.

### `SharkSshLogLevel`

`SharkSshLogTrace`, `SharkSshLogInfo`, `SharkSshLogWarning`,
`SharkSshLogError`, and `SharkSshLogAudit` classify messages delivered to the
optional platform log callback.

### Audit and timeout values

`SharkSshAuditType` identifies these core events:

| Event | Meaning and event-specific fields |
| --- | --- |
| `SharkSshAuditServerStarted`, `SharkSshAuditServerStopped` | Listener lifecycle. `connection` is `NULL`; `value` is the TCP port and `hasValue` is one. |
| `SharkSshAuditConnectionAccepted` | A moved or accepted socket began its connection task. |
| `SharkSshAuditConnectionRejected` | Admission, listener capacity, allocation, or socket-transfer policy rejected the connection. Listener-level capacity/allocation records use the corresponding `reason`. |
| `SharkSshAuditSessionStart`, `SharkSshAuditSessionEnd` | Start and final result of the SSH connection run loop. |
| `SharkSshAuditNegotiationFailure` | The client and server had no supported algorithm in one required category. |
| `SharkSshAuditProtocolFailure` | Malformed input or an invalid SSH state transition ended the connection. |
| `SharkSshAuditAuthenticationFailure`, `SharkSshAuditAuthenticationSuccess` | Authentication result, method, user, and public-key fingerprint when applicable. |
| `SharkSshAuditChannelOpened`, `SharkSshAuditChannelRejected`, `SharkSshAuditChannelClosed` | Session-channel lifecycle and result. |
| `SharkSshAuditServiceDenied`, `SharkSshAuditServiceStarted` | Shell, exec, or subsystem authorization/start result. `request` is the exec command or subsystem name and is empty for shell. |
| `SharkSshAuditServiceStopped` | Service termination status. When an exit status was sent, `value` contains it and `hasValue` is one. Correlate it with the service-start event using `connection`. |
| `SharkSshAuditRekey` | A completed transport rekey. |
| `SharkSshAuditTimeout` | A configured deadline or keepalive limit ended the connection; `reason` is a `SharkSshTimeoutType`. |
| `SharkSshAuditResourceRejected` | A configured or fixed resource bound rejected work; `reason` is a `SharkSshResourceType`. |
| `SharkSshAuditDisconnect` | An SSH disconnect was received or locally attempted. `value` is the SSH protocol reason code and `hasValue` is one. |

For `SharkSshAuditTimeout`, `reason` is `SharkSshTimeoutIo`,
`SharkSshTimeoutHandshake`, `SharkSshTimeoutAuthentication`,
`SharkSshTimeoutIdle`, `SharkSshTimeoutSession`, or
`SharkSshTimeoutKeepAlive`.

For `SharkSshAuditResourceRejected`, `reason` is
`SharkSshResourceUnspecified`, `SharkSshResourceConnectionLimit`,
`SharkSshResourceConnectionAllocation`,
`SharkSshResourceAuthenticationAttempts`,
`SharkSshResourceAuthenticationRequests`,
`SharkSshResourceGlobalRequests`, or `SharkSshResourceChannelLimit`.

Every `SharkSshAuditEvent` supplies `type` and `status`. Connection-level
events also supply `connection`, cumulative `bytesReceived` and `bytesSent`,
and the currently known authentication, user, fingerprint, and service
metadata. `request` is populated only while a service decision is being
reported. `hasValue` distinguishes a meaningful zero `value` from no value.
All spans and the event object are valid only until the callback returns.
The connection pointer may be used as a correlation token during that
connection's lifetime but must not be dereferenced or retained after the
connection task ends.

Core audit records cover the SSH transport, authentication, channel, and
service lifecycle. Optional shell and SFTP plugins provide their own
operation-level audit callbacks for individual commands and filesystem
operations; installing a plugin audit callback is independent of installing
`SharkSshPlatform.audit`.

### Authentication and service values

`SharkSshAuthNone`, `SharkSshAuthPassword`, and `SharkSshAuthPublicKey`
identify the method recorded for a connection. Authorization callbacks receive
one of the latter two after successful authentication.

`SharkSshServiceShell`, `SharkSshServiceExec`, and
`SharkSshServiceSubsystem` identify the operation being authorized and the
accepted service attached to the channel.

`SharkSshCancelNone`, `SharkSshCancelImmediate`, and
`SharkSshCancelGraceful` are the values returned by
`SharkSshPlatform.shouldCancel`.

### `SharkSshConfig`

Call `SharkSshConfig_constructor` first, then set these fields:

| Field | Use |
| --- | --- |
| `hostKey` | Required server host-key callbacks |
| `authenticator` | Independently selectable RSA public-key and password authentication callbacks |
| `services` | Authorization, session, PTY, shell, exec, and subsystem callbacks |
| `platform` | Optional logging, structured audit, monotonic time, cancellation, and cooperative scheduling callbacks |
| `abuse` | Optional connection admission, authentication policy/backoff, result, and cleanup callbacks |
| `fileSystem` | Optional [generic filesystem table](filesystem.md) passed to the subsystem callback |
| `ioTimeout` | Socket receive timeout in milliseconds, or `SHARKSSH_TIMEOUT_INFINITE`; the constructor selects infinite |
| `handshakeTimeout` | Maximum milliseconds for identification and initial key exchange; zero disables it and nonzero requires `platform.now` |
| `authenticationTimeout` | Maximum milliseconds in user authentication; zero disables it and nonzero requires `platform.now` |
| `idleTimeout` | Maximum inactive milliseconds after authentication; zero disables it and nonzero requires `platform.now` |
| `sessionTimeout` | Maximum total connection lifetime in milliseconds; zero disables it and nonzero requires `platform.now` |
| `rekeyBytes` | Initiate rekey after this many bytes sent or received since the preceding key exchange; zero disables server initiation but not peer initiation; the constructor selects `SHARKSSH_DEFAULT_REKEY_BYTES` |
| `rekeyTime` | Initiate rekey after this many milliseconds since the preceding key exchange; zero disables the trigger and nonzero requires `platform.now` |
| `rekeyPackets` | Initiate rekey after this many SSH packets are sent or received since the preceding key exchange; zero disables the trigger |
| `keepAliveInterval` | Send a reply-requesting server keepalive after this many milliseconds without a complete incoming SSH packet; zero disables it and nonzero requires `platform.now` |
| `cancelPollInterval` | Maximum receive-side wait between `shouldCancel` polls; zero adds no cancellation-only wakeup |
| `maxAuthAttempts` | Rejected authentication attempts allowed per connection; zero selects `SHARKSSH_MAX_AUTH_ATTEMPTS`. The client's initial `none` query and an accepted unsigned public-key probe do not consume an attempt. |
| `maxAuthRequests` | Total user-authentication requests allowed per connection, including `none` discovery and unsigned public-key probes; zero selects `SHARKSSH_MAX_AUTH_REQUESTS` |
| `maxGlobalRequests` | Valid incoming global requests allowed over the authenticated connection lifetime; zero disables the cap |
| `keepAliveMaxMissed` | Unanswered server keepalives allowed before a liveness timeout; zero selects `SHARKSSH_DEFAULT_KEEPALIVE_MISSES` |

### `SharkSshHostKey`

| Callback | Contract |
| --- | --- |
| `publicKey(context, data, capacity, size)` | Write the server public-key blob to `data`, set `*size`, and return zero. Return `SharkSshErrBounds` if `capacity` is insufficient. |
| `signHash(context, hash, signature, capacity, size)` | Sign the supplied 32-byte SHA-256 digest, write the raw RSA signature, set `*size`, and return zero. The private key need not leave the callback provider. |

Set `context` to the application object used by both callbacks. The current
protocol profile requires an RSA key usable with `rsa-sha2-256`.

### `SharkSshAuthenticator`

| Callback | Contract |
| --- | --- |
| `password(context, user, password)` | Verify counted credentials. Return zero to accept. The spans are transient, and SharkSSH erases the password bytes after return. |
| `publicKey(context, user, algorithm, keyBlob, fingerprint, verificationKey)` | Authorize an offered RSA/SHA-256 key and place the matching application-owned SharkSSL RSA key in `*verificationKey`. Return zero to permit cryptographic verification or nonzero to reject. |

Set `context` to the product's account/key service. At least one method must be
installed for a client to authenticate.

### `SharkSshServices`

All callbacks receive the table's `context` and the current channel.

| Callback | When called and how to use it |
| --- | --- |
| `authorize(context, channel, request)` | Optional operation-policy callback invoked after authentication but before `shell`, `exec`, or `subsystem`. Inspect the authenticated user, authentication method, optional key fingerprint, service type, and command/subsystem name. Return nonzero to reject without starting the plugin. |
| `open(context, channel, user)` | Optional session admission callback. It runs before the session channel is accepted. Initialize `channel->userData` here and return nonzero to reject the session. When rejecting after allocating state, release it before returning because `close` is not called for a rejected channel. |
| `close(context, channel)` | Optional, exactly-once cleanup notification for an accepted channel. Release `channel->userData`. It runs after the peer's channel-close message or when the connection is destroyed because of cancellation, network loss, or a protocol error. |
| `pty(context, channel, terminal, columns, rows, width, height, modes)` | Accept or reject a PTY request. Dimensions are character and pixel dimensions supplied by the client. `modes` is the counted SSH terminal-mode payload. An application using the [bounded shell plugin](plugins/sharkssh-shell.md) normally passes it to `SharkSshShell_pty` so interactive echo follows the client's PTY settings. |
| `windowChange(context, channel, columns, rows, width, height)` | Apply a later terminal-size change. |
| `shell(context, channel)` | Initialize the product's interactive command interface. Return zero to accept. Queue initial output in application state; `writable` is called after the core sends the channel-success reply. |
| `exec(context, channel, command)` | Initialize one allowlisted embedded command and return zero to accept it. The service owns subsequent input, output, exit-status, EOF, and close processing. |
| `subsystem(context, channel, name, fileSystem)` | Initialize a named subsystem. `fileSystem` is the configured [filesystem table](filesystem.md) or `NULL`. Return zero to accept it. |
| `data(context, channel, data)` | Consume or copy all counted standard-input bytes for the accepted shell, exec, or subsystem before returning. The span is transient. A callback that needs later processing must use bounded application-owned storage. `SharkSshTimeout` means the input was retained but output is waiting for window credit. |
| `eof(context, channel)` | Handle the peer's one-time input EOF. Finish any operation that depends on end of input; output may continue until the service closes its side. `SharkSshTimeout` likewise means queued output is paused. |
| `writable(context, channel)` | Produce or resume queued output after service acceptance and whenever the peer increases its channel window. Return `SharkSshTimeout` when `writeSome` exhausts the window; the core treats that as a normal pause and calls again after more credit arrives. |

SharkSSH does not launch an operating-system process or interpret shell text.
The application implements and restricts every exposed command. Exactly one
shell, exec, or subsystem request may be accepted on a channel. Later service
requests on that channel receive channel failure and do not reach their start
callback. PTY requests must arrive before the service starts.

The start callbacks run before the core can send their success reply, so they
should initialize state rather than transmit channel data directly. The first
`writable` call follows the reply. For a completed command, the normal outbound
order is remaining stdout/stderr, `SharkSshChannel_sendExitStatus`,
`SharkSshChannel_sendEof`, and channel close. `SharkSshChannel_close` combines
the last two steps.

### `SharkSshPlatform`

| Callback | Use |
| --- | --- |
| `log(context, level, message)` | Receive a transient NUL-terminated diagnostic message. Existing `SharkSshLogAudit` text remains available, but structured security processing should use `audit`. |
| `audit(context, event)` | Receive a transient structured security event independently of diagnostic logging. Server/listener events can arrive on the dispatcher or accept task and use `connection == NULL`; per-connection events arrive on that connection's task. The callback must return promptly and synchronize shared storage. |
| `now(context)` | Return monotonic milliseconds for policy deadlines, elapsed-time rekeying, and server keepalives. |
| `shouldCancel(context)` | Return `SharkSshCancelNone`, `SharkSshCancelImmediate`, or `SharkSshCancelGraceful`. Immediate termination closes without an SSH disconnect; graceful termination sends a best-effort by-application disconnect first. |
| `cooperate(context)` | Optional scheduling/watchdog hook called while processing network I/O. It must return promptly. |
| `delay(context, milliseconds)` | Sleep the current connection task for authentication backoff. It is required only when an abuse callback requests a nonzero delay. |

All callbacks are optional. The same `context` is passed to each.

### `SharkSshConnectionAllocator` (BAS/BWS only)

`allocate(context, size)` returns suitably aligned storage of at least `size`
bytes, or `NULL` when the pool is exhausted. `release(context, memory)` returns
that same storage after the connection has finished. Both callbacks are
required when the allocator is installed, and their shared `context` must
remain valid and provide any synchronization needed by the backing pool.

### `SharkSshFileSystem`

The optional filesystem table is a generic, RTOS-neutral callback interface.
Assign it to `SharkSshConfig.fileSystem`; the table and its context must remain
valid until every connection that can use them has finished. The core passes
the same pointer to `SharkSshServices.subsystem` and does not access storage
directly.

See the [generic filesystem interface](filesystem.md) for initialization,
callbacks, statuses, flags, metadata, handle ownership, concurrency, and
namespace-security requirements.

### Server, connection, and channel objects

- `SharkSshServer` holds a listening endpoint. Application storage must remain
  valid from construction through destruction.
- In standalone mode, the application supplies one `SharkSshCon` per accepted
  client. In BAS/BWS mode, normal connection creation is managed by the server.
- `SharkSshCon.abuseData` is application-owned from admission through the
  abuse-control `release` callback. Do not use it for service/plugin state.
- `SharkSshChannel` identifies the current session channel. Only `userData` is
  application-owned; use the channel functions to send or close.
- `SharkSshState` values (`SharkSshStateNew`, `SharkSshStateVersion`,
  `SharkSshStateKeyExchange`, `SharkSshStateAuthentication`,
  `SharkSshStateConnection`, and `SharkSshStateClosed`) describe connection
  progress for diagnostics. Applications should not modify the state.

## Function reference

### Configuration and host keys

`void SharkSshConfig_constructor(SharkSshConfig* config)`

: Clears the configuration, selects the default infinite I/O timeout,
  failed-attempt and total authentication-request limits, keepalive miss
  limit, and 1-GiB byte rekey threshold. It leaves the global-request cap,
  policy deadlines, server keepalives, time/packet rekeying, and cancellation
  polling disabled. Passing `NULL` has no effect.

`void SharkSshRsaHostKey_constructor(SharkSshRsaHostKey* hostKey,
SharkSslRSAKey privateKey)`

: Associates a SharkSSL software
  [RSA private key](https://realtimelogic.com/ba/doc/en/C/shark/group__RSA.html)
  with the adapter. The key
  remains application-owned and must outlive all uses.

`void SharkSshRsaHostKey_set(SharkSshHostKey* target,
SharkSshRsaHostKey* hostKey)`

: Installs the software adapter's callbacks and context in `target`. A common
  target is `&config.hostKey`.

`int SharkSshHostKey_fingerprint(const SharkSshHostKey* hostKey,
U8 fingerprint[32])`

: Writes the raw SHA-256 fingerprint of the encoded SSH host public key. The
  host-key callback context must be valid. The output is suitable for a
  commissioning display after application-selected hex or Base64 encoding.

### Common server functions

`int SharkSshServer_bind(SharkSshServer* server, U16 port)`

: Starts listening on `port`. Call it once after construction and optional
  server settings. Returns `SharkSshErrState` if already listening.

`void SharkSshServer_stop(SharkSshServer* server)`

: Stops accepting new clients. It is safe to call when already stopped. It
  does not cancel established sessions.

`void SharkSshServer_destructor(SharkSshServer* server)`

: Stops the listener and releases its transport resources. In BAS/BWS mode,
  all active connections must already have finished.

### Standalone-only server functions

`void SharkSshServer_constructor(SharkSshServer* server,
const SharkSshConfig* config, SeCtx* socketContext)`

: Initializes an application-owned standalone listener using the supplied
  `selib` context.

`int SharkSshServer_accept(SharkSshServer* server,
SharkSshCon* connection, SeCtx* socketContext, U32 timeout)`

: Waits for one client, constructs `connection`, and attaches the accepted
  socket. Returns `SharkSshTimeout` when the wait expires. On success, pass the
  connection to exactly one owner which calls `SharkSshCon_run` and then
  `SharkSshCon_destructor`.

### BAS/BWS-only server functions

`void SharkSshServer_constructor(SharkSshServer* server,
const SharkSshConfig* config, HttpServer* httpServer)`

: Initializes the SSH server against the application's existing `HttpServer`
  and its existing dispatcher. The HTTP server must outlive the SSH server and
  all SSH connections.

`int SharkSshServer_setConnectionAllocator(SharkSshServer* server,
const SharkSshConnectionAllocator* allocator)`

: Installs a copied `allocate`/`release` pair for connection storage. Both
  functions are required. Call before `bind` and while no connections are
  active. Pass `NULL` to restore the default allocator.

`int SharkSshServer_setMaxConnections(SharkSshServer* server,
U16 maxConnections)`

: Sets a nonzero admission limit. Call before `bind` and while no connections
  are active. The constructor selects `SHARKSSH_DEFAULT_MAX_CONNECTIONS`.

`U32 SharkSshServer_activeConnections(SharkSshServer* server)`

: Returns the number of currently active SSH connections, or zero for an
  invalid server.

`U32 SharkSshServer_completedConnections(SharkSshServer* server)`

: Returns the cumulative number of connections that completed after being
  admitted.

`U32 SharkSshServer_rejectedConnections(SharkSshServer* server)`

: Returns the cumulative number of connections not admitted because of the
  capacity limit, allocation failure, or transport handoff failure.

`U32 SharkSshServer_peakConnections(SharkSshServer* server)`

: Returns the highest simultaneous active-connection count observed by this
  server object.

### Connection functions

Standalone signature:

`void SharkSshCon_constructor(SharkSshCon* connection,
const SharkSshConfig* config, SeCtx* socketContext)`

BAS/BWS signature:

`void SharkSshCon_constructor(SharkSshCon* connection,
const SharkSshConfig* config)`

: Initializes connection storage for the selected integration. Standalone
  applications normally let `SharkSshServer_accept` call this function.
  BAS/BWS applications normally let the server manage connections.

`int SharkSshCon_run(SharkSshCon* connection)`

: Runs the SSH session synchronously until it closes, is canceled, times out,
  or fails. It requires a valid attached socket and configuration. The return
  value explains why processing stopped.

`void SharkSshCon_destructor(SharkSshCon* connection)`

: Closes the connection transport, notifies the service `close` callback when
  necessary, erases transient packet and session-secret storage, and makes the
  object reusable only after a new constructor call.

### Channel functions

`int SharkSshChannel_write(SharkSshChannel* channel,
const void* data, U32 size)`

: Sends standard output/data. The call may split the input into multiple SSH
  packets. It first checks the peer's current channel window and returns
  `SharkSshTimeout` without sending any bytes when the complete buffer does not
  fit. Use `writeSome` for resumable output. `data` may be `NULL` only when
  `size` is zero.

`int SharkSshChannel_writeError(SharkSshChannel* channel,
const void* data, U32 size)`

: Sends standard error/extended data. Its ownership and return rules match
  `SharkSshChannel_write`.

`int SharkSshChannel_writeSome(SharkSshChannel* channel,
const void* data, U32 size, U32* written)`

: Sends as much standard output/data as the peer's current window permits and
  writes the exact byte count to `*written`. It returns `SharkSshTimeout` when
  bytes remain. Retain the unsent suffix in bounded service state and resume
  from `writable`; never resend the reported prefix. Zero-length output is
  valid.

`int SharkSshChannel_writeErrorSome(SharkSshChannel* channel,
const void* data, U32 size, U32* written)`

: The resumable standard-error form of `SharkSshChannel_writeSome`. Standard
  output and standard error consume the same peer channel window.

`int SharkSshChannel_sendExitStatus(SharkSshChannel* channel, U32 status)`

: Sends a process-style exit status on an open channel. An `exec` callback
  normally calls this once after all output is sent. A second call or a call
  without an accepted service returns `SharkSshErrState`.

`int SharkSshChannel_sendEof(SharkSshChannel* channel)`

: Half-closes the service's output side while leaving the channel open for the
  peer's close message. Repeated calls after a successful send are harmless.
  No output may be written after local EOF.

`int SharkSshChannel_close(SharkSshChannel* channel)`

: Sends end-of-file and channel close. The connection loop remains active
  until the peer replies with channel close, so unread peer control packets do
  not cause a TCP reset. The service `close` callback runs only when that reply
  arrives or when connection teardown cancels the wait. Do not use the channel
  for output afterward; repeated calls after a successful send are harmless.

## Compile-time configuration

Define these macros before including or compiling SharkSSH to tune public
limits. Larger values generally increase object or stack requirements, so
measure the resulting target image and runtime usage.

| Macro | Default | Purpose |
| --- | ---: | --- |
| `SHARKSSH_MAX_PACKET_LEN` | 2048 | Maximum SSH packet workspace |
| `SHARKSSH_MAX_KEXINIT_LEN` | 2048 | Maximum stored key-exchange proposal; lower it only after checking every required SSH client |
| `SHARKSSH_MAX_HOST_KEY_LEN` | 544 | Maximum encoded host public key |
| `SHARKSSH_MAX_PATH_LEN` | 256 | Maximum path supported by adapters that use this limit |
| `SHARKSSH_MAX_AUTH_ATTEMPTS` | 3 | Default authentication-attempt limit |
| `SHARKSSH_MAX_AUTH_REQUESTS` | 8 | Default total authentication-request limit, including discovery and probes |
| `SHARKSSH_MAX_GLOBAL_REQUESTS` | 0 | Initial global-request cap; zero disables it |
| `SHARKSSH_DEFAULT_REKEY_BYTES` | 1 GiB | Default sent-or-received byte threshold for automatic rekey |
| `SHARKSSH_DEFAULT_KEEPALIVE_MISSES` | 3 | Default unanswered server-keepalive limit |
| `SHARKSSH_CHANNEL_WINDOW` | 32768 | Initial receive window advertised for the session channel |
| `SHARKSSH_CHANNEL_PACKET_LEN` | 1024 | Maximum incoming channel-data packet advertised to peers |
| `SHARKSSH_THREAD_STACK_SIZE` | 10000 | BAS/BWS connection-task stack size |
| `SHARKSSH_DEFAULT_MAX_CONNECTIONS` | 4 | BAS/BWS default concurrent-connection limit |

The last two macros exist only when `SHARKSSL_BA` is enabled.

## Related documentation

- [Design overview](design/overview.md)
- [Plugin index](plugins/README.md)
