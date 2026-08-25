# SFTP version 3 plugin

`SharkSshSftp` is an optional, allocation-free Secure File Transfer Protocol
(SFTP) version 3 subsystem. Use it when an embedded SSH server must expose a
controlled file namespace without depending on POSIX or a particular
filesystem.

The plugin follows
[SFTP version 3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
and uses only [`SharkSSH.h`](../../inc/SharkSSH.h) and a
[`SharkSshFileSystem`](../filesystem.md) callback table. The same plugin
therefore works with:

- standalone [SharkSSL](https://github.com/RealTimeLogic/SharkSSL) and
  [`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html);
- Barracuda App Server (BAS) or Barracuda Web Server (BWS) with
  [`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html);
  or
- a real-time operating system (RTOS) filesystem adapter.

It supports protocol negotiation, open, close, read, write, stat, lstat,
fstat, optional setstat and fsetstat, directory enumeration, realpath, mkdir,
rmdir, remove, and rename. Symbolic-link requests and unadvertised extensions
return `SSH_FX_OP_UNSUPPORTED`.

## Add the plugin

Compile these files with the application:

```text
src/plugins/Sftp/SharkSshSftp.c
src/plugins/Sftp/SharkSshSftp.h
```

Add `src/plugins/Sftp` and the SharkSSH public include directory to the include
path. A build that does not compile `SharkSshSftp.c` carries no SFTP code or
per-session SFTP storage.

Each active SFTP channel requires one caller-owned `SharkSshSftp` object.

## Configure SFTP

```c
#include <SharkSshSftp.h>

SharkSshSftpConfig sftpConfig;

memset(&sftpConfig, 0, sizeof(sftpConfig));
sftpConfig.context = &application;
sftpConfig.fileSystem = &application.fileSystem;
sftpConfig.root = "management";
sftpConfig.authorize = authorizeSftpOperation;
sftpConfig.audit = auditSftpOperation;
```

`root` is a trusted, filesystem-relative path. The client sees it as `/` and
never sees the backing prefix. `NULL`, `""`, and `"/"` export the filesystem
adapter's existing root. Set `readOnly` nonzero to reject file writes,
attribute changes, removes, renames, and directory changes.

The configuration and filesystem table must outlive every SFTP session that
uses them. Shared callback contexts must be safe for simultaneous connection
tasks.

## Connect it to SharkSSH

Each accepted channel needs its own `SharkSshSftp` object. It can be embedded
in the same application session object that contains shell or command state:

```c
typedef struct
{
   SharkSshSftp sftp;
   U8 sftpActive;
} DeviceSession;

static int
openSession(void* context, SharkSshChannel* channel, SharkSshSpan user)
{
   DeviceSession* session = allocateDeviceSession(context);
   (void)user;
   if( ! session)
      return SharkSshErrBounds;
   SharkSshSftp_constructor(&session->sftp, &application.sftpConfig);
   channel->userData = session;
   return SharkSshOk;
}

static int
startSubsystem(void* context, SharkSshChannel* channel,
               SharkSshSpan name, const SharkSshFileSystem* fileSystem)
{
   DeviceSession* session = (DeviceSession*)channel->userData;
   static const char sftpName[] = "sftp";
   (void)context;
   (void)fileSystem;
   if(name.len != sizeof(sftpName) - 1 ||
      memcmp(name.ptr, sftpName, sizeof(sftpName) - 1))
      return SharkSshErrService;
   session->sftpActive = 1;
   return SharkSshSftp_start(&session->sftp, channel);
}
```

When `sftpActive` is set, route `SharkSshServices.data`, `eof`, and `writable`
to `SharkSshSftp_data`, `SharkSshSftp_eof`, and
`SharkSshSftp_writable`. The session `close` callback must call
`SharkSshSftp_destructor` before releasing the session object. The destructor
closes every remaining file or directory and aborts every staged upload,
including after network loss or malformed input.

Set `SharkSshServices.subsystem` to `startSubsystem`, and independently allow
the `sftp` subsystem in `SharkSshServices.authorize`. Core service
authorization decides whether a user may start SFTP; the plugin's `authorize`
callback can then apply per-path and per-operation policy.

## Virtual paths and policy

Client paths are canonicalized to slash-separated absolute paths. Repeated
separators and `.` are removed, `..` is clamped at the exported root, and NUL,
colon, overlong, and backslash-based escape attempts are rejected or
normalized before a filesystem callback runs.

`authorize(context, channel, operation, path)` receives the canonical
client-visible path. Return `SharkSshOk` to allow the operation and nonzero to
return `SSH_FX_PERMISSION_DENIED`. Operations are the
`SharkSshSftpOperation` values. The callback may inspect the authenticated
channel connection when applying user or key policy.

`audit(context, event)` receives the channel, canonical path, operation, and
SFTP status for each filesystem-facing request. The event and path span are
transient. They contain no transferred file data.

## Staged uploads

Set `stageUpload` to place create/truncate uploads in an application-selected
staging object. The callback receives the final filesystem path and a session
token, and writes a counted staging path into the supplied bounded buffer.

After a successful file close, `commitUpload` receives the staging and final
paths. Use it to validate and atomically activate firmware or configuration
data. If `commitUpload` is unset, the plugin calls the filesystem `rename`
callback. When the connection ends early or commit fails, `abortUpload` is
called; if it is unset, the plugin removes the staging path.

An exclusive-create request bypasses staging and passes
`SharkSshFsOpenExclusive` to the filesystem. This preserves the required
atomic check against the final target; a separate staging path cannot provide
that guarantee.

The application owns uniqueness, validation, atomicity, and replacement
semantics. Do not generate a staging path outside storage that is safe for the
authenticated SFTP policy.

## Memory bounds and client compatibility

Defaults are:

| Macro | Default | Purpose |
| --- | ---: | --- |
| `SHARKSSH_SFTP_PACKET_SIZE` | 4096 | Maximum SFTP request payload |
| `SHARKSSH_SFTP_READ_SIZE` | 1024 | Maximum data in one read response |
| `SHARKSSH_SFTP_MAX_HANDLES` | 4 | Files and directories open per session |

The packet size must be from 512 through 65531 bytes. The read size must be at
least 64 bytes and must leave 32 bytes of packet space for the response
metadata. The handle count must be from 1 through 255. The header stops the
build when a configured value violates these relationships.

The plugin advertises and answers OpenSSH's
[`limits@openssh.com`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL#L2351)
extension.
Current OpenSSH clients therefore reduce their normal transfer block and open
handle limits to these values. Clients that do not implement this extension
must be configured not to exceed `SHARKSSH_SFTP_PACKET_SIZE`, or the target can
select a larger compile-time value.

One complete request and one response are retained per session. Requests are
executed synchronously in wire order; clients may keep requests outstanding,
but storage callbacks are never concurrent within one session. No dynamic
allocation, POSIX API, thread API, or transport API is used by the plugin.

## Filesystem requirements

Install callbacks only for operations the product supports. Missing callbacks
produce `SSH_FX_OP_UNSUPPORTED`. `open`, `close`, `read`, `write`, and `seek`
provide file transfer. Directory callbacks provide listings. `stat` provides
path and open-handle attributes; the plugin retains each handle's bounded path
for fstat. Optional `setStat` enables size, permission, and modification-time
updates selected by `SharkSshFsSetFlags`.

Filesystem callbacks should return the portable `SharkSshFsStatus` values so
the plugin can distinguish not-found, denied, unsupported, and generic
failures. See the [generic filesystem interface](../filesystem.md) for the
complete callback, status, flag, handle, concurrency, and path contracts.

## Public API

`void SharkSshSftp_constructor(SharkSshSftp* sftp,
const SharkSshSftpConfig* config)`

: Clears the per-session object and retains the non-owning configuration.

`void SharkSshSftp_destructor(SharkSshSftp* sftp)`

: Closes all remaining handles, aborts staged uploads, and detaches the
  channel. It is safe to call after partial startup.

`int SharkSshSftp_start(SharkSshSftp* sftp, SharkSshChannel* channel)`

: Validates the configuration root and attaches a newly accepted subsystem
  channel. It does not send data before the core sends channel success.

`int SharkSshSftp_data(SharkSshSftp* sftp, SharkSshChannel* channel,
SharkSshSpan data)`

: Retains and processes all SFTP bytes delivered by the core. Return its
  status from the service `data` callback.

`int SharkSshSftp_eof(SharkSshSftp* sftp, SharkSshChannel* channel)`

: Aborts unfinished handles and completes the subsystem channel.

`int SharkSshSftp_writable(SharkSshSftp* sftp,
SharkSshChannel* channel)`

: Resumes a partially sent SFTP response. Return its status from the service
  `writable` callback.

For the packet and state-machine rationale, see the
[SFTP plugin design](../design/sftp.md).
