# SFTP plugin design

This maintainer document explains the memory, request-processing, path, and
upload design of the Secure File Transfer Protocol (SFTP) plugin. For
application setup, use the [SFTP plugin guide](../plugins/sftp.md).

The [SFTP version 3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
implementation is a separate component under `src/plugins/Sftp`.
The SSH core knows only that an application accepted a subsystem and routes
channel data to application callbacks. A core-only or shell-only image does
not link SFTP code or reserve SFTP session storage.

## Supported operations

The plugin implements the version 3 wire format from
`draft-ietf-secsh-filexfer-02`.
The supported request set covers file transfer, metadata queries, optional
metadata updates, directory iteration, canonical paths, directory mutation,
remove, and rename. Unsupported request types receive a version 3
`SSH_FX_OP_UNSUPPORTED` status.

The VERSION response advertises `limits@openssh.com`. Its reply reports the
compile-time packet, read, write, and open-handle bounds. This lets
[OpenSSH](https://www.openssh.com/)
reduce its normal 32 KiB transfer blocks while the embedded default retains a
4 KiB request buffer and 1 KiB response data block.

## How requests and responses move

Each `SharkSshSftp` owns one fixed request buffer and one fixed response
buffer. Channel fragments accumulate until a complete SFTP length-prefixed
packet is present. One request is executed synchronously, its response is
queued, and `SharkSshChannel_writeSome` drains that response across as many SSH
channel packets and window adjustments as necessary. A response is never
overwritten while it is waiting for channel credit.

Requests execute in wire order. The SSH receive window and SFTP packet bound
limit retained input; no request list or unbounded pipelining allocation is
created. A declared packet above `SHARKSSH_SFTP_PACKET_SIZE` terminates the
malformed session at the plugin boundary.

## Paths and handles

Untrusted client paths are normalized into a client-visible absolute path,
then prefixed with the trusted configuration root before reaching storage.
Parent components remove only components below the virtual root. Backslash is
treated as a separator so a Windows-like backing adapter cannot reinterpret a
client component after validation. Embedded NUL, colon, and overlong paths are
rejected.

The fixed handle table contains an opaque storage handle, monotonically
changing 32-bit client token, access flags, and bounded path. Retaining the
path permits FSTAT and FSETSTAT through a path-oriented generic filesystem
without requiring a second file-handle metadata API. File and directory
tokens are type checked before use.

## Upload lifecycle

Without staging hooks, writes target the resolved filesystem path directly.
With `stageUpload`, non-exclusive create/truncate opens target an
application-generated staging path. CLOSE first closes storage and then
invokes the application commit callback, or the filesystem rename fallback.
Exclusive create bypasses staging so the backing filesystem can atomically
test the final target. Any close error, rejected commit, channel failure,
disconnect, malformed request, or destructor aborts the staged object.

This separation lets a real-time operating system (RTOS) map commit to a
firmware-slot switch or object transaction without imposing rename semantics
on every filesystem adapter.

## Policy and diagnostics

Core subsystem authorization controls entry to SFTP. The plugin read-only flag
and per-operation authorization callback run before mutating storage or
opening a protected object. Audit delivery is synchronous and records only
the operation, canonical virtual path, SFTP result, and channel reference.
File data is never included.

## Current limits

- SFTP version 3 only;
- one SFTP subsystem on the core's one session channel;
- no symbolic links or hard links;
- no ownership or user/group mapping;
- no filesystem-capacity extension;
- no asynchronous storage provider;
- no unbounded request queue;
- attribute updates only for size, permissions, and modification time when
  the filesystem supplies `setStat`.
