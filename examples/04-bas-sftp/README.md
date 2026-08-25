# 04 - BAS IoIntf shell and SFTP

This example shows how a Barracuda App Server (BAS) application can expose an
existing `IoIntf` filesystem through a SharkSSH shell and Secure File Transfer
Protocol (SFTP). It provides the same behavior as
[example 03](../03-sftp/README.md), but replaces its Windows/POSIX host
adapter with the generic Barracuda
[`IoIntf`](https://realtimelogic.com/ba/doc/en/C/reference/html/structIoIntf.html)
interface. It uses:

- `SharkSshShell` for shell and exec;
- `SharkSshSftp` for SFTP version 3; and
- `SharkSshBasIo` to adapt a [`BAS`](https://github.com/RealTimeLogic/BAS/)
  `IoIntf` filesystem to `SharkSshFileSystem`.

Use this example's
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
target from the
[Visual C++](../build/VC-Win/README.md),
[POSIX](../build/POSIX/README.md), or
[ESP-IDF](../build/ESP32/README.md) guide. It requires a sibling `BAS`
repository. It does not require a standalone
[`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL) sibling unless another
selib example is also being built, because `BAS/src/BWS.c` already contains
SharkSSL.

It implements the same transport-facing `SharkSshExample_configure` function
as the other examples, but it deliberately requires the BAS or Barracuda Web
Server (BWS) SharkSSL
configuration and the [SoDisp startup](../startup/README.md). The current BAS
headers select SharkSSL and thread-port settings that conflict with the
standalone SharkSSL/`selib` configuration; mixing those header environments
is not a supported build.

Compile this directory's `example.c`, example 03's reusable `sftpExample.c`
and `sftpService.c`, all three plugin sources, `soDispStartup.c`, and exactly
one BAS/BWS amalgamation. The host VC++ project also compiles the Windows
`BaFile.c` implementation and constructs a persistent `DiskIo` rooted at the
process working directory. Override `SHARKSSH_EXAMPLE_ROOT` at compile time
to select another fixed demonstration root.

The [ESP-IDF SoDisp project](../build/ESP32/README.md) instead compiles the
POSIX `BaFile.c` implementation over ESP-IDF FAT VFS and roots the same
`DiskIo` at the configured mount point.

For standalone `selib` or a non-BAS real-time operating system (RTOS), use
example 03's
`SharkSshFileSystem` boundary with the target's own adapter.

In a Barracuda product that already owns an
[`HttpServer`](https://realtimelogic.com/ba/doc/en/C/reference/html/structHttpServer.html)
the application operates that server before calling
`SharkSshSoDispStartup_start`. The optional example-host startup can instead
create the server when it supplies `main`. The authenticator may be
password-only, public-key-only, or both. The session allocator should normally
use a synchronized fixed-block RTOS pool.

The default host application uses the demonstration `testuser` /
`test-password` login and is intended only for local testing. Run it from a
dedicated test directory:

```text
server-program 2222
```

Connect from another terminal:

```text
ssh -p 2222 testuser@localhost
sftp -P 2222 testuser@localhost
```

Both clients use the example password `test-password`.
The shell and SFTP client should show the contents of the Barracuda `DiskIo`
root. The adapter intentionally reports unsupported operations when generic
`IoIntf` cannot preserve the required semantics. See the
[adapter limitations](../../doc/plugins/bas-io.md#supported-behavior-and-limitations).
