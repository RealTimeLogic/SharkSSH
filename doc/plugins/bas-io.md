# BAS IoIntf filesystem plugin

`SharkSshBasIo` lets SharkSSH plugins use storage that an application already
exposes through the Barracuda App Server (BAS)
[`IoIntf`](https://realtimelogic.com/ba/doc/en/C/reference/html/structIoIntf.html)
API. It converts an `IoIntf` object into the generic
[`SharkSshFileSystem`](../filesystem.md) callback table. The production
plugin's public header depends only on [`SharkSSH.h`](../../inc/SharkSSH.h) and
[`IoIntf.h`](https://realtimelogic.com/ba/doc/en/C/reference/html/IoIntf_8h_source.html);
it does not require
[`BaDiskIo.h`](https://realtimelogic.com/ba/doc/en/C/reference/html/BaDiskIo_8h_source.html),
HTTP/BWS headers, or a platform filesystem header.

Use this plugin only when the application already has an `IoIntf`. It is
normally compiled in the
[BAS/BWS](https://realtimelogic.com/ba/doc/en/C/reference/html/index.html)
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
configuration. The
plugin does not create a disk filesystem: the application constructs a
concrete `IoIntf` implementation and passes it to the adapter. For example,
the host demonstration constructs BAS
[`DiskIo`](https://realtimelogic.com/ba/doc/en/C/reference/html/structDiskIo.html),
while an embedded product may
provide a flash, ZIP, or product-specific `IoIntf`.

The [generic filesystem guide](../filesystem.md) documents the callback,
status, handle, concurrency, and namespace-security contracts. This document
covers the BAS-specific adapter and the capabilities exposed by `IoIntf`.

## Add the plugin

Compile these files with the application:

```text
src/plugins/BasIo/SharkSshBasIo.c
src/plugins/BasIo/SharkSshBasIo.h
```

Add the SharkSSH public include directory, the plugin directory, and the BAS
directory containing `IoIntf.h` to the include path.

## Initialize the adapter

```c
#include <SharkSshBasIo.h>

SharkSshBasIo fileSystemAdapter;
SharkSshConfig config;

SharkSshConfig_constructor(&config);
SharkSshBasIo_constructor(&fileSystemAdapter, myIoIntf);
config.fileSystem = SharkSshBasIo_getFileSystem(&fileSystemAdapter);
```

`myIoIntf`, `fileSystemAdapter`, and `config` must outlive every subsystem
operation that can use the filesystem table. The adapter does not take
ownership of `myIoIntf`.

## Public API

`void SharkSshBasIo_constructor(SharkSshBasIo* adapter, IoIntfPtr io)`

: Clears and initializes `adapter` for `io`. Passing a `NULL` adapter has no
  effect. A `NULL` `io` creates an unusable table whose operations reject
  requests.

`const SharkSshFileSystem*
SharkSshBasIo_getFileSystem(const SharkSshBasIo* adapter)`

: Returns the callback table to assign to `SharkSshConfig.fileSystem`, or
  `NULL` when `adapter` is `NULL`.

The `SharkSshBasIo` structure contains the generated `SharkSshFileSystem` and
the non-owning `IoIntfPtr`. Applications should initialize it with the
constructor and should not replace individual callback fields.

## Supported behavior and limitations

- Counted SSH paths are accepted up to `SHARKSSH_MAX_PATH_LEN` bytes. Embedded
  NUL bytes and longer paths are rejected.
- File and directory handles are the underlying opaque
  [`ResIntfPtr`](https://realtimelogic.com/ba/doc/en/C/reference/html/structResIntf.html)
  and
  [`DirIntfPtr`](https://realtimelogic.com/ba/doc/en/C/reference/html/structDirIntf.html)
  values and are closed through their BAS interfaces.
- Read end-of-file is reported as a successful read with zero bytes. Directory
  end is reported as `SharkSshFsEnd`.
- `IoIntf` write-open semantics always create and truncate. The adapter accepts
  that mode only when SharkSSH requests both create and truncate. A
  nontruncating write-open returns `SharkSshFsUnsupported` instead of silently
  destroying existing content. Append plus create selects BAS write-open plus
  append; append without create is unsupported because `IoIntf` may create the
  path.
- `IoIntf` has no atomic exclusive-create flag, so exclusive open returns
  `SharkSshFsUnsupported` instead of using a racy stat/open sequence.
- The generic permissions argument cannot be applied by `IoIntf` and is
  ignored when creating a directory. Returned stat permissions are zero.
- `IoIntf` has no generic attribute-update operation, so `setStat` is left
  unset. An SFTP client receives `SSH_FX_OP_UNSUPPORTED` for explicit size,
  timestamp, or permission updates through this adapter.
- Returned modification times are clamped to the 32-bit
  `SharkSshFsStat.modifiedTime` range.

Namespace confinement, `..` handling, symlink behavior, and access policy are
properties of the selected `IoIntf`, its configured root, and the subsystem
that exposes it. Do not expose an unrestricted physical filesystem to an SSH
client.

For the adapter's internal mapping, see the
[BAS IoIntf adapter design](../design/bas-io.md).
