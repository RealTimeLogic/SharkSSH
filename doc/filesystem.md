# Generic filesystem interface

[`SharkSshFileSystem`](../inc/SharkSSH.h) is SharkSSH's optional,
real-time operating system (RTOS) neutral storage interface. It lets the shell,
Secure File Transfer Protocol (SFTP), and custom services access files and
directories through one callback table. Those services do not need to depend
on [POSIX](https://pubs.opengroup.org/onlinepubs/9799919799/), C `FILE`, an
RTOS-specific filesystem API, or Barracuda App Server (BAS) and Barracuda Web
Server (BWS).

The interface is part of the public [`SharkSSH.h`](../inc/SharkSSH.h) API; it
is not itself a
plugin. The optional [shell](plugins/sharkssh-shell.md) and
[SFTP](plugins/sftp.md) plugins consume it, and an application can use the
same table from a custom subsystem.

Use this interface when the product already has a filesystem driver or storage
service and needs to expose only an approved part of it through SSH. The table
adapts storage operations. It does not provide access control or create a
sandbox.

## Configure the table

Create one persistent callback table, initialize the callbacks supported by
the product, and assign it to `SharkSshConfig.fileSystem`:

```c
#include <SharkSSH.h>
#include <string.h>

SharkSshFileSystem fileSystem;
SharkSshConfig config;

memset(&fileSystem, 0, sizeof(fileSystem));
fileSystem.context = &storage;
fileSystem.open = deviceFileOpen;
fileSystem.close = deviceFileClose;
fileSystem.read = deviceFileRead;
fileSystem.write = deviceFileWrite;
fileSystem.seek = deviceFileSeek;
fileSystem.stat = deviceFileStat;
fileSystem.openDirectory = deviceDirectoryOpen;
fileSystem.readDirectory = deviceDirectoryRead;
fileSystem.closeDirectory = deviceDirectoryClose;

SharkSshConfig_constructor(&config);
config.fileSystem = &fileSystem;
```

In this example, `storage` is an application-owned object and the callback
names represent application functions. Install
only the operations the backing store supports. A missing callback makes that
operation unavailable to a consumer.

The table, its `context`, and the objects reached through that context must
remain valid until every connection and plugin that can use them has
finished. The core passes `config.fileSystem`, which may be `NULL`, to the
`SharkSshServices.subsystem` callback. A plugin with its own configuration,
such as `SharkSshShell` or `SharkSshSftp`, retains the filesystem pointer
assigned to that plugin's configuration.

## Callback reference

Every callback receives the table's `context` as its first argument.

| Callback | Contract |
| --- | --- |
| `open(context, path, flags, file)` | Open a file, apply the bitwise `SharkSshFsOpenFlags`, and write an opaque handle to `*file`. |
| `close(context, file)` | Close a handle returned by `open`. |
| `read(context, file, data, capacity, size)` | Read at most `capacity` bytes into `data` and set `*size`. Success with a zero size is end of file. |
| `write(context, file, data, size, written)` | Write up to `size` bytes and set `*written`. A successful write may be partial. |
| `seek(context, file, offsetHi, offsetLo)` | Set the absolute unsigned 64-bit position `(offsetHi << 32) | offsetLo`. |
| `stat(context, path, stat)` | Fill `*stat` with metadata for `path`. |
| `setStat(context, path, stat, flags)` | Update only the metadata fields selected by the bitwise `SharkSshFsSetFlags`. Leave this callback unset when attribute updates are not supported. |
| `remove(context, path)` | Remove a non-directory entry. |
| `rename(context, oldPath, newPath)` | Rename or move an entry within the exposed namespace. |
| `makeDirectory(context, path, permissions)` | Create a directory, applying or rejecting `permissions` according to product policy. |
| `removeDirectory(context, path)` | Remove a directory. |
| `openDirectory(context, path, directory)` | Open a directory enumeration and write an opaque handle to `*directory`. |
| `readDirectory(context, directory, name, capacity, size, stat)` | Write the next entry name as at most `capacity` counted bytes, set `*size` and `*stat`, or return `SharkSshFsEnd` when no entries remain. |
| `closeDirectory(context, directory)` | Close a handle returned by `openDirectory`. |

## Return status

Filesystem callbacks return a `SharkSshFsStatus` value whenever one describes
the result:

| Status | Meaning |
| --- | --- |
| `SharkSshFsOk` | Success. Its value is zero. |
| `SharkSshFsEnd` | Directory enumeration is complete. Use it only as the normal completion result from `readDirectory`. |
| `SharkSshFsNotFound` | The requested entry does not exist. |
| `SharkSshFsExists` | An entry already exists where the operation requires a new one. |
| `SharkSshFsDenied` | Access or policy denied the operation. |
| `SharkSshFsNoSpace` | The backing store has insufficient capacity. |
| `SharkSshFsUnsupported` | The backing store cannot provide the requested operation or semantics. |
| `SharkSshFsInvalidName` | The supplied path or name is invalid for the exposed filesystem. |

All failures in this table are negative. An adapter may return another
negative value when a consumer only needs a generic failure, but portable
statuses let plugins preserve distinctions such as not found, denied, and
unsupported.

File end-of-file is different from directory completion: `read` returns
`SharkSshFsOk` and sets `*size` to zero, whereas `readDirectory` returns
`SharkSshFsEnd`.

## Open flags

Combine the required `SharkSshFsOpenFlags` values with bitwise OR:

| Flag | Requested behavior |
| --- | --- |
| `SharkSshFsOpenRead` | Open for reading. |
| `SharkSshFsOpenWrite` | Open for writing. |
| `SharkSshFsOpenCreate` | Create the file if required. |
| `SharkSshFsOpenTruncate` | Set the file length to zero when opening it. |
| `SharkSshFsOpenAppend` | Position writes at the end of the file. |
| `SharkSshFsOpenExclusive` | With create, fail atomically with `SharkSshFsExists` if the path already exists. |

Return `SharkSshFsUnsupported` when the backing API cannot implement a
requested semantic. In particular, do not emulate exclusive create with a
separate `stat` followed by `open`; that sequence is not atomic.

## File metadata

`SharkSshFsStat` contains:

| Field | Meaning |
| --- | --- |
| `sizeHi`, `sizeLo` | Unsigned 64-bit byte size `(sizeHi << 32) | sizeLo`. |
| `modifiedTime` | A 32-bit modification timestamp using the filesystem adapter's documented time basis. |
| `permissions` | Portable permission bits supplied by the adapter. |
| `type` | `SharkSshFsTypeFile`, `SharkSshFsTypeDirectory`, or `SharkSshFsTypeOther`. |

For `setStat`, combine these selection flags with bitwise OR:

| Flag | Field to update |
| --- | --- |
| `SharkSshFsSetSize` | `sizeHi` and `sizeLo` |
| `SharkSshFsSetPermissions` | `permissions` |
| `SharkSshFsSetModifiedTime` | `modifiedTime` |

The callback must ignore unselected fields. Return
`SharkSshFsUnsupported` when the backing store cannot apply a requested
update.

## Paths and namespace security

A `SharkSshSpan` path is a counted UTF-8 byte string. It is not terminated
by a zero byte (NUL). An adapter that converts it to a C string must first
enforce its path-length bound and reject embedded NUL bytes.

The callback table does not grant access, define a root, or normalize paths.
The shell, SFTP, or custom service that calls it must canonicalize client
paths, reject traversal, and authorize each operation before invoking the
adapter. The adapter and backing filesystem must still confine their physical
namespace and define behavior for symbolic links, quotas, replacement, and
atomic writes. Do not expose an unrestricted device filesystem merely by
assigning it to `config.fileSystem`.

## Handles and concurrency

File and directory handles are opaque to SharkSSH. A consumer must call the
matching close callback once for every successfully opened handle, including
when a connection ends or an operation fails partway through. Consumers must
also accept partial reads and writes rather than assuming one callback
transfers the complete requested amount.

Filesystem callbacks run synchronously in the task that owns the connection.
Callbacks for different connections may therefore reach a shared filesystem
context concurrently. The application must provide any locking required by
the adapter and backing store. A callback should return promptly and must not
use a `SharkSshSpan` after it returns.

## Available adapters and consumers

- The [BAS `IoIntf` adapter](plugins/bas-io.md) converts a generic
  [`IoIntf`](https://realtimelogic.com/ba/doc/en/C/reference/html/structIoIntf.html)
  to this callback table.
- The [bounded shell plugin](plugins/sharkssh-shell.md) uses the table for its
  navigation, file, directory, metadata, and copy commands.
- The [SFTP version 3 plugin](plugins/sftp.md) uses the table for bounded file
  transfer and directory management.
