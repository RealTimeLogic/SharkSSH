# BAS IoIntf adapter design

This maintainer document explains how `SharkSshBasIo` maps the Barracuda App
Server (BAS) `IoIntf` filesystem API to `SharkSshFileSystem`. For
application setup and limitations, use the
[BAS IoIntf plugin guide](../plugins/bas-io.md).

The [`BAS`](https://github.com/RealTimeLogic/BAS/) filesystem plugin is
isolated under `src/plugins/BasIo`. Its public
surface includes only `SharkSSH.h` and
[`IoIntf.h`](https://realtimelogic.com/ba/doc/en/C/reference/html/IoIntf_8h_source.html),
keeping
[`BaDiskIo`](https://realtimelogic.com/ba/doc/en/C/reference/html/structDiskIo.html), HTTP,
Barracuda Web Server (BWS), and
platform filesystem code outside the production adapter.

Counted paths are copied to a bounded `SHARKSSH_MAX_PATH_LEN + 1` stack buffer
because `IoIntf` accepts NUL-terminated names. The copy rejects embedded NUL
bytes and writes the terminator explicitly.

## Operation mapping

The callback mapping is:

| SharkSSH operation | IoIntf operation |
| --- | --- |
| file open | `IoIntf.openResFp` |
| file close/read/write/seek | `ResIntf.closeFp`, `readFp`, `writeFp`, `seekFp` |
| stat | `IoIntf.statFp` |
| remove/rename | `IoIntf.removeFp`, `renameFp` |
| create/remove directory | `IoIntf.mkDirFp`, `rmDirFp` |
| directory open/close | `IoIntf.openDirFp`, `closeDirFp` |
| directory read/name/stat | `DirIntf.readFp`, `getNameFp`, `statFp` |

`IOINTF_OK` maps to `SharkSshFsOk`. Common BAS errors map to the portable
not-found, exists, denied, no-space, unsupported, invalid-name, and bounds
statuses. Other failures become `SharkSshErrService`; `IOINTF_EOF` and
`IOINTF_NOTFOUND` during directory enumeration become `SharkSshFsEnd`.

## Deliberate behavior

The adapter leaves `setStat` unset because `IoIntf` has no generic operation
for truncating an existing path or changing its permissions or timestamps.
It likewise rejects exclusive-create because `IoIntf` cannot express that
operation atomically. Since `OpenRes_WRITE` always creates and truncates, the
adapter also rejects nontruncating write-open requests rather than changing
their semantics and destroying existing content.

The adapter deliberately does not normalize paths, resolve symlinks, enforce a
root, authorize a user, or implement protocol-specific error conversion.
Those policies belong above the generic storage adapter.
