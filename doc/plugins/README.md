# SharkSSH plugins

SharkSSH plugins are optional C source modules that provide ready-made
services or adapters on top of the core callback APIs. Use them to add a
management shell, Secure File Transfer Protocol (SFTP), or Barracuda
filesystem access without adding those dependencies to the SSH core.

They are compiled into the application. They are not components loaded at
runtime. Add only the plugin `.c` file and include directory needed by the
application. The Shell and SFTP plugins work with either TCP integration.
The Barracuda App Server (BAS)
[`IoIntf`](https://realtimelogic.com/ba/doc/en/C/reference/html/structIoIntf.html)
adapter is for applications built with BAS or Barracuda Web Server (BWS). It
also requires the public
[`IoIntf.h`](https://realtimelogic.com/ba/doc/en/C/reference/html/IoIntf_8h_source.html)
header.

Filesystem-facing plugins share the
[generic filesystem interface](../filesystem.md), which documents the common
callback, status, handle, concurrency, and path-security contracts.

## Available plugins

| If you need... | Read |
| --- | --- |
| Your own shell or command service | [Shell and exec integration](shell.md) |
| A ready-made bounded management shell | [`SharkSshShell` plugin](sharkssh-shell.md) |
| A BAS `IoIntf` storage adapter | [BAS `IoIntf` filesystem adapter](bas-io.md) |
| Bounded SFTP version 3 file transfer | [SFTP version 3 plugin](sftp.md) |

Plugin objects and their backing service objects are application-owned. Keep
them alive for every server connection or subsystem operation that can use
their callback table. The [core API guide](../core.md) documents the common
callback and concurrency rules.
