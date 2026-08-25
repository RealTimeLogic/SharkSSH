# SharkSSH

SharkSSH is a small
[Secure Shell version 2 (SSH-2)](https://www.rfc-editor.org/rfc/rfc4251)
server library for embedded systems and real-time operating system (RTOS)
products. It lets a device provide encrypted remote commands, an interactive
management shell, or Secure File Transfer Protocol (SFTP) access without
requiring a POSIX operating system.

SharkSSH uses
[SharkSSL](https://realtimelogic.com/ba/doc/en/C/shark/index.html) for
cryptography and supports two ways to connect to TCP:

- standalone SharkSSL with the portable
  [`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html)
  socket API;
- Barracuda App Server (BAS) or Barracuda Web Server (BWS), using an
  application's existing
  [`HttpServer`](https://realtimelogic.com/ba/doc/en/C/reference/html/structHttpServer.html)
  and [`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
  socket dispatcher.

The application supplies callback tables for authentication, commands,
shells, subsystems, platform services, and filesystem access. This keeps
operating-system and product policy out of the library. Optional callbacks
also let the application limit connection and authentication abuse and record
structured security events.

Password and [RSA/SHA-256](https://www.rfc-editor.org/rfc/rfc8332)
public-key authentication are independently
selectable. A public-key-only configuration provides passwordless SSH login;
see the [`ssh-keygen` provisioning example](doc/core.md#create-a-user-key-with-ssh-keygen).

## Choose an integration

The two integrations provide the same SSH protocol and callback APIs. Choose
one transport for each executable:

| If your application... | Use | Link with |
| --- | --- | --- |
| Uses SharkSSL as a standalone library | **selib** | `SharkSSL/src/SharkSSL.c`, `SharkSSL/src/selib.c`, and the target's selib port |
| Already uses Barracuda BAS or BWS | **SoDisp** | One Barracuda amalgamation (`BWS.c` for native C/C++, or `BAS.c` when Lua is required) and the target's Barracuda thread/dispatcher port |

`selib` is SharkSSL's small portable socket API. In the Barracuda build,
`SoDisp` accepts connections through an existing `HttpServer`, and SharkSSH
runs each accepted connection in a worker thread.

Do not compile standalone `SharkSSL.c` or `selib.c` into a SoDisp executable.
The BAS/BWS amalgamation already contains SharkSSL, and mixing the two
configurations in one executable is unsupported. `SharkSSL.h` selects the
correct SharkSSH declarations through `SHARKSSL_BA`; applications should not
define that macro themselves.

## Arrange the source trees

The supplied Visual C++, POSIX, and ESP-IDF builds use sibling-relative paths.
Keep the dependency directories beside this repository with these exact names:

```text
parent-directory/
|-- SharkSSH/
|-- SharkSSL/    required by *-selib builds
`-- BAS/         required by *-sodisp builds and example 04
```

You need only [`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL) for a
`selib` build and only [`BAS`](https://github.com/RealTimeLogic/BAS/) for a
`SoDisp` build.
Keep both siblings when building the complete example matrix. The POSIX
makefiles let advanced users override the dependency roots; the Visual C++ and
ESP-IDF projects use the layout above directly.

The expected standalone distribution contains `SharkSSL/inc/SharkSSL.h`,
`SharkSSL/src/SharkSSL.c`, and `SharkSSL/src/selib.c`. The expected Barracuda
distribution contains its public headers under `BAS/inc` and the native BWS
amalgamation at `BAS/src/BWS.c` (or `BAS/src/BAS.c` for a BAS/Lua application).

## Licensing

SharkSSH is licensed under the [MIT License](LICENSE). This license applies
only to the files in this repository.

**SharkSSH requires one separately obtained dependency:**

- Standalone `selib` builds require
  [SharkSSL](https://github.com/RealTimeLogic/SharkSSL), which is available
  under GPLv2 or a Real Time Logic commercial license.
- SoDisp builds require
  [BAS/BWS](https://github.com/RealTimeLogic/BAS/), which is available under
  GPLv2 or a Real Time Logic commercial license.

SharkSSH's MIT license does not change or replace the license of either
dependency. Review the applicable dependency license before distributing a
combined application. Real Time Logic also offers a
[free commercial license for eligible small companies](https://realtimelogic.com/startuplic/)
and [standard commercial licensing](https://realtimelogic.com/contactus/license/).

## Start here

For the fastest route to a working server:

1. Choose `selib` or SoDisp from the table above.
2. Arrange the required source tree as shown above.
3. Open the [examples guide](examples/README.md) and select the smallest
   example that demonstrates the features you need.
4. Follow the prepared instructions for
   [Visual C++](examples/build/VC-Win/README.md),
   [POSIX](examples/build/POSIX/README.md), or
   [ESP-IDF](examples/build/ESP32/README.md).
5. Before integrating SharkSSH into a product, read the
   [core API guide](doc/core.md), replace the published example credentials and
   host key, and install the product's authentication, authorization, entropy,
   allocation, and filesystem callbacks.

A successful first test starts a server and lets an SSH client connect with
the published example account. The credentials and host key are public test
material. Replace them before using an example as product code.

Port 22 is the default. On a development host, use an unprivileged port such
as 2222 when port 22 is occupied or requires administrator/root privileges.

## Documentation

- [Examples](examples/README.md) - four directly runnable examples covering
  minimal exec, a shell-API test, host filesystem shell/SFTP, and BAS `IoIntf`
  shell/SFTP, with shared `selib` and SoDisp startup modules.
- [Core API and integration guide](doc/core.md) - initialization, callbacks,
  standalone and BAS/BWS examples, object lifetimes, and the core public API.
- [Generic filesystem interface](doc/filesystem.md) - callback setup,
  operations, statuses, handles, concurrency, and namespace security.
- [Client compatibility](doc/compatibility.md) - validated OpenSSH, PuTTY,
  WinSCP, and wolfSSH versions, older-client limitations, and configurable
  interoperability bounds.
- [Plugins](doc/plugins/README.md) - plugin index and integration guides.
  - [Shell and exec integration](doc/plugins/shell.md) - service lifecycle and
    a link to the installable bounded `SharkSshShell` implementation.
  - [BAS `IoIntf` filesystem plugin](doc/plugins/bas-io.md) - expose any BAS
    [`IoIntf`](https://realtimelogic.com/ba/doc/en/C/reference/html/structIoIntf.html)
    through the generic SharkSSH filesystem API.
  - [SFTP version 3 plugin](doc/plugins/sftp.md) - bounded file transfer,
    virtual roots, policy callbacks, and optional staged uploads.
- [Design overview](doc/design/overview.md) - protocol profile, internal
  architecture, SharkSSL reuse, transport design, memory model, and current
  limitations.
- [Generated API reference](#generating-the-api-reference) - Doxygen output
  from the public header and all example source files.

### Generating the API reference

Install [Doxygen](https://www.doxygen.nl/), then run `doxygen Doxyfile` for the
standalone `selib` reference or `doxygen Doxyfile.SoDisp` for the BAS/BWS
reference. Open `build/html/index.html` or `build-sodisp/html/index.html`,
respectively. Generated files stay outside the source and are ignored by Git.
