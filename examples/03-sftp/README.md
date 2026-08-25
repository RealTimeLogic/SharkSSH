# 03 - host filesystem shell and SFTP

This example adds a real host filesystem to the bounded shell and Secure File
Transfer Protocol (SFTP) version 3 plugins. Use it to test shell file commands
and SFTP before replacing the host adapter with an embedded storage adapter.
Both plugins use the same persistent
`SharkSshFileSystem` callback table and the same read-only setting.

Prepared
[`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html) and
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
targets are listed in the
[Visual C++](../build/VC-Win/README.md) and
[POSIX](../build/POSIX/README.md) guides. The
[ESP-IDF guide](../build/ESP32/README.md) provides the selib version. A selib
build requires the sibling
[`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL) tree; a SoDisp build
requires the sibling [`BAS`](https://github.com/RealTimeLogic/BAS/) tree and
uses the SharkSSL already contained in `BWS.c`.

`hostFileSystem.c` keeps all host storage code separate from the SSH feature
code. It implements the public filesystem callbacks with
[Win32 APIs](https://learn.microsoft.com/en-us/windows/win32/api/) when
`_WIN32` is defined and
[POSIX APIs](https://pubs.opengroup.org/onlinepubs/9799919799/) otherwise.
[ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/) uses the
POSIX branch over its virtual filesystem (VFS), with link and permission
operations omitted because its File Allocation Table (FAT) VFS
does not provide them. The adapter rejects absolute, drive-qualified,
backslash, `.` and `..` input components. The shell and SFTP plugins also
canonicalize client paths before calling it.

The demonstration root defaults to the process working directory. Override
`SHARKSSH_EXAMPLE_ROOT` at compile time to select another fixed directory.
Use only a dedicated test directory: the compact host adapter is example code,
uses the platform's ordinary path APIs, and is not a sandbox against links,
reparse points, or a hostile local process changing the directory tree.

Compile these example files:

```text
hostFileSystem.c
sftpService.c
sftpExample.c
example.c
```

Also compile the SharkSSH core, the Shell and SFTP plugin sources, and one
[shared startup module](../startup/README.md). The same feature sources build
with standalone SharkSSL/`selib` and BAS/BWS/`SoDisp`.

`SharkSshSftpExample_constructor` remains the reusable, transport-neutral
entry point for a product that supplies its own authenticator, filesystem,
and allocator. A real-time operating system (RTOS) normally replaces
`hostFileSystem.c`, connects the allocator to a fixed block pool, and retains
the same shell/SFTP feature code.
Service state uses a union because one SSH channel can run either shell/exec
or SFTP, not both.

The [ESP-IDF selib project](../build/ESP32/README.md) is the deliberate
exception to replacing the adapter: ESP-IDF exposes its FAT filesystem through
a compatible VFS, so the example can reuse this source directly.

The default host application uses the demonstration `testuser` /
`test-password` login. Run the server from a dedicated directory:

```text
server-program 2222
```

From a second terminal, test the shell or SFTP:

```text
ssh -p 2222 testuser@localhost
sftp -P 2222 testuser@localhost
```

Both clients use the example password `test-password`.
The shell should display a `sharkssh:/>` prompt. The SFTP client should show
the contents of the dedicated directory. Omit the server port argument and the
client port options to use port 22.
