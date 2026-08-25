# POSIX example makefiles

These makefiles build and run the complete
[SharkSSH example set](../../README.md) on a
[POSIX](https://pubs.opengroup.org/onlinepubs/9799919799/) host. A C compiler,
[GNU Make](https://www.gnu.org/software/make/), and POSIX threads are required;
[GCC](https://gcc.gnu.org/) is supported on Linux. The SoDisp targets use
Barracuda App Server (BAS) and
Barracuda Web Server (BWS).

## Required source layout

By default the makefiles expect the dependency directories beside SharkSSH:

```text
parent-directory/
|-- SharkSSH/
|   `-- examples/build/POSIX/
|-- SharkSSL/    required by *-selib.mk
`-- BAS/         required by *-sodisp.mk
```

A [`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html)
makefile uses only `SharkSSH` and
[`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL). A
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
makefile uses only `SharkSSH` and
[`BAS`](https://github.com/RealTimeLogic/BAS/); `BAS/src/BWS.c` already
contains SharkSSL. Do not compile standalone `SharkSSL.c` or `selib.c` into a
SoDisp executable. Keep all three trees when building the complete matrix.

## Choose a makefile

| Example | Standalone SharkSSL/selib | BAS/BWS SoDisp |
| --- | --- | --- |
| 01 minimal | `makefile-01-minimal-selib.mk` | `makefile-01-minimal-sodisp.mk` |
| 02 shell | `makefile-02-shell-selib.mk` | `makefile-02-shell-sodisp.mk` |
| 03 host SFTP | `makefile-03-sftp-selib.mk` | `makefile-03-sftp-sodisp.mk` |
| 04 BAS SFTP | Not applicable | `makefile-04-bas-sftp-sodisp.mk` |

Example 04 has no selib makefile because BAS `IoIntf` selects the BAS/BWS
SharkSSL and thread configuration. Every SoDisp makefile compiles exactly one
amalgamation, `BAS/src/BWS.c`; it does not compile standalone `SharkSSL.c` or
`selib.c`.

## Build and run

Change to `SharkSSH/examples/build/POSIX`, then build one target, for example:

```sh
make -f makefile-01-minimal-selib.mk
make -f makefile-04-bas-sftp-sodisp.mk
```

Executables are written to `obj/<project-name>`. Each build has a separate
intermediate directory under `obj/intermediate/<project-name>`. Build all
seven makefiles independently; they do not share transport objects.

Run an example with an optional SSH port argument:

```sh
make -f makefile-01-minimal-selib.mk run args=2222
```

For example 01, connect from another terminal with:

```sh
ssh -p 2222 testuser@localhost status
```

When prompted, enter the example password `test-password`.
The expected output is `device is ready`. The executable remains in
`obj/<project-name>` for later runs.

Omitting `args` selects port 22. On many POSIX hosts, binding port 22 requires
root privileges and may conflict with an existing SSH daemon. Port 2222 avoids
both problems. Connect to that port with:

```sh
ssh -p 2222 testuser@localhost
sftp -P 2222 testuser@localhost
```

Both clients use the same example password, `test-password`.

Remove one build with its `clean` target:

```sh
make -f makefile-01-minimal-selib.mk clean
```

The makefiles honor standard `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, and
`LDLIBS` overrides. If the dependency repositories are not siblings, override
`sharkSslRoot` for a selib target or `basRoot` for a SoDisp target:

```sh
make -f makefile-03-sftp-selib.mk \
  sharkSslRoot=/opt/SharkSSL CFLAGS='-O0 -g -Wall'

make -f makefile-04-bas-sftp-sodisp.mk \
  basRoot=/opt/BAS CFLAGS='-O0 -g -Wall'
```

Examples 03 and 04 expose the process working directory as their demonstration
filesystem root. Run them from a dedicated test directory and never from a
directory containing sensitive files. The login is `testuser` with password
`test-password`.

The compiled private host key and login are public test material. Replace both
before using any example as the starting point for a product.

Use the [Python protocol integration suite](../../tests/README.md) to exercise
every shell command and SFTP operation against examples 03 and 04.

## Verify the examples

Build each required makefile independently. Run the minimal example's
`status` command and the shell example's `help` command as quick smoke tests.
Then use the [protocol integration suite](../../tests/README.md) for the
filesystem examples. The SoDisp profiles also exercise concurrent clients.
