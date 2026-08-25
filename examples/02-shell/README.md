# 02 - bounded shell and exec

This example proves the shell and command callback APIs without involving a
filesystem. It replaces example 01's fixed `status` command with the optional
`SharkSshShell` plugin. It accepts interactive shell requests,
pseudo-terminal (PTY) modes, and exec requests. With no filesystem configured,
`help`, `pwd`, `exit`, and any
application commands in `SharkSshShellConfig.commands` are available.
This example is a test of the shell API and deliberately does not connect to
a physical filesystem. It prints that limitation in its login banner. If a
filesystem command such as `ls` or `cd` is entered, the command remains
visible as part of the API demonstration and reports, for example,
`ls: filesystem not configured` instead of attempting storage access.

Use the prepared
[`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html) or
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
target in the
[Visual C++](../build/VC-Win/README.md) or
[POSIX](../build/POSIX/README.md) guide. A selib build requires the sibling
[`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL) tree. A SoDisp build
requires the sibling
[Barracuda App Server (BAS)](https://github.com/RealTimeLogic/BAS/) tree,
whose Barracuda Web Server file, `BWS.c`,
already contains SharkSSL.

Use the [host filesystem and Secure File Transfer Protocol (SFTP)
example](../03-sftp/README.md) when testing
filesystem commands. That example attaches a Windows/POSIX implementation
through the `SharkSshFileSystem` callback table.

Compile `shellExample.c`, `example.c`, and
`src/plugins/Shell/SharkSshShell.c` with the core and one
[shared startup module](../startup/README.md). Initialize
`SharkSshShellExample` with the authenticator, allocator, and shell
configuration. The configuration and its command table are copied by value;
their callback contexts and pointed-to command data remain application-owned.

Each channel obtains its `SharkSshShell` from the allocator callbacks. The
same feature code therefore works with either transport and concurrent SoDisp
workers without embedding a heap policy.

After building the selected target, start it on port 2222:

```text
server-program 2222
```

Connect from a second terminal:

```text
ssh -p 2222 testuser@localhost
```

When prompted, enter the example password `test-password`.
Run `help` to see the built-in and application commands. A filesystem command
such as `ls` should report `filesystem not configured`. That message is the
expected result for this example, not a startup failure.

The example supplies a self-contained host constructor using the demonstration
`testuser` / `test-password` login and `malloc`-based channel allocation. This
allows the shared selib or SoDisp host startup to build a complete executable
without another application source. Define
`SHARKSSH_EXAMPLE_CUSTOM_APPLICATION=1` when the product supplies its own
authentication, allocator, command configuration, and example constructor.
