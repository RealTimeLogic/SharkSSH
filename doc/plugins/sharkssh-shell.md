# Bounded SharkSshShell plugin

`SharkSshShell` is an optional, allocation-free management shell for
embedded products. It handles interactive shell and one-command exec requests,
provides a small set of filesystem commands, and lets the application register
fixed custom commands.

It implements the [SharkSSH shell and exec callbacks](shell.md), including
pseudo-terminal (PTY) echo handling. It uses only the public SharkSSH API and
the C string library. It does not depend on Barracuda App Server (BAS),
Barracuda Web Server (BWS),
[`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html),
[POSIX](https://pubs.opengroup.org/onlinepubs/9799919799/), a process launcher,
or a particular real-time operating system (RTOS).

## Install the plugin

Compile these files with the application:

```text
src/plugins/Shell/SharkSshShell.c
src/plugins/Shell/SharkSshShell.h
```

Add `inc` and `src/plugins/Shell` to the include path. A build that does not
compile `SharkSshShell.c` carries no shell-plugin code or per-session shell
storage.

Use one `SharkSshShell` object for each active SSH channel. The plugin does
not allocate that object for you.

Each active shell or exec channel needs one caller-owned `SharkSshShell`.
The configuration, custom-command array, filesystem table, and callback
contexts must remain valid until all shells using them have been destroyed.

## Configure the shell

Clear the configuration before assigning fields so later optional fields
default to disabled:

```c
#include <SharkSshShell.h>

SharkSshShellConfig shellConfig;

memset(&shellConfig, 0, sizeof(shellConfig));
shellConfig.context = &application;
shellConfig.fileSystem = &application.fileSystem;
shellConfig.commands = applicationCommands;
shellConfig.commandCount = applicationCommandCount;
shellConfig.banner = "Device management shell\r\n";
shellConfig.authorizeFile = authorizeFileOperation;
shellConfig.auditFile = auditFileOperation;
shellConfig.readOnly = 0;
```

`fileSystem` is optional. When it is not configured, filesystem commands
remain listed by `help` but do not attempt an operation. They report the
command and the configuration error, for example
`ls: filesystem not configured`. This lets a shell-only integration exercise
command parsing, PTY handling, custom commands, and exec handling without
pretending that storage is available. Commands whose required
[`SharkSshFileSystem`](../filesystem.md) callbacks are individually missing
report that the operation is unavailable or failed.
Set `readOnly` nonzero to reject `rm`, `mkdir`, `rmdir`, `mv`, and `cp` before
they reach storage. Navigation, listing, reading, and stat remain available.

## Connect it to SharkSSH

The application's `open` callback constructs or obtains the channel session,
calls `SharkSshShell_constructor`, and assigns that session to
`channel->userData`. Its `close` callback calls `SharkSshShell_destructor`
before releasing the session.

Forward the service callbacks to that per-channel object:

```c
static int
startShell(void* context, SharkSshChannel* channel)
{
   (void)context;
   return SharkSshShell_start(getShell(channel), channel);
}

static int
startCommand(void* context, SharkSshChannel* channel, SharkSshSpan command)
{
   (void)context;
   return SharkSshShell_execute(getShell(channel), channel, command);
}

static int
receiveData(void* context, SharkSshChannel* channel, SharkSshSpan data)
{
   (void)context;
   return SharkSshShell_data(getShell(channel), channel, data);
}

static int
receiveEof(void* context, SharkSshChannel* channel)
{
   (void)context;
   return SharkSshShell_eof(getShell(channel), channel);
}

static int
resumeOutput(void* context, SharkSshChannel* channel)
{
   (void)context;
   return SharkSshShell_writable(getShell(channel), channel);
}
```

Set the corresponding `SharkSshServices.shell`, `exec`, `data`, `eof`, and
`writable` fields. A PTY callback should pass its counted terminal modes to
`SharkSshShell_pty` before starting the shell.

Core service authorization independently decides whether a user may start a
shell or execute a command. The plugin's filesystem authorization callback
then applies per-operation and per-path policy inside an approved shell.

## Built-in commands

| Command | Behavior and required callbacks |
| --- | --- |
| `help` | Lists built-ins and configured application commands. |
| `pwd` | Prints the current virtual path. |
| `ls [path]` | Enumerates `path`, or the current per-session directory when omitted, through `openDirectory`, `readDirectory`, and `closeDirectory`. |
| `cd [path]` | Changes the per-session directory after `stat` confirms a directory. |
| `cat file` | Streams a file through `open`, `read`, and `close`, resuming on SSH channel credit. |
| `stat path` | Prints type, unsigned 64-bit size, modification time, and four-digit octal permissions from `stat`. |
| `rm file` | Removes a non-directory entry through `remove`. |
| `mkdir dir` | Creates a directory through `makeDirectory` with requested mode `0755`. |
| `rmdir dir` | Removes an empty directory through `removeDirectory`. |
| `mv from to` | Renames or moves an entry through `rename`. |
| `cp from to` | Copies a file through bounded `open`, `read`, `write`, `close`, `stat`, and `remove` operations. |
| `exit` or `quit` | Sends the selected exit status and closes after pending output. |

The commands do not implement recursion, wildcards, quoting, pipes,
redirection, ownership, symbolic links, or external programs. `rm` does not
remove directories, and `rmdir` removes only an empty directory. Paths with
spaces are not accepted by the two-path `cp` and `mv` syntax.

An interactive shell prints `sharkssh:/path> ` after each completed command.
An exec request runs exactly one built-in or registered command, sends its exit
status, EOF, and close, and does not print a prompt.

## Copy behavior

`cp` opens the source for reading and creates a new destination. It refuses to
replace an existing destination. The plugin first requests
`SharkSshFsOpenExclusive`, providing an atomic existing-target check when the
filesystem supports it. If exclusive create returns
`SharkSshFsUnsupported`, it uses `stat` followed by ordinary create; that
fallback is necessarily not atomic.

This distinction matters for the BAS [`IoIntf` adapter](bas-io.md), because
generic `IoIntf` has no exclusive-create operation. The standalone filesystem
or an RTOS adapter can implement the exclusive flag atomically.

Copy data uses the existing fixed shell output storage as a private transfer
buffer while no channel output is pending. Both file handles and partial-write
offsets remain in the per-session object. The platform `cooperate` callback is
called between completed chunks. A read, write, or close failure removes the
partial destination when `remove` is available; destruction also closes both
handles and removes an unfinished destination.

Copy is not an `IoIntf` or
[`SharkSshFileSystem`](../filesystem.md) primitive. It is constructed
from the portable callbacks and therefore works with any adapter satisfying
the required contracts.

## Filesystem policy and audit

Paths are canonicalized to slash-separated, client-visible absolute paths.
Repeated separators and `.` are removed, `..` is clamped at the filesystem
root, and drive-colon components are rejected before callbacks run. The
filesystem adapter must still confine its root and define symlink policy.

`authorizeFile(context, channel, operation, path, target)` receives canonical
client-visible paths. `target` is nonempty only for `mv` and `cp`. Return
`SharkSshOk` to allow the operation and nonzero to deny it. Operations are the
`SharkSshShellFsOperation` values.

`auditFile(context, event)` receives the channel, operation, canonical path,
optional target, and final filesystem status. Spans and the event are
transient. File contents are never included. Listing, reading, stat,
navigation, denied requests, mutations, and completed or failed copies are
audited when the callback is installed.

## Custom commands

Each `SharkSshShellCommand` contains a command `name`, optional `help` text,
and `run(context, shell, argument)`. The argument is a transient counted span.
Every registered command is appended to `help`. Return zero after queueing a
successful response. Use:

- `SharkSshShell_write` or `SharkSshShell_writeText` for bounded output;
- `SharkSshShell_setExitStatus` to select the exec or close status;
- `SharkSshShell_requestClose` to close after pending output; and
- `SharkSshShell_setDirectory` and `SharkSshShell_getDirectory` for the
  per-session virtual path.

A custom command whose output does not fit must use its own bounded service
state and `SharkSshChannel_writeSome`; it should not enlarge the plugin into a
general process or pipe manager.

## Terminal behavior and memory bounds

`SharkSshShell_pty` parses the SSH `ECHO`, `ECHOE`, `ECHONL`, and `ECHOCTL`
terminal modes. A PTY defaults to character echo and destructive erase when a
client omits those modes. Input is not echoed without a PTY or when the PTY
disables `ECHO`.

The object contains all mutable storage and performs no allocation. These
macros are configurable at build time:

| Macro | Default | Purpose |
| --- | ---: | --- |
| `SHARKSSH_SHELL_LINE_SIZE` | 128 | Maximum command-line bytes. |
| `SHARKSSH_SHELL_INPUT_SIZE` | `SHARKSSH_SHELL_LINE_SIZE` | Pending pasted input retained while output is blocked. |
| `SHARKSSH_SHELL_OUTPUT_SIZE` | `SHARKSSH_MAX_PATH_LEN + 64` | Prompt, help, listing, file-read, copy, and custom-command buffer. |

If a line or pending-input bound is exceeded, the plugin returns
`SharkSshErrBounds`; no unbounded buffer is created. Ctrl+C selects exit
status 130 and closes the shell. Peer EOF closes an interactive shell after
pending output.

## Public API

`SharkSshShell_constructor` clears an object and retains its non-owning config
pointer. `SharkSshShell_destructor` closes active filesystem handles and
removes an incomplete copy target. `SharkSshShell_pty` applies terminal modes.
`SharkSshShell_start` initializes interactive mode and
`SharkSshShell_execute` initializes one-command exec mode. `data`, `eof`, and
`writable` implement the matching `SharkSshServices` callbacks. The remaining
write, exit-status, close, and directory helpers support custom commands.
