# Shell and exec integration

This guide explains the callback boundary for an application-defined
interactive shell or one-shot command service. Use it when the product already
has a command processor or needs a custom one.

SharkSSH does not require a command interpreter, process launcher,
[POSIX API](https://pubs.opengroup.org/onlinepubs/9799919799/), or particular
terminal implementation. An application accepts or rejects SSH
shell and exec requests through `SharkSshServices` and supplies the behavior
appropriate for its product.

## Service callbacks

The core first calls `SharkSshServices.authorize` for a shell or exec request.
Only an approved request reaches `shell` or `exec`. The application then owns
the service until the channel closes and receives its input, EOF, and output-
resumption notifications through `data`, `eof`, and `writable`.

An implementation normally keeps one caller-owned state object per accepted
channel. It must:

- retain incomplete command input within a documented bound;
- honor SSH channel-window backpressure when producing output;
- preserve pending output until `writable` resumes it;
- send an exit status and close in the correct order;
- release files, command state, and other resources on EOF, disconnect, or
  service close; and
- keep filesystem, authorization, scheduling, and platform behavior behind
  callbacks rather than assuming POSIX or a real-time operating system (RTOS)
  API.

Pseudo-terminal (PTY) requests arrive separately through `pty`. Applications
that implement terminal editing should parse the SSH terminal-mode payload and
honor at least the echo modes they advertise.

## Use the provided implementation

The core can be integrated with a product-specific shell, or with the optional
[bounded `SharkSshShell` plugin](sharkssh-shell.md). That implementation is
allocation-free, supports interactive shell and single-command exec requests,
includes bounded generic filesystem commands, and provides a fixed custom-
command registry.

The plugin guide explains how to install and connect `SharkSshShell.c`, lists
its commands and public APIs, and documents its read-only, authorization,
audit, path, copy, and memory behavior.
