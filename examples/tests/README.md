# Protocol integration tests

`test_examples.py` is the end-to-end verification suite for the filesystem
examples. It can build the Windows targets, launch each server with an isolated
temporary directory, and drive real
[SSH](https://www.rfc-editor.org/rfc/rfc4251) and
[Secure File Transfer Protocol (SFTP) version 3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
protocol connections.

Use it after changing the core, shell, SFTP plugin, filesystem adapters, or
example startup. It covers:

- rejected password authentication;
- interactive shell state, every built-in command, error responses, exec
  requests, and concurrent SoDisp clients;
- SFTP version 3 file creation, exclusive create, append, read, write, seek,
  close, stat, lstat, fstat, directory enumeration, realpath, mkdir, rmdir,
  remove, and rename;
- optional setstat and fsetstat behavior; and
- path normalization and rejection, the four-handle bound, multi-packet
  transfers, abrupt disconnect cleanup, and the expected rejection of
  symbolic-link and unadvertised extension requests.

The test does not add [Python](https://www.python.org/) or
[Paramiko](https://docs.paramiko.org/en/stable/) to SharkSSH itself. Paramiko
implements Curve25519 under the older
`curve25519-sha256@libssh.org` name. The test transport registers the
standardized `curve25519-sha256` name as an alias to that same implementation;
it does not enable a weaker SharkSSH algorithm.

Local test builds require Python 3,
[Visual Studio 2022](https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170)
with the C++ workload,
and the same sibling repositories as the example projects:

```text
parent-directory/
|-- SharkSSH/
|-- SharkSSL/    required by 03-sftp-selib
`-- BAS/         required by both *-sodisp targets
```

The [`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html)
target links standalone
[`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL). The
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
targets link the [`BAS`](https://github.com/RealTimeLogic/BAS/) amalgamation,
`BAS/src/BWS.c`, which already contains SharkSSL; they do not link the
standalone SharkSSL amalgamation.

It tests these Visual C++ executables:

| Executable | Filesystem | Concurrent clients |
| --- | --- | --- |
| `03-sftp-selib.exe` | Windows/POSIX example adapter | No |
| `03-sftp-sodisp.exe` | Windows/POSIX example adapter | Yes |
| `04-bas-sftp-sodisp.exe` | BAS `IoIntf` adapter | Yes |

## Set up and run

From `SharkSSH\examples\tests` in a Windows command prompt:

```bat
py -3 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python test_examples.py --build
```

A successful run ends with a per-target check count and no failed checks. The
script selects unused local ports, so it does not require port 22.

`--build` locates Visual Studio MSBuild and rebuilds the selected Debug Win32
projects before testing. Omit it to test the existing binaries. Select one or
more targets with repeated `--target` options:

```bat
.venv\Scripts\python test_examples.py --target 03-sftp-selib
.venv\Scripts\python test_examples.py --target 03-sftp-sodisp --target 04-bas-sftp-sodisp
```

Each server uses a dynamically selected localhost port and the example-only
`testuser` / `test-password` credentials. Test roots are deleted after the
server stops. Add `--keep-root` to retain them for inspection. The script
does not interact with an already running server.

## Test an embedded target

Use `--host` to test an already-running server instead of launching a Windows
executable. Select exactly one target profile so the suite knows which
filesystem capabilities and concurrency behavior to expect. For example, from
Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python test_examples.py \
  --host DEVICE_ADDRESS --target 03-sftp-selib --esp32
```

Replace `DEVICE_ADDRESS` with the target's IP address or hostname. Port 22 is
the default; use `--port` to override it. Remote mode creates and
removes only the fixture names used by the suite (`seed.txt`, `nav`, and the
temporary shell/SFTP test names). Run it against a test filesystem, since
pre-existing entries with those names are replaced.
The `--esp32` option models ESP-IDF FAT semantics: path-based size and
modification-time updates are supported, but POSIX permission changes and
handle-based truncation are not.

Example 04 intentionally lacks the optional `setStat` callback and BAS
`IoIntf` cannot represent atomic exclusive-create or a nontruncating random
write-open. Those requests must return unsupported without changing the
target. Examples 03 support those operations plus size, permission, and
modification-time updates through their host adapter.
