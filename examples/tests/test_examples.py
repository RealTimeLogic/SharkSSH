#!/usr/bin/env python3
"""Protocol integration tests for SharkSSH filesystem examples."""

from __future__ import annotations

import argparse
import contextlib
import glob
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from typing import Callable, Iterator

try:
    import paramiko
except ImportError:
    print(
        "ERROR: Paramiko is required. Run: "
        "py -3 -m pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(2)


USERNAME = "testuser"
PASSWORD = "test-password"
HOST = "127.0.0.1"
PROMPT = re.compile(rb"sharkssh:/[^>\r\n]*> $")
TIMEOUT = 8.0


class SharkSshTransport(paramiko.Transport):
    """Expose Paramiko's Curve25519 implementation under the RFC 8731 name."""

    _preferred_kex = ("curve25519-sha256",) + paramiko.Transport._preferred_kex
    _kex_info = dict(paramiko.Transport._kex_info)
    _kex_info["curve25519-sha256"] = _kex_info[
        "curve25519-sha256@libssh.org"
    ]


@dataclass(frozen=True)
class Target:
    name: str
    project: str
    set_permissions: bool
    set_time: bool
    set_size: bool
    set_file_size: bool
    random_write: bool
    exclusive_create: bool
    concurrent: bool


TARGETS = {
    target.name: target
    for target in (
        Target(
            "03-sftp-selib",
            "03-sftp-selib.vcxproj",
            True,
            True,
            True,
            True,
            True,
            True,
            False,
        ),
        Target(
            "03-sftp-sodisp",
            "03-sftp-sodisp.vcxproj",
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        ),
        Target(
            "04-bas-sftp-sodisp",
            "04-bas-sftp-sodisp.vcxproj",
            False,
            False,
            False,
            False,
            False,
            False,
            True,
        ),
    )
}


class TestFailure(RuntimeError):
    pass


class Checks:
    def __init__(self) -> None:
        self.count = 0

    def true(self, condition: bool, message: str) -> None:
        self.count += 1
        if not condition:
            raise TestFailure(message)

    def equal(self, actual: object, expected: object, message: str) -> None:
        self.true(actual == expected, f"{message}: {actual!r} != {expected!r}")

    def contains(self, text: str, expected: str, message: str) -> None:
        self.true(expected in text, f"{message}: {expected!r} not in {text!r}")


class ShellSession:
    def __init__(self, client: paramiko.SSHClient) -> None:
        self.channel = client.invoke_shell(term="xterm", width=80, height=24)
        self.channel.settimeout(TIMEOUT)
        initial = self._read_prompt()
        if b"SharkSSH management shell" not in initial:
            raise TestFailure(f"shell banner missing: {initial!r}")

    def _read_prompt(self) -> bytes:
        data = bytearray()
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
                if PROMPT.search(bytes(data)):
                    return bytes(data)
            elif self.channel.closed:
                break
            else:
                time.sleep(0.01)
        raise TestFailure(f"timed out waiting for shell prompt: {bytes(data)!r}")

    def run(self, command: str) -> str:
        self.channel.sendall((command + "\r").encode("utf-8"))
        response = self._read_prompt()
        prefix = (command + "\r\n").encode("utf-8")
        if not response.startswith(prefix):
            raise TestFailure(f"shell did not echo {command!r}: {response!r}")
        body = response[len(prefix) :]
        prompt = PROMPT.search(body)
        if not prompt or prompt.end() != len(body):
            raise TestFailure(f"malformed shell response: {response!r}")
        return (
            body[: prompt.start()]
            .decode("utf-8", "replace")
            .replace("\r\n", "\n")
            .rstrip("\n")
        )

    def exit(self) -> str:
        self.channel.sendall(b"exit\r")
        data = bytearray()
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                data.extend(self.channel.recv(4096))
            elif self.channel.closed or self.channel.exit_status_ready():
                break
            else:
                time.sleep(0.01)
        self.channel.close()
        return bytes(data).decode("utf-8", "replace").replace("\r\n", "\n")


class ExampleServer:
    def __init__(self, executable: Path, root: Path) -> None:
        self.executable = executable
        self.root = root
        self.port = reserve_port()
        self.log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            [str(executable), str(self.port)],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )

    def wait(self) -> None:
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise TestFailure(
                    f"server exited with {self.process.returncode}:\n{self.output()}"
                )
            try:
                with socket.create_connection((HOST, self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise TestFailure(f"server did not listen on port {self.port}")

    def output(self) -> str:
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind((HOST, 0))
        return int(listener.getsockname()[1])


def connect(
    port: int, password: str = PASSWORD, username: str = USERNAME
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            HOST,
            port=port,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=TIMEOUT,
            banner_timeout=TIMEOUT,
            auth_timeout=TIMEOUT,
            transport_factory=SharkSshTransport,
        )
    except Exception:
        client.close()
        raise
    return client


def execute(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(command, timeout=TIMEOUT)
    output = stdout.read().decode("utf-8", "replace").replace("\r\n", "\n")
    error = stderr.read().decode("utf-8", "replace").replace("\r\n", "\n")
    return stdout.channel.recv_exit_status(), output, error


def expect_sftp_failure(checks: Checks, action: Callable[[], object], name: str) -> None:
    try:
        action()
    except (OSError, IOError):
        checks.true(True, name)
        return
    raise TestFailure(f"{name}: request unexpectedly succeeded")


def read_sftp_file(sftp: paramiko.SFTPClient, name: str) -> bytes:
    with sftp.open(name, "rb") as remote:
        return remote.read()


def expect_sftp_missing(
    sftp: paramiko.SFTPClient, checks: Checks, name: str, message: str
) -> None:
    expect_sftp_failure(checks, lambda: sftp.stat(name), message)


def test_authentication(port: int, checks: Checks) -> None:
    try:
        client = connect(port, "wrong-password")
    except paramiko.AuthenticationException:
        checks.true(True, "wrong password rejected")
    else:
        client.close()
        raise TestFailure("wrong password was accepted")

    try:
        client = connect(port, username="wrong-user")
    except paramiko.AuthenticationException:
        checks.true(True, "unknown user rejected")
    else:
        client.close()
        raise TestFailure("unknown user was accepted")


def test_concurrent_client(port: int, checks: Checks) -> None:
    with contextlib.closing(connect(port)) as second:
        status, output, error = execute(second, "pwd")
        checks.equal(status, 0, "concurrent exec status")
        checks.equal(output.strip(), "/", "concurrent exec output")
        checks.equal(error, "", "concurrent exec stderr")


def test_shell(
    port: int, root: Path | None, target: Target, checks: Checks
) -> None:
    with contextlib.closing(connect(port)) as client:
        shell = ShellSession(client)
        help_text = shell.run("help")
        for command in (
            "help",
            "pwd",
            "ls [path]",
            "cd [path]",
            "cat <file>",
            "stat <path>",
            "rm <file>",
            "mkdir <dir>",
            "rmdir <dir>",
            "mv <from> <to>",
            "cp <from> <to>",
            "exit",
        ):
            checks.contains(help_text, command, f"help lists {command}")

        checks.equal(shell.run("pwd"), "/", "initial directory")
        root_listing = shell.run("ls")
        checks.contains(root_listing, "- seed.txt", "root listing file")
        checks.contains(root_listing, "d nav", "root listing directory")

        checks.equal(shell.run("cd nav"), "", "cd output")
        checks.equal(shell.run("pwd"), "/nav", "cd retained directory")
        nav_listing = shell.run("ls")
        checks.contains(nav_listing, "- inside.txt", "relative listing")
        checks.true("seed.txt" not in nav_listing, "relative listing is not root")
        checks.equal(shell.run("cat inside.txt"), "inside-content", "relative cat")
        stat_text = shell.run("stat inside.txt")
        checks.true(
            re.fullmatch(r"file size=15 modified=\d+ permissions=\d{4}", stat_text)
            is not None,
            f"file stat output: {stat_text!r}",
        )

        checks.equal(shell.run("cd .."), "", "cd parent")
        checks.equal(shell.run("pwd"), "/", "parent directory")
        checks.contains(shell.run("ls nav"), "- inside.txt", "explicit ls path")
        checks.contains(
            shell.run("cat ../../seed.txt"),
            "seed-content\nline-two",
            "parent traversal clamps at root",
        )
        checks.equal(shell.run("cd nav/../nav/."), "", "normalized cd")
        checks.equal(shell.run("pwd"), "/nav", "normalized directory")
        checks.equal(shell.run("cd"), "", "cd without path")
        checks.equal(shell.run("pwd"), "/", "cd without path selects root")

        checks.equal(shell.run("mkdir shell-dir"), "", "mkdir")
        if root is not None:
            checks.true((root / "shell-dir").is_dir(), "mkdir changed host filesystem")
        checks.true(
            shell.run("stat shell-dir").startswith("directory "),
            "stat directory",
        )
        checks.equal(shell.run("cp seed.txt shell-copy.txt"), "", "cp")
        if root is not None:
            checks.equal(
                (root / "shell-copy.txt").read_bytes(),
                (root / "seed.txt").read_bytes(),
                "cp content",
            )
        checks.equal(shell.run("mv shell-copy.txt shell-moved.txt"), "", "mv")
        if root is not None:
            checks.true(
                (root / "shell-moved.txt").is_file()
                and not (root / "shell-copy.txt").exists(),
                "mv changed host filesystem",
            )
        checks.contains(
            shell.run("cat shell-moved.txt"),
            "seed-content\nline-two",
            "cat copied file",
        )
        checks.equal(shell.run("rm shell-moved.txt"), "", "rm")
        checks.equal(shell.run("stat shell-moved.txt"), "stat: failed", "rm removed file")
        checks.equal(shell.run("rmdir shell-dir"), "", "rmdir")
        checks.equal(shell.run("stat shell-dir"), "stat: failed", "rmdir removed directory")

        checks.equal(shell.run("cat missing.txt"), "cat: file not found", "cat error")
        checks.equal(shell.run("stat missing.txt"), "stat: failed", "stat error")
        checks.equal(
            shell.run("cd missing-directory"),
            "cd: directory not found",
            "cd error",
        )
        checks.equal(shell.run("pwd"), "/", "failed cd retains directory")
        checks.equal(shell.run("unknown-command"), "Unknown command", "unknown command")

        if target.concurrent:
            test_concurrent_client(port, checks)

        exit_text = shell.exit()
        checks.contains(exit_text, "Bye", "exit response")

    with contextlib.closing(connect(port)) as client:
        status, output, error = execute(client, "pwd")
        checks.equal(status, 0, "exec pwd status")
        checks.equal(output.strip(), "/", "exec pwd output")
        checks.equal(error, "", "exec pwd stderr")

    with contextlib.closing(connect(port)) as client:
        status, output, _ = execute(client, "stat missing.txt")
        checks.equal(status, 1, "exec failure status")
        checks.equal(output.strip(), "stat: failed", "exec failure output")


def test_sftp(
    port: int, root: Path | None, target: Target, checks: Checks
) -> None:
    with contextlib.closing(connect(port)) as client:
        with contextlib.closing(client.open_sftp()) as sftp:
            checks.equal(sftp.normalize("."), "/", "realpath root")
            names = set(sftp.listdir("/"))
            checks.true({"seed.txt", "nav"}.issubset(names), "directory listing")
            attrs = {entry.filename: entry for entry in sftp.listdir_attr("/")}
            checks.true("seed.txt" in attrs and "nav" in attrs, "directory attributes")

            seed_size = len(b"seed-content\nline-two\n")
            checks.equal(sftp.stat("/seed.txt").st_size, seed_size, "stat")
            checks.equal(sftp.lstat("/seed.txt").st_size, seed_size, "lstat")
            with sftp.open("/seed.txt", "rb") as remote:
                checks.equal(remote.stat().st_size, seed_size, "fstat")
                checks.equal(remote.read(), b"seed-content\nline-two\n", "read")
                remote.seek(5)
                checks.equal(remote.read(7), b"content", "seek and partial read")

            handles = []
            try:
                for _ in range(4):
                    handles.append(sftp.open("/seed.txt", "rb"))
                expect_sftp_failure(
                    checks,
                    lambda: sftp.open("/seed.txt", "rb"),
                    "fifth handle rejected",
                )
            finally:
                for handle in handles:
                    handle.close()

            with sftp.open("/sftp-file.bin", "wb") as remote:
                remote.write(b"0123456789")
            checks.equal(read_sftp_file(sftp, "/sftp-file.bin"), b"0123456789", "write")
            with sftp.open("/sftp-file.bin", "ab") as remote:
                remote.write(b"append")
            checks.equal(
                read_sftp_file(sftp, "/sftp-file.bin"),
                b"0123456789append",
                "append",
            )

            payload = bytes(range(251)) * 40
            with sftp.open("/large.bin", "wb") as remote:
                remote.MAX_REQUEST_SIZE = 1024
                remote.write(payload)
            with sftp.open("/large.bin", "rb") as remote:
                remote.MAX_REQUEST_SIZE = 1024
                checks.equal(remote.read(), payload, "multi-packet transfer")
            if target.random_write:
                with sftp.open("/sftp-file.bin", "r+b") as remote:
                    remote.seek(3)
                    remote.write(b"XYZ")
                checks.equal(
                    read_sftp_file(sftp, "/sftp-file.bin"),
                    b"012XYZ6789append",
                    "seek and overwrite",
                )
            else:
                expect_sftp_failure(
                    checks,
                    lambda: sftp.open("/sftp-file.bin", "r+b"),
                    "unsupported nontruncating write open",
                )
                checks.equal(
                    read_sftp_file(sftp, "/sftp-file.bin"),
                    b"0123456789append",
                    "unsupported write open preserves content",
                )

            if target.exclusive_create:
                with sftp.open("/exclusive.bin", "wx") as remote:
                    remote.write(b"exclusive")
                expect_sftp_failure(
                    checks,
                    lambda: sftp.open("/exclusive.bin", "wx"),
                    "exclusive create rejects existing file",
                )
            else:
                expect_sftp_failure(
                    checks,
                    lambda: sftp.open("/exclusive.bin", "wx"),
                    "unsupported exclusive create",
                )
                with sftp.open("/exclusive.bin", "wb") as remote:
                    remote.write(b"exclusive")

            sftp.rename("/sftp-file.bin", "/renamed.bin")
            checks.equal(
                read_sftp_file(sftp, "/renamed.bin"),
                b"012XYZ6789append" if target.random_write else b"0123456789append",
                "rename",
            )
            expect_sftp_missing(sftp, checks, "/sftp-file.bin", "rename removed source")
            sftp.mkdir("/sftp-dir", mode=0o750)
            checks.true(
                (sftp.stat("/sftp-dir").st_mode & 0o170000) == 0o040000,
                "mkdir",
            )
            sftp.chdir("/sftp-dir")
            checks.equal(sftp.getcwd(), "/sftp-dir", "client chdir")
            with sftp.open("nested.txt", "wb") as remote:
                remote.write(b"nested")
            checks.equal(sftp.listdir("."), ["nested.txt"], "relative directory listing")
            expect_sftp_failure(
                checks,
                lambda: sftp.rmdir("/sftp-dir"),
                "nonempty directory rejected",
            )
            sftp.remove("nested.txt")
            sftp.chdir("/")
            sftp.rmdir("/sftp-dir")
            expect_sftp_missing(sftp, checks, "/sftp-dir", "rmdir")

            if target.set_permissions:
                sftp.chmod("/renamed.bin", 0o444)
                checks.equal(
                    sftp.stat("/renamed.bin").st_mode & 0o777,
                    0o444,
                    "setstat read-only permissions",
                )
                sftp.chmod("/renamed.bin", 0o666)
                checks.equal(
                    sftp.stat("/renamed.bin").st_mode & 0o777,
                    0o666,
                    "setstat writable permissions",
                )
            else:
                expect_sftp_failure(
                    checks,
                    lambda: sftp.chmod("/renamed.bin", 0o600),
                    "unsupported permission setstat",
                )

            modified = int(time.time()) - 120
            if target.set_time:
                sftp.utime("/renamed.bin", (modified, modified))
                checks.true(
                    abs(int(sftp.stat("/renamed.bin").st_mtime) - modified) <= 2,
                    "setstat modification time",
                )
            else:
                expect_sftp_failure(
                    checks,
                    lambda: sftp.utime("/renamed.bin", (modified, modified)),
                    "unsupported time setstat",
                )

            if target.set_size:
                sftp.truncate("/renamed.bin", 8)
                checks.equal(sftp.stat("/renamed.bin").st_size, 8, "setstat size")
            else:
                expect_sftp_failure(
                    checks,
                    lambda: sftp.truncate("/renamed.bin", 4),
                    "unsupported size setstat",
                )

            if target.set_file_size:
                with sftp.open("/renamed.bin", "r+b") as remote:
                    remote.truncate(4)
                checks.equal(sftp.stat("/renamed.bin").st_size, 4, "fsetstat size")
            else:
                with sftp.open("/renamed.bin", "ab") as remote:
                    expect_sftp_failure(
                        checks,
                        lambda: remote.truncate(4),
                        "unsupported fsetstat",
                    )

            expect_sftp_failure(
                checks,
                lambda: sftp.symlink("/seed.txt", "/link.txt"),
                "unsupported symlink",
            )
            expect_sftp_failure(
                checks,
                lambda: sftp.readlink("/seed.txt"),
                "unsupported readlink",
            )
            expect_sftp_failure(
                checks,
                lambda: sftp.posix_rename("/renamed.bin", "/extension.bin"),
                "unsupported posix-rename extension",
            )
            expect_sftp_failure(
                checks,
                lambda: sftp.stat("/missing.txt"),
                "missing path",
            )
            checks.equal(
                sftp.normalize("/nav/../."),
                "/",
                "normalized parent path",
            )
            with sftp.open("/../../seed.txt", "rb") as remote:
                checks.equal(
                    remote.read(),
                    b"seed-content\nline-two\n",
                    "SFTP parent traversal clamps at root",
                )
            expect_sftp_failure(
                checks,
                lambda: sftp.stat("/bad:name"),
                "colon path rejected",
            )
            expect_sftp_failure(
                checks,
                lambda: sftp.stat("/bad\\name"),
                "backslash path rejected",
            )

            sftp.remove("/renamed.bin")
            sftp.remove("/exclusive.bin")
            sftp.remove("/large.bin")
            expect_sftp_missing(sftp, checks, "/renamed.bin", "remove renamed file")
            expect_sftp_missing(sftp, checks, "/exclusive.bin", "remove exclusive file")
            expect_sftp_missing(sftp, checks, "/large.bin", "remove large file")


def test_sftp_disconnect_cleanup(
    port: int, root: Path | None, checks: Checks
) -> None:
    client = connect(port)
    sftp = client.open_sftp()
    remote = sftp.open("/abandoned.bin", "wb")
    remote.write(b"unfinished")
    client.close()

    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        try:
            with contextlib.closing(connect(port)) as cleanup_client:
                with contextlib.closing(cleanup_client.open_sftp()) as cleanup_sftp:
                    cleanup_sftp.remove("/abandoned.bin")
                    expect_sftp_missing(
                        cleanup_sftp,
                        checks,
                        "/abandoned.bin",
                        "abandoned file removable",
                    )
            checks.true(True, "disconnect closes abandoned SFTP handle")
            return
        except (OSError, EOFError, paramiko.SSHException):
            time.sleep(0.05)
    raise TestFailure("SFTP handle remained locked after disconnect")


def make_fixture(root: Path) -> None:
    (root / "seed.txt").write_bytes(b"seed-content\nline-two\n")
    (root / "nav").mkdir()
    (root / "nav" / "inside.txt").write_bytes(b"inside-content\n")


def remove_remote_file(sftp: paramiko.SFTPClient, name: str) -> None:
    try:
        sftp.remove(name)
    except OSError:
        pass


def remove_remote_directory(sftp: paramiko.SFTPClient, name: str) -> None:
    try:
        sftp.rmdir(name)
    except OSError:
        pass


def prepare_remote_fixture(port: int) -> None:
    with contextlib.closing(connect(port)) as client:
        with contextlib.closing(client.open_sftp()) as sftp:
            for name in (
                "/nav/inside.txt",
                "/shell-copy.txt",
                "/shell-moved.txt",
                "/sftp-file.bin",
                "/renamed.bin",
                "/exclusive.bin",
                "/large.bin",
                "/sftp-dir/nested.txt",
                "/abandoned.bin",
                "/seed.txt",
            ):
                remove_remote_file(sftp, name)
            for name in ("/sftp-dir", "/shell-dir", "/nav"):
                remove_remote_directory(sftp, name)
            sftp.mkdir("/nav")
            with sftp.open("/seed.txt", "wb") as remote:
                remote.write(b"seed-content\nline-two\n")
            with sftp.open("/nav/inside.txt", "wb") as remote:
                remote.write(b"inside-content\n")


def cleanup_remote_fixture(port: int) -> None:
    try:
        with contextlib.closing(connect(port)) as client:
            with contextlib.closing(client.open_sftp()) as sftp:
                for name in (
                    "/nav/inside.txt",
                    "/shell-copy.txt",
                    "/shell-moved.txt",
                    "/sftp-file.bin",
                    "/renamed.bin",
                    "/exclusive.bin",
                    "/large.bin",
                    "/sftp-dir/nested.txt",
                    "/abandoned.bin",
                    "/seed.txt",
                ):
                    remove_remote_file(sftp, name)
                for name in ("/sftp-dir", "/shell-dir", "/nav"):
                    remove_remote_directory(sftp, name)
    except (OSError, EOFError, paramiko.SSHException):
        pass


def locate_msbuild() -> Path:
    found = shutil.which("MSBuild.exe") or shutil.which("msbuild")
    if found:
        return Path(found)
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    candidates = glob.glob(
        str(
            Path(program_files)
            / "Microsoft Visual Studio"
            / "*"
            / "*"
            / "MSBuild"
            / "Current"
            / "Bin"
            / "MSBuild.exe"
        )
    )
    if not candidates:
        raise TestFailure("MSBuild.exe was not found; omit --build or install Visual Studio")
    return Path(sorted(candidates)[-1])


def build_targets(vc_dir: Path, targets: list[Target]) -> None:
    msbuild = locate_msbuild()
    for target in targets:
        print(f"BUILD {target.name}")
        subprocess.run(
            [
                str(msbuild),
                str(vc_dir / target.project),
                "/t:Rebuild",
                "/p:Configuration=Debug",
                "/p:Platform=Win32",
                "/nologo",
                "/verbosity:minimal",
            ],
            check=True,
        )


@contextlib.contextmanager
def test_root(target: Target, keep: bool) -> Iterator[Path]:
    if keep:
        root = Path(tempfile.mkdtemp(prefix=f"sharkssh-{target.name}-"))
        print(f"ROOT  {root}")
        yield root
    else:
        with tempfile.TemporaryDirectory(prefix=f"sharkssh-{target.name}-") as name:
            yield Path(name)


def test_target(executable: Path, target: Target, keep_root: bool) -> int:
    checks = Checks()
    with test_root(target, keep_root) as root:
        make_fixture(root)
        server = ExampleServer(executable, root)
        try:
            server.wait()
            test_authentication(server.port, checks)
            test_shell(server.port, root, target, checks)
            test_sftp(server.port, root, target, checks)
            test_sftp_disconnect_cleanup(server.port, root, checks)
        except Exception:
            output = server.output()
            if output:
                print(f"--- {target.name} server output ---\n{output}", file=sys.stderr)
            raise
        finally:
            server.close()
    return checks.count


def test_remote_target(target: Target, port: int) -> int:
    checks = Checks()
    try:
        deadline = time.monotonic() + 30.0
        while True:
            try:
                with socket.create_connection((HOST, port), timeout=1.0):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TestFailure(
                        f"remote server did not listen at {HOST}:{port}"
                    )
                time.sleep(0.25)
        prepare_remote_fixture(port)
        test_authentication(port, checks)
        test_shell(port, None, target, checks)
        test_sftp(port, None, target, checks)
        test_sftp_disconnect_cleanup(port, None, checks)
    finally:
        cleanup_remote_fixture(port)
    return checks.count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        action="append",
        choices=tuple(TARGETS),
        help="test one target; repeat to select more than one",
    )
    parser.add_argument("--build", action="store_true", help="rebuild before testing")
    parser.add_argument(
        "--host",
        help="test an already-running remote target instead of a local executable",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="remote SSH port used with --host (default: 22)",
    )
    parser.add_argument(
        "--esp32",
        action="store_true",
        help="use ESP-IDF FAT filesystem capabilities with --host",
    )
    parser.add_argument(
        "--keep-root",
        action="store_true",
        help="retain each temporary filesystem root",
    )
    return parser.parse_args()


def main() -> int:
    global HOST
    args = parse_args()
    selected = [TARGETS[name] for name in (args.target or TARGETS)]
    if args.host:
        if args.build:
            raise TestFailure("--build cannot be used with --host")
        if len(selected) != 1:
            raise TestFailure("--host requires exactly one --target")
        HOST = args.host
        target = selected[0]
        if args.esp32 and target.name.startswith("03-sftp-"):
            target = replace(
                target,
                set_permissions=False,
                set_file_size=False,
            )
        print(f"TEST  {target.name} at {HOST}:{args.port}")
        count = test_remote_target(target, args.port)
        print(f"PASS  {target.name}: {count} checks")
        return 0
    if args.esp32:
        raise TestFailure("--esp32 requires --host")

    vc_dir = Path(__file__).resolve().parents[1] / "build" / "VC-Win"
    bin_dir = vc_dir / "obj" / "Debug-Win32"
    if args.build:
        build_targets(vc_dir, selected)

    total = 0
    for target in selected:
        executable = bin_dir / f"{target.name}.exe"
        if not executable.is_file():
            raise TestFailure(f"missing {executable}; rerun with --build")
        print(f"TEST  {target.name}")
        count = test_target(executable, target, args.keep_root)
        total += count
        print(f"PASS  {target.name}: {count} checks")
    print(f"PASS  all targets: {total} checks")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (TestFailure, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
