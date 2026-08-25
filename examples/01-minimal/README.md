# 01 - minimal core and exec

This is the fastest way to prove that the SharkSSH core, host key,
authentication, and selected TCP transport work together. It links no
optional plugin and accepts only the exec command `status`.

For the easiest build, choose this example's
[`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html) or
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
target in the
[Visual C++](../build/VC-Win/README.md) or
[POSIX](../build/POSIX/README.md) build guide. The selib target needs the
sibling [`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL) repository. The
SoDisp target needs the sibling
[Barracuda App Server (BAS)](https://github.com/RealTimeLogic/BAS/)
repository and does not separately link SharkSSL.

Compile `example.c`, the core, and one
[shared startup module](../startup/README.md). The example includes demo
password authentication (`testuser` / `test-password`) and a `malloc`-based
session allocator. `SharkSshMinimalExample_constructorDefault` installs
these defaults. A product can instead call `SharkSshMinimalExample_constructor`
with its own authenticator and allocator.

The authenticator may omit password authentication entirely and install only
the RSA public-key callback. Each command receives its own allocator-backed
state, so this same feature example works with serial `selib` connections and
concurrent SoDisp workers.

On a POSIX host, this complete level-01 selib server builds without another
application source file. Run the command from the parent directory that
contains sibling `SharkSSH` and `SharkSSL` directories:

```sh
gcc -o sharkssh-minimal -D_xprintf=printf \
  -ISharkSSL/inc -ISharkSSL/inc/arch/Posix \
  -ISharkSSL/src -ISharkSSL/src/arch/Posix -ISharkSSH/inc \
  SharkSSL/src/SharkSSL.c SharkSSL/src/selib.c \
  SharkSSH/src/SharkSSH.c SharkSSH/src/SharkSshCrypto.c \
  SharkSSH/examples/startup/selibStartup.c \
  SharkSSH/examples/01-minimal/example.c
```

Run it with an optional port:

```sh
./sharkssh-minimal 2222
ssh -p 2222 testuser@localhost status
```

When the SSH client prompts for a password, enter `test-password`.
The client should print `device is ready` and exit. An interactive shell or
any command other than `status` is rejected by design.

Omit the argument to use port 22. The host launcher securely seeds SharkSSL
from the host operating system and uses the shared compiled development key
described by the startup guide. The demo password and private key are not
production credentials. Define `SHARKSSH_EXAMPLE_CUSTOM_APPLICATION=1` to
replace the example lifecycle functions. Define
`SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY=1` to make the generic launcher load a
PEM host key from `host-key.pem [port]` instead.

The equivalent SoDisp source command is documented under
[owned server with `main`](../startup/README.md#owned-server-with-main). The
prepared build files are preferable for normal example use because they keep
all include paths, platform ports, and definitions together.
