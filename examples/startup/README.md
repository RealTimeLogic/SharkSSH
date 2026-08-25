# Shared startup modules

These modules connect one numbered feature example to one TCP transport. They
belong to the example harness, not to the SharkSSH core library.

You do not need to understand them to run a prepared example. Use one of the
prepared
[Visual C++](../build/VC-Win/README.md),
[POSIX](../build/POSIX/README.md), or
[ESP-IDF](../build/ESP32/README.md) builds instead. Read this document when
porting an example, supplying a real-time operating system (RTOS) entry point,
or reusing the common startup behavior.

| Application environment | Startup source | Connection model |
| --- | --- | --- |
| Standalone SharkSSL | `selibStartup.c` | The calling task accepts and serves connections serially |
| Existing Barracuda App Server (BAS) or Barracuda Web Server (BWS) | `soDispStartup.c` | SoDisp accepts connections and SharkSSH uses one worker per connection |
| Example-owned BAS/BWS server | `soDispStartup.c` with an ownership macro | The module creates and runs the dispatcher and server |

Every feature example implements the same transport-neutral function:

```c
int SharkSshExample_configure(SharkSshConfig* config,
                              SharkSshRsaHostKey* rsaHostKey,
                              SharkSslRSAKey privateKey,
                              void* exampleContext);
```

Compile exactly one numbered feature example, then select one startup module:

- `selibStartup.c` implements the blocking accept/run loop for standalone
  [`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL) and
  [`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html).
- `soDispStartup.c` registers a listener with an existing Barracuda
  [`HttpServer`](https://realtimelogic.com/ba/doc/en/C/reference/html/structHttpServer.html)
  or can optionally construct its own server and
  [`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html).

The selected example owns authentication and service callbacks. The startup
module owns `SharkSshConfig`, the RSA host-key adapter, and the server object.
Consequently, changing transport does not change shell, SFTP, filesystem,
authentication, or authorization behavior.

The startup module must match the linked dependency. `selibStartup.c` is
compiled with standalone `SharkSSL.c` and `selib.c`. `soDispStartup.c` is
compiled with one BAS/BWS amalgamation and its platform dispatcher/thread
sources; it must not be combined with standalone `SharkSSL.c` or `selib.c`.
See the repository [dependency layout](../../README.md#arrange-the-source-trees).

After constructing the selected feature's context, standalone startup is:

```c
static volatile U8 run = TRUE;

status = SharkSshSelibStartup_run(socketContext, privateKey,
                                  &exampleContext, 22, &run);
```

The function accepts and serves clients until the application changes `run`
to false as an administrative shutdown action. A session ending because of
`exit`, Ctrl+C, peer EOF, a socket error, or a client disconnect must not
change `run`; the listener continues serving later clients. A target that
permits concurrent standalone clients can replace this small serial launcher
with its own accept-task/worker-task policy without changing the feature entry
function.

## Use the device-lifetime entry points

The normal embedded entry points construct the selected example and run for
the lifetime of the device:

```c
SharkSshApplicationConfig application = {0};

application.privateKey = privateKey;
application.getEntropy = getEntropy;
application.entropyContext = entropyContext;
application.constructExample = SharkSshExample_constructor;

status = SharkSshSelibStartup_runApplication(socketContext, &application);
```

For SoDisp, use the same configuration with:

```c
application.connectionAllocator = 0;
application.maxConnections = 0;
status = SharkSshSoDispStartup_runApplication(&application);
```

`port == 0` selects port 22. In a SoDisp build, `maxConnections == 0`
selects four connections and `connectionAllocator == NULL` selects the
BAS/BWS allocator. The entropy callback fills the requested byte buffer and
returns `SharkSshOk`; the shared startup code feeds that entropy to SharkSSL.

These functions do not accept a run flag and do not call an example or host
destructor. After successful initialization they normally do not return. A
return value therefore reports an initialization failure or an unrecoverable
transport error. Products that support server shutdown or restart use the
lower-level lifecycle APIs instead.

An RTOS entry point initializes its network interface, waits until it has an
address, selects a protected host key, and supplies the platform entropy
callback. For example, an ESP-IDF entry point can call `esp_fill_random` from
its entropy callback and then call either application startup function. No
ESP-IDF code is required in the shared startup modules.

## Use the optional host `main`

On a host platform, `selibStartup.c` also supplies `main` unless `NO_MAIN` is
defined. A platform for which `HOST_PLATFORM` is false can enable the same
entry point by defining `SHARKSSH_SELIB_MAIN=1`. `soDispStartup.c` supplies
the equivalent entry point when `SHARKSSH_SODISP_MAIN=1` is defined.

The selected example implements one constructor. It does not contain
transport, argument, host-key, entropy, or teardown logic. Every release
example supplies a host-test constructor by default; define
`SHARKSSH_EXAMPLE_CUSTOM_APPLICATION=1` to replace it. A product filesystem,
allocator, authenticator, or another platform object can be installed by
providing:

```c
static MyApplication myApplication;

int
SharkSshExample_constructor(void** exampleContext)
{
   /* Construct authentication, allocation, filesystem, and services. */
   *exampleContext = &myApplication.example;
   return SharkSshOk;
}
```

Both supplied entry points accept `program [port]`; omitting the argument
selects port 22. They initialize Winsock on Windows, seed SharkSSL from the
host operating system, select the shared development host key, and call the
same permanent application startup function. They do not perform application,
socket-library, host-key, trace, or example teardown. The constructor must
leave its output context null when it returns an error.

Define `SHARKSSH_EXAMPLE_EXTERNAL_HOST_KEY=1` to compile PEM file loading
instead of the shared key. The syntax then becomes
`program host-key.pem [port]`, still defaulting to port 22. This option
requires the SharkSSL PEM API.

Define `NO_MAIN` when the product already owns `main` or an RTOS entry point
such as `app_main`. In that case its task calls the applicable
`runApplication` function directly.

## Shared development host key

`exampleHostKey.h` contains one 2048-bit RSA private key in SharkSSL's binary
key format. It is included only by the optional selib or SoDisp host launcher
and is shared by all selected feature examples. This keeps the example
command line small, avoids filesystem and PEM conversion dependencies by
default, and gives every example the same SSH host fingerprint.

The published private key is development material. Never use it as the host
identity of a product or deployed device. Production code passes a unique,
protected `SharkSslRSAKey` to the startup API.

The header was produced by generating a temporary RSA PEM key and converting
it with the SharkSSL `SharkSSLParseKey` command-line tool. That tool converts
keys; it does not generate RSA key material. Its C-vector output was named
`sharkSshExampleHostKey` and made `static const` for safe inclusion by one
selected startup translation unit. The temporary PEM key was not retained.

## Choose a SoDisp ownership model

`soDispStartup.c` supports three build modes:

| Definitions | Server and entry-point ownership |
| --- | --- |
| Neither macro defined | The application supplies an existing `HttpServer`. This is the default and adds no owned-server or `main` code. |
| `SHARKSSH_SODISP_CREATE_SERVER=1` | The module can construct `ThreadMutex`, `SoDisp`, and `HttpServer`; the application supplies its entry point. |
| `SHARKSSH_SODISP_MAIN=1` | The module includes owned-server support and supplies `main`. |

Defining `NO_MAIN` suppresses `main`. Thus, defining both
`SHARKSSH_SODISP_MAIN=1` and `NO_MAIN` also makes only the owned-server API
available.

### Existing Barracuda server

With an already operating Barracuda dispatcher, startup remains:

```c
SharkSshSoDispStartup startup;

status = SharkSshSoDispStartup_start(&startup, httpServer, privateKey,
                                     &exampleContext, 22, 4,
                                     &connectionAllocator);
```

Pass `NULL` as the final argument to use the BAS/BWS allocator, or supply a
synchronized fixed connection pool. The plugin-session allocator remains part
of the selected feature context because it is shared by both transports.

On shutdown, call `SharkSshSoDispStartup_stop`, continue operating the
dispatcher until `SharkSshSoDispStartup_canDestroy` is true, and then call
`SharkSshSoDispStartup_destructor`.

### Owned server without `main`

Define `SHARKSSH_SODISP_CREATE_SERVER=1` and call the permanent application
entry point:

```c
SharkSshApplicationConfig application = {0};

application.privateKey = privateKey;
application.getEntropy = getEntropy;
application.constructExample = SharkSshExample_constructor;
status = SharkSshSoDispStartup_runApplication(&application);
```

Use the lower-level API only when the product intentionally supports stopping
the owned server:

```c
static volatile U8 run = TRUE;

status = SharkSshSoDispStartup_run(
   privateKey, &exampleContext, 22, 4, &connectionAllocator, &run);
```

Pass `NULL` for the connection allocator to use the BAS/BWS allocator. The
run function creates the mutex, dispatcher, and `HttpServer` in that order,
using the default `HttpServer` configuration. It opens the SSH listener but
does not open an HTTP listener. When `run` becomes false, `run` closes the SSH
listener and continues dispatching until all SSH worker connections finish,
making destruction safe.

Only application or platform shutdown logic changes `run`. Session cleanup
must release its per-client resources without changing this server-lifetime
flag, including cleanup caused by `exit`, Ctrl+C, peer EOF, socket failure, or
an abrupt client disconnect.

Use the existing-server mode when the product requires a customized
`HttpServerConfig`, already runs HTTP services, or owns the dispatcher.

### Owned server with `main`

Define `SHARKSSH_SODISP_MAIN=1`. The resulting entry point uses the same
`SharkSshExample_constructor`, host-key selection, entropy callback, and
optional `[port]` argument as the selib entry point. It constructs the
dispatcher and `HttpServer`, permits four concurrent SSH connections by
default, and uses the BAS/BWS allocator for connection objects. It does not
install an application teardown path.

Override the connection limit at compile time when necessary:

```c
#define SHARKSSH_SODISP_MAX_CONNECTIONS 8
```

For example, the following builds the minimal example with the BWS
amalgamation. Run it from the parent directory containing sibling `BAS` and
`SharkSSH` directories:

```sh
gcc -o test-sodisp \
  -DSHARKSSH_SODISP_MAIN=1 \
  -IBAS/inc -IBAS/inc/arch/NET/Posix -IBAS/inc/arch/Posix \
  -ISharkSSH/inc -ISharkSSH/examples/startup \
  BAS/src/BWS.c \
  BAS/src/arch/Posix/ThreadLib.c \
  BAS/src/arch/NET/generic/SoDisp.c \
  SharkSSH/src/SharkSSH.c SharkSSH/src/SharkSshCrypto.c \
  SharkSSH/examples/startup/soDispStartup.c \
  SharkSSH/examples/01-minimal/example.c \
  -pthread
```

This command compiles exactly one amalgamation. `BWS.c` contains SharkSSL, so
do not also compile the standalone `SharkSSL.c` or `selib.c` sources.
The `_xprintf` definition used by standalone `selib` examples is not needed;
BWS sends socket and dispatcher diagnostics through `HttpTrace`.

When no callback is already configured, the optional SoDisp `main` installs a
console `HttpTrace` callback and enables trace priority 10 so startup socket
failures include the platform error. It also installs a host fatal-error
handler and reports a nonzero SharkSSH startup status before exiting. This
host setup is compiled only when
`SHARKSSH_SODISP_MAIN=1` and `NO_MAIN` is not defined. The existing-server and
owned-server-without-`main` modes do not configure the application's global
Barracuda trace or fatal-error handler.

#### Host-specific compatibility hooks

Define both `SHARKSSH_SODISP_MAIN=1` and
`SHARKSSH_SODISP_APPLICATION_HOOKS=1` only when a host test program or legacy
launcher must retain additional command-line arguments or construct objects
outside the common example lifecycle. In this mode the application implements:

```c
static MyApplication myApplication;

int
SharkSshSoDispApplication_constructor(
   SharkSshSoDispApplication* application, int argc, char** argv)
{
   /* Seed SharkSSL and construct the key, authentication, allocator,
      filesystem, and selected example context in myApplication. */
   application->privateKey = myApplication.privateKey;
   application->exampleContext = &myApplication.example;
   application->connectionAllocator = 0;
   application->port = 22;
   application->maxConnections = 4;
   return SharkSshOk;
}
```

This compatibility entry point initializes Winsock on Windows, calls the
application constructor, and enters `SharkSshSoDispStartup_run` with an
internal permanently true run flag. It does not call an application
destructor. Normal examples should use the common application startup instead.

The standalone launcher serves clients serially in its calling RTOS task.
The SoDisp launcher uses the core's dedicated worker per accepted connection.
In both cases, plugin session storage comes from the feature example's
application-supplied allocator callbacks.
