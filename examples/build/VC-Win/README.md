# Visual C++ example projects

These projects are the shortest Windows route to a running SharkSSH example.
They build the complete [example set](../../README.md) as 32-bit Debug console
applications with
[Visual Studio 2022](https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170)
and its `v143` toolset. Install the Desktop development with C++ workload
before opening them. The SoDisp projects use Barracuda App Server (BAS) and
Barracuda Web Server (BWS).

## Required source layout

The projects contain no machine-specific absolute paths. They expect the
dependency directories beside the SharkSSH repository:

```text
parent-directory/
|-- SharkSSH/
|   `-- examples/build/VC-Win/
|-- SharkSSL/    required by *-selib.vcxproj
`-- BAS/         required by *-sodisp.vcxproj
```

A [`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html)
project uses only `SharkSSH` and
[`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL). A
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
project uses only `SharkSSH` and
[`BAS`](https://github.com/RealTimeLogic/BAS/); `BAS/src/BWS.c` already
contains SharkSSL. Do not add standalone `SharkSSL.c` or `selib.c` to a SoDisp
project. Keep all three trees when you want to build every row below.

The exact roots from a project file are:

```text
SharkSSH  $(ProjectDir)..\..\..
SharkSSL  $(ProjectDir)..\..\..\..\SharkSSL
BAS       $(ProjectDir)..\..\..\..\BAS
```

## Choose a project

| Example | Standalone SharkSSL/selib | BAS/BWS SoDisp |
| --- | --- | --- |
| 01 minimal | `01-minimal-selib.vcxproj` | `01-minimal-sodisp.vcxproj` |
| 02 shell | `02-shell-selib.vcxproj` | `02-shell-sodisp.vcxproj` |
| 03 host SFTP | `03-sftp-selib.vcxproj` | `03-sftp-sodisp.vcxproj` |
| 04 BAS SFTP | Not applicable | `04-bas-sftp-sodisp.vcxproj` |

Example 04 has no selib project because BAS `IoIntf` selects the BAS/BWS
SharkSSL and thread configuration. Every SoDisp project compiles exactly one
amalgamation, `BAS/src/BWS.c`; it does not also compile standalone SharkSSL.

## Build and run

1. Open the selected `.vcxproj` directly in Visual Studio.
2. Select `Debug` and `Win32`.
3. Build and run the project.
4. Connect from a second terminal with the example account.

The optional command-line argument is the SSH port. Omitting it selects port
22; use 2222 if port 22 is already occupied or Visual Studio is not running
with permission to bind a privileged port. Configure an argument in
**Project Properties > Debugging > Command Arguments**, or run the executable
from a command prompt:

```bat
obj\Debug-Win32\03-sftp-selib.exe 2222
```

Output and independent intermediate directories are under `obj/Debug-Win32`
and are ignored by Git. The demonstration login is `testuser` with password
`test-password`.

Examples 03 and 04 expose the process working directory as their demonstration
filesystem root. Set Visual Studio's Debugging Working Directory to a
dedicated test directory before running either project. Never run these
development examples from a directory containing sensitive files.

Connect to a server on port 2222 with, for example:

```bat
ssh -p 2222 testuser@localhost
sftp -P 2222 testuser@localhost
```

When prompted, enter the example password `test-password`.
For example 01, run `ssh -p 2222 testuser@localhost status`. The expected
output is `device is ready`.

The compiled private host key and login are public test material. Replace both
before using any example as the starting point for a product.

Use the [Python host integration suite](../../tests/README.md) to rebuild and
exercise every shell command and SFTP operation against examples 03 and 04 in
isolated temporary directories.
