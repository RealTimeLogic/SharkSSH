# ESP-IDF example projects

This guide builds the two complete ESP-IDF filesystem examples for an embedded
target. One uses standalone SharkSSL and the other uses Barracuda App Server
(BAS), Barracuda Web Server (BWS), and the Barracuda socket dispatcher. Both
expose the same shell and Secure File Transfer Protocol (SFTP) behavior.

This directory contains exactly two
[ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/)
projects:

| Project | SharkSSL integration | Filesystem integration |
| --- | --- | --- |
| `03-sftp-selib` | Standalone [`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL) and [`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html) | SharkSSH callback filesystem over ESP-IDF FAT VFS |
| `04-bas-sftp-sodisp` | [`BAS/BWS`](https://github.com/RealTimeLogic/BAS/) and [`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html) | BAS [`DiskIo`](https://realtimelogic.com/ba/doc/en/C/reference/html/structDiskIo.html)/[`IoIntf`](https://realtimelogic.com/ba/doc/en/C/reference/html/structIoIntf.html) over the same FAT VFS |

Both projects use the numbered examples without copying their SSH, shell, or
SFTP logic. Shared ESP-IDF-only startup code is under `platform`. It mounts a
wear-levelled File Allocation Table (FAT) partition, seeds SharkSSL with
`esp_fill_random`, starts the
network, selects the published example host key, and calls the same
`runApplication` startup API used by the host examples.

Install and activate ESP-IDF before using
[`idf.py`](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-py.html).
You also need a board-specific network configuration, a writable FAT
partition, and the serial device used for flashing and monitoring.

The FAT filesystem is mounted at `/ssh` by default. It supports directories,
so the complete shell and SFTP examples can exercise `cd`, `mkdir`, `rm`,
directory enumeration, upload, download, and rename operations. The storage
partition is formatted automatically when it cannot be mounted. Change that
policy in `menuconfig` before using storage that must never be reformatted.

## Configure the target and board

Neither project sets `IDF_TARGET`, and no generated `sdkconfig` is checked in.
Select the CPU with the standard ESP-IDF configuration command before the
first build. For the ESP32-P4, for example:

```sh
cd examples/build/ESP32/03-sftp-selib
idf.py set-target esp32p4
idf.py menuconfig
```

Use the same commands in `04-bas-sftp-sodisp`. Replace `esp32p4` with another
ESP-IDF target name to configure another CPU. Running `set-target` creates the
project-local `sdkconfig`; the checked-in `sdkconfig.defaults` contains no
CPU or silicon-revision selection.

The default network hook uses an ESP-IDF internal EMAC with a generic PHY.
Its initial GPIO values provide one ESP32-P4 Ethernet configuration and may
not match your board. Select the target first, then adjust the PHY address and
RMII pins under `SharkSSH ESP32 example` in `menuconfig`. On a CPU without an
internal EMAC, or on a Wi-Fi/SPI-Ethernet board, add the board network source
to the project and provide a strong implementation of:

```c
int SharkSshEspNetwork_start(void);
```

The shared weak implementation then drops out at link time. The function must
return `ESP_OK` only after the interface has an IP address. This keeps CPU and
board selection outside the SSH, shell, SFTP, and filesystem code.

Target-specific settings belong in an ESP-IDF target defaults overlay. The
checked-in `sdkconfig.defaults.esp32p4` selects revision 1.0 through 1.99 and
the compatible 360 MHz CPU frequency. Review these defaults for the selected
hardware. The overlay is loaded only after selecting `esp32p4`; other CPU
targets do not consume it.

## Source layout

The projects expect sibling source trees with this layout:

```text
parent-directory/
|-- SharkSSH/
|-- SharkSSL/    required by 03-sftp-selib
`-- BAS/         required by 04-bas-sftp-sodisp
```

`03-sftp-selib` compiles the standalone SharkSSL amalgamation and `selib`.
`04-bas-sftp-sodisp` compiles exactly one BAS/BWS amalgamation (`BWS.c`), the
[FreeRTOS](https://www.freertos.org/) thread port, the
[lwIP](https://savannah.nongnu.org/projects/lwip/) dispatcher, and the POSIX
`DiskIo` adapter used
with ESP-IDF VFS. It does not compile a second SharkSSL amalgamation.

Thus, project 03 needs only the `SharkSSL` sibling, while project 04 needs only
the `BAS` sibling. Keep both dependencies when building both projects. The
ESP-IDF CMake files use these sibling names directly.

Both projects listen on port 22 and use the example-only credentials
`testuser` / `test-password`. The compiled host key is public development
material and must not be used to identify a production device.

## Build, flash, and monitor

Run build, flash, and monitor as separate commands from the selected project
directory. Replace `SERIAL_PORT` with the serial device for the connected
board:

```sh
idf.py build
idf.py -p SERIAL_PORT flash
idf.py -p SERIAL_PORT monitor
```

The monitor prints the address assigned by the network. A DHCP address may
change between boots.

When the log reports the IP address, connect from another machine with
`ssh testuser@device-address` or `sftp testuser@device-address`. A successful
shell login displays a `sharkssh:/>` prompt. When prompted, enter the example
password `test-password`.

## Verify the target

Use the [remote protocol integration suite](../../tests/README.md) to exercise
the shell and SFTP operations supported by the selected example. The SoDisp
profile also verifies a concurrent SSH client.
