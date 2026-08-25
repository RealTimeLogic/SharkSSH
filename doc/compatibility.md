# SSH client compatibility

Use this page to decide whether an SSH or Secure File Transfer Protocol (SFTP)
client is suitable for a SharkSSH product. SharkSSH deliberately implements
one compact, modern
[SSH profile](design/overview.md#supported-protocol-profile). A client must
offer all of these algorithms:

- `curve25519-sha256` for key exchange;
- `rsa-sha2-256` for server and user signatures;
- `aes128-ctr` for encryption;
- `hmac-sha2-256` for packet integrity; and
- no compression.

The table below records clients that completed real protocol sessions. Treat
it as a validation baseline, then retest the exact client version and settings
that the product will support.

## Why older clients can fail

Older clients that do not offer every algorithm in this profile cannot
connect. This is intentional: SharkSSH does not fall back to SHA-1 signatures,
legacy Diffie-Hellman groups, CBC ciphers, or other obsolete algorithms merely
for client compatibility. Update or replace the client instead of weakening
the server profile.

In particular, the tested PuTTY 0.70 and 0.71 clients do not offer the
standard `curve25519-sha256` key-exchange name required by SharkSSH. Current
PuTTY, OpenSSH, WinSCP, and wolfSSH versions should still be validated in the
configuration a product intends to support.

## Validated clients

The following clients completed real exec or SFTP sessions through both
the standalone [`SharkSSL`](https://github.com/RealTimeLogic/SharkSSL)/
[`selib`](https://realtimelogic.com/ba/doc/en/C/shark/group__selib.html)
transport and the Barracuda App Server (BAS) or Barracuda Web Server (BWS)
[`SoDisp`](https://realtimelogic.com/ba/doc/en/C/reference/html/structSoDisp.html)
transport:

| Client | Version | Validated operations |
| --- | --- | --- |
| [OpenSSH for Windows](https://www.openssh.com/) | 9.5p2 | Password and public-key authentication, exec, pseudo-terminal shell, SFTP, rekey, keepalive, and negative protocol cases |
| [PuTTY Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) | 0.85 | Password-authenticated exec and clean channel shutdown |
| [PuTTY PSFTP](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) | 0.85 | SFTP upload, download, and remove |
| [WinSCP](https://winscp.net/downloads.php) | 6.5.6 | SFTP upload, download, and remove |
| [wolfSSH and wolfSFTP](https://github.com/wolfSSL/wolfssh) | 1.5.0 with wolfSSL 5.9.2 | Password-authenticated exec plus SFTP upload and download |

Other versions may also work. A product should still retest every client and
configuration it ships or supports.

## Compatibility bounds

`SHARKSSH_MAX_KEXINIT_LEN` defaults to 2048 bytes. PuTTY 0.85 sends a
1697-byte KEXINIT payload with its default algorithm list, so reducing this
limit below the default can reject a valid modern client before negotiation.
The buffer is stored per connection and can still be reduced by products that
control and test every permitted client.

The SFTP plugin defaults `SHARKSSH_SFTP_PACKET_SIZE` to 4096. OpenSSH learns
this limit through `limits@openssh.com`. Clients that do not use that extension
can send a larger write request; configure their transfer block size or raise
the compile-time SFTP packet limit after accounting for per-session memory.
See the
[SFTP plugin guide](plugins/sftp.md#memory-bounds-and-client-compatibility).

Channel requests and zero-length channel data already in flight when SharkSSH
sends channel close are ignored after their common framing is validated. No
application callback or reply is generated. This permits clean shutdown with
clients that queue an empty stdin write, terminal update, or shutdown request
concurrently with server-side exec completion. Non-empty post-close data is
still rejected.
