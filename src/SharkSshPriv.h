/* Private SharkSSH declarations. */

#ifndef _SharkSshPriv_h
#define _SharkSshPriv_h

#include <SharkSSH.h>

#define SHARKSSH_MSG_DISCONNECT                 1
#define SHARKSSH_MSG_IGNORE                     2
#define SHARKSSH_MSG_UNIMPLEMENTED              3
#define SHARKSSH_MSG_DEBUG                      4
#define SHARKSSH_MSG_SERVICE_REQUEST            5
#define SHARKSSH_MSG_SERVICE_ACCEPT             6
#define SHARKSSH_MSG_EXT_INFO                    7
#define SHARKSSH_MSG_KEXINIT                    20
#define SHARKSSH_MSG_NEWKEYS                    21
#define SHARKSSH_MSG_KEX_ECDH_INIT              30
#define SHARKSSH_MSG_KEX_ECDH_REPLY             31
#define SHARKSSH_MSG_USERAUTH_REQUEST           50
#define SHARKSSH_MSG_USERAUTH_FAILURE           51
#define SHARKSSH_MSG_USERAUTH_SUCCESS           52
#define SHARKSSH_MSG_USERAUTH_PK_OK             60
#define SHARKSSH_MSG_GLOBAL_REQUEST             80
#define SHARKSSH_MSG_REQUEST_SUCCESS            81
#define SHARKSSH_MSG_REQUEST_FAILURE            82
#define SHARKSSH_MSG_CHANNEL_OPEN               90
#define SHARKSSH_MSG_CHANNEL_OPEN_CONFIRMATION  91
#define SHARKSSH_MSG_CHANNEL_OPEN_FAILURE       92
#define SHARKSSH_MSG_CHANNEL_WINDOW_ADJUST      93
#define SHARKSSH_MSG_CHANNEL_DATA               94
#define SHARKSSH_MSG_CHANNEL_EXTENDED_DATA      95
#define SHARKSSH_MSG_CHANNEL_EOF                96
#define SHARKSSH_MSG_CHANNEL_CLOSE              97
#define SHARKSSH_MSG_CHANNEL_REQUEST            98
#define SHARKSSH_MSG_CHANNEL_SUCCESS            99
#define SHARKSSH_MSG_CHANNEL_FAILURE           100

#define SHARKSSH_DISCONNECT_PROTOCOL_ERROR       2
#define SHARKSSH_DISCONNECT_KEY_EXCHANGE_FAILED  3
#define SHARKSSH_DISCONNECT_MAC_ERROR             5
#define SHARKSSH_DISCONNECT_SERVICE_NOT_AVAILABLE 7
#define SHARKSSH_DISCONNECT_CONNECTION_LOST      10
#define SHARKSSH_DISCONNECT_BY_APPLICATION       11
#define SHARKSSH_DISCONNECT_TOO_MANY_CONNECTIONS 12

typedef struct
{
   U8* begin;
   U8* ptr;
   U8* end;
   int status;
} SharkSshWriter;

typedef struct
{
   const U8* ptr;
   const U8* end;
   int status;
} SharkSshReader;

void sharkSshWriter_constructor(SharkSshWriter* writer, U8* data, U32 size);
void sharkSshWriter_byte(SharkSshWriter* writer, U8 value);
void sharkSshWriter_u32(SharkSshWriter* writer, U32 value);
void sharkSshWriter_data(SharkSshWriter* writer, const void* data, U32 size);
void sharkSshWriter_string(SharkSshWriter* writer, const void* data, U32 size);
void sharkSshWriter_cstring(SharkSshWriter* writer, const char* value);
void sharkSshWriter_mpint(SharkSshWriter* writer, const U8* data, U32 size);
U32 sharkSshWriter_size(const SharkSshWriter* writer);

void sharkSshReader_constructor(SharkSshReader* reader,
                                const U8* data, U32 size);
U8 sharkSshReader_byte(SharkSshReader* reader);
U32 sharkSshReader_u32(SharkSshReader* reader);
SharkSshSpan sharkSshReader_string(SharkSshReader* reader);
int sharkSshReader_done(const SharkSshReader* reader);

int sharkSshX25519(U8 privateKey[32], U8 publicKey[32],
                   const U8 peerPublicKey[32], U8 sharedSecret[32]);

#endif
