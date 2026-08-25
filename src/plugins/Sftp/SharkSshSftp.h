/* Bounded SFTP version 3 plugin for SharkSSH. */

#ifndef _SharkSshSftp_h
#define _SharkSshSftp_h

#include <SharkSSH.h>

#ifndef SHARKSSH_SFTP_PACKET_SIZE
#define SHARKSSH_SFTP_PACKET_SIZE 4096
#endif

#ifndef SHARKSSH_SFTP_READ_SIZE
#define SHARKSSH_SFTP_READ_SIZE 1024
#endif

#ifndef SHARKSSH_SFTP_MAX_HANDLES
#define SHARKSSH_SFTP_MAX_HANDLES 4
#endif

#if SHARKSSH_SFTP_PACKET_SIZE < 512 || SHARKSSH_SFTP_PACKET_SIZE > 65531
#error SHARKSSH_SFTP_PACKET_SIZE must be in the range 512..65531
#endif

#if SHARKSSH_SFTP_READ_SIZE < 64 || \
    SHARKSSH_SFTP_READ_SIZE + 32 > SHARKSSH_SFTP_PACKET_SIZE
#error SHARKSSH_SFTP_READ_SIZE does not fit SHARKSSH_SFTP_PACKET_SIZE
#endif

#if SHARKSSH_SFTP_MAX_HANDLES < 1 || SHARKSSH_SFTP_MAX_HANDLES > 255
#error SHARKSSH_SFTP_MAX_HANDLES must be in the range 1..255
#endif

typedef struct SharkSshSftp SharkSshSftp;

typedef enum
{
   SharkSshSftpOpenRead,
   SharkSshSftpOpenWrite,
   SharkSshSftpClose,
   SharkSshSftpRead,
   SharkSshSftpWrite,
   SharkSshSftpStat,
   SharkSshSftpSetStat,
   SharkSshSftpOpenDirectory,
   SharkSshSftpReadDirectory,
   SharkSshSftpRemove,
   SharkSshSftpRename,
   SharkSshSftpMakeDirectory,
   SharkSshSftpRemoveDirectory,
   SharkSshSftpRealPath
} SharkSshSftpOperation;

typedef enum
{
   SharkSshSftpFxOk,
   SharkSshSftpFxEof,
   SharkSshSftpFxNoSuchFile,
   SharkSshSftpFxPermissionDenied,
   SharkSshSftpFxFailure,
   SharkSshSftpFxBadMessage,
   SharkSshSftpFxNoConnection,
   SharkSshSftpFxConnectionLost,
   SharkSshSftpFxUnsupported
} SharkSshSftpFxStatus;

typedef struct
{
   SharkSshChannel* channel;
   SharkSshSpan path; /* Canonical client-visible path. */
   U8 operation;      /* SharkSshSftpOperation */
   U8 status;         /* SharkSshSftpFxStatus */
} SharkSshSftpEvent;

typedef struct
{
   void* context;
   const SharkSshFileSystem* fileSystem;
   const char* root; /* Trusted filesystem-relative virtual root. */
   int (*authorize)(void* context, SharkSshChannel* channel,
                    U8 operation, SharkSshSpan path);
   void (*audit)(void* context, const SharkSshSftpEvent* event);

   /* Optional atomic-upload hooks. Paths use the filesystem namespace. */
   int (*stageUpload)(void* context, SharkSshSpan target, U32 token,
                      U8* stagePath, U16 capacity, U16* size);
   int (*commitUpload)(void* context, SharkSshSpan stagePath,
                       SharkSshSpan target);
   void (*abortUpload)(void* context, SharkSshSpan stagePath,
                       SharkSshSpan target);
   U8 readOnly;
} SharkSshSftpConfig;

typedef struct
{
   void* object;
   U32 token;
   U8 type;
   U8 flags;
   U8 staged;
   char path[SHARKSSH_MAX_PATH_LEN + 1];
   char target[SHARKSSH_MAX_PATH_LEN + 1];
} SharkSshSftpHandle;

struct SharkSshSftp
{
   const SharkSshSftpConfig* config;
   SharkSshChannel* channel;
   SharkSshSftpHandle handles[SHARKSSH_SFTP_MAX_HANDLES];
   U32 nextToken;
   U16 inputSize;
   U16 outputSize;
   U16 outputOffset;
   U16 rootSize;
   U8 initialized;
   U8 eof;
   char root[SHARKSSH_MAX_PATH_LEN + 1];
   U8 input[SHARKSSH_SFTP_PACKET_SIZE + 4];
   U8 output[SHARKSSH_SFTP_READ_SIZE + 64];
};

#ifdef __cplusplus
extern "C" {
#endif

void SharkSshSftp_constructor(SharkSshSftp* sftp,
                              const SharkSshSftpConfig* config);
void SharkSshSftp_destructor(SharkSshSftp* sftp);
int SharkSshSftp_start(SharkSshSftp* sftp, SharkSshChannel* channel);
int SharkSshSftp_data(SharkSshSftp* sftp, SharkSshChannel* channel,
                      SharkSshSpan data);
int SharkSshSftp_eof(SharkSshSftp* sftp, SharkSshChannel* channel);
int SharkSshSftp_writable(SharkSshSftp* sftp, SharkSshChannel* channel);

#ifdef __cplusplus
}
#endif

#endif
