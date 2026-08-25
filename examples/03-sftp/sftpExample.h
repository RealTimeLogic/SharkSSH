#ifndef _SharkSshSftpFeatureExample_h
#define _SharkSshSftpFeatureExample_h

#include "sftpService.h"

/** Permanent shell-and-SFTP feature configuration. */
typedef struct
{
   SharkSshAuthenticator authenticator; /**< Copied login callbacks. */
   const SharkSshFileSystem* fileSystem; /**< Shared storage adapter. */
   SharkSshShellConfig shellConfig; /**< Shell plugin settings. */
   SharkSshSftpConfig sftpConfig; /**< SFTP plugin settings. */
   SharkSshExampleService service; /**< Channel callback multiplexer. */
} SharkSshSftpExample;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Construct a shell-and-SFTP feature set around one filesystem adapter.
 *
 * @param example Permanent example storage to initialize.
 * @param authenticator Password and/or public-key callbacks to copy.
 * @param fileSystem Filesystem shared by shell and SFTP sessions.
 * @param allocator Per-session allocation callbacks.
 * @param readOnly Nonzero to reject mutating shell and SFTP operations.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshSftpExample_constructor(
   SharkSshSftpExample* example,
   const SharkSshAuthenticator* authenticator,
   const SharkSshFileSystem* fileSystem,
   const SharkSshExampleAllocator* allocator,
   U8 readOnly);

/**
 * Install a constructed shell-and-SFTP feature set in SharkSSH.
 *
 * @param config Core configuration to initialize and populate.
 * @param rsaHostKey Host-key adapter storage to initialize.
 * @param privateKey Parsed RSA host private key, not owned.
 * @param example Constructed example that outlives all sessions.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshSftpExample_configure(
   SharkSshConfig* config, SharkSshRsaHostKey* rsaHostKey,
   SharkSslRSAKey privateKey, SharkSshSftpExample* example);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshSftpFeatureExample_h */
