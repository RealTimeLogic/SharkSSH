#ifndef _SharkSshShellExample_h
#define _SharkSshShellExample_h

#include "../startup/SharkSshExample.h"
#include <SharkSshShell.h>

/** Reusable shell-service state shared by examples 02 and 03. */
typedef struct
{
   SharkSshAuthenticator authenticator; /**< Copied login callbacks. */
   SharkSshExampleAllocator allocator; /**< Per-channel shell allocator. */
   SharkSshShellConfig shellConfig; /**< Copied shell plugin configuration. */
} SharkSshShellExample;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Construct the reusable shell service with application dependencies.
 *
 * @param example Permanent service storage to initialize.
 * @param authenticator Password and/or public-key callbacks to copy.
 * @param allocator Allocation callbacks used for each shell channel.
 * @param shellConfig Shell plugin settings to copy.
 * @return @ref SharkSshOk on success, or @ref SharkSshErrArgument.
 */
int SharkSshShellExample_constructor(
   SharkSshShellExample* example,
   const SharkSshAuthenticator* authenticator,
   const SharkSshExampleAllocator* allocator,
   const SharkSshShellConfig* shellConfig);

/**
 * Install the shell service in a SharkSSH configuration.
 *
 * @param config Core configuration to initialize and populate.
 * @param rsaHostKey Host-key adapter storage to initialize.
 * @param privateKey Parsed RSA host private key, not owned.
 * @param example Constructed shell service that outlives all sessions.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshShellExample_configure(
   SharkSshConfig* config, SharkSshRsaHostKey* rsaHostKey,
   SharkSslRSAKey privateKey, SharkSshShellExample* example);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshShellExample_h */
