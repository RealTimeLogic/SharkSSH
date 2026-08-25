#ifndef _SharkSshExampleSftpService_h
#define _SharkSshExampleSftpService_h

#include <SharkSshShell.h>
#include <SharkSshSftp.h>
#include "../startup/SharkSshExample.h"

/** Callback multiplexer that activates either shell or SFTP per channel. */
typedef struct
{
   const SharkSshShellConfig* shellConfig; /**< Persistent shell settings. */
   const SharkSshSftpConfig* sftpConfig; /**< Persistent SFTP settings. */
   SharkSshExampleAllocator allocator; /**< Copied session allocator. */
} SharkSshExampleService;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Construct the service multiplexer used by examples 03 and 04.
 *
 * @param service Permanent service storage to initialize.
 * @param shellConfig Persistent shell configuration.
 * @param sftpConfig Persistent SFTP configuration.
 * @param allocator Allocation callbacks copied into the service.
 * @return @ref SharkSshOk on success, or @ref SharkSshErrArgument.
 */
int SharkSshExampleService_constructor(
   SharkSshExampleService* service,
   const SharkSshShellConfig* shellConfig,
   const SharkSshSftpConfig* sftpConfig,
   const SharkSshExampleAllocator* allocator);

/**
 * Install the combined shell/SFTP callbacks in a core configuration.
 *
 * @param service Constructed service that outlives all connections.
 * @param config Configuration whose service table will be replaced.
 */
void SharkSshExampleService_install(SharkSshExampleService* service,
                                    SharkSshConfig* config);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshExampleSftpService_h */
