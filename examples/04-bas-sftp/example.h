#ifndef _SharkSshBasIoExample_h
#define _SharkSshBasIoExample_h

#include <SharkSshBasIo.h>
#include "../03-sftp/sftpExample.h"

#if ! SHARKSSL_BA
#error The BAS IoIntf example requires a BAS/BWS SharkSSL configuration
#endif /* ! SHARKSSL_BA */

/** Permanent BAS IoIntf adapter and shell/SFTP state for example 04. */
typedef struct
{
   SharkSshBasIo fileSystemAdapter; /**< Generic-I/O filesystem adapter. */
   SharkSshSftpExample sftp; /**< Shared shell and SFTP feature set. */
} SharkSshBasIoExample;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Construct the BAS/BWS example around an existing generic I/O interface.
 *
 * @param example Permanent example storage to initialize.
 * @param authenticator Password and/or public-key callbacks to copy.
 * @param io Existing BAS generic I/O interface; it is not owned.
 * @param allocator Per-session allocation callbacks.
 * @param readOnly Nonzero to reject mutating shell and SFTP operations.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshBasIoExample_constructor(
   SharkSshBasIoExample* example,
   const SharkSshAuthenticator* authenticator,
   IoIntfPtr io,
   const SharkSshExampleAllocator* allocator,
   U8 readOnly);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshBasIoExample_h */
