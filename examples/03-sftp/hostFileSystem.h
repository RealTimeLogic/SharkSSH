#ifndef _SharkSshExampleHostFileSystem_h
#define _SharkSshExampleHostFileSystem_h

#include <SharkSSH.h>

#ifndef SHARKSSH_HOST_PATH_SIZE
#define SHARKSSH_HOST_PATH_SIZE 1024
#endif /* SHARKSSH_HOST_PATH_SIZE */

/** Host-only filesystem adapter rooted beneath one canonical directory. */
typedef struct
{
   SharkSshFileSystem fileSystem; /**< Callback table exposed to SharkSSH. */
   char root[SHARKSSH_HOST_PATH_SIZE]; /**< Canonical host root path. */
} SharkSshHostFileSystem;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Construct a Windows or POSIX host-filesystem adapter.
 *
 * All client paths are confined beneath the canonical `root`. The adapter is
 * intended for host examples, not as a generic RTOS filesystem dependency.
 *
 * @param adapter Permanent adapter storage to initialize.
 * @param root Existing host directory exposed as the SSH root.
 * @return @ref SharkSshFsOk on success, or a filesystem status.
 */
int SharkSshHostFileSystem_constructor(SharkSshHostFileSystem* adapter,
                                       const char* root);
/**
 * Return the generic callback table owned by a constructed adapter.
 *
 * @param adapter Constructed host-filesystem adapter.
 * @return Its embedded filesystem table, or `NULL` for an invalid adapter.
 */
const SharkSshFileSystem*
SharkSshHostFileSystem_getFileSystem(const SharkSshHostFileSystem* adapter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshExampleHostFileSystem_h */
