/* Example 03 entry point: shell and SFTP on the host filesystem. */

#include "example.h"
#include <stdlib.h>
#include <string.h>

#ifndef SHARKSSH_EXAMPLE_ROOT
#define SHARKSSH_EXAMPLE_ROOT "."
#endif /* SHARKSSH_EXAMPLE_ROOT */

/** Permanent host-filesystem and shell/SFTP state for example 03. */
typedef struct
{
   SharkSshHostFileSystem fileSystem; /**< Root-confined host adapter. */
   SharkSshSftpExample sftp; /**< Combined shell and SFTP service. */
} SharkSshHostSftpApplication;

/** Accept only the deliberately simple credentials used by this host demo. */
static int
authenticatePassword(void* context, SharkSshSpan user,
                     SharkSshSpan password)
{
   static const char expectedUser[] = "testuser";
   static const char expectedPassword[] = "test-password";
   (void)context;
   return user.len == sizeof(expectedUser) - 1 &&
      password.len == sizeof(expectedPassword) - 1 &&
      ! memcmp(user.ptr, expectedUser, sizeof(expectedUser) - 1) &&
      ! memcmp(password.ptr, expectedPassword,
               sizeof(expectedPassword) - 1) ? SharkSshOk : SharkSshErrAuth;
}

/** Allocate per-session shell or SFTP state using the C heap. */
static void*
allocateMemory(void* context, U32 size)
{
   (void)context;
   return malloc((size_t)size);
}

/** Release session state allocated by the example's heap allocator. */
static void
releaseMemory(void* context, void* memory)
{
   (void)context;
   free(memory);
}

/**
 * Install example 03's combined shell and SFTP service.
 *
 * The shared startup modules call this after constructing the example state.
 */
int
SharkSshExample_configure(SharkSshConfig* config,
                          SharkSshRsaHostKey* rsaHostKey,
                          SharkSslRSAKey privateKey,
                          void* exampleContext)
{
   return SharkSshSftpExample_configure(
      config, rsaHostKey, privateKey,
      (SharkSshSftpExample*)exampleContext);
}

#ifndef SHARKSSH_EXAMPLE_CUSTOM_APPLICATION
#define SHARKSSH_EXAMPLE_CUSTOM_APPLICATION 0
#endif /* SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */

#if !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION

static SharkSshHostSftpApplication defaultApplication;

/**
 * Construct the default host-filesystem example used by shared startup.
 *
 * The returned static context has process or firmware lifetime.
 */
int
SharkSshExample_constructor(void** exampleContext)
{
   SharkSshAuthenticator authenticator;
   SharkSshExampleAllocator allocator;
   const SharkSshFileSystem* fileSystem;
   int status;
   if( ! exampleContext)
      return SharkSshErrArgument;
   *exampleContext = 0;
   memset(&authenticator, 0, sizeof(authenticator));
   authenticator.password = authenticatePassword;
   memset(&allocator, 0, sizeof(allocator));
   allocator.allocate = allocateMemory;
   allocator.release = releaseMemory;
   status = SharkSshHostFileSystem_constructor(
      &defaultApplication.fileSystem, SHARKSSH_EXAMPLE_ROOT);
   if(status)
      return status;
   fileSystem = SharkSshHostFileSystem_getFileSystem(
      &defaultApplication.fileSystem);
   status = SharkSshSftpExample_constructor(
      &defaultApplication.sftp, &authenticator, fileSystem, &allocator, 0);
   if( ! status)
      *exampleContext = &defaultApplication.sftp;
   return status;
}

#endif /* !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */
