/* Example 04 entry point: shell and SFTP using the BAS IoIntf adapter. */

#include "example.h"
#include <BaDiskIo.h>
#include <stdlib.h>
#include <string.h>

#ifndef SHARKSSH_EXAMPLE_ROOT
#define SHARKSSH_EXAMPLE_ROOT "."
#endif /* SHARKSSH_EXAMPLE_ROOT */

/** Host demonstration state combining DiskIo with the BAS SSH example. */
typedef struct
{
   DiskIo diskIo; /**< BAS disk interface rooted for the demonstration. */
   SharkSshBasIoExample ssh; /**< BAS adapter plus shell/SFTP service. */
} SharkSshBasSftpApplication;

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

/** Adapt the supplied BAS I/O interface and construct shell plus SFTP. */
int
SharkSshBasIoExample_constructor(
   SharkSshBasIoExample* example,
   const SharkSshAuthenticator* authenticator,
   IoIntfPtr io,
   const SharkSshExampleAllocator* allocator,
   U8 readOnly)
{
   const SharkSshFileSystem* fileSystem;
   if( ! example || ! io)
      return SharkSshErrArgument;
   memset(example, 0, sizeof(*example));
   SharkSshBasIo_constructor(&example->fileSystemAdapter, io);
   fileSystem = SharkSshBasIo_getFileSystem(&example->fileSystemAdapter);
   return SharkSshSftpExample_constructor(
      &example->sftp, authenticator, fileSystem, allocator, readOnly);
}

/**
 * Install example 04's BAS-backed shell and SFTP service.
 *
 * The shared startup modules call this after constructing the example state.
 */
int
SharkSshExample_configure(SharkSshConfig* config,
                          SharkSshRsaHostKey* rsaHostKey,
                          SharkSslRSAKey privateKey,
                          void* exampleContext)
{
   SharkSshBasIoExample* example =
      (SharkSshBasIoExample*)exampleContext;
   if( ! example)
      return SharkSshErrArgument;
   return SharkSshSftpExample_configure(
      config, rsaHostKey, privateKey, &example->sftp);
}

#ifndef SHARKSSH_EXAMPLE_CUSTOM_APPLICATION
#define SHARKSSH_EXAMPLE_CUSTOM_APPLICATION 0
#endif /* SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */

#if !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION

static SharkSshBasSftpApplication defaultApplication;

/**
 * Construct the default DiskIo-backed example used by shared startup.
 *
 * The returned static context has process or firmware lifetime.
 */
int
SharkSshExample_constructor(void** exampleContext)
{
   SharkSshAuthenticator authenticator;
   SharkSshExampleAllocator allocator;
   int status;
   if( ! exampleContext)
      return SharkSshErrArgument;
   *exampleContext = 0;
   memset(&authenticator, 0, sizeof(authenticator));
   authenticator.password = authenticatePassword;
   memset(&allocator, 0, sizeof(allocator));
   allocator.allocate = allocateMemory;
   allocator.release = releaseMemory;
   DiskIo_constructor(&defaultApplication.diskIo);
   if(DiskIo_setRootDir(&defaultApplication.diskIo, SHARKSSH_EXAMPLE_ROOT))
      return SharkSshErrService;
   status = SharkSshBasIoExample_constructor(
      &defaultApplication.ssh, &authenticator,
      (IoIntfPtr)&defaultApplication.diskIo.super, &allocator, 0);
   if( ! status)
      *exampleContext = &defaultApplication.ssh;
   return status;
}

#endif /* !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */
