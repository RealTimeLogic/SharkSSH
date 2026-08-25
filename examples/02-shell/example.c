/* Example 02 entry point: bounded shell without filesystem callbacks. */

#include "shellExample.h"
#include <stdlib.h>
#include <string.h>

/** Compare a temporary SSH byte span with a NUL-terminated literal. */
static int
spanEquals(SharkSshSpan span, const char* text)
{
   U32 size = (U32)strlen(text);
   return span.len == size && ! memcmp(span.ptr, text, size);
}

/** Accept only the deliberately simple credentials used by this host demo. */
static int
authenticatePassword(void* context, SharkSshSpan user,
                     SharkSshSpan password)
{
   (void)context;
   return spanEquals(user, "testuser") &&
      spanEquals(password, "test-password") ? SharkSshOk : SharkSshErrAuth;
}

/** Allocate per-channel shell state using the C heap. */
static void*
allocateMemory(void* context, U32 size)
{
   (void)context;
   return malloc(size);
}

/** Release shell state allocated by the example's heap allocator. */
static void
releaseMemory(void* context, void* memory)
{
   (void)context;
   free(memory);
}

/**
 * Install the shell API demonstration without a physical filesystem.
 *
 * It rejects accidental attachment of a filesystem to keep this example
 * focused on shell API wiring rather than storage.
 */
int
SharkSshExample_configure(SharkSshConfig* config,
                          SharkSshRsaHostKey* rsaHostKey,
                          SharkSslRSAKey privateKey,
                          void* exampleContext)
{
   SharkSshShellExample* example =
      (SharkSshShellExample*)exampleContext;
   if(example && example->shellConfig.fileSystem)
      return SharkSshErrArgument;
   return SharkSshShellExample_configure(
      config, rsaHostKey, privateKey, example);
}

#ifndef SHARKSSH_EXAMPLE_CUSTOM_APPLICATION
#define SHARKSSH_EXAMPLE_CUSTOM_APPLICATION 0
#endif /* SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */

#if !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION

static SharkSshShellExample defaultExample;

/**
 * Construct the default no-filesystem shell used by shared startup modules.
 *
 * The returned static context has process or firmware lifetime.
 */
int
SharkSshExample_constructor(void** exampleContext)
{
   SharkSshAuthenticator authenticator;
   SharkSshExampleAllocator allocator;
   SharkSshShellConfig shellConfig;
   int status;
   if( ! exampleContext)
      return SharkSshErrArgument;
   memset(&authenticator, 0, sizeof(authenticator));
   authenticator.password = authenticatePassword;
   memset(&allocator, 0, sizeof(allocator));
   allocator.allocate = allocateMemory;
   allocator.release = releaseMemory;
   memset(&shellConfig, 0, sizeof(shellConfig));
   shellConfig.banner =
      "SharkSSH shell API test; no physical file system is connected\r\n";
   status = SharkSshShellExample_constructor(
      &defaultExample, &authenticator, &allocator, &shellConfig);
   *exampleContext = status ? 0 : &defaultExample;
   return status;
}

#endif /* !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */
