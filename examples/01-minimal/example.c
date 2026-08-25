/* Smallest feature example: authentication and one fixed exec command. */

#include "example.h"
#include <stdlib.h>
#include <string.h>

/** Pending output for the example's one supported `status` command. */
typedef struct
{
   const U8* output; /**< Static response bytes currently being sent. */
   U32 size; /**< Total response size. */
   U32 offset; /**< Bytes already accepted by the SSH channel. */
} MinimalCommand;

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

/** Allocate one minimal-command state object using the C heap. */
static void*
allocateMemory(void* context, U32 size)
{
   (void)context;
   return malloc(size);
}

/** Release memory allocated by the example's heap allocator. */
static void
releaseMemory(void* context, void* memory)
{
   (void)context;
   free(memory);
}

/** Authorize only an exec request whose complete command is `status`. */
static int
authorizeService(void* context, SharkSshChannel* channel,
                 const SharkSshAuthorization* request)
{
   (void)context;
   (void)channel;
   return request->serviceType == SharkSshServiceExec &&
          spanEquals(request->request, "status") ?
      SharkSshOk : SharkSshErrAuth;
}

/** Allocate and attach per-channel state before the command starts. */
static int
openCommand(void* context, SharkSshChannel* channel, SharkSshSpan user)
{
   SharkSshMinimalExample* example = (SharkSshMinimalExample*)context;
   MinimalCommand* command;
   (void)user;
   command = (MinimalCommand*)example->allocator.allocate(
      example->allocator.context, (U32)sizeof(*command));
   if( ! command)
      return SharkSshErrBounds;
   memset(command, 0, sizeof(*command));
   channel->userData = command;
   return SharkSshOk;
}

/** Detach and free the per-channel command state. */
static void
closeCommand(void* context, SharkSshChannel* channel)
{
   SharkSshMinimalExample* example = (SharkSshMinimalExample*)context;
   void* command = channel->userData;
   channel->userData = 0;
   if(command)
      example->allocator.release(example->allocator.context, command);
}

/** Select the fixed response for an authorized `status` command. */
static int
executeCommand(void* context, SharkSshChannel* channel,
               SharkSshSpan request)
{
   static const U8 response[] = "device is ready\r\n";
   MinimalCommand* command = (MinimalCommand*)channel->userData;
   (void)context;
   if( ! command || ! spanEquals(request, "status"))
      return SharkSshErrService;
   command->output = response;
   command->size = sizeof(response) - 1;
   return SharkSshOk;
}

/** Resume response output and close the channel when it is fully sent. */
static int
writeCommand(void* context, SharkSshChannel* channel)
{
   MinimalCommand* command = (MinimalCommand*)channel->userData;
   U32 written = 0;
   int status;
   (void)context;
   if( ! command || ! command->output)
      return SharkSshErrState;
   status = SharkSshChannel_writeSome(
      channel, command->output + command->offset,
      command->size - command->offset, &written);
   command->offset += written;
   if(status)
      return status;
   status = SharkSshChannel_sendExitStatus(channel, 0);
   return status ? status : SharkSshChannel_close(channel);
}

/** Construct the minimal example from copied authentication and allocation hooks. */
int
SharkSshMinimalExample_constructor(
   SharkSshMinimalExample* example,
   const SharkSshAuthenticator* authenticator,
   const SharkSshExampleAllocator* allocator)
{
   if( ! example || ! authenticator ||
      (! authenticator->password && ! authenticator->publicKey) ||
      ! allocator || ! allocator->allocate || ! allocator->release)
      return SharkSshErrArgument;
   memset(example, 0, sizeof(*example));
   example->authenticator = *authenticator;
   example->allocator = *allocator;
   return SharkSshOk;
}

/** Construct the minimal example with its documented host-test defaults. */
int
SharkSshMinimalExample_constructorDefault(SharkSshMinimalExample* example)
{
   SharkSshAuthenticator authenticator;
   SharkSshExampleAllocator allocator;
   memset(&authenticator, 0, sizeof(authenticator));
   authenticator.password = authenticatePassword;
   memset(&allocator, 0, sizeof(allocator));
   allocator.allocate = allocateMemory;
   allocator.release = releaseMemory;
   return SharkSshMinimalExample_constructor(
      example, &authenticator, &allocator);
}

/**
 * Install the minimal example's host key, login, and exec callbacks.
 *
 * The shared startup modules call this after constructing the example state.
 */
int
SharkSshExample_configure(SharkSshConfig* config,
                          SharkSshRsaHostKey* rsaHostKey,
                          SharkSslRSAKey privateKey,
                          void* exampleContext)
{
   SharkSshMinimalExample* example =
      (SharkSshMinimalExample*)exampleContext;
   if( ! config || ! rsaHostKey || ! privateKey || ! example)
      return SharkSshErrArgument;
   SharkSshConfig_constructor(config);
   SharkSshRsaHostKey_constructor(rsaHostKey, privateKey);
   SharkSshRsaHostKey_set(&config->hostKey, rsaHostKey);
   config->authenticator = example->authenticator;
   config->services.context = example;
   config->services.authorize = authorizeService;
   config->services.open = openCommand;
   config->services.close = closeCommand;
   config->services.exec = executeCommand;
   config->services.writable = writeCommand;
   return SharkSshOk;
}


#ifndef SHARKSSH_EXAMPLE_CUSTOM_APPLICATION
#define SHARKSSH_EXAMPLE_CUSTOM_APPLICATION 0
#endif /* SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */

#if !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION

static SharkSshMinimalExample defaultExample;

/**
 * Construct the default minimal example used by the shared startup modules.
 *
 * The returned static context has process or firmware lifetime.
 */
int
SharkSshExample_constructor(void** exampleContext)
{
   int status;
   if( ! exampleContext)
      return SharkSshErrArgument;
   status = SharkSshMinimalExample_constructorDefault(&defaultExample);
   *exampleContext = status ? 0 : &defaultExample;
   return status;
}

#endif /* !SHARKSSH_EXAMPLE_CUSTOM_APPLICATION */
