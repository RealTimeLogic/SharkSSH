/* Transport-neutral bounded shell service shared by examples 02 and 03. */

#include "shellExample.h"
#include <string.h>

/** Return the shell plugin instance attached to a channel, when present. */
static SharkSshShell*
getShell(SharkSshChannel* channel)
{
   return channel ? (SharkSshShell*)channel->userData : 0;
}

/** Permit interactive shell and exec requests, but no subsystem requests. */
static int
authorizeService(void* context, SharkSshChannel* channel,
                 const SharkSshAuthorization* request)
{
   (void)context;
   (void)channel;
   return request->serviceType == SharkSshServiceShell ||
          request->serviceType == SharkSshServiceExec ?
      SharkSshOk : SharkSshErrAuth;
}

/** Allocate and construct one shell plugin instance for a channel. */
static int
openShell(void* context, SharkSshChannel* channel, SharkSshSpan user)
{
   SharkSshShellExample* example = (SharkSshShellExample*)context;
   SharkSshShell* shell;
   (void)user;
   shell = (SharkSshShell*)example->allocator.allocate(
      example->allocator.context, (U32)sizeof(*shell));
   if( ! shell)
      return SharkSshErrBounds;
   SharkSshShell_constructor(shell, &example->shellConfig);
   channel->userData = shell;
   return SharkSshOk;
}

/** Destroy and release the shell instance attached to a channel. */
static void
closeShell(void* context, SharkSshChannel* channel)
{
   SharkSshShellExample* example = (SharkSshShellExample*)context;
   SharkSshShell* shell = getShell(channel);
   channel->userData = 0;
   if(shell)
   {
      SharkSshShell_destructor(shell);
      example->allocator.release(example->allocator.context, shell);
   }
}

/** Pass terminal modes from a PTY request to the shell plugin. */
static int
setPty(void* context, SharkSshChannel* channel, SharkSshSpan terminal,
       U32 columns, U32 rows, U32 width, U32 height, SharkSshSpan modes)
{
   (void)context;
   (void)terminal;
   (void)columns;
   (void)rows;
   (void)width;
   (void)height;
   return SharkSshShell_pty(getShell(channel), modes);
}

/** Start the channel's interactive shell. */
static int
startShell(void* context, SharkSshChannel* channel)
{
   (void)context;
   return SharkSshShell_start(getShell(channel), channel);
}

/** Execute one command through the channel's shell plugin. */
static int
executeCommand(void* context, SharkSshChannel* channel,
               SharkSshSpan command)
{
   (void)context;
   return SharkSshShell_execute(getShell(channel), channel, command);
}

/** Deliver client keystrokes or other channel data to the shell plugin. */
static int
receiveData(void* context, SharkSshChannel* channel, SharkSshSpan data)
{
   (void)context;
   return SharkSshShell_data(getShell(channel), channel, data);
}

/** Tell the shell plugin that the client has finished sending input. */
static int
receiveEof(void* context, SharkSshChannel* channel)
{
   (void)context;
   return SharkSshShell_eof(getShell(channel), channel);
}

/** Resume pending shell output after the peer grants more window space. */
static int
resumeOutput(void* context, SharkSshChannel* channel)
{
   (void)context;
   return SharkSshShell_writable(getShell(channel), channel);
}

/** Copy the supplied login, allocator, and shell settings into service state. */
int
SharkSshShellExample_constructor(
   SharkSshShellExample* example,
   const SharkSshAuthenticator* authenticator,
   const SharkSshExampleAllocator* allocator,
   const SharkSshShellConfig* shellConfig)
{
   if( ! example || ! authenticator ||
      (! authenticator->password && ! authenticator->publicKey) ||
      ! allocator || ! allocator->allocate || ! allocator->release ||
      ! shellConfig)
      return SharkSshErrArgument;
   memset(example, 0, sizeof(*example));
   example->authenticator = *authenticator;
   example->allocator = *allocator;
   example->shellConfig = *shellConfig;
   return SharkSshOk;
}

/** Install the reusable shell callbacks and optional filesystem in SharkSSH. */
int
SharkSshShellExample_configure(
   SharkSshConfig* config, SharkSshRsaHostKey* rsaHostKey,
   SharkSslRSAKey privateKey, SharkSshShellExample* example)
{
   if( ! config || ! rsaHostKey || ! privateKey || ! example)
      return SharkSshErrArgument;
   SharkSshConfig_constructor(config);
   SharkSshRsaHostKey_constructor(rsaHostKey, privateKey);
   SharkSshRsaHostKey_set(&config->hostKey, rsaHostKey);
   config->authenticator = example->authenticator;
   config->fileSystem = example->shellConfig.fileSystem;
   config->services.context = example;
   config->services.authorize = authorizeService;
   config->services.open = openShell;
   config->services.close = closeShell;
   config->services.pty = setPty;
   config->services.shell = startShell;
   config->services.exec = executeCommand;
   config->services.data = receiveData;
   config->services.eof = receiveEof;
   config->services.writable = resumeOutput;
   return SharkSshOk;
}
