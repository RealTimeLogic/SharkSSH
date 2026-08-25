/* Shared shell/SFTP service callbacks used by examples 03 and 04. */

#include "sftpService.h"
#include <string.h>

/** Memory shared by the mutually exclusive shell and SFTP plugins. */
typedef union
{
   SharkSshShell shell; /**< Active storage when the client selects shell. */
   SharkSshSftp sftp; /**< Active storage when the client selects SFTP. */
} ExamplePlugin;

/** Per-channel plugin state allocated after a session channel opens. */
typedef struct
{
   ExamplePlugin plugin; /**< Storage for the selected plugin. */
   U8 type; /**< One of the private `ExamplePlugin...` values. */
} ExampleSession;

enum
{
   ExamplePluginNone,
   ExamplePluginShell,
   ExamplePluginSftp
};

/** Compare a temporary SSH byte span with a NUL-terminated literal. */
static int
spanEquals(SharkSshSpan span, const char* text)
{
   U32 size = (U32)strlen(text);
   return span.len == size && ! memcmp(span.ptr, text, size);
}

/** Return the example session attached to a channel, when present. */
static ExampleSession*
getSession(SharkSshChannel* channel)
{
   return channel ? (ExampleSession*)channel->userData : 0;
}

/** Construct the shell plugin unless this session already selected SFTP. */
static int
activateShell(SharkSshExampleService* service, ExampleSession* session)
{
   if( ! session || session->type == ExamplePluginSftp)
      return SharkSshErrState;
   if(session->type == ExamplePluginNone)
   {
      SharkSshShell_constructor(&session->plugin.shell,
                                service->shellConfig);
      session->type = ExamplePluginShell;
   }
   return SharkSshOk;
}

/** Construct the SFTP plugin for a session that has not selected a service. */
static int
activateSftp(SharkSshExampleService* service, ExampleSession* session)
{
   if( ! session || session->type != ExamplePluginNone)
      return SharkSshErrState;
   SharkSshSftp_constructor(&session->plugin.sftp, service->sftpConfig);
   session->type = ExamplePluginSftp;
   return SharkSshOk;
}

/** Authorize shell, exec, and the specifically named `sftp` subsystem. */
static int
authorizeService(void* context, SharkSshChannel* channel,
                 const SharkSshAuthorization* request)
{
   (void)context;
   (void)channel;
   if(request->serviceType == SharkSshServiceShell ||
      request->serviceType == SharkSshServiceExec)
      return SharkSshOk;
   return request->serviceType == SharkSshServiceSubsystem &&
          spanEquals(request->request, "sftp") ?
      SharkSshOk : SharkSshErrAuth;
}

/** Allocate neutral per-channel state before a service type is selected. */
static int
openSession(void* context, SharkSshChannel* channel, SharkSshSpan user)
{
   SharkSshExampleService* service = (SharkSshExampleService*)context;
   ExampleSession* session;
   (void)user;
   session = (ExampleSession*)service->allocator.allocate(
      service->allocator.context, (U32)sizeof(*session));
   if( ! session)
      return SharkSshErrBounds;
   memset(session, 0, sizeof(*session));
   channel->userData = session;
   return SharkSshOk;
}

/** Destroy the active plugin and release the per-channel session state. */
static void
closeSession(void* context, SharkSshChannel* channel)
{
   SharkSshExampleService* service = (SharkSshExampleService*)context;
   ExampleSession* session = getSession(channel);
   if( ! session)
      return;
   channel->userData = 0;
   if(session->type == ExamplePluginShell)
      SharkSshShell_destructor(&session->plugin.shell);
   else if(session->type == ExamplePluginSftp)
      SharkSshSftp_destructor(&session->plugin.sftp);
   service->allocator.release(service->allocator.context, session);
}

/** Activate the shell, then pass it the client's PTY terminal modes. */
static int
setPty(void* context, SharkSshChannel* channel, SharkSshSpan terminal,
       U32 columns, U32 rows, U32 width, U32 height, SharkSshSpan modes)
{
   SharkSshExampleService* service = (SharkSshExampleService*)context;
   ExampleSession* session = getSession(channel);
   int status;
   (void)terminal;
   (void)columns;
   (void)rows;
   (void)width;
   (void)height;
   status = activateShell(service, session);
   return status ? status :
      SharkSshShell_pty(&session->plugin.shell, modes);
}

/** Activate and start an interactive shell. */
static int
startShell(void* context, SharkSshChannel* channel)
{
   SharkSshExampleService* service = (SharkSshExampleService*)context;
   ExampleSession* session = getSession(channel);
   int status = activateShell(service, session);
   return status ? status :
      SharkSshShell_start(&session->plugin.shell, channel);
}

/** Activate the shell plugin and execute one command. */
static int
executeCommand(void* context, SharkSshChannel* channel,
               SharkSshSpan command)
{
   SharkSshExampleService* service = (SharkSshExampleService*)context;
   ExampleSession* session = getSession(channel);
   int status = activateShell(service, session);
   return status ? status :
      SharkSshShell_execute(&session->plugin.shell, channel, command);
}

/** Activate and start the requested SFTP subsystem. */
static int
startSubsystem(void* context, SharkSshChannel* channel,
               SharkSshSpan name, const SharkSshFileSystem* fileSystem)
{
   SharkSshExampleService* service = (SharkSshExampleService*)context;
   ExampleSession* session = getSession(channel);
   int status;
   (void)fileSystem;
   if( ! spanEquals(name, "sftp"))
      return SharkSshErrService;
   status = activateSftp(service, session);
   return status ? status :
      SharkSshSftp_start(&session->plugin.sftp, channel);
}

/** Route incoming channel data to the session's active plugin. */
static int
receiveData(void* context, SharkSshChannel* channel, SharkSshSpan data)
{
   ExampleSession* session = getSession(channel);
   (void)context;
   if( ! session)
      return SharkSshErrState;
   if(session->type == ExamplePluginShell)
      return SharkSshShell_data(&session->plugin.shell, channel, data);
   if(session->type == ExamplePluginSftp)
      return SharkSshSftp_data(&session->plugin.sftp, channel, data);
   return SharkSshErrState;
}

/** Route client end-of-file notification to the active plugin. */
static int
receiveEof(void* context, SharkSshChannel* channel)
{
   ExampleSession* session = getSession(channel);
   (void)context;
   if( ! session)
      return SharkSshErrState;
   if(session->type == ExamplePluginShell)
      return SharkSshShell_eof(&session->plugin.shell, channel);
   if(session->type == ExamplePluginSftp)
      return SharkSshSftp_eof(&session->plugin.sftp, channel);
   return SharkSshErrState;
}

/** Resume pending output in the session's active plugin. */
static int
resumeOutput(void* context, SharkSshChannel* channel)
{
   ExampleSession* session = getSession(channel);
   (void)context;
   if( ! session)
      return SharkSshErrState;
   if(session->type == ExamplePluginShell)
      return SharkSshShell_writable(&session->plugin.shell, channel);
   if(session->type == ExamplePluginSftp)
      return SharkSshSftp_writable(&session->plugin.sftp, channel);
   return SharkSshErrState;
}

/** Store persistent plugin settings and copy the session allocator. */
int
SharkSshExampleService_constructor(
   SharkSshExampleService* service,
   const SharkSshShellConfig* shellConfig,
   const SharkSshSftpConfig* sftpConfig,
   const SharkSshExampleAllocator* allocator)
{
   if( ! service || ! shellConfig || ! sftpConfig || ! allocator ||
      ! allocator->allocate || ! allocator->release)
      return SharkSshErrArgument;
   memset(service, 0, sizeof(*service));
   service->shellConfig = shellConfig;
   service->sftpConfig = sftpConfig;
   service->allocator = *allocator;
   return SharkSshOk;
}

/** Populate SharkSSH's service table with the shell/SFTP multiplexer. */
void
SharkSshExampleService_install(SharkSshExampleService* service,
                               SharkSshConfig* config)
{
   config->services.context = service;
   config->services.authorize = authorizeService;
   config->services.open = openSession;
   config->services.close = closeSession;
   config->services.pty = setPty;
   config->services.shell = startShell;
   config->services.exec = executeCommand;
   config->services.subsystem = startSubsystem;
   config->services.data = receiveData;
   config->services.eof = receiveEof;
   config->services.writable = resumeOutput;
}
