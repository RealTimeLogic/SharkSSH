/* Reusable BAS/BWS SoDisp startup for every feature example. */

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif /* _CRT_SECURE_NO_WARNINGS */
#ifndef _CRT_RAND_S
#define _CRT_RAND_S
#endif /* _CRT_RAND_S */
#endif /* _WIN32 */

#include "soDispStartup.h"
#include "applicationStartup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if SHARKSSH_SODISP_MAIN && !defined(NO_MAIN)
#include <HttpTrace.h>
#endif /* SHARKSSH_SODISP_MAIN && !defined(NO_MAIN) */

/** Attach and bind a dedicated SSH listener on an existing dispatcher. */
int
SharkSshSoDispStartup_start(SharkSshSoDispStartup* startup,
                            HttpServer* httpServer,
                            SharkSslRSAKey privateKey,
                            void* exampleContext,
                            U16 port, U16 maxConnections,
                            const SharkSshConnectionAllocator* allocator)
{
   int status;
   if( ! startup || ! httpServer || ! privateKey || ! exampleContext ||
      ! port || ! maxConnections)
      return SharkSshErrArgument;
   memset(startup, 0, sizeof(*startup));
   status = SharkSshExample_configure(
      &startup->config, &startup->rsaHostKey, privateKey, exampleContext);
   if(status)
      return status;

   SharkSshServer_constructor(&startup->server, &startup->config,
                              httpServer);
   startup->constructed = 1;
   status = allocator ? SharkSshServer_setConnectionAllocator(
      &startup->server, allocator) : SharkSshOk;
   if( ! status)
      status = SharkSshServer_setMaxConnections(&startup->server,
                                                 maxConnections);
   if( ! status)
      status = SharkSshServer_bind(&startup->server, port);
   if(status)
      SharkSshSoDispStartup_destructor(startup);
   return status;
}

/** Stop the dedicated SSH listener without canceling active workers. */
void
SharkSshSoDispStartup_stop(SharkSshSoDispStartup* startup)
{
   if(startup && startup->constructed)
      SharkSshServer_stop(&startup->server);
}

/** Return nonzero once the constructed listener has no active workers. */
int
SharkSshSoDispStartup_canDestroy(SharkSshSoDispStartup* startup)
{
   return startup && startup->constructed &&
      SharkSshServer_activeConnections(&startup->server) == 0;
}

/** Destroy the SSH listener after its workers have finished. */
void
SharkSshSoDispStartup_destructor(SharkSshSoDispStartup* startup)
{
   if(startup && startup->constructed)
   {
      SharkSshServer_destructor(&startup->server);
      startup->constructed = 0;
   }
}

#if SHARKSSH_SODISP_CREATE_SERVER || SHARKSSH_SODISP_MAIN

/** Create a small BAS/BWS host and run its dispatcher until told to stop. */
int
SharkSshSoDispStartup_run(
   SharkSslRSAKey privateKey, void* exampleContext,
   U16 port, U16 maxConnections,
   const SharkSshConnectionAllocator* allocator, volatile U8* run)
{
   ThreadMutex mutex;
   SoDisp dispatcher;
   HttpServer httpServer;
   SharkSshSoDispStartup startup;
   int status;
   if( ! privateKey || ! exampleContext || ! port || ! maxConnections ||
      ! run)
      return SharkSshErrArgument;
   memset(&startup, 0, sizeof(startup));
   ThreadMutex_constructor(&mutex);
   SoDisp_constructor(&dispatcher, &mutex);
   HttpServer_constructor(&httpServer, &dispatcher, 0);
   status = SharkSshSoDispStartup_start(
      &startup, &httpServer, privateKey, exampleContext,
      port, maxConnections, allocator);
   if( ! status)
   {
      while(*run)
         SoDisp_run(&dispatcher, 1000);
      SharkSshSoDispStartup_stop(&startup);
      while( ! SharkSshSoDispStartup_canDestroy(&startup))
         SoDisp_run(&dispatcher, 1000);
      SharkSshSoDispStartup_destructor(&startup);
   }
   HttpServer_destructor(&httpServer);
   SoDisp_destructor(&dispatcher);
   ThreadMutex_destructor(&mutex);
   return status;
}

/** Prepare common application state and enter the SoDisp server loop. */
int
SharkSshSoDispStartup_runApplication(
   const SharkSshApplicationConfig* application)
{
   void* exampleContext;
   volatile U8 run = 1;
   int status = sharkSshApplicationPrepare(application, &exampleContext);
   return status ? status : SharkSshSoDispStartup_run(
      application->privateKey, exampleContext,
      application->port ? application->port : 22,
      application->maxConnections ? application->maxConnections : 4,
      application->connectionAllocator, &run);
}

#endif /* SHARKSSH_SODISP_CREATE_SERVER || SHARKSSH_SODISP_MAIN */

#if SHARKSSH_SODISP_MAIN && !defined(NO_MAIN)

#ifdef HTTP_TRACE
/** Forward one BAS/BWS trace fragment to standard error. */
static void
sharkSshHostWriteTrace(char* buffer, int length)
{
   fwrite(buffer, 1, (size_t)length, stderr);
   fflush(stderr);
}
#endif /* HTTP_TRACE */

/** Report an unrecoverable BAS/BWS error and terminate the host process. */
static void
sharkSshHostFatalError(BaFatalErrorCodes error,
                       unsigned int detail,
                       const char* file,
                       int line)
{
   fprintf(stderr,
           "Fatal Barracuda error: error=%d detail=%u file=%s line=%d\n",
           (int)error, detail, file, line);
   fflush(stderr);
#ifdef HTTP_TRACE
   HttpTrace_flush();
#endif /* HTTP_TRACE */
   abort();
}

/** Install host trace and fatal-error reporting for the optional `main`. */
static void
sharkSshHostTraceStart(void)
{
#ifdef HTTP_TRACE
   if( ! HttpTrace_getFLushCallback())
   {
      HttpTrace_setFLushCallback(sharkSshHostWriteTrace);
      if(HttpTrace_getFLushCallback() == sharkSshHostWriteTrace)
         HttpTrace_setPrio(10);
   }
#endif /* HTTP_TRACE */
   HttpServer_setErrHnd(sharkSshHostFatalError);
}

/** Report a normal startup failure through HttpTrace or standard error. */
static void
sharkSshHostReportError(int status)
{
#ifdef HTTP_TRACE
   if(HttpTrace_getFLushCallback())
   {
      HttpTrace_printf(0, "SharkSSH startup failed, status=%d\n", status);
      HttpTrace_flush();
      return;
   }
#endif /* HTTP_TRACE */
   fprintf(stderr, "SharkSSH startup failed, status=%d\n", status);
}

#if SHARKSSH_SODISP_APPLICATION_HOOKS

/**
 * Host entry point that obtains startup settings from an application hook.
 *
 * @param argc Command-line argument count.
 * @param argv Command-line argument vector.
 * @return Zero after an orderly server stop, otherwise one.
 */
int
main(int argc, char** argv)
{
   SharkSshSoDispApplication application;
   volatile U8 run = 1;
   int status = SharkSshOk;

   sharkSshHostTraceStart();

#ifdef _WIN32
   {
      WSADATA wsaData;
      if(WSAStartup(MAKEWORD(2,2), &wsaData))
         status = SharkSshErrSocket;
   }
#endif /* _WIN32 */

   if( ! status)
   {
      memset(&application, 0, sizeof(application));
      status = SharkSshSoDispApplication_constructor(
         &application, argc, argv);
      if( ! status)
      {
         status = SharkSshSoDispStartup_run(
            application.privateKey, application.exampleContext,
            application.port, application.maxConnections,
            application.connectionAllocator, &run);
      }
   }
   if(status)
      sharkSshHostReportError(status);
   return status ? 1 : 0;
}

#else

#include "hostMain.h"

/**
 * Host entry point for any SoDisp-compatible feature example.
 *
 * With the built-in example key, the optional argument is the TCP port. With
 * an external key build, arguments are `host-key.pem [port]`. Port 22 is used
 * when omitted.
 *
 * @param argc Command-line argument count.
 * @param argv Command-line argument vector.
 * @return Zero after an orderly server stop, otherwise one.
 */
int
main(int argc, char** argv)
{
   SharkSshApplicationConfig application;
   SharkSshExampleHost host;
   int status;

   sharkSshHostTraceStart();
   status = SharkSshExampleHost_constructor(&host, argc, argv);
   if( ! status)
   {
      memset(&application, 0, sizeof(application));
      application.privateKey = host.privateKey;
      application.getEntropy = sharkSshExampleGetEntropy;
      application.constructExample = SharkSshExample_constructor;
      application.port = host.port;
      application.maxConnections = SHARKSSH_SODISP_MAX_CONNECTIONS;
      status = SharkSshSoDispStartup_runApplication(&application);
   }
   if(status)
      sharkSshHostReportError(status);
   return status ? 1 : 0;
}

#endif /* SHARKSSH_SODISP_APPLICATION_HOOKS */

#endif /* SHARKSSH_SODISP_MAIN && !defined(NO_MAIN) */
