/* Reusable standalone SharkSSL/selib startup for every feature example. */

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif /* _CRT_SECURE_NO_WARNINGS */
#ifndef _CRT_RAND_S
#define _CRT_RAND_S
#endif /* _CRT_RAND_S */
#endif /* _WIN32 */

#include "selibStartup.h"
#include "applicationStartup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if SHARKSSL_BA
#error This startup module is for standalone SharkSSL and selib
#endif /* SHARKSSL_BA */

/** Run the standalone listener and process one accepted client at a time. */
int
SharkSshSelibStartup_run(SeCtx* socketContext,
                         SharkSslRSAKey privateKey,
                         void* exampleContext,
                         U16 port, volatile U8* run)
{
   SharkSshConfig config;
   SharkSshRsaHostKey rsaHostKey;
   SharkSshServer server;
   SharkSshCon connection;
   int status;

   if( ! privateKey || ! exampleContext || ! port || ! run)
      return SharkSshErrArgument;
   status = SharkSshExample_configure(
      &config, &rsaHostKey, privateKey, exampleContext);
   if(status)
      return status;

   SharkSshServer_constructor(&server, &config, socketContext);
   status = SharkSshServer_bind(&server, port);
   while(status == SharkSshOk && *run)
   {
      status = SharkSshServer_accept(&server, &connection, socketContext,
                                     1000);
      if(status == SharkSshTimeout)
      {
         status = SharkSshOk;
         continue;
      }
      if(status != SharkSshOk)
         break;
      (void)SharkSshCon_run(&connection);
      SharkSshCon_destructor(&connection);
   }
   SharkSshServer_destructor(&server);
   return status;
}

/** Prepare common application state and enter the standalone server loop. */
int
SharkSshSelibStartup_runApplication(
   SeCtx* socketContext, const SharkSshApplicationConfig* application)
{
   void* exampleContext;
   volatile U8 run = 1;
   int status = sharkSshApplicationPrepare(application, &exampleContext);
   return status ? status : SharkSshSelibStartup_run(
      socketContext, application->privateKey, exampleContext,
      application->port ? application->port : 22, &run);
}


#ifndef SHARKSSH_SELIB_MAIN
#define SHARKSSH_SELIB_MAIN HOST_PLATFORM
#endif /* SHARKSSH_SELIB_MAIN */

#if SHARKSSH_SELIB_MAIN && !defined(NO_MAIN)

#include "hostMain.h"

/**
 * Host-platform entry point for any standalone feature example.
 *
 * With the built-in example key, the optional argument is the TCP port. With
 * an external key build, arguments are `host-key.pem [port]`. Port 22 is used
 * when omitted.
 *
 * @param argc Command-line argument count.
 * @param argv Command-line argument vector.
 * @return Zero after an orderly server stop, otherwise one.
 */
int main(int argc, char **argv)
{
   SharkSshApplicationConfig application;
   SharkSshExampleHost host;
   int status;

   status = SharkSshExampleHost_constructor(&host, argc, argv);
   if( ! status)
   {
      memset(&application, 0, sizeof(application));
      application.privateKey = host.privateKey;
      application.getEntropy = sharkSshExampleGetEntropy;
      application.constructExample = SharkSshExample_constructor;
      application.port = host.port;
      status = SharkSshSelibStartup_runApplication(0, &application);
   }
   return status ? 1 : 0;
}
#endif /* SHARKSSH_SELIB_MAIN && !defined(NO_MAIN) */
