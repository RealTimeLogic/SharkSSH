#ifndef _SharkSshSoDispStartup_h
#define _SharkSshSoDispStartup_h

#include "SharkSshExample.h"

#if ! SHARKSSL_BA
#error This startup module requires a BAS/BWS SharkSSL build
#endif /* ! SHARKSSL_BA */

#ifndef SHARKSSH_SODISP_CREATE_SERVER
#define SHARKSSH_SODISP_CREATE_SERVER 0
#endif /* SHARKSSH_SODISP_CREATE_SERVER */

#ifndef SHARKSSH_SODISP_MAIN
#define SHARKSSH_SODISP_MAIN 0
#endif /* SHARKSSH_SODISP_MAIN */

#ifndef SHARKSSH_SODISP_APPLICATION_HOOKS
#define SHARKSSH_SODISP_APPLICATION_HOOKS 0
#endif /* SHARKSSH_SODISP_APPLICATION_HOOKS */

#ifndef SHARKSSH_SODISP_MAX_CONNECTIONS
#define SHARKSSH_SODISP_MAX_CONNECTIONS 4
#endif /* SHARKSSH_SODISP_MAX_CONNECTIONS */

/** State owned by an application that adds SSH to an existing dispatcher. */
typedef struct
{
   SharkSshConfig config; /**< Persistent core configuration. */
   SharkSshRsaHostKey rsaHostKey; /**< Software host-key adapter. */
   SharkSshServer server; /**< Dedicated SSH listener. */
   U8 constructed; /**< Nonzero after the listener is constructed. */
} SharkSshSoDispStartup;

#if SHARKSSH_SODISP_MAIN && !defined(NO_MAIN) && \
   SHARKSSH_SODISP_APPLICATION_HOOKS
/** Optional inputs supplied by an application-defined host entry point. */
typedef struct
{
   SharkSslRSAKey privateKey; /**< Parsed host private key, not owned. */
   void* exampleContext; /**< Permanent selected-example context. */
   /** Optional connection-worker allocator. */
   const SharkSshConnectionAllocator* connectionAllocator;
   U16 port; /**< Nonzero TCP listening port. */
   U16 maxConnections; /**< Nonzero concurrent-client limit. */
} SharkSshSoDispApplication;
#endif /* SHARKSSH_SODISP_MAIN && !defined(NO_MAIN) &&
          SHARKSSH_SODISP_APPLICATION_HOOKS */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Add a dedicated SSH listener to an existing BAS/BWS server and dispatcher.
 *
 * @param startup Application-owned startup state.
 * @param httpServer Existing BAS/BWS server; it is not owned by this module.
 * @param privateKey Parsed RSA host private key, not owned.
 * @param exampleContext Permanent context for the selected feature example.
 * @param port Nonzero TCP listening port.
 * @param maxConnections Nonzero concurrent-client limit.
 * @param allocator Optional worker allocator, or `NULL` for the default.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshSoDispStartup_start(SharkSshSoDispStartup* startup,
                                HttpServer* httpServer,
                                SharkSslRSAKey privateKey,
                                void* exampleContext,
                                U16 port, U16 maxConnections,
                                const SharkSshConnectionAllocator* allocator);
/** Stop accepting new clients without interrupting active sessions. */
void SharkSshSoDispStartup_stop(SharkSshSoDispStartup* startup);
/**
 * Test whether every SSH worker has finished and destruction is now safe.
 * @return Nonzero when `SharkSshSoDispStartup_destructor` may be called.
 */
int SharkSshSoDispStartup_canDestroy(SharkSshSoDispStartup* startup);
/** Release the stopped SSH listener after all workers have finished. */
void SharkSshSoDispStartup_destructor(SharkSshSoDispStartup* startup);

#if SHARKSSH_SODISP_CREATE_SERVER || SHARKSSH_SODISP_MAIN
/**
 * Create a small BAS/BWS server and run its dispatcher for one example.
 *
 * This convenience path is for hosts and simple RTOS demos. Applications
 * with an existing dispatcher use `SharkSshSoDispStartup_start` instead.
 *
 * @param privateKey Parsed RSA host private key, not owned.
 * @param exampleContext Permanent context for the selected example.
 * @param port Nonzero TCP listening port.
 * @param maxConnections Nonzero concurrent-client limit.
 * @param allocator Optional worker allocator, or `NULL` for the default.
 * @param run Application flag; clear it to leave the dispatcher loop.
 * @return @ref SharkSshOk on orderly stop, or the failure status.
 */
int SharkSshSoDispStartup_run(
   SharkSslRSAKey privateKey, void* exampleContext,
   U16 port, U16 maxConnections,
   const SharkSshConnectionAllocator* allocator, volatile U8* run);
/** Seed SharkSSL, construct the feature example, and run SoDisp startup. */
int SharkSshSoDispStartup_runApplication(
   const SharkSshApplicationConfig* application);
#endif /* SHARKSSH_SODISP_CREATE_SERVER || SHARKSSH_SODISP_MAIN */

#if SHARKSSH_SODISP_MAIN && !defined(NO_MAIN) && \
   SHARKSSH_SODISP_APPLICATION_HOOKS
/**
 * Populate the optional SoDisp host application's startup inputs.
 *
 * Implement this hook only when both the optional `main` function and
 * application hooks are enabled.
 *
 * @param application Structure to populate.
 * @param argc Command-line argument count.
 * @param argv Command-line argument vector.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshSoDispApplication_constructor(
   SharkSshSoDispApplication* application, int argc, char** argv);
#endif /* SHARKSSH_SODISP_MAIN && !defined(NO_MAIN) &&
          SHARKSSH_SODISP_APPLICATION_HOOKS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshSoDispStartup_h */
