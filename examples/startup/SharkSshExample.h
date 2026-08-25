#ifndef _SharkSshExample_h
#define _SharkSshExample_h

#include <SharkSSH.h>

/** Memory callbacks used by examples that need dynamically allocated state. */
typedef struct
{
   void* context; /**< Value passed unchanged to both callbacks. */
   /** Allocate at least `size` bytes, or return `NULL` on failure. */
   void* (*allocate)(void* context, U32 size);
   /** Release memory previously returned by @ref allocate. */
   void (*release)(void* context, void* memory);
} SharkSshExampleAllocator;

/**
 * Fill a buffer with cryptographically secure random bytes.
 *
 * @param context Platform-specific entropy context.
 * @param buffer Destination buffer.
 * @param size Number of random bytes required.
 * @return @ref SharkSshOk on success, or a negative status.
 */
typedef int (*SharkSshEntropySource)(void* context, U8* buffer, U32 size);

/**
 * Construct the permanent context for one selected feature example.
 *
 * @param exampleContext Receives the example-owned context on success.
 * @return @ref SharkSshOk on success, or a negative status.
 */
typedef int (*SharkSshExampleConstructor)(void** exampleContext);

/** Shared inputs consumed by the reusable selib and SoDisp startup modules. */
typedef struct
{
   SharkSslRSAKey privateKey; /**< Parsed host private key, not owned. */
   SharkSshEntropySource getEntropy; /**< Required platform entropy source. */
   void* entropyContext; /**< Context passed to @ref getEntropy. */
   SharkSshExampleConstructor constructExample; /**< Selected example hook. */
#if SHARKSSL_BA
   /** Optional SoDisp connection-worker allocator. */
   const SharkSshConnectionAllocator* connectionAllocator;
#endif /* SHARKSSL_BA */
   U16 port; /**< TCP port; zero selects the default port 22. */
#if SHARKSSL_BA
   U16 maxConnections; /**< Concurrent clients; zero selects four. */
#endif /* SHARKSSL_BA */
} SharkSshApplicationConfig;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Construct the permanent context for the linked feature example.
 *
 * Exactly one example supplies this common hook to the startup module.
 *
 * @param exampleContext Receives the example-owned context on success.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshExample_constructor(void** exampleContext);

/**
 * Configure SharkSSH for the linked feature example.
 *
 * Exactly one example supplies this common hook. The startup module calls it
 * after constructing the example context and before binding the listener.
 *
 * @param config SharkSSH configuration to initialize and populate.
 * @param rsaHostKey Host-key adapter storage to initialize.
 * @param privateKey Parsed RSA host private key, not owned.
 * @param exampleContext Context returned by `SharkSshExample_constructor`.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshExample_configure(SharkSshConfig* config,
                              SharkSshRsaHostKey* rsaHostKey,
                              SharkSslRSAKey privateKey,
                              void* exampleContext);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshExample_h */
