#ifndef _SharkSshMinimalExample_h
#define _SharkSshMinimalExample_h

#include "../startup/SharkSshExample.h"

/** Permanent configuration for the fixed-command minimal example. */
typedef struct
{
   SharkSshAuthenticator authenticator; /**< Copied login callbacks. */
   SharkSshExampleAllocator allocator; /**< Per-channel state allocator. */
} SharkSshMinimalExample;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Construct the minimal example with application-provided dependencies.
 *
 * @param example Permanent example storage to initialize.
 * @param authenticator Password and/or public-key login callbacks to copy.
 * @param allocator Allocation callbacks used for each command channel.
 * @return @ref SharkSshOk on success, or @ref SharkSshErrArgument.
 */
int SharkSshMinimalExample_constructor(
   SharkSshMinimalExample* example,
   const SharkSshAuthenticator* authenticator,
   const SharkSshExampleAllocator* allocator);

/**
 * Construct the host-test variant using `testuser` / `test-password`.
 *
 * @param example Permanent example storage to initialize.
 * @return @ref SharkSshOk on success, or a negative status.
 */
int SharkSshMinimalExample_constructorDefault(
   SharkSshMinimalExample* example);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshMinimalExample_h */
