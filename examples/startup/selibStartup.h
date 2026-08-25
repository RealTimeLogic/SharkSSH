#ifndef _SharkSshSelibStartup_h
#define _SharkSshSelibStartup_h

#include "SharkSshExample.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Run the standalone example listener and its sequential accept loop.
 *
 * @param socketContext Optional initialized `selib` platform context.
 * @param privateKey Parsed RSA host private key, not owned.
 * @param exampleContext Permanent context for the selected example.
 * @param port Nonzero TCP listening port.
 * @param run Application flag; clear it to leave the accept loop.
 * @return @ref SharkSshOk on orderly stop, or the failure status.
 */
int SharkSshSelibStartup_run(SeCtx* socketContext,
                             SharkSslRSAKey privateKey,
                             void* exampleContext,
                             U16 port, volatile U8* run);
/**
 * Seed SharkSSL, construct the feature example, and run standalone startup.
 *
 * Port zero selects TCP port 22. The example context intentionally has
 * process or firmware lifetime, matching typical embedded applications.
 *
 * @param socketContext Optional initialized `selib` platform context.
 * @param application Persistent startup inputs and callbacks.
 * @return @ref SharkSshOk on orderly stop, or the failure status.
 */
int SharkSshSelibStartup_runApplication(
   SeCtx* socketContext, const SharkSshApplicationConfig* application);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _SharkSshSelibStartup_h */
